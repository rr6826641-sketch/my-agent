"""Smoke test: Live Sandbox Feedback Loop Engine (task-scoped)."""
import sys
sys.path.insert(0, ".")

from ai_agent.sandbox.feedback_loop import (
    TerminalStreamAnalyzer, DynamicCommandCorrector,
    LiveFeedbackLoop, run_with_feedback,
    SIG_PROMPT, SIG_SYNTAX, SIG_DENIED, SIG_TIMEOUT)

FAILED = []


def check(name, cond, detail=""):
    print("[%s] %s %s" % ("PASS" if cond else "FAIL", name, detail))
    if not cond:
        FAILED.append(name)


# ---- 1. stream signature detection -------------------------------------
a = TerminalStreamAnalyzer()
tests = [
    ("[sudo] password for root:", SIG_PROMPT),
    ('File "x.py", line 4\nSyntaxError: invalid syntax', SIG_SYNTAX),
    ("nginx: Permission denied", SIG_DENIED),
    ("[command timed out after 60s]", SIG_TIMEOUT),
    ("bash: syntax error near unexpected token", SIG_SYNTAX),
    ("HTTP/1.1 403 Forbidden", SIG_DENIED),
    ("scan finished cleanly", None),
    ("unrecognized option '--top-portsx'", SIG_SYNTAX),
]
for text, expect in tests:
    sigs = a.analyze(text)
    got = sigs[0].kind if sigs else None
    check("detect:%s" % (expect or "none"), got == expect,
          "got=%s text=%r" % (got, text[:40]))

# priority: timeout > denied > syntax > prompt
sigs = a.analyze("SyntaxError: invalid syntax\n[command timed out after 9s]")
check("priority_timeout_first", sigs and sigs[0].kind == SIG_TIMEOUT)

# ---- 2. dynamic correction ---------------------------------------------
corr = DynamicCommandCorrector(platform="nix")
fix = corr.correct("nmap --top-portsx 100 10.0.0.1", a.analyze(
    "nmap: unrecognized option '--top-portsx'")[0], target="10.0.0.1")
check("fix_flag_typo", fix["corrected"] == "nmap --top-ports 100 10.0.0.1",
      "got=%r" % fix["corrected"])
check("reflection_rooted", bool(fix["reflection"].get("failure_root")),
      "root=%s" % fix["reflection"].get("failure_root"))

fix_t = corr.correct("nmap -T5 -sV target", a.analyze(
    "[command timed out after 45s]")[0])
check("timeout_mutation", fix_t["corrected"] == "nmap -T3 -sV target",
      "got=%r" % fix_t["corrected"])

fix_d = corr.correct("cat /etc/shadow", a.analyze(
    "cat: /etc/shadow: Permission denied")[0])
check("denied_nix_sudo", fix_d["corrected"] == "sudo cat /etc/shadow",
      "got=%r" % fix_d["corrected"])

fix_p = corr.correct("scan.sh", a.analyze("(y/n)?")[0])
check("prompt_autoanswer", fix_p["interactive_answer"] == "y")

# ---- 3. full loop with mock executor ------------------------------------
CALLS = []


def mock_executor(cmd, timeout=45):
    CALLS.append(cmd)
    if "--top-portsx" in cmd:
        return "[exit code 1]\nnmap: unrecognized option '--top-portsx'"
    return "[exit code 0]\nscan complete, 3 hosts up"


loop = LiveFeedbackLoop(executor=mock_executor, max_rounds=3)
res = loop.run("nmap --top-portsx 100 10.0.0.1", target="10.0.0.1")
check("loop_success", res["success"])
check("loop_self_healed", res["final_command"] ==
      "nmap --top-ports 100 10.0.0.1", res["final_command"])
check("loop_rounds", len(res["rounds"]) == 2)
check("loop_correction_logged",
      res["corrections"] and res["corrections"][0]["signature"] == SIG_SYNTAX)

# non-correctable failure stops cleanly
res2 = run_with_feedback(
    "totalgarbagecmd zzz", executor=lambda c, timeout=45:
        "[exit code 127]\ntotalgarbagecmd: command not found",
    max_rounds=3)
check("uncorrectable_stops", not res2["success"] and len(res2["rounds"]) <= 3)

print("\n%d failed" % len(FAILED))
sys.exit(1 if FAILED else 0)
