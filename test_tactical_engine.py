"""Unit tests for the dynamic tactical reasoning engine (Task 4).

Run:  py test_tactical_engine.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ai_agent.core as core

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] %s %s" % (name, detail))
    else:
        FAIL += 1
        print("[FAIL] %s %s" % (name, detail))


class MockLLM:
    def __init__(self):
        self.model = "mock"

    def complete(self, *a, **k):
        return "mock"

    def chat_stream(self, prompt, tools=None, cancel_event=None, model=None):
        yield {"type": "message",
               "message": {"content": "mock", "tool_calls": []}}


def run_tests():
    # ---- objective detection ------------------------------------------
    ts = core.TacticalState()
    ren = core.TacticalReasoner(ts)
    ren.detect_objective("scan http://target.local for sqli")
    check("objective_detected", ts.active and ts.objective.startswith("scan"),
          ts.objective[:50])
    check("initial_phase_recon", ts.phase == "reconnaissance", ts.phase)

    # ---- queue_vector dedup -------------------------------------------
    ts.queue_vector("sqli_test", "http://x/?id=1", "why a")
    ts.queue_vector("sqli_test", "http://x/?id=1", "why b")
    check("vector_dedup", len(ts.pending_vectors) == 1,
          str(len(ts.pending_vectors)))
    ts.queue_vector("xss_test", "http://x/?q=2", "why c")
    check("vector_distinct", len(ts.pending_vectors) == 2)

    # ---- drop_vector + mark_completed ---------------------------------
    ts.drop_vector("sqli_test", "http://x/?id=1")
    check("vector_drop", len(ts.pending_vectors) == 1)
    ts.mark_completed("xss_test http://x/?q=2")
    check("step_completed", ts.completed_steps[-1] == "xss_test http://x/?q=2")

    # ---- caps ----------------------------------------------------------
    ts2 = core.TacticalState()
    for i in range(50):
        ts2.mark_completed("step%d" % i)
    check("completed_cap_40", len(ts2.completed_steps) <= 40,
          str(len(ts2.completed_steps)))
    ts3 = core.TacticalState()
    for i in range(20):
        ts3.add_finding("sqli", "value%d" % i)
    check("findings_cap_12", len(ts3.findings) <= 12,
          str(len(ts3.findings)))

    # ---- analyze: phase + findings + chaining --------------------------
    ts4 = core.TacticalState()
    ren4 = core.TacticalReasoner(ts4)
    ren4.analyze(ts4, "nmap_scan", {"host": "10.0.0.5"},
                 "PORT STATE SERVICE\n80/tcp open http\n443/tcp open https\n"
                 "CVE-2024-1234 referenced")
    check("phase_enumeration", ts4.phase == "enumeration", ts4.phase)
    check("finding_open_port", any(
        f["type"] == "open_port" for f in ts4.findings),
        str(ts4.findings))
    check("finding_cve", any(f["type"] == "cve" for f in ts4.findings))
    actions = [v["action"] for v in ts4.pending_vectors]
    check("chain_web_fingerprint",
          "tech_detect" in actions and "check_headers" in actions
          and "dir_fuzz" in actions, str(actions))
    check("vector_target_built", any(
        v["target"] == "http://10.0.0.5" for v in ts4.pending_vectors),
        str([v["target"] for v in ts4.pending_vectors]))

    # http_request with a dynamic param -> mapped injection probe
    ts5 = core.TacticalState()
    ren5 = core.TacticalReasoner(ts5)
    ren5.analyze(ts5, "http_request", {"url": "http://x/page?id=5"},
                 "200 OK, page rendered")
    a5 = [v["action"] for v in ts5.pending_vectors]
    check("chain_param_probe", "sqli_test" in a5, str(a5))

    # empty scan -> alternate re-scan (one retry only)
    ts6 = core.TacticalState()
    ren6 = core.TacticalReasoner(ts6)
    ren6.analyze(ts6, "dir_fuzz", {"url": "http://x/"}, "no results found")
    a6 = [v["action"] for v in ts6.pending_vectors]
    check("chain_empty_rescan", "ffuf_fuzz" in a6, str(a6))

    # write_report satisfies
    ts7 = core.TacticalState()
    ren7 = core.TacticalReasoner(ts7)
    ts7.pending_vectors.append({"action": "x", "target": "y", "why": "z"})
    ren7.analyze(ts7, "write_report", {}, "report done")
    check("report_satisfies", ts7.satisfied_flag and not ts7.pending_vectors)

    # ---- reasoning_block EXACT 5-line format ---------------------------
    block = ren4.reasoning_block(ts4, "nmap_scan")
    lines = [l for l in block.strip().split("\n") if l.strip()]
    check("block_5_lines", len(lines) == 5, str(len(lines)))
    check("block_headers", lines[0].startswith("FINDINGS SUMMARY:")
          and "PENDING VECTORS:" in lines[-1])

    # ---- exit_guard_block ----------------------------------------------
    g = ren4.exit_guard_block(ts4)
    check("guard_text", "[TACTICAL GUARD]" in g and "Do not stop now" in g)

    # ---- Agent integration ---------------------------------------------
    a = core.Agent(llm=MockLLM(), memory=None, name="tactical-test")
    check("engine_default_on", a.reasoning_engine is True)
    sp = a._system_prompt()
    check("prompt_has_tactical", "TACTICAL THOUGHT LOOP" in sp)
    check("prompt_formatted", "{name}" not in sp and "{memory_block}" not in sp)
    a2 = core.Agent(llm=MockLLM(), memory=None, name="no-engine",
                    reasoning_engine=False)
    check("engine_can_disable", a2.reasoning_engine is False)

    # _tactical_step emits tactical_reasoning events
    a._tactical.active = True
    a._tactical.objective = "test objective"
    ev = a._tactical_step("nmap_scan", {"host": "10.0.0.5"},
                          "PORT STATE SERVICE\n80/tcp open http")
    check("step_event_type", ev and ev["type"] == "tactical_reasoning")
    check("step_event_fields",
          ev.get("phase") and ev.get("reasoning") and ev.get("state"),
          str(ev.keys()) if ev else "None")
    check("step_reasoning_count", a._tactical.reasoning_count >= 1)
    check("blocks_cap_4", len(a._tactical_blocks) <= 4,
          str(len(a._tactical_blocks)))

    # engine off -> no events
    a2._tactical.active = True
    check("step_off_no_event", a2._tactical_step("nmap_scan",
                                                 {"host": "1.2.3.4"}, "x")
          is None)

    # _render_tactical_context gating
    a3 = core.Agent(llm=MockLLM(), memory=None, name="gm", game_master=True)
    check("ctx_gm_empty", a3._render_tactical_context() == "")
    a4 = core.Agent(llm=MockLLM(), memory=None, name="npc",
                    npc_persona="Bob")
    check("ctx_npc_empty", a4._render_tactical_context() == "")

    # ---- findings extraction with real probe verdict wording ------------
    for text, expect in [
        ("VERDICT: REFLECTED XSS candidate", True),
        ("VERDICT: COMMAND EXECUTION CANDIDATE", True),
        ("VERDICT: PATH TRAVERSAL / LFI CONFIRMED", True),
        ("VERDICT: SSRF CONFIRMED", True),
        ("nothing found", False),
    ]:
        found = any(f["type"] == "vuln"
                    for f in core._extract_result_findings(text))
        check("vuln_regex_%s" % text.split(":")[-1].strip().split()[0],
              found == expect)

    # ---- _TACTICAL_PHASE_OF integrity ----------------------------------
    phases = set(core._TACTICAL_PHASE_OF.values())
    check("phase_values_valid",
          phases <= {"reconnaissance", "enumeration", "vuln-identification",
                     "safe-verification", "reporting"},
          str(sorted(phases)))
    check("phase_map_size", len(core._TACTICAL_PHASE_OF) >= 40,
          str(len(core._TACTICAL_PHASE_OF)))


if __name__ == "__main__":
    print("=== HackerAI tactical engine unit tests ===")
    t0 = time.time()
    run_tests()
    dt = time.time() - t0
    print("\n%d passed, %d failed (%.1fs)" % (PASS, FAIL, dt))
    sys.exit(1 if FAIL else 0)
