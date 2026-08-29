"""Unit tests for Task 6 - Rigorous Code Auditing & Multi-File Refactoring.

Verifies the system-prompt framework (built-in SYSTEM_PROMPT and the
runtime system_prompt.txt override) mandates:
  # PRODUCTION CODE RULES   - PEP 8, type hints, error handling, logging,
                              security checks, resource safety.
  # CODE AUDIT & REFACTORING LOOP - the mandatory 3-step internal pass:
                              1) Functional Implementation
                              2) Security Vulnerability Audit (SAST/DAST)
                              3) Edge Case & Exception Handling Optimization
And that the CODE_AUDIT_PASSES / CODE_QUALITY_RULES constants in
ai_agent/core.py are present and consistent with the prompt text.

Run:  py test_code_audit.py
"""
import os
import sys
import tempfile

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


def section(title):
    print("\n=== %s ===" % title)


def run_tests():
    section("Task 6 - production code rules in SYSTEM_PROMPT")
    p = core.SYSTEM_PROMPT
    check("prompt_section_production_rules", "# PRODUCTION CODE RULES" in p)
    check("prompt_pep8", "PEP 8" in p and "88" in p)
    check("prompt_type_hinting", "Type hinting" in p and "-> str" in p)
    check("prompt_error_handling",
          "Error handling" in p and "never bare `except:`" in p)
    check("prompt_logging",
          "`logging` module" in p and "logging.getLogger" in p)
    check("prompt_security_checks",
          "eval/exec" in p and "parameterized queries" in p
          and "hardcode secrets" in p and "timeouts" in p)
    check("prompt_resource_safety",
          "Resource safety" in p and "try/finally" in p)
    check("prompt_complete_working",
          "never pseudocode" in p or "pseudocode, stubs" in p)

    section("Task 6 - 3-step audit loop in SYSTEM_PROMPT")
    check("prompt_section_audit_loop",
          "# CODE AUDIT & REFACTORING LOOP" in p)
    check("prompt_mandatory_pass",
          "3-step internal pass" in p and "mandatory" in p.lower())
    check("prompt_pass1_functional",
          "1. FUNCTIONAL IMPLEMENTATION" in p)
    check("prompt_pass2_security",
          "2. SECURITY VULNERABILITY AUDIT (SAST/DAST)" in p)
    check("prompt_pass2_sast", "SAST" in p and "SQLi" in p
          and "traversal" in p and "hardcoded secrets" in p)
    check("prompt_pass2_dast",
          "DAST" in p and "hostile inputs" in p)
    check("prompt_pass3_edge",
          "3. EDGE CASE & EXCEPTION HANDLING OPTIMIZATION" in p)
    check("prompt_pass3_hardening",
          "Empty/None/missing inputs" in p and "unicode" in p
          and "retry/backoff" in p)
    check("prompt_audit_trail_deliverable",
          "PASS 1 functional" in p and "PASS 2 security" in p
          and "PASS 3 edge cases" in p)
    check("prompt_payloads_still_supported",
          "security-testing material" in p and "payloads" in p)

    section("Task 6 - constants in ai_agent/core.py")
    passes = core.CODE_AUDIT_PASSES
    check("constants_audit_passes_3", len(passes) == 3,
          str(passes))
    check("constants_pass1",
          passes[0] == "functional-implementation")
    check("constants_pass2",
          passes[1] == "security-audit-sast-dast")
    check("constants_pass3",
          passes[2] == "edge-case-exception-hardening")
    rules = core.CODE_QUALITY_RULES
    required = {"pep8", "type-hinting", "error-handling", "logging",
                "security-checks", "resource-safety",
                "complete-working-code"}
    check("constants_quality_rules_complete",
          required.issubset(set(rules)), str(rules))

    section("Task 6 - runtime override system_prompt.txt")
    sp_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "system_prompt.txt")
    check("override_file_exists", os.path.exists(sp_file))
    if os.path.exists(sp_file):
        with open(sp_file, "r", encoding="utf-8") as f:
            txt = f.read()
        check("override_has_production_rules",
              "# PRODUCTION CODE RULES" in txt)
        check("override_has_audit_loop",
              "# CODE AUDIT & REFACTORING LOOP" in txt)
        check("override_pass1", "1. FUNCTIONAL IMPLEMENTATION" in txt)
        check("override_pass2",
              "2. SECURITY VULNERABILITY AUDIT (SAST/DAST)" in txt)
        check("override_pass3",
              "3. EDGE CASE & EXCEPTION HANDLING OPTIMIZATION" in txt)
        check("override_audit_trail",
              "PASS 1 functional" in txt and "PASS 2 security" in txt
              and "PASS 3 edge cases" in txt)
        check("override_pep8", "PEP 8" in txt)
        check("override_typing", "Type hinting" in txt)
        check("override_logging", "`logging` module" in txt)
        check("override_placeholders",
              "{name}" in txt and "{memory_block}" in txt)

    section("Task 6 - prompt still renders")
    try:
        out = core.SYSTEM_PROMPT.format(name="HackerAI", memory_block="",
                                        knowledge_block="")
        check("prompt_renders", "# PENTEST FRAMEWORK" in out
              and "# PRODUCTION CODE RULES" in out)
    except Exception as exc:
        check("prompt_renders", False, "%s: %s" % (type(exc).__name__, exc))

    section("Task 6 - runtime override is actually applied")
    fd, path = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("OVERRIDE-MARKER {name} {memory_block} {knowledge_block}\n"
                    "# CODE AUDIT & REFACTORING LOOP\n"
                    "# PRODUCTION CODE RULES\n")
        orig = core.SYSTEM_PROMPT_FILE
        core.SYSTEM_PROMPT_FILE = path
        try:
            class FakeLLM:
                model = "mock"
            from ai_agent.core import Agent
            a = Agent(llm=FakeLLM())
            sp = a._system_prompt()
            check("runtime_override_applied",
                  sp.startswith("OVERRIDE-MARKER"), sp[:40])
            check("runtime_override_audit_section",
                  "# CODE AUDIT & REFACTORING LOOP" in sp)
            check("runtime_override_name_filled",
                  "HackerAI" in sp)
        finally:
            core.SYSTEM_PROMPT_FILE = orig
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    # Ensure the edit did not break the tactical context rendering.
    section("Task 6 - regression: tactical context unaffected")
    try:
        from ai_agent.core import TacticalState, TacticalReasoner
        ts = TacticalState()
        ren = TacticalReasoner(ts)
        ren.detect_objective("scan http://target.local for sqli")
        ren.analyze(ts, "nmap_scan", {"host": "10.0.0.5"},
                    "PORT STATE SERVICE\n80/tcp open http")
        ctx = ren.reasoning_block(ts, "nmap_scan")
        check("regression_tactical_ctx",
              "FINDINGS SUMMARY" in ctx and "PENDING VECTORS" in ctx,
              ctx[:60])
    except Exception as exc:
        check("regression_tactical_ctx", False,
              "%s: %s" % (type(exc).__name__, exc))


if __name__ == "__main__":
    print("=== HackerAI code audit framework unit tests ===")
    import time
    t0 = time.time()
    run_tests()
    dt = time.time() - t0
    print("\n%d passed, %d failed (%.1fs)" % (PASS, FAIL, dt))
    sys.exit(1 if FAIL else 0)
