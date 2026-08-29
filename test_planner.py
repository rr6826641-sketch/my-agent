"""Unit tests for the dynamic multi-step task planning engine (Task 7).

Covers: Tactical Action Plan generation (Discovery / Analysis /
Verification), real-time strategy adaptation (post-tool pivot evaluation),
plan advancement, the pivot cap, plan_block rendering, snapshot fields, and
the DYNAMIC STRATEGY PLANNER / REAL-TIME STRATEGY ADAPTATION prompt sections.

Run:  py test_planner.py
"""
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
    # ---- PLAN_PHASES constant integrity -------------------------------
    check("plan_phases_3", len(core.PLAN_PHASES) == 3,
          str(len(core.PLAN_PHASES)))
    keys = [p[0] for p in core.PLAN_PHASES]
    check("plan_phase_keys",
          keys == ["discovery", "analysis", "verification"], str(keys))
    labels = [p[1] for p in core.PLAN_PHASES]
    check("plan_phase_labels",
          labels == ["Discovery", "Analysis", "Verification"], str(labels))
    check("plan_phase_goals",
          all(len(p[2]) > 10 for p in core.PLAN_PHASES))
    check("pivot_cap_const", core._MAX_PLAN_PIVOTS >= 1,
          str(core._MAX_PLAN_PIVOTS))

    # ---- _PLAN_PHASE_OF mapping integrity -----------------------------
    plan_keys = set(keys)
    mapped = set(core._PLAN_PHASE_OF.values())
    check("plan_phase_of_values",
          mapped <= plan_keys, str(sorted(mapped)))
    check("plan_phase_of_covers_all",
          set(core._PLAN_PHASE_OF) >= {"reconnaissance", "enumeration",
                                       "vuln-identification",
                                       "safe-verification", "reporting"},
          str(sorted(core._PLAN_PHASE_OF)))

    # ---- plan auto-build on detect_objective --------------------------
    ts = core.TacticalState()
    ren = core.TacticalReasoner(ts)
    ren.detect_objective("scan http://target.local for sqli")
    check("plan_auto_built", ts.plan_built is True)
    check("plan_3_entries", len(ts.plan) == 3, str(len(ts.plan)))
    check("plan_first_active",
          ts.plan[0]["status"] == "active",
          str(ts.plan[0]))
    check("plan_pending_rest",
          all(p["status"] == "pending" for p in ts.plan[1:]))
    check("plan_fields",
          all(set(p) == {"key", "label", "goal", "status"} for p in ts.plan))
    check("plan_status_line",
          ts.plan_status_line() ==
          "discovery:active|analysis:pending|verification:pending",
          ts.plan_status_line())

    # ---- plan_status_line fallback ------------------------------------
    ts0 = core.TacticalState()
    check("plan_line_not_built", ts0.plan_status_line() == "not-built",
          ts0.plan_status_line())

    # ---- build_plan idempotency + objective refresh -------------------
    tsb = core.TacticalState()
    tsb.build_plan("objective A")
    first = tsb.plan
    tsb.build_plan("objective B")
    check("build_plan_idempotent", tsb.plan is first
          and len(tsb.plan) == 3)
    check("build_plan_refreshes_objective", tsb.objective == "objective B",
          tsb.objective)
    tsb2 = core.TacticalState()
    tsb2.build_plan("")
    check("build_plan_default_objective",
          "security assessment" in tsb2.objective, tsb2.objective)

    # ---- plan_phase_for mapping ---------------------------------------
    check("plan_of_recon", tsb2.plan_phase_for("reconnaissance")
          == "discovery")
    check("plan_of_enum", tsb2.plan_phase_for("enumeration") == "discovery")
    check("plan_of_vuln", tsb2.plan_phase_for("vuln-identification")
          == "analysis")
    check("plan_of_safe", tsb2.plan_phase_for("safe-verification")
          == "verification")
    check("plan_of_report", tsb2.plan_phase_for("reporting")
          == "verification")
    check("plan_of_unknown", tsb2.plan_phase_for("bogus-phase")
          == "discovery")

    # ---- phase progression via tools ----------------------------------
    ts3 = core.TacticalState()
    ren3 = core.TacticalReasoner(ts3)
    ren3.detect_objective("test http://web.local")
    ren3.analyze(ts3, "nmap_scan", {"host": "10.0.0.5"},
                 "PORT STATE SERVICE\n80/tcp open http\n443/tcp open https")
    check("phase_progress_discovery_active",
          ts3.plan[0]["status"] == "active",
          ts3.plan_status_line())
    check("phase_progress_analysis_pending",
          ts3.plan[1]["status"] == "pending")
    ren3.analyze(ts3, "sqli_test", {"url": "http://x/?id=1"},
                 "VERDICT: SQL INJECTION CONFIRMED")
    check("phase_progress_analysis_active",
          ts3.plan[1]["status"] == "active", ts3.plan_status_line())
    check("phase_progress_discovery_completed",
          ts3.plan[0]["status"] == "completed")
    # a later discovery-phase tool must never downgrade a completed phase
    ren3.analyze(ts3, "port_scan", {"host": "10.0.0.5"},
                 "PORT STATE SERVICE\n80/tcp open http")
    check("phase_no_downgrade",
          ts3.plan[0]["status"] == "completed"
          and ts3.plan[1]["status"] == "active", ts3.plan_status_line())

    # ---- write_report -> finalize_plan --------------------------------
    ts4 = core.TacticalState()
    ren4 = core.TacticalReasoner(ts4)
    ren4.detect_objective("test http://x.local")
    ren4.analyze(ts4, "write_report", {}, "report written")
    check("write_report_satisfied", ts4.satisfied_flag is True)
    check("write_report_plan_all_completed",
          all(p["status"] == "completed" for p in ts4.plan),
          ts4.plan_status_line())
    check("write_report_plan_completed_event",
          any(e["event"] == "plan_completed"
              for e in ts4.adaptation_events),
          str(ts4.adaptation_events))
    # finalize_plan is a no-op when the plan was never built
    ts5 = core.TacticalState()
    ts5.finalize_plan()
    check("finalize_no_plan_noop", ts5.plan == [] and not ts5.plan_built)
    ts5b = core.TacticalState()
    ren5b = core.TacticalReasoner(ts5b)
    ren5b.analyze(ts5b, "write_report", {}, "done")
    check("write_report_no_plan_ok", ts5b.satisfied_flag is True)

    # ---- real-time strategy adaptation: new vulnerability evidence ----
    ts6 = core.TacticalState()
    ren6 = core.TacticalReasoner(ts6)
    ren6.detect_objective("test http://vuln.local")
    ren6.analyze(ts6, "nmap_scan", {"host": "10.0.0.9"},
                 "PORT STATE SERVICE\n80/tcp open http\n"
                 "CVE-2024-4321 referenced by banner")
    check("pivot_vuln_evidence",
          any(e["event"] == "new_vulnerability_evidence"
              for e in ts6.adaptation_events),
          str(ts6.adaptation_events))
    check("pivot_reason_mentions_cve",
          any("CVE-2024-4321" in e["reason"]
              for e in ts6.adaptation_events))
    check("pivot_events_capped_1", len(ts6.adaptation_events) <=
          core._MAX_PLAN_PIVOTS, str(len(ts6.adaptation_events)))

    # ---- empty scan -> pivot to alternative approach ------------------
    ts7 = core.TacticalState()
    ren7 = core.TacticalReasoner(ts7)
    ren7.detect_objective("test http://empty.local")
    ren7.analyze(ts7, "dir_fuzz", {"url": "http://x/"}, "no results found")
    check("pivot_empty_result",
          any(e["event"] == "empty_result"
              for e in ts7.adaptation_events),
          str(ts7.adaptation_events))
    check("pivot_empty_alt_chain",
          any(v["action"] == "ffuf_fuzz"
              for v in ts7.pending_vectors),
          str([v["action"] for v in ts7.pending_vectors]))
    # non-tactical tool returning empty must NOT trigger an empty pivot
    ts7b = core.TacticalState()
    ren7b = core.TacticalReasoner(ts7b)
    ren7b.detect_objective("test http://x.local")
    ren7b.analyze(ts7b, "custom_utility", {}, "")
    check("pivot_empty_non_tool",
          not any(e["event"] == "empty_result"
                  for e in ts7b.adaptation_events),
          str(ts7b.adaptation_events))

    # ---- phase-transition pivot ---------------------------------------
    check("pivot_phase_advanced",
          any(e["event"] == "phase_advanced"
              for e in ts3.adaptation_events),
          str(ts3.adaptation_events))
    # no fresh evidence -> no new pivot (dedup / stability)
    n_before = len(ts6.adaptation_events)
    ren6.analyze(ts6, "nmap_scan", {"host": "10.0.0.9"},
                 "PORT STATE SERVICE\n80/tcp open http\n"
                 "CVE-2024-4321 referenced by banner")
    check("pivot_no_repeat_on_same",
          len(ts6.adaptation_events) == n_before,
          "%d -> %d" % (n_before, len(ts6.adaptation_events)))

    # ---- record_adaptation: dedup + cap + revision count --------------
    ts8 = core.TacticalState()
    ts8.build_plan("t")
    e1 = ts8.record_adaptation("pivot_a", "first pivot reason")
    e2 = ts8.record_adaptation("pivot_a", "first pivot reason")
    check("adaptation_dedup", e1 is not None and e2 is None)
    check("adaptation_revisions", ts8.plan_revisions == 1,
          str(ts8.plan_revisions))
    check("adaptation_empty_reason",
          ts8.record_adaptation("x", "  ") is None)
    for i in range(10):
        ts8.record_adaptation("evt%d" % i, "unique reason %d" % i)
    check("adaptation_cap",
          len(ts8.adaptation_events) <= core._MAX_PLAN_PIVOTS,
          str(len(ts8.adaptation_events)))
    check("adaptation_keeps_latest",
          ts8.adaptation_events[-1]["event"] == "evt9",
          str(ts8.adaptation_events[-1]["event"]))

    # ---- plan_block rendering -----------------------------------------
    pb = ren3.plan_block(ts3)
    check("plan_block_prefix", pb.startswith("TACTICAL ACTION PLAN:"),
          pb[:40])
    check("plan_block_labels",
          "Discovery[" in pb and "Analysis[" in pb
          and "Verification[" in pb)
    check("plan_block_revisions", "REVISIONS:" in pb)
    check("plan_block_last_pivot", "LAST PIVOT:" in pb)
    check("plan_block_empty_no_plan", ren.plan_block(ts0) == "")

    # ---- snapshot extension -------------------------------------------
    snap = ts3.snapshot()
    check("snapshot_plan", "plan" in snap and isinstance(snap["plan"], list)
          and len(snap["plan"]) == 3)
    check("snapshot_revisions", snap["plan_revisions"] ==
          ts3.plan_revisions)
    check("snapshot_adaptations",
          "adaptations" in snap
          and all(set(a) == {"event", "reason"} for a in snap["adaptations"]),
          str(snap.get("adaptations")))

    # ---- Agent integration: prompt sections ---------------------------
    a = core.Agent(llm=MockLLM(), memory=None, name="planner-test")
    sp = a._system_prompt()
    up = sp.upper()
    check("prompt_planner_section", "DYNAMIC STRATEGY PLANNER" in up)
    check("prompt_plan_phases",
          all(k in up for k in ("DISCOVERY", "ANALYSIS", "VERIFICATION")))
    check("prompt_adaptation_section",
          "REAL-TIME STRATEGY ADAPTATION" in up
          and "[PLAN PIVOT]" in up)
    import re as _re
    flat = _re.sub(r"\s+", " ", up)
    check("prompt_adaptation_triggers",
          all(k in flat for k in ("NEW FINDING TYPE", "EMPTY SCAN",
                                  "PHASE TRANSITION")))
    check("prompt_adaptation_contradiction",
          "CONTRADICTS" in up)
    check("prompt_planner_before_deep",
          up.index("DYNAMIC STRATEGY PLANNER")
          < up.index("MULTI-PERSPECTIVE EVALUATION"))

    # ---- runtime override file (system_prompt.txt) --------------------
    sp_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "system_prompt.txt")
    if os.path.isfile(sp_file):
        txt = open(sp_file, encoding="utf-8", errors="replace").read()
        check("prompt_file_planner_section",
              "# DYNAMIC STRATEGY PLANNER" in txt)
        check("prompt_file_adaptation_section",
              "# REAL-TIME STRATEGY ADAPTATION" in txt)
        check("prompt_file_before_deep",
              txt.index("# DYNAMIC STRATEGY PLANNER")
              < txt.index("# DEEP ANALYSIS"))
    else:
        check("prompt_file_planner_section", False, "system_prompt.txt missing")
        check("prompt_file_adaptation_section", False, "system_prompt.txt missing")
        check("prompt_file_before_deep", False, "system_prompt.txt missing")

    # ---- _tactical_step carries plan + pivot --------------------------
    a2 = core.Agent(llm=MockLLM(), memory=None, name="planner-step")
    a2._tactical.build_plan("step test objective")
    a2._tactical.active = True
    ev = a2._tactical_step("nmap_scan", {"host": "10.0.0.5"},
                           "PORT STATE SERVICE\n80/tcp open http")
    check("step_plan_field",
          ev and isinstance(ev.get("plan"), str)
          and ev["plan"].startswith("TACTICAL ACTION PLAN:"),
          str(ev.get("plan"))[:60] if ev else "None")
    check("step_pivot_field",
          ev and isinstance(ev.get("pivot"), dict)
          and ev["pivot"]["event"] == "phase_advanced",
          str(ev.get("pivot")) if ev else "None")
    check("step_state_plan",
          ev and ev["state"]["plan"][0]["status"] == "active",
          str(ev["state"]["plan"]) if ev else "None")

    # second identical step -> no fresh pivot carried
    ev2 = a2._tactical_step("nmap_scan", {"host": "10.0.0.5"},
                            "PORT STATE SERVICE\n80/tcp open http")
    check("step_pivot_none_on_repeat",
          ev2 and ev2.get("pivot") is None,
          str(ev2.get("pivot")) if ev2 else "None")

    # ---- _render_tactical_context: plan tail + gating -----------------
    a3 = core.Agent(llm=MockLLM(), memory=None, name="planner-ctx")
    a3._tactical.build_plan("ctx objective")
    a3._tactical.active = True
    a3._tactical_step("nmap_scan", {"host": "10.0.0.5"},
                      "PORT STATE SERVICE\n80/tcp open http")
    ctx = a3._render_tactical_context()
    check("ctx_plan_tail", "plan=discovery:active|analysis:pending"
          in ctx, ctx[:120])
    check("ctx_revisions_tail", "revisions=" in ctx)
    a4 = core.Agent(llm=MockLLM(), memory=None, name="gm", game_master=True)
    check("ctx_gm_empty", a4._render_tactical_context() == "")
    a5 = core.Agent(llm=MockLLM(), memory=None, name="npc",
                    npc_persona="Bob")
    check("ctx_npc_empty", a5._render_tactical_context() == "")


if __name__ == "__main__":
    print("=== HackerAI dynamic task planning engine unit tests ===")
    t0 = time.time()
    run_tests()
    dt = time.time() - t0
    print("\n%d passed, %d failed (%.1fs)" % (PASS, FAIL, dt))
    sys.exit(1 if FAIL else 0)
