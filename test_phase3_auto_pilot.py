"""PHASE 3 regression: Auto-Pilot = backend Continuous Execution.

Covers the request-interception contract implemented in set_run_control
and the relaxed GOAP gate in _goap_build:

* mode="auto" / "Auto"  -> run_mode "auto" + Continuous Execution ON
  (Self-Evolution engine hot, GOAP allowed on objective-shaped prompts
  even when the tactical classifier is idle).
* mode="step" / "research" -> Continuous Execution OFF (step keeps its
  per-tool HITL gate from Phase 2; research keeps its own pipeline).
* step/research runs never widen the original GOAP tactical gate.
"""
import types

import pytest

from ai_agent.core.main import Agent


class _GateProbe(Exception):
    """Raised by the fake planner when _goap_build reaches plan_graph,
    proving the gate let the call through (no early return)."""


class _ProbePlanner:
    active = False

    def plan_graph(self, *a, **k):
        # reachable only when the gate let the call through; a truthy
        # plan forces _goap_build past the `if not plan` early return
        # so render_plan_block raises the probe.
        return ["probe-plan"]

    def render_plan_block(self, *a, **k):
        raise _GateProbe()

    def snapshot(self, *a, **k):
        return {}


def _bare_agent(**kw):
    a = object.__new__(Agent)
    a.reasoning_engine = True
    a.npc_persona = None
    a.game_master = False
    a.run_continuous = kw.get("run_continuous", False)
    a._tactical = types.SimpleNamespace(active=kw.get("tactical_active", False))
    a._goap = _ProbePlanner()
    return a


def test_auto_mode_activates_continuous_execution():
    a = _bare_agent()
    a.set_run_control(mode="auto")
    assert a.run_mode == "auto"
    assert a.run_continuous is True
    assert a._evolution_enabled is True


def test_mode_param_is_case_insensitive():
    a = _bare_agent()
    a.set_run_control(mode="Auto")
    assert a.run_mode == "auto"
    assert a.run_continuous is True


def test_step_mode_keeps_hitl_and_disables_continuous():
    a = _bare_agent()
    a.set_run_control(mode="step")
    assert a.run_mode == "step"
    assert a.run_continuous is False


def test_research_mode_disables_continuous():
    a = _bare_agent()
    a.set_run_control(mode="research")
    assert a.run_mode == "research"
    assert a.run_continuous is False


def test_unknown_mode_falls_back_to_auto_pilot():
    a = _bare_agent()
    a.set_run_control(mode="  ")
    assert a.run_mode == "auto"
    assert a.run_continuous is True


def test_goap_engaged_in_continuous_even_when_tactical_idle():
    # tactical idle + Auto-Pilot: planner must be reached.
    a = _bare_agent(run_continuous=True, tactical_active=False)
    with pytest.raises(_GateProbe):
        a._goap_build("map 10.0.0.5 then exploit the web app")


def test_goap_gate_unchanged_outside_continuous():
    # tactical idle + NOT continuous (step/research or direct run):
    # original behaviour - no planning, empty block.
    a = _bare_agent(run_continuous=False, tactical_active=False)
    assert a._goap_build("map 10.0.0.5 then exploit the web app") == ""


def test_goap_still_engaged_when_tactical_active():
    # tactical active always plans (original behaviour preserved).
    a = _bare_agent(run_continuous=False, tactical_active=True)
    with pytest.raises(_GateProbe):
        a._goap_build("map 10.0.0.5 then exploit the web app")
