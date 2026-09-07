"""Step-By-Step HITL approval-gate regression tests (Phase 2).

Covers the per-run operator approval machinery in Agent
(ai_agent/core/main.py):

  * _step_enabled()   - gate is active only in run_mode="step"
  * _step_register()  - a pending approval key is tracked
  * submit_step_decision()
      approve/reject  -> apply only to a still-pending key
      allow_all/reject_all -> per-run switches, expire-proof
  * _step_wait()      - fail closed: unknown/timeout/cancel -> None

All tests build a bare Agent via object.__new__ (no LLM, no config,
no network) so they run in milliseconds.
"""
import sys
import os
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_agent.core.main import Agent


def _bare_agent():
    a = object.__new__(Agent)
    a._step_lock = threading.Lock()
    a._step_approvals = {}
    a.run_step_allow_all = False
    a.run_step_reject_all = False
    return a


# ---------------------------------------------------------------------------
# gate enablement
# ---------------------------------------------------------------------------

def test_step_enabled_only_in_step_mode():
    a = _bare_agent()
    a.run_mode = "auto"
    assert a._step_enabled() is False
    a.run_mode = "step"
    assert a._step_enabled() is True


def test_step_enabled_off_after_allow_all():
    a = _bare_agent()
    a.run_mode = "step"
    a.run_step_allow_all = True
    assert a._step_enabled() is False


# ---------------------------------------------------------------------------
# register + approve / reject round trip (no waiting thread needed)
# ---------------------------------------------------------------------------

def test_approve_pending_key():
    a = _bare_agent()
    key = a._new_step_key()
    a._step_register(key)
    assert key in a._step_approvals
    assert a.submit_step_decision(key, "approve") is True
    # decision recorded; _step_wait would now return it
    assert a._step_approvals[key]["decision"] == "approve"
    assert a._step_approvals[key]["event"].is_set()


def test_reject_pending_key():
    a = _bare_agent()
    key = a._new_step_key()
    a._step_register(key)
    assert a.submit_step_decision(key, "reject") is True
    assert a._step_approvals[key]["decision"] == "reject"


def test_unknown_key_approve_rejected():
    a = _bare_agent()
    assert a.submit_step_decision("no-such-key", "approve") is False


# ---------------------------------------------------------------------------
# run-wide switches: allow_all / reject_all
# ---------------------------------------------------------------------------

def test_allow_all_sets_run_switch_even_for_unknown_key():
    a = _bare_agent()
    a.run_step_allow_all = False
    # run switch is honoured even when the key already expired
    assert a.submit_step_decision("expired-key", "allow_all") is True
    assert a.run_step_allow_all is True


def test_reject_all_sets_run_switch():
    a = _bare_agent()
    assert a.submit_step_decision("anything", "reject_all") is True
    assert a.run_step_reject_all is True


def test_allow_all_then_register_then_step_disabled():
    a = _bare_agent()
    a.run_mode = "step"
    assert a.submit_step_decision("x", "allow_all") is True
    assert a._step_enabled() is False


# ---------------------------------------------------------------------------
# _step_wait semantics (decision consumed + registry cleaned)
# ---------------------------------------------------------------------------

def test_step_wait_returns_recorded_decision_and_pops():
    a = _bare_agent()
    key = a._new_step_key()
    a._step_register(key)
    assert a.submit_step_decision(key, "approve") is True

    dec = a._step_wait(key)
    assert dec == "approve"
    assert key not in a._step_approvals  # consumed


def test_step_wait_unknown_key_returns_none():
    a = _bare_agent()
    assert a._step_wait("missing", timeout=0.6) is None  # fail closed


def test_step_wait_cancel_returns_none():
    a = _bare_agent()
    key = a._new_step_key()
    a._step_register(key)
    stop = threading.Event()
    stop.set()  # run cancelled before the operator answers
    assert a._step_wait(key, stop_event=stop, timeout=0.6) is None
    assert key not in a._step_approvals  # cancelled keys are cleaned


def test_submit_bad_decision_payload_no_crash():
    """Backend route /api/chat/step validates decisions; the gate must
    tolerate garbage without raising."""
    a = _bare_agent()
    key = a._new_step_key()
    a._step_register(key)
    assert a.submit_step_decision(key, "maybe") is True  # still recorded
    assert a._step_approvals[key]["decision"] == "maybe"


def test_set_run_control_resets_per_run_switches():
    a = _bare_agent()
    a.run_mode = "step"
    assert a.submit_step_decision("x", "allow_all") is True
    assert a.run_step_allow_all is True
    # next run resets everything back to step-gated
    a.set_run_control(access="full", scope="local", mode="step")
    assert a.run_step_allow_all is False
    assert a.run_step_reject_all is False
    assert a._step_enabled() is True
