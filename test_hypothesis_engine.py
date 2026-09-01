"""Tests for the Hypothesis-Driven Vulnerability Discovery Engine."""

import json

import pytest

from ai_agent.tools.hypothesis_engine import (
    generate_security_hypotheses,
    tool_generate_security_hypotheses,
)

SURFACE = [
    {"route": "/api/v1/orders/123", "method": "GET",
     "code": "order = db.get_order(id); return order"},
    {"route": "/api/v1/coupons/apply", "method": "POST",
     "notes": "checkout step 2, one-time redeem of coupon"},
    {"route": "/api/v1/password/reset/confirm", "method": "POST",
     "code": "token = req.token; user = verify(token)"},
    {"route": "/admin/invoice/download", "method": "GET",
     "notes": "internal attachment export"},
]

REQUIRED_KEYS = {
    "hypothesis_id", "vulnerability_type", "target_component",
    "logic_reasoning", "proposed_test_strategy", "confidence_score",
}


def _parse(raw):
    return json.loads(raw)


def test_schema_fields_present():
    data = _parse(generate_security_hypotheses("shop.example.com", SURFACE))
    assert data["hypothesis_count"] == len(data["hypotheses"]) > 0
    for h in data["hypotheses"]:
        assert REQUIRED_KEYS == set(h)
        assert h["hypothesis_id"].startswith("HYP-")
        assert 0.0 < h["confidence_score"] <= 0.92
        assert h["logic_reasoning"] and h["proposed_test_strategy"]


def test_reasoning_only_no_generic_patterns():
    data = _parse(generate_security_hypotheses("t", SURFACE))
    types = {h["vulnerability_type"] for h in data["hypotheses"]}
    assert any("state" in v.lower() or "race" in v.lower() for v in types)
    assert all("XSS" not in v and "injection" not in v.lower() for v in types)


def test_confidence_grows_with_code_evidence():
    plain = _parse(generate_security_hypotheses("t", [
        {"route": "/api/coupons/apply", "notes": "redeem coupon"}]))
    coded = _parse(generate_security_hypotheses("t", [
        {"route": "/api/coupons/apply", "notes": "redeem coupon",
         "code": "if not coupon.used: apply(coupon)"}]))
    assert (coded["hypotheses"][0]["confidence_score"]
            > plain["hypotheses"][0]["confidence_score"])


def test_invalid_json_returns_error_object():
    out = _parse(generate_security_hypotheses("t", "not json{{{"))
    assert "error" in out and "hypotheses" not in out


def test_empty_surface_yields_no_hypotheses():
    out = _parse(generate_security_hypotheses("t", "[]"))
    assert out["hypothesis_count"] == 0 and "note" in out


def test_cap_clamped_and_deterministic_ids():
    capped = _parse(generate_security_hypotheses("t", SURFACE * 5,
                                                 max_hypotheses=99))
    assert len(capped["hypotheses"]) <= 15
    again = _parse(generate_security_hypotheses("t", SURFACE * 5,
                                                max_hypotheses=99))
    ids1 = [h["hypothesis_id"] for h in capped["hypotheses"]]
    ids2 = [h["hypothesis_id"] for h in again["hypotheses"]]
    assert ids1 == ids2
    assert len(set(ids1)) == len(ids1)


def test_tool_wrapper_renders_ranked_text():
    text = tool_generate_security_hypotheses("shop.example.com", SURFACE)
    assert "Security hypotheses for shop.example.com" in text
    assert "test plan:" in text
    scores = [float(line.split("[confidence ")[1].split("]")[0])
              for line in text.splitlines() if "[confidence " in line]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.parametrize("max_h", [1, 3, 8])
def test_max_hypotheses_respected(max_h):
    data = _parse(generate_security_hypotheses("t", SURFACE, max_h))
    assert len(data["hypotheses"]) == max_h


# ------------------------------------------------- chaining & wiring tests

from ai_agent.tools.hypothesis_engine import (
    chain_to_verification_plan,
    tool_chain_to_verification_plan,
)


def test_chain_produces_plans_with_criteria():
    hyps = _parse(generate_security_hypotheses("shop.example.com", SURFACE))
    raw = chain_to_verification_plan(hyps["hypotheses"])
    plans = _parse(raw)["plans"]
    assert len(plans) == len(hyps["hypotheses"])
    for p in plans:
        assert {"hypothesis_id", "vulnerability_type", "verification_task",
                "success_criteria", "proposed_test_strategy",
                "confidence_score"} == set(p)
        assert p["hypothesis_id"].startswith("HYP-")
        assert len(p["success_criteria"]) >= 3
        assert all(c.startswith("evidence: ") for c in p["success_criteria"])
        assert "VERDICT" in p["verification_task"]
    scores = [p["confidence_score"] for p in plans]
    assert scores == sorted(scores, reverse=True)


def test_chain_accepts_full_result_dict():
    hyps = _parse(generate_security_hypotheses("t", SURFACE))
    plans = _parse(chain_to_verification_plan(hyps))["plans"]
    assert plans


def test_chain_invalid_and_empty():
    assert "error" in _parse(chain_to_verification_plan("not json{"))
    out = _parse(chain_to_verification_plan("[]"))
    assert out["plan_count"] == 0


def test_chain_rule_specific_criteria():
    hyps = _parse(generate_security_hypotheses("t", [
        {"route": "/api/coupons/apply", "notes": "one-time redeem"}]))
    plans = _parse(chain_to_verification_plan(hyps["hypotheses"]))["plans"]
    race = [p for p in plans if "Race" in p["vulnerability_type"]]
    assert race and "concurrent burst" in " ".join(race[0]["success_criteria"])


def test_tool_chain_wrapper_text():
    hyps = _parse(generate_security_hypotheses("t", SURFACE))
    text = tool_chain_to_verification_plan(hyps)
    assert "Verification plans" in text and "criteria:" in text


def test_core_wires_hypothesis_criteria_into_spawn():
    import tempfile, os
    from ai_agent.core import Agent

    called = {}

    class FakeOrchestrator:
        def spawn(self, task, wait=False, success_criteria=None, **kw):
            called["task"] = task
            called["criteria"] = success_criteria
            return '{"agent_id": "fake", "status": "queued"}'

        def spawn_many(self, tasks, **kw):
            return "[]"

    agent = object.__new__(Agent)
    agent.allow_subagents = True
    agent.spawn_depth = 0
    agent.max_spawn_depth = 2
    agent._orchestrator = FakeOrchestrator()

    plan = {
        "hypothesis_id": "HYP-ab12cd34",
        "vulnerability_type": "Race condition",
        "verification_task": "Validate hypothesis HYP-ab12cd34 on '/api/x'.",
        "success_criteria": ["evidence: a", "evidence: b", "evidence: c"],
        "proposed_test_strategy": "burst",
        "confidence_score": 0.6,
    }
    agent.spawn_agent(json.dumps(plan))
    assert called["criteria"] == plan["success_criteria"]
    assert called["task"] == plan["verification_task"]
    # explicit criteria pass through untouched
    agent.spawn_agent("plain task text", success_criteria=["my criterion"])
    assert called["criteria"] == ["my criterion"]
    assert called["task"] == "plain task text"
