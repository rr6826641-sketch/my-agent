"""Route-level regression tests for the Step-By-Step approval endpoint
(POST /api/chat/step in webui.py).

Validates the HTTP contract without any real agent/LLM:
  400 -> no agent / missing key / unknown decision
  200 {"ok": true|false} -> delegation to agent.submit_step_decision
key/decision accepted from JSON body or query-string fallback.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import webui


class _FakeStepAgent:
    """Minimal stand-in: records every submitted decision."""

    def __init__(self, result=True):
        self.result = result
        self.calls = []

    def submit_step_decision(self, key, decision):
        self.calls.append((key, decision))
        return self.result


@pytest.fixture()
def step_client(monkeypatch):
    agent = _FakeStepAgent()
    monkeypatch.setitem(webui._state, "agent", agent)
    return webui.app.test_client(), agent


def _post(client, **payload):
    return client.post("/api/chat/step", json=payload)


# ---------------------------------------------------------------------------
# validation -> 400
# ---------------------------------------------------------------------------

def test_step_route_missing_agent_400(monkeypatch):
    monkeypatch.setitem(webui._state, "agent", None)
    c = webui.app.test_client()
    r = _post(c, key="abc", decision="approve")
    assert r.status_code == 400
    assert r.get_json()["ok"] is False


def test_step_route_missing_key_400(step_client):
    c, _ = step_client
    r = _post(c, decision="approve")
    assert r.status_code == 400


def test_step_route_bad_decision_400(step_client):
    c, _ = step_client
    r = _post(c, key="abc", decision="banana")
    assert r.status_code == 400
    # case is normalised server-side, so uppercase is fine
    r2 = _post(c, key="abc", decision="ALLOW_ALL")
    assert r2.status_code == 200


def test_step_route_no_payload_400(step_client):
    c, _ = step_client
    r = c.post("/api/chat/step", data="")
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# delegation -> 200 {"ok": ...}
# ---------------------------------------------------------------------------

def test_step_route_approve_delegates(step_client):
    c, agent = step_client
    r = _post(c, key="k1", decision="approve")
    assert r.status_code == 200
    assert r.get_json() == {"ok": True}
    assert agent.calls == [("k1", "approve")]


def test_step_route_unknown_key_ok_false(step_client):
    c, agent = step_client
    agent.result = False
    r = _post(c, key="expired", decision="approve")
    assert r.status_code == 200
    assert r.get_json() == {"ok": False}


def test_step_route_query_string_fallback(step_client):
    c, agent = step_client
    r = c.post("/api/chat/step?key=k2&decision=reject")
    assert r.status_code == 200
    assert agent.calls == [("k2", "reject")]
