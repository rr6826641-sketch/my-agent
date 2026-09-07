"""End-to-end Step-By-Step handshake over the real HTTP contract.

Simulates the browser flow without a browser:

  GET  /api/chat?mode=step&...   (SSE stream)
        -> agent registers a step_approval key, then blocks in _step_wait
  POST /api/chat/step {key, decision}   (what the Approve/Reject buttons do)
        -> _step_wait resolves; the run continues (approve) or is
           hard-blocked (reject) and ends cleanly.

A real Agent approval gate (object.__new__) is used, so _new_step_key /
_step_register / _step_wait / submit_step_decision / the registry lock are
the genuine production code.  Only run_stream is faked, to drive a
deterministic single-tool scenario.
"""
import re
import sys
import os
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import types

import pytest

import webui
from ai_agent.core.main import Agent


def _make_gate_agent():
    a = object.__new__(Agent)
    a._step_lock = threading.Lock()
    a._step_approvals = {}
    a.run_step_allow_all = False
    a.run_step_reject_all = False
    a.run_mode = "auto"
    return a


def _fake_run_stream(self, user_input, stop_event=None, model=None, **kw):
    """One tool call, gated for real: register -> emit -> wait -> outcome."""
    yield {"type": "start", "content": user_input}
    key = self._new_step_key()
    self._step_register(key)
    yield {"type": "step_approval", "key": key, "tool": "probe",
           "arguments": "{}", "parallel": False}
    decision = self._step_wait(key, stop_event=stop_event, timeout=6.0)
    if decision == "approve":
        yield {"type": "tool_result", "name": "probe",
               "content": "EXECUTED-by-operator"}
        yield {"type": "delta", "content": "approved-tool-ran"}
    elif decision == "reject":
        yield {"type": "delta", "content": "rejected-tool-blocked"}
    else:
        yield {"type": "delta", "content": "no-decision:%s" % decision}
    yield {"type": "final", "content": "done"}


@pytest.fixture()
def handshake_env(monkeypatch, tmp_path):
    """Isolated webui state: gate agent installed, chat-history persistence
    and model routing neutralised so nothing touches the real repo."""
    agent = _make_gate_agent()
    agent.run_stream = types.MethodType(_fake_run_stream, agent)
    monkeypatch.setitem(webui._state, "agent", agent)
    store = {"sessions": {}}
    monkeypatch.setattr(webui, "_read_chats_unlocked", lambda: store)
    monkeypatch.setattr(webui, "_write_chats_unlocked", lambda d: store.update(d))
    monkeypatch.setattr(webui, "_record_event", lambda *a, **k: None)
    monkeypatch.setattr(webui, "_record_stream_done", lambda *a, **k: None)
    monkeypatch.setattr(webui, "route_model", lambda msg, cfg: (None, "e2e"))
    monkeypatch.setattr(webui.artifacts, "worth_capturing",
                        lambda *a, **k: False)
    monkeypatch.setattr(webui, "PROJECT_DIR", str(tmp_path))
    return webui.app.test_client()


def _stream_all(query):
    """Read the SSE stream in a background thread; return chunk list."""
    chunks = []
    errors = []

    def read():
        try:
            reader = webui.app.test_client()
            with reader.get("/api/chat", query_string=query,
                            buffered=False) as resp:
                for chunk in resp.response:
                    if chunk:
                        chunks.append(chunk.decode("utf-8", "replace"))
        except Exception as exc:  # pragma: no cover - surfaced in asserts
            errors.append(exc)

    t = threading.Thread(target=read, daemon=True)
    t.start()
    return chunks, errors, t


def _wait_for_key(chunks, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        m = re.search(r'"type"\s*:\s*"step_approval"[^{}]*?"key"\s*:\s*"([0-9a-f]+)"',
                      "".join(chunks))
        if m:
            return m.group(1)
        time.sleep(0.05)
    return None


def test_e2e_approve_resolves_gate(handshake_env):
    client = handshake_env
    chunks, errors, t = _stream_all({"message": "e2e approve", "mode": "step",
                                     "access": "full", "scope": "local"})
    key = _wait_for_key(chunks)
    assert key, "no step_approval seen in stream: %r" % "".join(chunks)[-500:]

    r = client.post("/api/chat/step", json={"key": key, "decision": "approve"})
    assert r.status_code == 200
    assert r.get_json() == {"ok": True}

    t.join(timeout=12)
    body = "".join(chunks)
    assert "EXECUTED-by-operator" in body, body[-800:]
    assert "approved-tool-ran" in body
    assert not errors


def test_e2e_reject_blocks_tool(handshake_env):
    client = handshake_env
    chunks, errors, t = _stream_all({"message": "e2e reject", "mode": "step",
                                     "access": "full", "scope": "local"})
    key = _wait_for_key(chunks)
    assert key, "no step_approval seen in stream: %r" % "".join(chunks)[-500:]

    r = client.post("/api/chat/step", json={"key": key, "decision": "reject"})
    assert r.status_code == 200
    assert r.get_json() == {"ok": True}

    t.join(timeout=12)
    body = "".join(chunks)
    assert "rejected-tool-blocked" in body, body[-800:]
    assert "EXECUTED-by-operator" not in body
    assert not errors
