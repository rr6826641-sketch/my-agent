"""Regression tests: infinite "agent is working" fix.

Covers both sides of the fix:
  * Fix 2 (retry strategy): _post_with_retry retries transient network
    failures (DNS/connect/read timeout, connection reset, mid-stream
    chunked drop) with exponential backoff, then raises NetworkError
    carrying the friendly UI fallback text; non-transient request errors
    fail fast without retries.
  * Fix 1 (state reset): when an LLM call dies mid-answer, Agent.run_stream
    surfaces an error event and TERMINATES, so the SSE worker sends its
    terminal marker and the UI can never stay stuck on "agent is working".

Run: py -m pytest test_network_resilience.py -v
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import types

import pytest
import requests

import ai_agent.llm as llm
from ai_agent.core import Agent
from ai_agent.llm import (
    LLMError,
    NETWORK_FALLBACK_MSG,
    NetworkError,
    _post_with_retry,
)


# ---------------------------------------------------------------- Fix 2


def _ok_response():
    return types.SimpleNamespace(
        status_code=200,
        text="""{"choices":[{"message":{"content":"ok","role":"assistant"}}]}""",
    )


def _patch_session(monkeypatch, post_fn):
    """Route _post_with_retry through a fake pooled session.

    The speed upgrade made every request ride a process-wide keep-alive
    Session, so patching requests.post no longer intercepts the call; we
    patch the session factory instead.
    """
    fake = types.SimpleNamespace(post=post_fn, close=lambda: None)
    monkeypatch.setattr(llm, "_get_session", lambda: fake)


def test_fallback_message_is_exact_ui_sentence():
    assert NETWORK_FALLBACK_MSG == (
        "Internet connection interrupted while reaching "
        "LLM API. Please check connection and retry."
    )


def test_transient_timeout_then_success_retries_with_backoff(monkeypatch):
    """Two transient failures followed by success => 3 HTTP attempts and
    exponential sleeps of backoff then backoff*2 between them."""
    calls = []
    sleeps = []
    real_sleep = llm.time.sleep

    def fake_post(*a, **k):
        calls.append(k.get("timeout"))
        if len(calls) < 3:
            raise requests.exceptions.Timeout("read timed out")
        return _ok_response()

    def fake_sleep(secs):
        sleeps.append(secs)

    _patch_session(monkeypatch, fake_post)
    monkeypatch.setattr(llm.time, "sleep", fake_sleep)

    resp = _post_with_retry("model-x", "http://u", {}, {}, timeout=120,
                            stream=True, retries=3, backoff=0.1)
    assert resp.status_code == 200
    assert len(calls) == 3                      # 2 fails + 1 success
    assert calls[0] == 120                     # first attempt: full timeout
    assert all(t == 30 for t in calls[1:])     # later attempts: capped at 30s
    # jittered exponential backoff: base 0.1 then 0.2, each with up
    # to +25% random jitter to avoid a synchronized retry stampede
    assert 0.1 <= sleeps[0] <= 0.125
    assert 0.2 <= sleeps[1] <= 0.25


def test_transient_exhaustion_raises_network_error_fallback(monkeypatch):
    """ConnectionError (DNS failure / reset) every time => bounded retries,
    then NetworkError carrying the UI fallback text — never a silent hang."""
    calls = []
    sleeps = []

    def fake_post(*a, **k):
        calls.append(1)
        raise requests.exceptions.Timeout("read timed out")

    def fake_sleep(secs):
        sleeps.append(secs)

    _patch_session(monkeypatch, fake_post)
    monkeypatch.setattr(llm.time, "sleep", fake_sleep)

    with pytest.raises(NetworkError) as ei:
        _post_with_retry("model-x", "http://u", {}, {}, timeout=120,
                         retries=3, backoff=0.1)
    assert len(calls) == 3                      # bounded: no infinite retry loop
    assert 0.1 <= sleeps[0] <= 0.125
    assert 0.2 <= sleeps[1] <= 0.25
    msg = str(ei.value)
    assert NETWORK_FALLBACK_MSG in msg
    assert "after 3 attempt(s)" in msg


def test_permanent_net_error_fails_fast(monkeypatch):
    """A DNS failure / connection-refused can never succeed on retry, so the
    speed upgrade fails it immediately instead of burning the backoff budget
    (~3 s) before the failover chain moves on."""
    calls = []
    sleeps = []

    def fake_post(*a, **k):
        calls.append(1)
        # requests wraps DNS-resolution failures in ConnectionError
        raise requests.exceptions.ConnectionError("Failed to resolve host")

    _patch_session(monkeypatch, fake_post)
    monkeypatch.setattr(llm.time, "sleep", lambda s_: sleeps.append(s_))

    with pytest.raises(NetworkError) as ei:
        _post_with_retry("model-x", "http://u", {}, {}, timeout=120,
                         retries=3, backoff=0.1)
    assert len(calls) == 1                       # no retries for a dead host
    assert sleeps == []                          # no backoff burned
    assert NETWORK_FALLBACK_MSG in str(ei.value)
    assert "after 3 attempt(s)" not in str(ei.value)


def test_non_transient_request_error_fails_fast(monkeypatch):
    """Bad URL / malformed request must NOT be retried."""
    calls = []

    def fake_post(*a, **k):
        calls.append(1)
        raise requests.exceptions.InvalidURL("bad url")

    _patch_session(monkeypatch, fake_post)

    with pytest.raises(LLMError) as ei:
        _post_with_retry("model-x", "http://u", {}, {}, timeout=120,
                         retries=3, backoff=0.1)
    assert "API request failed" in str(ei.value)
    assert len(calls) == 1
    assert not isinstance(ei.value, NetworkError)


# ---------------------------------------------------------------- Fix 1


class _MockBase:
    model = "mock"


class _DropAfterDeltaLLM(_MockBase):
    """Streams one token, then the socket drops mid-answer (the exact case
    that used to leave the UI stuck on 'agent is working')."""

    def chat_stream(self, prompt, tools=None, cancel_event=None, model=None):
        yield {"type": "delta", "content": "partial"}
        raise NetworkError("%s (model 'mock'; connection dropped "
                           "mid-stream: Connection broken)" % NETWORK_FALLBACK_MSG)

    def complete(self, *a, **k):
        raise NetworkError(NETWORK_FALLBACK_MSG)


class _HardFailLLM(_MockBase):
    """Model completely unreachable before the first token."""

    def chat_stream(self, prompt, tools=None, cancel_event=None, model=None):
        raise LLMError(NETWORK_FALLBACK_MSG + " (model 'mock'; API unreachable)")

    def complete(self, *a, **k):
        raise LLMError("hard down")


def _agent(llm_client):
    return Agent(llm=llm_client, memory=None, name="net-test",
                 auto_verify=False, reasoning_engine=False)


def test_run_stream_terminates_after_midstream_drop():
    """A network drop after tokens => an error event is surfaced AND the
    generator ends, so the webui worker can release the busy state."""
    events = list(_agent(_DropAfterDeltaLLM()).run_stream("ping me"))
    types_seen = [e["type"] for e in events]
    assert types_seen[0] == "start"
    assert "delta" in types_seen
    errs = [e for e in events if e["type"] == "error"]
    assert errs and NETWORK_FALLBACK_MSG in errs[-1]["content"]
    assert types_seen[-1] == "error"     # stream ends on the error, no hang
    assert "final" not in types_seen


def test_run_stream_terminates_on_hard_llm_error():
    """Unreachable API before any token => error event, clean termination."""
    events = list(_agent(_HardFailLLM()).run_stream("hello"))
    types_seen = [e["type"] for e in events]
    errs = [e for e in events if e["type"] == "error"]
    assert errs and "[LLM error]" in errs[-1]["content"]
    assert types_seen[-1] == "error"
    assert "final" not in types_seen


def test_network_error_is_llm_error_subclass():
    """Existing failover code paths catch LLMError; NetworkError must ride
    the same lane so nothing falls through uncaught and hangs a turn."""
    assert issubclass(NetworkError, LLMError)
