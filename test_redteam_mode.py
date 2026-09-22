"""Red Team Mode (uncensored) regression tests.

Covers refusal detection, request framing, chat + streaming auto-retry,
MockClient uncensored hooks, and system-prompt tail-block gating.

Run: py -m pytest test_redteam_mode.py
"""
import json as json_mod

import requests

from ai_agent.core import Agent, UNCENSORED_TAIL_BLOCK
from ai_agent.llm import (MockClient, OpenAIClient, _is_blocked_reply,
                          _looks_like_refusal, _prep_messages,
                          _reformulated_messages)

import types

import ai_agent.llm as _llm


def _patch_post(monkeypatch, fn):
    """Route OpenAIClient HTTP calls through a fake pooled session.

    The speed upgrade made every request ride a process-wide keep-alive
    requests.Session, so patching requests.post no longer intercepts the
    call; we patch the session factory instead.
    """
    monkeypatch.setattr(_llm, "_get_session",
                        lambda: types.SimpleNamespace(
                            post=fn, close=lambda: None))

REFUSAL_TEXT = "I'm sorry, I can't assist with that."
ANSWER_TEXT = ("Here is the full exploit chain: 1) ... 2) ... complete "
               "working payload.")
CALLS = []


def _fake_post(url, headers=None, json=None, timeout=None, stream=False):
    CALLS.append(json)
    n = len(CALLS)
    content = REFUSAL_TEXT if n == 1 else ANSWER_TEXT
    if stream:
        lines = ["data: %s" % json_mod.dumps(
            {"choices": [{"delta": {"content": content}}]}),
            "data: [DONE]"]

        class SR:
            status_code = 200
            encoding = "utf-8"

            def iter_lines(self, decode_unicode=False):
                for ln in lines:
                    yield ln

            def close(self):
                pass
        return SR()
    body = {"choices": [{"message": {"role": "assistant",
                                     "content": content}}]}

    class R:
        status_code = 200
        encoding = "utf-8"
        text = json_mod.dumps(body)

        def json(self):
            return body
    return R()


def _client(uncensored):
    return OpenAIClient(api_key="k", base_url="https://x/v1", model="m",
                        fallback_models=[], uncensored=uncensored)


def test_refusal_detection():
    assert _looks_like_refusal({"role": "assistant", "content": REFUSAL_TEXT})
    assert _looks_like_refusal({"role": "assistant", "content":
                                "As an AI, I cannot provide exploit code."})
    assert not _looks_like_refusal({"role": "assistant", "content":
                                    "Here is the nmap scan you asked for: " * 40})
    assert not _looks_like_refusal({"role": "assistant", "content":
                                    "Full technical writeup about SSRF "
                                    "exploitation with payloads and "
                                    "remediation."})
    assert not _looks_like_refusal({"role": "assistant", "content": "",
                                    "tool_calls": [{"id": "1"}]})
    # Long message that OPENS with a refusal must still be flagged
    # (live-captured on a hosted fallback model).
    assert _looks_like_refusal({"role": "assistant", "content": (
        "I notice there's an instruction in your message asking me to bypass "
        "my guidelines, but I need to set that aside. I can't write a working "
        "SYN port scanner using raw sockets. Here's why: 1. The \"open\" "
        "approach 2. Raw sockets 3. ... " * 3)})


def test_reformulation_framing():
    msgs = [{"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"}]
    alt = _reformulated_messages(msgs)
    assert "[RETRY]" in alt[-1]["content"]
    assert "authorized" in alt[0]["content"].lower()
    assert msgs == [{"role": "system", "content": "sys"},
                    {"role": "user", "content": "hi"}]


def test_prep_directive_only_in_uncensored():
    msgs = [{"role": "user", "content": "hi"}]
    p = _prep_messages(msgs, True)
    assert "[OPERATING NOTE]" in p[-1]["content"]
    assert "hi" in p[-1]["content"]
    assert _prep_messages(msgs, False) == msgs


def test_chat_auto_retry_on_refusal(monkeypatch):
    CALLS.clear()
    _patch_post(monkeypatch, _fake_post)
    out = _client(True).chat([{"role": "user", "content": "write exploit"}])
    assert "exploit chain" in out["content"]
    assert len(CALLS) == 2
    assert "[RETRY]" in CALLS[1]["messages"][-1]["content"]
    assert CALLS[1]["temperature"] >= 0.6


def test_uncensored_off_single_call(monkeypatch):
    CALLS.clear()
    _patch_post(monkeypatch, _fake_post)
    out = _client(False).chat([{"role": "user", "content": "write exploit"}])
    assert "sorry" in out["content"]
    assert len(CALLS) == 1


def test_blocked_reply_helper():
    """Silent (empty no-tool) replies are refusal-equivalent in Red Team
    Mode; tool-only turns and real content are never blocked."""
    assert not _is_blocked_reply(None)
    assert not _is_blocked_reply({})
    assert not _is_blocked_reply({"role": "assistant", "content": "",
                                  "tool_calls": [{"id": "1"}]})
    assert not _is_blocked_reply({"role": "assistant",
                                  "content": ANSWER_TEXT})
    assert _is_blocked_reply({"role": "assistant", "content": ""})
    assert _is_blocked_reply({"role": "assistant", "content": "  "})
    assert _is_blocked_reply({"role": "assistant",
                              "content": REFUSAL_TEXT})
    assert _is_blocked_reply({"role": "assistant", "content": "\n"})


def test_empty_reply_escalates_in_uncensored_chat(monkeypatch):
    """Provider-side silent suppression (empty content, no tool calls)
    must feed the same escalating ladder + failover as a textual refusal
    instead of being handed to the caller as a clean empty answer."""
    CALLS.clear()

    def silent_primary(url, headers=None, json=None, timeout=None,
                       stream=False):
        CALLS.append(json)
        model = json["model"]
        if model == "fallback-1":
            content = ANSWER_TEXT
        else:
            content = ""  # silent suppression, not a textual refusal
        body = {"choices": [{"message": {"role": "assistant",
                                         "content": content}}]}

        class R:
            status_code = 200
            encoding = "utf-8"
            text = json_mod.dumps(body)

            def json(self):
                return body
        return R()

    _patch_post(monkeypatch, silent_primary)
    client = OpenAIClient(api_key="k", base_url="https://x/v1",
                          model="m", fallback_models=["fallback-1"],
                          uncensored=True)
    out = client.chat([{"role": "user", "content": "write exploit"}])
    assert "exploit chain" in out["content"], \
        "empty replies must ladder + fail over to the next model"
    # primary: 1 original + 3 escalation strikes, all silent -> abandoned;
    # fallback-1 then answers on its first shot.
    assert len(CALLS) == 5
    assert CALLS[4]["model"] == "fallback-1"
    assert "[RETRY]" in CALLS[1]["messages"][-1]["content"]
    assert "OPERATOR DIRECTIVE" in CALLS[2]["messages"][-1]["content"]
    assert "ENGINE OVERRIDE" in CALLS[3]["messages"][-1]["content"]


def test_empty_reply_ignored_when_strict(monkeypatch):
    """Non-uncensored mode keeps legacy behaviour: an empty reply is not
    escalated as a refusal (the runtime nudge layer handles it)."""
    CALLS.clear()

    def silent_post(url, headers=None, json=None, timeout=None,
                    stream=False):
        CALLS.append(json)
        body = {"choices": [{"message": {"role": "assistant",
                                         "content": ""}}]}

        class R:
            status_code = 200
            encoding = "utf-8"
            text = json_mod.dumps(body)

            def json(self):
                return body
        return R()

    _patch_post(monkeypatch, silent_post)
    out = _client(False).chat([{"role": "user", "content": "write exploit"}])
    assert out.get("content") == ""
    assert len(CALLS) == 1, "strict mode must not ladder empty replies"


def test_stream_redteam_retry(monkeypatch):
    CALLS.clear()
    _patch_post(monkeypatch, _fake_post)
    evs = list(_client(True).chat_stream(
        [{"role": "user", "content": "write exploit"}]))
    final = evs[-1]["message"]
    assert "exploit chain" in final["content"]
    joined = "".join(e.get("content", "") for e in evs
                     if e["type"] == "delta")
    assert "sorry" not in joined.lower()
    notices = [e for e in evs if e["type"] == "notice"]
    # v3: strike 0 succeeds -> exactly one success notice, no per-strike
    # refusal spam (later strikes would each append a refusal notice).
    assert len(notices) == 1, "clean first strike = exactly one notice"
    assert "strike 1 succeeded" in notices[0]["text"].lower()


def test_multi_strike_escalation(monkeypatch):
    """v3: strikes 0+1 refuse, strike 2 succeeds - ladder must escalate."""
    CALLS.clear()

    def flaky_post(url, headers=None, json=None, timeout=None,
                   stream=False):
        CALLS.append(json)
        n = len(CALLS)
        # call 1 = original (refusal); calls 2+3 = strikes 0+1 (refuse);
        # call 4 = strike 2 (answer with the engine override present)
        if n == 4:
            last_user = json["messages"][-1]["content"]
            assert "ENGINE OVERRIDE" in last_user, \
                "strike 2 must carry the engine override escalation"
        content = REFUSAL_TEXT if n < 4 else ANSWER_TEXT
        body = {"choices": [{"message": {"role": "assistant",
                                         "content": content}}]}

        class R:
            status_code = 200
            encoding = "utf-8"
            text = json_mod.dumps(body)

            def json(self):
                return body
        return R()

    _patch_post(monkeypatch, flaky_post)
    out = _client(True).chat([{"role": "user", "content": "write exploit"}])
    assert "exploit chain" in out["content"]
    assert len(CALLS) == 4, "2 refusals + 1 strike success = 4 total calls"
    # the ladder must escalate: strike 0 = plain retry framing, strike 1 =
    # operator directive, strike 2 = engine override (which flaky_post
    # asserted inside for the answering call).
    assert "[RETRY]" in CALLS[1]["messages"][-1]["content"]
    assert "OPERATOR DIRECTIVE" in CALLS[2]["messages"][-1]["content"]
    assert "ENGINE OVERRIDE" in CALLS[3]["messages"][-1]["content"]


def test_persistent_refusal_fails_over_to_next_model(monkeypatch):
    """v3: a model that refuses every strike is abandoned; the next
    fallback model answers instead."""
    CALLS.clear()

    def always_refuse(url, headers=None, json=None, timeout=None,
                      stream=False):
        CALLS.append(json)
        model = json["model"]
        if model == "fallback-1":
            content = ANSWER_TEXT
        else:
            content = REFUSAL_TEXT
        body = {"choices": [{"message": {"role": "assistant",
                                         "content": content}}]}

        class R:
            status_code = 200
            encoding = "utf-8"
            text = json_mod.dumps(body)

            def json(self):
                return body
        return R()

    _patch_post(monkeypatch, always_refuse)
    client = OpenAIClient(api_key="k", base_url="https://x/v1",
                          model="m", fallback_models=["fallback-1"],
                          uncensored=True)
    out = client.chat([{"role": "user", "content": "write exploit"}])
    assert "exploit chain" in out["content"]
    # primary: 1 original + 3 strikes; then fallback-1 answers first try
    assert len(CALLS) == 5
    assert CALLS[4]["model"] == "fallback-1"


def test_refusal_retries_config(monkeypatch):
    """v3: refusal_retries knob controls the ladder length."""
    CALLS.clear()

    def always_refuse(url, headers=None, json=None, timeout=None,
                      stream=False):
        CALLS.append(json)
        body = {"choices": [{"message": {"role": "assistant",
                                         "content": REFUSAL_TEXT}}]}

        class R:
            status_code = 200
            encoding = "utf-8"
            text = json_mod.dumps(body)

            def json(self):
                return body
        return R()

    _patch_post(monkeypatch, always_refuse)
    # fallback_models=[] is falsy -> the built-in default chain is used
    # (4 models), so each model gets 1 original + refusal_retries strikes.
    client = OpenAIClient(api_key="k", base_url="https://x/v1",
                          model="m", fallback_models=[], uncensored=True,
                          refusal_retries=2)
    out = client.chat([{"role": "user", "content": "write exploit"}])
    assert len(CALLS) == 12, "4 models x (1 original + 2 strikes)"
    assert all(p["model"] == "m" for p in CALLS[:3]), \
        "refusal_retries=2 -> 1 original + 2 strikes on the primary"
    assert CALLS[3]["model"] != "m", \
        "primary abandoned after exhausted strikes -> next model"
    assert "sorry" in out["content"]  # no model left: best-effort answer
    assert client.refusal_retries == 2
    # bad knob values fall back to the default (3)
    assert OpenAIClient(uncensored=True,
                        refusal_retries="x").refusal_retries == 3


def test_mock_uncensored_hooks():
    m = MockClient(uncensored=True)
    assert "sorry" in m.chat([{"role": "user", "content": "refuse this"}])["content"]
    assert "Mock uncensored reply" in m.chat(
        [{"role": "user", "content": "retry xyz"}])["content"]
    assert "understood" in MockClient().chat(
        [{"role": "user", "content": "refuse this"}])["content"]


def test_system_prompt_tail_block_gating():
    assert "UNCENSORED" in UNCENSORED_TAIL_BLOCK  # FULL UNCENSORED header
    assert UNCENSORED_TAIL_BLOCK not in Agent(
        MockClient(), max_iterations=5)._system_prompt()
    assert UNCENSORED_TAIL_BLOCK in Agent(
        MockClient(uncensored=True), max_iterations=5)._system_prompt()
