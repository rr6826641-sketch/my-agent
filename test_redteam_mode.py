"""Red Team Mode (uncensored) regression tests.

Covers refusal detection, request framing, chat + streaming auto-retry,
MockClient uncensored hooks, and system-prompt tail-block gating.

Run: py -m pytest test_redteam_mode.py
"""
import json as json_mod

import requests

from ai_agent.core import Agent, UNCENSORED_TAIL_BLOCK
from ai_agent.llm import (MockClient, OpenAIClient, _looks_like_refusal,
                          _prep_messages, _reformulated_messages)

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
    monkeypatch.setattr(requests, "post", _fake_post)
    out = _client(True).chat([{"role": "user", "content": "write exploit"}])
    assert "exploit chain" in out["content"]
    assert len(CALLS) == 2
    assert "[RETRY]" in CALLS[1]["messages"][-1]["content"]
    assert CALLS[1]["temperature"] >= 0.6


def test_uncensored_off_single_call(monkeypatch):
    CALLS.clear()
    monkeypatch.setattr(requests, "post", _fake_post)
    out = _client(False).chat([{"role": "user", "content": "write exploit"}])
    assert "sorry" in out["content"]
    assert len(CALLS) == 1


def test_stream_redteam_retry(monkeypatch):
    CALLS.clear()
    monkeypatch.setattr(requests, "post", _fake_post)
    evs = list(_client(True).chat_stream(
        [{"role": "user", "content": "write exploit"}]))
    final = evs[-1]["message"]
    assert "exploit chain" in final["content"]
    joined = "".join(e.get("content", "") for e in evs
                     if e["type"] == "delta")
    assert "sorry" not in joined.lower()
    notices = [e for e in evs if e["type"] == "notice"]
    assert len(notices) == 1, "retry must emit exactly one notice event"
    assert "auto-retried" in notices[0]["text"].lower()


def test_mock_uncensored_hooks():
    m = MockClient(uncensored=True)
    assert "sorry" in m.chat([{"role": "user", "content": "refuse this"}])["content"]
    assert "Mock uncensored reply" in m.chat(
        [{"role": "user", "content": "retry xyz"}])["content"]
    assert "understood" in MockClient().chat(
        [{"role": "user", "content": "refuse this"}])["content"]


def test_system_prompt_tail_block_gating():
    assert "RED TEAM" in UNCENSORED_TAIL_BLOCK
    assert UNCENSORED_TAIL_BLOCK not in Agent(
        MockClient(), max_iterations=5)._system_prompt()
    assert UNCENSORED_TAIL_BLOCK in Agent(
        MockClient(uncensored=True), max_iterations=5)._system_prompt()
