"""Non-image file context injection into chat turns (Phase 1b / item 2).

Item 2 of the remaining Phase-1 items: when the session holds non-image
uploads (TXT/JSON/PCAP/PDF), OpenAIClient appends inline text context to
the LAST user message of the next ``chat()`` / ``chat_stream()`` call and
then clears it - one-shot, model-agnostic semantics (unlike vision blocks,
which only apply to vision-capable models).

Everything here runs offline - the HTTP transport is fully faked, so the
tests verify payload construction, not network behaviour.
"""

import json

import pytest

import ai_agent.llm as llm_mod
from ai_agent.llm import OpenAIClient

NOTES = "plain text notes\nsecond line"
JSON_BODY = '{"name": "demo", "count": 3}'


@pytest.fixture()
def txt_file(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text(NOTES, encoding="utf-8")
    return str(p)


@pytest.fixture()
def json_file(tmp_path):
    p = tmp_path / "data.json"
    p.write_text(JSON_BODY, encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# fake transport capture (same pattern as tests/test_vision_chat.py)
# ---------------------------------------------------------------------------


class _FakeResp:
    status_code = 200
    encoding = "utf-8"
    text = json.dumps({"choices": [
        {"message": {"role": "assistant", "content": "ok"}}]})

    def json(self):
        return json.loads(self.text)


class _FakeStreamResp:
    status_code = 200
    encoding = "utf-8"
    text = ""

    def json(self):
        return {"choices": [{"message": {"role": "assistant", "content": ""}}]}

    def iter_lines(self, decode_unicode=False):
        yield "data: " + json.dumps(
            {"choices": [{"delta": {"role": "assistant", "content": "hi "}}]})
        yield "data: [DONE]"

    def close(self):
        pass


def _capture_client(model, monkeypatch, stream=False):
    captured = {}

    def fake_post(model, url, headers, payload, timeout, stream=False):
        captured["payload"] = payload
        return _FakeStreamResp() if stream else _FakeResp()

    c = OpenAIClient(api_key="test-key", model=model,
                     fallback_models=[], timeout=5)
    monkeypatch.setattr(c, "_request_target",
                        lambda model: ("https://api.test/v1", {}))
    monkeypatch.setattr(llm_mod, "_post_with_retry", fake_post)
    return c, captured


# ---------------------------------------------------------------------------
# attach_text_context() input handling
# ---------------------------------------------------------------------------


def test_attach_text_context_cleans_input():
    c = OpenAIClient(api_key="test-key", model="llama-3.3-70b-instruct",
                     fallback_models=[], timeout=5)
    c.attach_text_context("single line")
    assert c.text_context == ["single line"]
    c.attach_text_context(["  a  ", "", "   ", "b"])
    # whitespace-only and empty entries dropped; text preserved as-is
    assert c.text_context == ["  a  ", "b"]
    c.attach_text_context(123)  # coerced to str
    assert c.text_context == ["123"]


def test_attach_text_context_empty_clears():
    c = OpenAIClient(api_key="test-key", model="m", fallback_models=[],
                     timeout=5)
    c.attach_text_context(["x"])
    c.attach_text_context([])
    assert c.text_context == []


# ---------------------------------------------------------------------------
# _messages_with_context() one-shot behaviour
# ---------------------------------------------------------------------------


def test_messages_with_context_appends_and_clears(txt_file):
    c = OpenAIClient(api_key="test-key", model="m", fallback_models=[],
                     timeout=5)
    c.attach_text_context(["FILE %s:\n%s" % (txt_file, NOTES)])
    msgs = [{"role": "user", "content": "summarize the notes"}]
    out = c._messages_with_context(msgs)
    assert out[-1]["content"].endswith(NOTES + "\n")
    assert "[ATTACHED FILES" in out[-1]["content"]
    assert c.text_context == []  # one-shot: cleared after injection
    # caller's message objects are never mutated
    assert msgs[0]["content"] == "summarize the notes"


def test_messages_with_context_targets_last_user_message():
    c = OpenAIClient(api_key="test-key", model="m", fallback_models=[],
                     timeout=5)
    c.attach_text_context(["ctx-a", "ctx-b"])
    msgs = [{"role": "system", "content": "sys"},
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": "mid"},
            {"role": "user", "content": "second"}]
    out = c._messages_with_context(msgs)
    # only the LAST user message receives the note
    assert out[1]["content"] == "first"
    assert "[ATTACHED FILES" in out[-1]["content"]
    assert "ctx-a\nctx-b" in out[-1]["content"]
    assert c.text_context == []


def test_messages_with_context_no_user_message_keeps_context():
    c = OpenAIClient(api_key="test-key", model="m", fallback_models=[],
                     timeout=5)
    c.attach_text_context(["ctx"])
    msgs = [{"role": "system", "content": "sys"}]
    out = c._messages_with_context(msgs)
    assert out is msgs  # unchanged object identity
    assert len(c.text_context) == 1  # still pending


def test_messages_with_context_no_context_returns_same_list():
    c = OpenAIClient(api_key="test-key", model="m", fallback_models=[],
                     timeout=5)
    msgs = [{"role": "user", "content": "hi"}]
    assert c._messages_with_context(msgs) is msgs


# ---------------------------------------------------------------------------
# End-to-end: real chat()/chat_stream() payload capture
# ---------------------------------------------------------------------------


def test_chat_payload_embeds_context(monkeypatch, txt_file):
    c, captured = _capture_client("llama-3.3-70b-instruct", monkeypatch)
    c.attach_text_context(["FILE %s:\n%s" % (txt_file, NOTES)])
    msgs = [{"role": "user", "content": "read the notes"}]
    reply = c.chat(list(msgs))
    assert reply["content"] == "ok"
    last = captured["payload"]["messages"][-1]
    assert captured["payload"]["model"] == "llama-3.3-70b-instruct"
    assert last["role"] == "user"
    assert "[ATTACHED FILES" in last["content"]
    assert NOTES in last["content"]
    # one-shot: cleared after the first call
    assert c.text_context == []
    assert msgs[0]["content"] == "read the notes"  # caller untouched


def test_chat_context_injected_for_text_model_only_once(monkeypatch, txt_file):
    c, captured = _capture_client("gpt-4o-mini", monkeypatch)
    c.attach_text_context(["FILE %s:\n%s" % (txt_file, NOTES)])
    c.chat([{"role": "user", "content": "first"}])
    assert c.text_context == []
    c.chat([{"role": "user", "content": "second"}])
    last = captured["payload"]["messages"][-1]
    assert last["content"] == "second"  # plain follow-up turn


def test_chat_stream_payload_embeds_context(monkeypatch, txt_file):
    c, captured = _capture_client("gemini-2.5-flash", monkeypatch,
                                  stream=True)
    c.attach_text_context(["FILE %s:\n%s" % (txt_file, NOTES)])
    events = list(c.chat_stream(
        [{"role": "user", "content": "look at these notes"}]))
    assert any(e["type"] == "delta" for e in events)
    assert captured["payload"]["stream"] is True
    last = captured["payload"]["messages"][-1]
    assert "[ATTACHED FILES" in last["content"]
    assert c.text_context == []


def test_json_attachment_inlined_as_text(monkeypatch, json_file):
    c, captured = _capture_client("llama-3.3-70b-instruct", monkeypatch)
    c.attach_text_context(["JSON FILE %s (%d bytes):\n%s"
                           % (json_file, len(JSON_BODY), JSON_BODY)])
    c.chat([{"role": "user", "content": "parse the payload"}])
    last = captured["payload"]["messages"][-1]
    assert JSON_BODY in last["content"]
    assert c.text_context == []
