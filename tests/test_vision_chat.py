"""Live vision payload injection into chat completions (Phase 1b / item 1).

Item 1 of the remaining Phase-1 items: when the routed model is
vision-capable and the session holds image uploads, OpenAIClient embeds
OpenAI-style ``image_url`` content blocks (Base64 data URLs) into the
actual request payload of ``chat()`` and ``chat_stream()``.

Everything here runs offline - the HTTP transport is fully faked, so the
tests verify payload construction, not network behaviour.
"""

import base64
import json

import pytest

import ai_agent.llm as llm_mod
from ai_agent.llm import (OpenAIClient, _append_user_content,
                          _inject_vision_blocks, model_supports_vision)

PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
    "z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)

VISION_POSITIVES = [
    "qwen2.5-vl-7b-instruct",
    "Qwen/Qwen2-VL-72B-Instruct",
    "qwen3-vl-235b-a22b",
    "openai/gpt-4o",
    "openai/gpt-4o-mini",
    "openai/gpt-4.1-mini",
    "gpt-4-turbo",
    "google/gemini-2.5-flash",
    "anthropic/claude-3-5-sonnet",
    "anthropic/claude-4-sonnet",
    "mistralai/pixtral-12b",
    "llava-hf/llava-1.5-7b-hf",
    "OpenGVLab/InternVL2-8B",
    "vikhyatk/moondream2",
    "openbmb/MiniCPM-V-2_6",
    "microsoft/phi-4-v",
    "xai/grok-2-vision",
]

VISION_NEGATIVES = [
    "deepseek/deepseek-r1",
    "cognitivecomputations/dolphin-mistral-24b",
    "meta-llama/llama-3.3-70b-instruct",
    "openai/o4-mini",          # reasoning family, excluded
    "openai/gpt-4o-prose",     # prose subclass, excluded
    "openai/o1-preview",       # reasoning family, excluded
    "",
    None,
]


@pytest.fixture()
def png_file(tmp_path):
    p = tmp_path / "shot.png"
    p.write_bytes(base64.b64decode(PNG_B64))
    return str(p)


@pytest.fixture()
def txt_file(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("plain text notes", encoding="utf-8")
    return str(p)


def _png_bytes():
    return base64.b64decode(PNG_B64)


# ---------------------------------------------------------------------------
# model_supports_vision() heuristic
# ---------------------------------------------------------------------------


def test_vision_heuristic_positives():
    for mid in VISION_POSITIVES:
        assert model_supports_vision(mid), "expected vision=True for %r" % mid


def test_vision_heuristic_negatives():
    for mid in VISION_NEGATIVES:
        assert not model_supports_vision(mid), "expected vision=False for %r" % mid


def test_vision_heuristic_case_insensitive():
    assert model_supports_vision("OpenAI/GPT-4O-MINI")
    assert not model_supports_vision("Llama-3.3-70B")


# ---------------------------------------------------------------------------
# _append_user_content(): string OR multimodal content-block list
# ---------------------------------------------------------------------------


def test_append_user_content_string():
    m = {"role": "user", "content": "hello"}
    _append_user_content(m, " world")
    assert m["content"] == "hello world"


def test_append_user_content_list_merges_into_last_text_block():
    m = {"role": "user",
         "content": [{"type": "text", "text": "what is this?"}]}
    _append_user_content(m, " [RETRY] again")
    assert m["content"] == [{"type": "text",
                             "text": "what is this? [RETRY] again"}]


def test_append_user_content_list_appends_text_block_after_image():
    m = {"role": "user",
         "content": [
             {"type": "image_url",
              "image_url": {"url": "data:image/png;base64,AAAA"}}]}
    _append_user_content(m, " describe it")
    assert m["content"][-1] == {"type": "text", "text": " describe it"}
    assert m["content"][0]["type"] == "image_url"


# ---------------------------------------------------------------------------
# _inject_vision_blocks(): pure transformation
# ---------------------------------------------------------------------------


def test_inject_no_attachments_is_noop():
    msgs = [{"role": "user", "content": "hi"}]
    out, injected = _inject_vision_blocks(msgs, [])
    assert out is msgs and not injected


def test_inject_no_user_message_is_noop():
    msgs = [{"role": "system", "content": "be helpful"}]
    out, injected = _inject_vision_blocks(msgs, [("x.png", "image/png")])
    assert not injected and out == msgs


def test_inject_string_content_becomes_multimodal(png_file):
    msgs = [{"role": "system", "content": "sys"},
            {"role": "user", "content": "analyze the screenshot"}]
    out, injected = _inject_vision_blocks(
        msgs, [(png_file, "image/png")])
    assert injected
    last = out[-1]
    assert last["content"][0] == {"type": "text",
                                  "text": "analyze the screenshot"}
    img = last["content"][1]
    assert img["type"] == "image_url"
    assert img["image_url"]["url"] == (
        "data:image/png;base64," + base64.b64encode(_png_bytes()).decode())
    # original message list is not mutated
    assert msgs[-1]["content"] == "analyze the screenshot"


def test_inject_list_content_appends_blocks(png_file, txt_file):
    msgs = [{"role": "user",
             "content": [{"type": "text", "text": "look"},
                         {"type": "text", "text": "again"}]}]
    out, injected = _inject_vision_blocks(
        msgs, [(png_file, "image/png"), (txt_file, "text/plain")])
    assert injected
    types = [b["type"] for b in out[-1]["content"]]
    # text-only attachments are NOT embedded on the list branch
    assert types == ["text", "text", "image_url"]


def test_inject_missing_file_is_skipped(tmp_path):
    missing = str(tmp_path / "nope.png")
    msgs = [{"role": "user", "content": "hi"}]
    out, injected = _inject_vision_blocks(msgs, [(missing, "image/png")])
    assert injected  # message rewritten even when the file vanished
    assert all(b["type"] == "text" for b in out[-1]["content"])


def test_inject_last_user_message_only(png_file):
    msgs = [{"role": "user", "content": "first"},
            {"role": "assistant", "content": "mid"},
            {"role": "user", "content": "last"}]
    out, injected = _inject_vision_blocks(msgs, [(png_file, "image/png")])
    assert injected
    assert out[0]["content"] == "first"
    assert isinstance(out[2]["content"], list)


def test_inject_non_image_notes_on_string_branch(png_file, txt_file):
    msgs = [{"role": "user", "content": "what about this"}]
    out, injected = _inject_vision_blocks(
        msgs, [(png_file, "image/png"), (txt_file, "text/plain")])
    texts = [b["text"] for b in out[-1]["content"] if b["type"] == "text"]
    assert any("notes.txt" in t for t in texts)


# ---------------------------------------------------------------------------
# set_vision_attachments() / _messages_with_vision() (one-shot behaviour)
# ---------------------------------------------------------------------------


def _client(model="qwen2.5-vl-7b"):
    return OpenAIClient(api_key="test-key", model=model,
                        fallback_models=[], timeout=5)


def test_set_vision_attachments_cleans_input():
    c = _client()
    c.set_vision_attachments([("a.png", "image/png"), ("b", "image/jpeg"),
                              "garbage", None, ("c.png",)])
    # garbage and too-short entries are dropped, valid tuples survive
    assert c.vision_attachments == [("a.png", "image/png"),
                                    ("b", "image/jpeg")]


def test_set_vision_attachments_empty_clears():
    c = _client()
    c.set_vision_attachments([("a.png", "image/png")])
    c.set_vision_attachments([])
    assert c.vision_attachments == []


def test_messages_with_vision_injects_and_clears(png_file):
    c = _client()
    c.set_vision_attachments([(png_file, "image/png")])
    msgs = [{"role": "user", "content": "analyze"}]
    out = c._messages_with_vision("qwen2.5-vl-7b", msgs)
    assert isinstance(out[-1]["content"], list)
    assert c.vision_attachments == []  # one-shot: cleared after injection


def test_messages_with_vision_non_vision_model_keeps_attachments(png_file):
    c = _client()
    c.set_vision_attachments([(png_file, "image/png")])
    msgs = [{"role": "user", "content": "analyze"}]
    out = c._messages_with_vision("dolphin-mistral-24b", msgs)
    assert out is msgs
    assert len(c.vision_attachments) == 1  # still pending for a vision call


# ---------------------------------------------------------------------------
# End-to-end: real chat()/chat_stream() payload capture with a faked transport
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

    c = _client(model)
    monkeypatch.setattr(c, "_request_target",
                        lambda model: ("https://api.test/v1", {}))
    monkeypatch.setattr(llm_mod, "_post_with_retry", fake_post)
    return c, captured


def test_chat_payload_embeds_vision_for_vision_model(monkeypatch, png_file):
    c, captured = _capture_client("qwen2.5-vl-7b", monkeypatch)
    c.set_vision_attachments([(png_file, "image/png")])
    msgs = [{"role": "user", "content": "analyze the screenshot"}]
    reply = c.chat(list(msgs))
    assert reply["content"] == "ok"
    last = captured["payload"]["messages"][-1]
    assert captured["payload"]["model"] == "qwen2.5-vl-7b"
    assert [b["type"] for b in last["content"]] == ["text", "image_url"]
    # caller's message objects are never mutated
    assert msgs[0]["content"] == "analyze the screenshot"


def test_chat_payload_stays_text_for_non_vision_model(monkeypatch, png_file):
    c, captured = _capture_client("dolphin-mistral-24b", monkeypatch)
    c.set_vision_attachments([(png_file, "image/png")])
    c.chat([{"role": "user", "content": "analyze"}])
    last = captured["payload"]["messages"][-1]
    assert last["content"] == "analyze"
    assert len(c.vision_attachments) == 1  # not consumed by a text model


def test_chat_second_call_does_not_reinject(monkeypatch, png_file):
    c, captured = _capture_client("gpt-4o", monkeypatch)
    c.set_vision_attachments([(png_file, "image/png")])
    c.chat([{"role": "user", "content": "first"}])
    assert c.vision_attachments == []
    c.chat([{"role": "user", "content": "second"}])
    last = captured["payload"]["messages"][-1]
    assert last["content"] == "second"  # text-only follow-up turn


def test_chat_stream_payload_embeds_vision(monkeypatch, png_file):
    c, captured = _capture_client("gemini-2.5-flash", monkeypatch,
                                  stream=True)
    c.set_vision_attachments([(png_file, "image/png")])
    events = list(c.chat_stream(
        [{"role": "user", "content": "look at this"}]))
    assert any(e["type"] == "delta" for e in events)
    assert captured["payload"]["stream"] is True
    last = captured["payload"]["messages"][-1]
    assert [b["type"] for b in last["content"]] == ["text", "image_url"]
    assert c.vision_attachments == []
