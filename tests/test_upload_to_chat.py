"""Phase 2 end-to-end seam: uploaded image travels to the model payload.

Proof that the HTTP upload pipeline (``POST /api/upload``) feeds the chat
turn exactly as designed:

  1. a PNG POSTed to the webui upload route is stored and linked to the
     active chat session (auto-minted when no chat exists yet);
  2. the session vision endpoint exposes OpenAI-style image content blocks;
  3. the same attach step the /api/chat worker runs
     (``webui._attach_session_files``) registers that image on a
     vision-capable OpenAIClient;
  4. ``chat()`` with a plain text prompt emits ONE message whose content is
     ``[text, image_url]`` - i.e. the image is sent together with the text.

Everything runs offline against a temp dir - real uploads dir, chats.json
and HTTP transport are all replaced, so the developer repo is untouched.
"""

import base64
import io
import json

import pytest

import ai_agent.llm as llm_mod
import webui
from ai_agent.core.file_handler import FileHandler
from ai_agent.llm import OpenAIClient

PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
    "z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def _png_bytes():
    return base64.b64decode(PNG_B64)


class _FakeAgent:
    """Minimal stand-in for webui._state['agent'] with an .llm client."""

    def __init__(self, llm):
        self.llm = llm


class _FakeResp:
    status_code = 200
    encoding = "utf-8"
    text = json.dumps({"choices": [
        {"message": {"role": "assistant", "content": "ok"}}]})

    def json(self):
        return json.loads(self.text)


@pytest.fixture()
def isolated_webui(monkeypatch, tmp_path):
    """Point webui storage globals at a throwaway temp dir."""
    uploads_root = tmp_path / "data" / "uploads"
    uploads_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(webui, "uploads", FileHandler(str(uploads_root)))
    monkeypatch.setattr(webui, "CHATS_PATH", str(tmp_path / "chats.json"))
    monkeypatch.setitem(webui._state, "agent", None)
    monkeypatch.setitem(webui._state, "session_id", None)
    return webui


def test_uploaded_image_flows_into_vision_chat_payload(
        monkeypatch, isolated_webui):
    client = isolated_webui.app.test_client()

    # 1) upload the PNG exactly like the paperclip UI does (FormData -> /api/upload)
    res = client.post(
        "/api/upload",
        data={"file": (io.BytesIO(_png_bytes()), "shot.png")},
        content_type="multipart/form-data")
    assert res.status_code == 200
    body = res.get_json()
    assert body.get("ok") is True
    rec = body["upload"]
    assert rec["original_name"] == "shot.png"
    assert rec["ext"] == "png"
    sid = rec.get("sid")
    assert sid  # auto-minted session, no orphaned upload

    # 2) the session vision endpoint exposes OpenAI-style content blocks
    vision_res = isolated_webui.app.test_client().get(
        "/api/upload/session/%s/vision" % sid)
    assert vision_res.status_code == 200
    blocks = vision_res.get_json()["content"]
    assert len(blocks) == 1
    assert blocks[0]["type"] == "image_url"
    assert blocks[0]["image_url"]["url"].startswith(
        "data:image/png;base64,")

    # 3) the api_chat attach step registers the upload on a vision client
    llm_client = OpenAIClient(api_key="test-key", model="qwen2.5-vl-7b",
                              fallback_models=[], timeout=5)
    captured = {}

    def fake_post(model, url, headers, payload, timeout, stream=False):
        captured["payload"] = payload
        return _FakeResp()

    monkeypatch.setattr(llm_mod, "_post_with_retry", fake_post)
    monkeypatch.setattr(llm_client, "_request_target",
                        lambda model: ("https://api.test/v1", {}))
    monkeypatch.setitem(isolated_webui._state, "agent",
                        _FakeAgent(llm_client))

    isolated_webui._attach_session_files(sid)
    assert len(llm_client.vision_attachments) == 1

    # 4) one chat() call with the text prompt -> image + text in ONE message
    llm_client.chat([{"role": "user",
                      "content": "analyze the screenshot"}])
    last = captured["payload"]["messages"][-1]
    assert [b["type"] for b in last["content"]] == ["text", "image_url"]
    assert last["content"][0]["text"] == "analyze the screenshot"
    img_url = last["content"][1]["image_url"]["url"]
    assert img_url == ("data:image/png;base64," +
                       base64.b64encode(_png_bytes()).decode())


def test_rejects_unsupported_type_before_reaching_model(
        monkeypatch, isolated_webui):
    client = isolated_webui.app.test_client()
    res = client.post(
        "/api/upload",
        data={"file": (io.BytesIO(b"MZ\x90\x00 not an allowed artifact"),
                       "evil.exe")},
        content_type="multipart/form-data")
    assert res.status_code == 400
    body = res.get_json()
    assert "unsupported file type" in body.get("error", "").lower()
