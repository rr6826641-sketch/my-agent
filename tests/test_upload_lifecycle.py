"""Phase 3 - attachment lifecycle: uploaded artifacts can be deleted again.

Proves three things end to end:

  1. ``FileHandler.delete`` removes the index record AND the disk file,
     is idempotent (second delete returns False) and immediately stops
     the session resolver from returning the artifact.
  2. ``DELETE /api/uploads/<file_id>`` (webui seam) returns 200 and the
     record/file are really gone; the same id then 404s.
  3. Session ownership is enforced: deleting another session's upload
     (sid mismatch) is refused with 403, and after deletion the session
     vision endpoint no longer emits an image content block for it - so a
     removed screenshot can never leak back into a chat payload.

Everything runs offline against a temp dir (real uploads dir, chats.json
and the Flask app under test are all isolated via monkeypatch).
"""

import base64
import io
import json
import os

import pytest

import webui
from ai_agent.core.file_handler import FileHandler

PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
    "z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def _png_bytes():
    return base64.b64decode(PNG_B64)


def _upload_png(client, sid=None, name="shot.png"):
    data = {"file": (io.BytesIO(_png_bytes()), name)}
    if sid:
        data["sid"] = sid
    return client.post("/api/upload", data=data,
                       content_type="multipart/form-data")


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


# ---------------------------------------------------------------------------
# 1) storage layer
# ---------------------------------------------------------------------------


def test_handler_delete_removes_record_and_disk(tmp_path):
    handler = FileHandler(str(tmp_path / "uploads"))
    rec = handler.save(io.BytesIO(_png_bytes()), "shot.png", sid="s1")
    path = rec["path"]
    assert os.path.isfile(path)
    assert handler.get(rec["id"]) is not None

    assert handler.delete(rec["id"]) is True
    assert handler.get(rec["id"]) is None
    assert handler.files_for_session("s1") == []
    assert not os.path.isfile(path)  # disk file removed too


def test_handler_delete_idempotent_and_unknown(tmp_path):
    handler = FileHandler(str(tmp_path / "uploads"))
    rec = handler.save(io.BytesIO(_png_bytes()), "shot.png", sid="s1")
    assert handler.delete(rec["id"]) is True
    assert handler.delete(rec["id"]) is False   # already gone
    assert handler.delete("no-such-id") is False


def test_handler_delete_stale_record_does_not_raise(tmp_path):
    """Index says the file exists but the disk file vanished -> still clean."""
    handler = FileHandler(str(tmp_path / "uploads"))
    rec = handler.save(io.BytesIO(_png_bytes()), "shot.png", sid="s1")
    os.remove(rec["path"])
    assert handler.delete(rec["id"]) is True  # no exception
    assert handler.get(rec["id"]) is None


# ---------------------------------------------------------------------------
# 2) HTTP seam
# ---------------------------------------------------------------------------


def test_delete_route_removes_upload_and_vision_block(isolated_webui):
    client = isolated_webui.app.test_client()

    up = _upload_png(client, sid="ses-1")
    assert up.status_code == 200
    fid = up.get_json()["upload"]["id"]

    vis = client.get("/api/upload/session/ses-1/vision").get_json()
    assert vis["count"] == 1  # image currently embedded in the session

    res = client.delete("/api/uploads/" + fid + "?sid=ses-1")
    assert res.status_code == 200
    assert res.get_json()["deleted"] == fid

    # gone from the store and from every future chat payload
    assert client.delete("/api/uploads/" + fid).status_code == 404
    assert client.get("/api/upload/session/ses-1/vision").get_json()["count"] == 0


def test_delete_route_refuses_other_sessions_upload(isolated_webui):
    client = isolated_webui.app.test_client()

    up = _upload_png(client, sid="ses-owner")
    fid = up.get_json()["upload"]["id"]

    res = client.delete("/api/uploads/" + fid + "?sid=ses-other")
    assert res.status_code == 403
    assert "another session" in res.get_json()["error"]

    # and the rightful owner can still remove it afterwards
    assert client.delete("/api/uploads/" + fid + "?sid=ses-owner").status_code == 200
