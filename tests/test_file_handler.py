"""Phase 1 tests: file saving, MIME/content validation, vision payloads."""

import base64
import io
import json
import os

import pytest

from ai_agent.core.file_handler import (
    FileHandler,
    MAX_UPLOAD_BYTES,
    image_content_block,
    multimodal_content,
    sniff_mime,
)

# minimal valid byte samples -------------------------------------------------

_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32 + b"IEND\xaeB`\x82"
_JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
_WEBP = b"RIFF" + (16).to_bytes(4, "little") + b"WEBPVP8 " + b"\x00" * 32
_PDF = b"%PDF-1.4\n" + b"%%EOF\n".rjust(48, b" ")  # minimal structural pdf
_PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 32
_TXT = "hello agent\nline two\n".encode("utf-8")
_JSON = json.dumps({"target": "10.0.0.1", "port": 443}).encode("utf-8")

_HEADER = {".png": _PNG, ".jpg": _JPEG, ".jpeg": _JPEG, ".webp": _WEBP,
           ".pdf": _PDF, ".pcap": _PCAP, ".txt": _TXT, ".json": _JSON}


def _stream(data: bytes) -> io.BytesIO:
    return io.BytesIO(data)


# -- MIME / content sniffing ------------------------------------------------


@pytest.mark.parametrize("name,payload", [
    ("shot.png", _PNG),
    ("shot.jpg", _JPEG),
    ("shot.jpeg", _JPEG),
    ("anim.webp", _WEBP),
    ("traffic.pcap", _PCAP),
    ("notes.txt", _TXT),
    ("scan.json", _JSON),
    ("report.pdf", _PDF),
])
def test_sniff_accepts_valid_content(name, payload):
    assert sniff_mime(name, payload[:4096]) is not None


@pytest.mark.parametrize("name,payload", [
    ("evil.exe", _PNG),                 # extension outside allow-list
    ("shot.png", _TXT),                 # renamed text pretending to be png
    ("notes.txt", _PNG),                # binary pretending to be text
    ("report.pdf", _JSON),              # json body faking a pdf
    ("traffic.pcap", _PNG),             # wrong capture magic
    ("shot.jpg", b"\x00" * 64),         # no jpeg magic
])
def test_sniff_rejects_mismatched_content(name, payload):
    assert sniff_mime(name, payload[:4096]) is None


# -- FileHandler.save -------------------------------------------------------


def test_save_persists_upload_with_uuid_name(tmp_path):
    handler = FileHandler(str(tmp_path / "uploads"))
    rec = handler.save(_stream(_PNG), "screenshot.png", sid="sess-1")

    assert rec["original_name"] == "screenshot.png"
    assert rec["mime"] == "image/png"
    assert rec["sid"] == "sess-1"
    assert rec["size"] == len(_PNG)
    # stored under a uuid-based name inside the uploads root
    stored = os.path.join(handler.root, rec["id"] + ".png")
    assert rec["path"] == stored
    assert os.path.isfile(stored)
    assert open(stored, "rb").read() == _PNG
    # index persists so a fresh handler sees the record
    handler2 = FileHandler(str(tmp_path / "uploads"))
    assert handler2.get(rec["id"])["original_name"] == "screenshot.png"


def test_save_rejects_unallowed_extension(tmp_path):
    handler = FileHandler(str(tmp_path / "uploads"))
    with pytest.raises(ValueError, match="unsupported file type"):
        handler.save(_stream(_PNG), "tool.exe")


def test_save_rejects_content_type_mismatch(tmp_path):
    handler = FileHandler(str(tmp_path / "uploads"))
    with pytest.raises(ValueError, match="does not match"):
        handler.save(_stream(_TXT), "fake.png")


def test_save_rejects_empty_file(tmp_path):
    handler = FileHandler(str(tmp_path / "uploads"))
    with pytest.raises(ValueError, match="empty"):
        handler.save(_stream(b""), "empty.png")


def test_save_rejects_oversized_upload(tmp_path):
    handler = FileHandler(str(tmp_path / "uploads"))
    big = _PNG + b"\x00" * (MAX_UPLOAD_BYTES + 1)
    with pytest.raises(ValueError, match="upload limit"):
        handler.save(_stream(big), "huge.png")


def test_save_links_files_to_session(tmp_path):
    handler = FileHandler(str(tmp_path / "uploads"))
    a = handler.save(_stream(_PNG), "a.png", sid="sess-1")
    handler.save(_stream(_TXT), "b.txt", sid="sess-2")
    ids = [r["id"] for r in handler.files_for_session("sess-1")]
    assert ids == [a["id"]]


# -- vision payload generation ----------------------------------------------


def test_image_content_block_encodes_base64_data_url(tmp_path):
    handler = FileHandler(str(tmp_path / "uploads"))
    rec = handler.save(_stream(_PNG), "diagram.png", sid="sess-1")
    block = image_content_block(rec["path"], rec["mime"])

    assert block["type"] == "image_url"
    url = block["image_url"]["url"]
    assert url.startswith("data:image/png;base64,")
    raw = base64.b64decode(url.split(",", 1)[1])
    assert raw == _PNG


def test_vision_blocks_for_session_only_images(tmp_path):
    handler = FileHandler(str(tmp_path / "uploads"))
    handler.save(_stream(_PNG), "diagram.png", sid="sess-1")
    handler.save(_stream(_TXT), "notes.txt", sid="sess-1")
    handler.save(_stream(_PNG), "other.png", sid="sess-2")

    blocks = handler.vision_blocks_for_session("sess-1")
    assert len(blocks) == 1
    assert blocks[0]["image_url"]["url"].startswith("data:image/png;base64,")


def test_multimodal_content_combines_text_and_images(tmp_path):
    handler = FileHandler(str(tmp_path / "uploads"))
    img = handler.save(_stream(_PNG), "diagram.png", sid="sess-1")
    txt = handler.save(_stream(_TXT), "notes.txt", sid="sess-1")

    content = multimodal_content("analyze this",
                                 [(img["path"], img["mime"]), txt["path"]])
    assert content[0] == {"type": "text", "text": "analyze this"}
    assert any(b["type"] == "image_url" for b in content)
    assert any("not embedded" in b.get("text", "")
               for b in content if b["type"] == "text")
