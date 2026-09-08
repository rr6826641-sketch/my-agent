"""Multimodal file ingestion pipeline (Phase 1).

Owns the backend contract for /api/upload:

* Accepts a fixed, explicit allow-list of artifact types - images
  (PNG / JPG / WEBP), packet captures (PCAP), plain text (TXT),
  structured data (JSON) and documents (PDF).
* Persists every accepted artifact under ``data/uploads/`` with a
  UUID-based filename so the original name can never collide or be
  used for path traversal.
* Validates both the extension AND the real content (magic-byte
  sniffing / UTF-8 sniffing), so a renamed .exe cannot slip in as
  a "png".
* Records each upload in a small JSON index keyed by file id and
  linked to the chat session (``sid``) that owns it, so later
  phases can attach the artifact to the active chat context.
* Generates OpenAI-compatible multimodal content blocks (Base64
  data-URLs) for vision-capable models to analyze screenshots and
  diagrams.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
import uuid

# ---------------------------------------------------------------------------
# Allow-list + content sniffing
# ---------------------------------------------------------------------------

# ext -> (mime, category, magic-check name)
_EXT_PNG = (".png", "image/png", "image", "png")
_EXT_JPG = (".jpg", "image/jpeg", "image", "jpg")
_EXT_JPEG = (".jpeg", "image/jpeg", "image", "jpg")
_EXT_WEBP = (".webp", "image/webp", "image", "webp")
_EXT_PCAP = (".pcap", "application/vnd.tcpdump.pcap", "capture", "pcap")
_EXT_TXT = (".txt", "text/plain", "text", "txt")
_EXT_JSON = (".json", "application/json", "text", "json")
_EXT_PDF = (".pdf", "application/pdf", "document", "pdf")

ALLOWED_TYPES = {
    _EXT_PNG[0]: _EXT_PNG,
    _EXT_JPG[0]: _EXT_JPG,
    _EXT_JPEG[0]: _EXT_JPEG,
    _EXT_WEBP[0]: _EXT_WEBP,
    _EXT_PCAP[0]: _EXT_PCAP,
    _EXT_TXT[0]: _EXT_TXT,
    _EXT_JSON[0]: _EXT_JSON,
    _EXT_PDF[0]: _EXT_PDF,
}

# Mime types that the vision pipeline can embed as image content blocks.
VISION_MIMES = {"image/png", "image/jpeg", "image/webp"}

# Hard ceiling for one upload (50 MB) - protects the local disk and the
# Base64 payload builder from pathological inputs.
MAX_UPLOAD_BYTES = 50 * 1024 * 1024

_SNIFF_HEAD = 4096


def _sniff(ext: str, head: bytes) -> bool:
    """Magic-byte / text sniffing for the canonical extension name."""
    if ext == "png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if ext == "jpg":
        return head.startswith(b"\xff\xd8\xff")
    if ext == "webp":
        return head.startswith(b"RIFF") and head[8:12] == b"WEBP"
    if ext == "pdf":
        return head.startswith(b"%PDF-")
    if ext == "pcap":
        # classic little/big endian + nanosecond variants of the magic
        return head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                            b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    if ext in ("txt", "json"):
        if b"\x00" in head:
            return False
        try:
            head.decode("utf-8")
        except UnicodeDecodeError:
            return False
        if ext == "json":
            sample = head.strip().lstrip(b"\xef\xbb\xbf")
            try:
                json.loads(sample.decode("utf-8", errors="strict")[:65536])
            except ValueError:
                # JSON payloads can legitimately outgrow the sniff window;
                # a leading structural char is a good-enough backend gate,
                # the full parse happens in the consuming tool.
                if not (sample[:1] in (b"{", b"[")):
                    return False
        return True
    return False


def sniff_mime(filename: str, head: bytes) -> str | None:
    """Return the canonical MIME iff content matches the declared type."""
    spec = ALLOWED_TYPES.get(os.path.splitext(filename)[1].lower())
    if spec is None:
        return None
    if not _sniff(spec[3], head):
        return None
    return spec[1]


# ---------------------------------------------------------------------------
# Vision payload builder (OpenAI multimodal message content)
# ---------------------------------------------------------------------------


def encode_file_base64(path: str) -> str:
    """Base64-encode a stored artifact for a vision payload."""
    with open(path, "rb") as fh:
        return base64.b64encode(fh.read()).decode("ascii")


def image_content_block(path: str, mime: str | None = None) -> dict:
    """One OpenAI-style image_url content block (data URL) for an image.

    Only image artifacts (PNG/JPG/WEBP) are meaningful vision inputs;
    callers should guard with ``mime in VISION_MIMES`` first.
    """
    if mime is None:
        mime = "image/png"
    return {
        "type": "image_url",
        "image_url": {
            "url": "data:%s;base64,%s" % (mime, encode_file_base64(path)),
        },
    }


def text_content_block(text: str) -> dict:
    """One OpenAI-style text content block."""
    return {"type": "text", "text": text}


def multimodal_content(text: str, image_paths):
    """Build a full message ``content`` array: text block + vision blocks.

    ``image_paths`` may be (path, mime) tuples or bare paths (mime is
    then re-sniffed). Non-image attachments are skipped with a note so
    the model still knows they exist.
    """
    blocks = [text_content_block(text)]
    notes = []
    for item in image_paths or []:
        if isinstance(item, (tuple, list)) and len(item) >= 2:
            path, mime = item[0], item[1]
        else:
            path = item
            mime = sniff_mime(os.path.basename(path), _read_head(path))
        if mime in VISION_MIMES:
            blocks.append(image_content_block(path, mime))
        else:
            notes.append(os.path.basename(path))
    if notes:
        blocks.append(text_content_block(
            "[attachments not embedded (non-image): %s]" % ", ".join(notes)))
    return blocks


def _read_head(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(_SNIFF_HEAD)


# ---------------------------------------------------------------------------
# Storage layer
# ---------------------------------------------------------------------------


class FileHandler:
    """Persists validated uploads under ``data/uploads`` with UUID names.

    Records are kept in ``index.json`` inside the uploads dir, safe to
    re-read after restarts, and grouped by chat ``sid`` so the active
    session can resolve its attachments later.
    """

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.index_path = os.path.join(self.root, "index.json")
        self._lock = threading.Lock()
        os.makedirs(self.root, exist_ok=True)
        self._records = self._load_index()

    # -- persistence -----------------------------------------------------

    def _load_index(self) -> dict:
        try:
            with open(self.index_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
        return {}

    def _save_index(self) -> None:
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._records, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.index_path)

    # -- public API ------------------------------------------------------

    def save(self, fileobj, original_name: str, sid: str | None = None,
             max_bytes: int = MAX_UPLOAD_BYTES) -> dict:
        """Validate + persist one uploaded file. Returns its record.

        Raises ValueError with a user-safe message for wrong extensions,
        content/MIME mismatches, empty bodies and oversized uploads.
        """
        original_name = os.path.basename((original_name or "").strip())
        if not original_name or original_name in (".", ".."):
            raise ValueError("missing file name")

        ext = os.path.splitext(original_name)[1].lower()
        spec = ALLOWED_TYPES.get(ext)
        if spec is None:
            raise ValueError(
                "unsupported file type %r - allowed: png, jpg, jpeg, webp, "
                "pcap, txt, json, pdf" % ext)

        head = fileobj.read(_SNIFF_HEAD)
        if not head:
            raise ValueError("empty file")
        if not _sniff(spec[3], head):
            raise ValueError(
                "content does not match a real %s file (renamed binary?)"
                % spec[3].upper())

        # stream the rest with a hard size ceiling
        chunks = [head]
        total = len(head)
        while True:
            chunk = fileobj.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("file exceeds the %d MB upload limit"
                                 % (max_bytes // (1024 * 1024)))
            chunks.append(chunk)
        if total < 4:
            raise ValueError("file too small to be a valid artifact")

        file_id = uuid.uuid4().hex
        store_name = file_id + ext
        abs_path = os.path.join(self.root, store_name)
        with open(abs_path, "wb") as out:
            for chunk in chunks:
                out.write(chunk)

        record = {
            "id": file_id,
            "original_name": original_name,
            "ext": ext.lstrip("."),
            "mime": spec[1],
            "category": spec[2],
            "size": total,
            "path": abs_path,
            "sid": sid or "",
            "created": time.time(),
        }
        with self._lock:
            self._records[file_id] = record
            self._save_index()
        return dict(record)

    def get(self, file_id: str) -> dict | None:
        rec = self._records.get(file_id)
        return dict(rec) if rec else None

    def files_for_session(self, sid: str) -> list:
        if not sid:
            return []
        out = []
        for rec in self._records.values():
            if rec.get("sid") == sid:
                out.append(dict(rec))
        out.sort(key=lambda r: r.get("created", 0))
        return out

    def all_files(self) -> list:
        return [dict(r) for r in sorted(
            self._records.values(), key=lambda r: r.get("created", 0))]

    def vision_blocks_for_session(self, sid: str) -> list:
        """Image content blocks for every image upload owned by a session."""
        blocks = []
        for rec in self.files_for_session(sid):
            if rec["mime"] in VISION_MIMES and os.path.isfile(rec["path"]):
                blocks.append(image_content_block(rec["path"], rec["mime"]))
        return blocks
