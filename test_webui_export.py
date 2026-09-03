"""Feature: Chat/session export as a Markdown pentest report.

GET /api/sessions/<sid>/export builds a full Markdown report (executive
summary, tool timeline with trimmed outputs, validation findings, artifact
downloads) and serves it as an attachment. A missing session is a 404.

Runs the real Flask app in mock mode; chats.json is backed up and restored
so the developer's live chat history is never modified by the test run.
"""

import json
import os
import time

import pytest

import webui


@pytest.fixture()
def mock_app():
    """Mock-mode Flask test client with chats.json backup/restore."""
    backup = None
    if os.path.exists(webui.CHATS_PATH):
        with open(webui.CHATS_PATH, "r", encoding="utf-8") as f:
            backup = f.read()
    webui._reload_state(mock_override=True)
    yield webui.app.test_client()
    # restore the developer's original chats.json no matter what happened
    if backup is not None:
        with open(webui.CHATS_PATH, "w", encoding="utf-8") as f:
            f.write(backup)
    elif os.path.exists(webui.CHATS_PATH):
        os.remove(webui.CHATS_PATH)
    webui._reload_state(mock_override=True)


def _seed_session(sid="testsess123", long_output=False):
    """Insert a synthetic assessment session directly into chats.json."""
    result = "open ports: 22, 80, 443"
    if long_output:
        result = "x" * 5000
    now = time.time()
    session = {
        "id": sid,
        "title": "Assessment scanme.nmap.org",
        "created": now,
        "updated": now,
        "messages": [
            {"role": "user", "content": "scan scanme.nmap.org", "ts": now - 30},
            {"role": "tool", "name": "port_scan", "arguments": '{"target": "scanme.nmap.org"}',
             "result": result, "ts": now - 20},
            {"role": "assistant", "kind": "final",
             "content": "Target has SSH + web open, next step: service enum.",
             "ts": now - 10},
            {"role": "assistant", "kind": "validation", "status": "verified",
             "finding": "OpenSSH 8.2 banner on :22",
             "reason": "banner captured directly",
             "content": "[VALIDATION SUB-AGENT] Finding Verified: ssh banner",
             "ts": now - 5},
        ],
        "artifacts": [],
    }
    with webui._chat_lock:
        data = webui._read_chats_unlocked()
        data.setdefault("sessions", {})[sid] = session
        webui._write_chats_unlocked(data)
    return session


def test_export_missing_session_404(mock_app):
    r = mock_app.get("/api/sessions/doesnotexist/export")
    assert r.status_code == 404


def test_export_report_content(mock_app):
    _seed_session()
    r = mock_app.get("/api/sessions/testsess123/export")
    assert r.status_code == 200
    body = r.data.decode("utf-8")
    assert "Pentest Export" in body
    assert "Assessment scanme.nmap.org" in body
    assert "Executive Summary" in body
    assert "Timeline" in body
    assert "port_scan" in body
    assert "scanme.nmap.org" in body
    assert "open ports: 22, 80, 443" in body
    assert "Finding Verified" in body
    # served as an attachment download
    assert "attachment" in r.headers.get("Content-Disposition", "")


def test_export_trims_long_tool_output(mock_app):
    _seed_session(long_output=True)
    r = mock_app.get("/api/sessions/testsess123/export")
    assert r.status_code == 200
    body = r.data.decode("utf-8")
    assert "first 2000 of 5000 chars" in body
    # trimmed content stays under the 2000-char fence
    assert "x" * 2001 not in body


def test_export_filename_is_safe(mock_app):
    # session ids are app-generated, but a hand-edited weird one must still
    # produce a filesystem-safe download name (spaces/asterisk/dots)
    _seed_session(sid="weird id With Spaces.and*chars")
    r = mock_app.get("/api/sessions/weird%20id%20With%20Spaces.and%2Achars/export")
    assert r.status_code == 200
    disp = r.headers.get("Content-Disposition", "")
    assert "pentest_export_assessment_scanme.nmap.org.md" in disp
