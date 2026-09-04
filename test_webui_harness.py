"""Regression tests: WebUI harness-parity endpoints.

The local Flask UI now mirrors hosted-harness capabilities as first-class
JSON endpoints:

  * /api/files ............ safe workspace directory listing
  * /api/files/download ... single workspace file download (traversal-safe,
                            hidden paths and secret-material extensions denied)
  * /api/notes ............ CRUD + search over the cross-conversation
                            institutional memory
  * /api/subagents ........ managed sub-agent registry: list / spawn / detail
                            / transcript / cancel / continue

Every test monkeypatches PROJECT_DIR / INSTITUTIONAL_NOTES_PATH / the live
agent away from the developer's real files and databases, so nothing in the
repo is touched or polluted.
"""

import json
import threading

import pytest

import webui


# ---------------------------------------------------------------------------
# fakes (kept in-memory; no real orchestration threads or LLM clients)
# ---------------------------------------------------------------------------

class _FakeRecord:
    def __init__(self, aid, status="done", task="probe task"):
        self.agent_id = aid
        self.status = status
        self.task = task
        self.output = "probe output done"

    def snapshot(self, include_output=True):
        out = {"agent_id": self.agent_id, "status": self.status,
               "task": self.task}
        if include_output and self.status == "done":
            out["output"] = self.output
            out["output_verified"] = False
        return out


class _FakeOrch:
    """Stands in for OrchestrationManager; records calls so the endpoints'
    JSON contract can be asserted without spawning real children."""

    def __init__(self):
        self._order = []
        self._records = {}
        self._lock = threading.RLock()
        self.spawn_error = None
        self.spawn_calls = []

    def add(self, rec):
        self._records[rec.agent_id] = rec
        self._order.append(rec.agent_id)

    def registry_summary(self):
        return {"parent": "fake", "tracked": len(self._records),
                "max_children": 4, "max_siblings": 2, "active": 0,
                "running": 0}

    def spawn(self, task, wait=False, success_criteria=None,
              capabilities=None, persona=None, timeout=None, meta=None):
        self.spawn_calls.append({"task": task, "wait": wait,
                                 "success_criteria": success_criteria,
                                 "capabilities": capabilities,
                                 "meta": meta})
        if self.spawn_error:
            return self.spawn_error
        return json.dumps({"agent_id": "fake1", "status": "queued",
                           "depth": 0, "note": "spawned via webui"})

    def check_status(self, agent_id=""):
        if agent_id and agent_id not in self._records:
            return "Error: unknown sub-agent %s." % agent_id
        return "Sub-agent %s status: queued" % (agent_id or "fake1")

    def fetch_transcript(self, agent_id=""):
        if agent_id and agent_id not in self._records:
            return "Error: unknown sub-agent %s." % agent_id
        return "=== Transcript ===\n[ts] note: hello"

    def cancel_agent(self, agent_id=""):
        if agent_id and agent_id not in self._records:
            return "Error: unknown sub-agent %s." % agent_id
        return "Sub-agent %s cancel requested." % (agent_id or "fake1")

    def continue_agent(self, agent_id, follow_up):
        if agent_id not in self._records:
            return "Error: unknown sub-agent %s." % agent_id
        return json.dumps({"agent_id": agent_id, "status": "queued",
                           "note": "resumed"})


class _FakeAgent:
    allow_subagents = True
    institutional = None

    def __init__(self, orch=None):
        self._orchestrator = orch or _FakeOrch()


@pytest.fixture()
def fake_agent(monkeypatch):
    """Install a fake agent (with a fake orchestrator) as the live state."""
    agent = _FakeAgent()
    monkeypatch.setitem(webui._state, "agent", agent)
    return agent


@pytest.fixture()
def clean_client(monkeypatch, tmp_path):
    """No live agent + isolated notes db + isolated workspace root."""
    monkeypatch.setitem(webui._state, "agent", None)
    monkeypatch.setattr(webui, "PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(webui, "INSTITUTIONAL_NOTES_PATH",
                        str(tmp_path / "inst_notes.db"))
    return webui.app.test_client()


# ---------------------------------------------------------------------------
# /api/files
# ---------------------------------------------------------------------------

def test_files_list_root(clean_client, tmp_path):
    (tmp_path / "report.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    r = clean_client.get("/api/files")
    assert r.status_code == 200
    body = r.get_json()
    names = [e["name"] for e in body["entries"]]
    assert "report.txt" in names
    assert "sub" in names


def test_files_list_skips_hidden(clean_client, tmp_path):
    (tmp_path / ".env").write_text("SECRET=1", encoding="utf-8")
    (tmp_path / "visible.txt").write_text("x", encoding="utf-8")
    r = clean_client.get("/api/files")
    assert r.status_code == 200
    names = [e["name"] for e in r.get_json()["entries"]]
    assert "visible.txt" in names
    assert not any(n.startswith(".") for n in names)


def test_files_list_missing_dir_404(clean_client):
    r = clean_client.get("/api/files", query_string={"path": "nope"})
    assert r.status_code == 404


def test_files_list_traversal_denied(clean_client):
    r = clean_client.get("/api/files", query_string={"path": "../secret"})
    assert r.status_code == 400


def test_files_download_ok(clean_client, tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "note.txt").write_text("MARKER-9f3a",
                                               encoding="utf-8")
    r = clean_client.get("/api/files/download",
                         query_string={"path": "sub/note.txt"})
    assert r.status_code == 200
    assert r.data.decode("utf-8") == "MARKER-9f3a"


def test_files_download_missing_path_400(clean_client):
    r = clean_client.get("/api/files/download")
    assert r.status_code == 400


def test_files_download_traversal_403(clean_client, tmp_path):
    outside = tmp_path.parent / "secret.txt"
    outside.write_text("nope", encoding="utf-8")
    r = clean_client.get("/api/files/download",
                         query_string={"path": "../secret.txt"})
    assert r.status_code == 403


def test_files_download_hidden_403(clean_client, tmp_path):
    (tmp_path / ".env").write_text("SECRET=1", encoding="utf-8")
    r = clean_client.get("/api/files/download",
                         query_string={"path": ".env"})
    assert r.status_code == 403


def test_files_download_sensitive_ext_403(clean_client, tmp_path):
    (tmp_path / "key.pem").write_text("PRIVATE", encoding="utf-8")
    r = clean_client.get("/api/files/download",
                         query_string={"path": "key.pem"})
    assert r.status_code == 403


def test_files_download_missing_file_404(clean_client):
    r = clean_client.get("/api/files/download",
                         query_string={"path": "ghost.txt"})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# /api/notes (isolated db)
# ---------------------------------------------------------------------------

def _add_note(client, title="t", content="body", category="findings",
              target="scanme.example", tags=None):
    return client.post("/api/notes", json={
        "category": category, "title": title, "content": content,
        "target": target, "tags": tags or ["xss"]})


def test_notes_crud_roundtrip(clean_client):
    r = _add_note(clean_client, title="SQLi in login", content="id param")
    assert r.status_code == 201
    note = r.get_json()["note"]
    nid = note["id"]
    assert note["category"] == "findings"
    assert note["title"] == "SQLi in login"
    assert note["tags"] == ["xss"]

    r = clean_client.get("/api/notes/%d" % nid)
    assert r.status_code == 200
    assert r.get_json()["title"] == "SQLi in login"

    r = clean_client.put("/api/notes/%d" % nid,
                         json={"content": "updated body", "tags": ["sqli"]})
    assert r.status_code == 200
    assert r.get_json()["note"]["content"] == "updated body"
    assert r.get_json()["note"]["tags"] == ["sqli"]

    r = clean_client.delete("/api/notes/%d" % nid)
    assert r.status_code == 200
    assert r.get_json()["ok"] is True

    r = clean_client.get("/api/notes/%d" % nid)
    assert r.status_code == 404


def test_notes_add_requires_content(clean_client):
    r = clean_client.post("/api/notes", json={"title": "empty"})
    assert r.status_code == 400


def test_notes_list_and_category_filter(clean_client):
    _add_note(clean_client, title="port 22", content="ssh banner",
              category="findings", target="a.example")
    _add_note(clean_client, title="how to fuzz", content="wordlist steps",
              category="methodology", target="b.example")
    r = clean_client.get("/api/notes")
    assert r.status_code == 200
    assert r.get_json()["count"] == 2
    r = clean_client.get("/api/notes",
                         query_string={"category": "methodology"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["count"] == 1
    assert body["notes"][0]["category"] == "methodology"


def test_notes_search_recall(clean_client):
    _add_note(clean_client, title="nmap basics", content="syn scan")
    _add_note(clean_client, title="gobuster run", content="directory brute")
    r = clean_client.get("/api/notes/search",
                         query_string={"q": "directory brute"})
    assert r.status_code == 200
    titles = [n["title"] for n in r.get_json()["notes"]]
    assert "gobuster run" in titles
    assert "nmap basics" not in titles


def test_notes_form_encoding_supported(clean_client):
    r = clean_client.post("/api/notes", data={
        "category": "plan", "title": "next steps", "content": "enum first",
        "target": "x.example", "tags": "a,b"})
    assert r.status_code == 201
    note = r.get_json()["note"]
    # "plan" is normalised to the canonical institutional category
    assert note["category"] == "active_plans"
    assert note["tags"] == ["a", "b"]


# ---------------------------------------------------------------------------
# /api/subagents (fake orchestrator)
# ---------------------------------------------------------------------------

def test_subagents_unavailable_without_agent(clean_client):
    r = clean_client.get("/api/subagents")
    assert r.status_code == 503


def test_subagents_list_empty(fake_agent):
    c = webui.app.test_client()
    r = c.get("/api/subagents")
    assert r.status_code == 200
    body = r.get_json()
    assert body["count"] == 0
    assert body["agents"] == []
    assert body["summary"]["tracked"] == 0


def test_subagents_list_returns_snapshots(fake_agent):
    fake_agent._orchestrator.add(_FakeRecord("ag-1", status="done"))
    c = webui.app.test_client()
    r = c.get("/api/subagents")
    assert r.status_code == 200
    body = r.get_json()
    assert body["count"] == 1
    # lightweight list must NOT include full output
    assert body["agents"][0]["agent_id"] == "ag-1"
    assert "output" not in body["agents"][0]


def test_subagents_spawn_requires_task(fake_agent):
    c = webui.app.test_client()
    r = c.post("/api/subagents", json={"capabilities": ["web_research"]})
    assert r.status_code == 400


def test_subagents_spawn_ok(fake_agent):
    orch = fake_agent._orchestrator
    c = webui.app.test_client()
    r = c.post("/api/subagents", json={
        "task": "enumerate scanme.nmap.org",
        "success_criteria": ["port list produced"],
        "capabilities": ["terminal", "web_research"]})
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["agent_id"] == "fake1"
    assert orch.spawn_calls[0]["task"] == "enumerate scanme.nmap.org"
    assert orch.spawn_calls[0]["success_criteria"] == \
        ["port list produced"]


def test_subagents_spawn_cap_error_400(fake_agent):
    fake_agent._orchestrator.spawn_error = \
        "Error: sub-agent cap reached (2 children tracked; ...)"
    c = webui.app.test_client()
    r = c.post("/api/subagents", json={"task": "any task"})
    assert r.status_code == 400
    assert r.get_json()["ok"] is False


def test_subagents_detail_unknown_404(fake_agent):
    c = webui.app.test_client()
    r = c.get("/api/subagents/ghost")
    assert r.status_code == 404


def test_subagents_detail_includes_output(fake_agent):
    fake_agent._orchestrator.add(_FakeRecord("ag-9", status="done"))
    c = webui.app.test_client()
    r = c.get("/api/subagents/ag-9")
    assert r.status_code == 200
    agent = r.get_json()["agent"]
    assert agent["agent_id"] == "ag-9"
    assert agent["output"] == "probe output done"


def test_subagents_transcript(fake_agent):
    fake_agent._orchestrator.add(_FakeRecord("ag-7"))
    c = webui.app.test_client()
    r = c.get("/api/subagents/ag-7/transcript")
    assert r.status_code == 200
    assert "hello" in r.get_json()["transcript"]


def test_subagents_transcript_unknown_404(fake_agent):
    c = webui.app.test_client()
    r = c.get("/api/subagents/nope/transcript")
    assert r.status_code == 404


def test_subagents_cancel(fake_agent):
    fake_agent._orchestrator.add(_FakeRecord("ag-3", status="running"))
    c = webui.app.test_client()
    r = c.post("/api/subagents/ag-3/cancel")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


def test_subagents_cancel_unknown_400(fake_agent):
    c = webui.app.test_client()
    r = c.post("/api/subagents/nope/cancel")
    assert r.status_code == 400
    assert r.get_json()["ok"] is False


def test_subagents_continue_requires_followup(fake_agent):
    c = webui.app.test_client()
    r = c.post("/api/subagents/ag-1/continue", json={})
    assert r.status_code == 400


def test_subagents_continue_ok(fake_agent):
    fake_agent._orchestrator.add(_FakeRecord("ag-5", status="done"))
    c = webui.app.test_client()
    r = c.post("/api/subagents/ag-5/continue",
               json={"follow_up": "also check udp"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["agent_id"] == "ag-5"


def test_subagents_continue_unknown_400(fake_agent):
    c = webui.app.test_client()
    r = c.post("/api/subagents/nope/continue",
               json={"follow_up": "go on"})
    assert r.status_code == 400
