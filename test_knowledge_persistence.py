"""Cross-chat persistence tests for validation verdicts (v2).

Guards the knowledge-base wiring of the independent validation pipeline:
  1. VERIFIED / REJECTED verdicts land in BOTH SQLite stores
     (GlobalKnowledge -> knowledge.db, InstitutionalMemory -> notes db)
  2. UNVERIFIED findings are deliberately NOT persisted
  3. storage errors are swallowed - validation never breaks the pipeline
  4. a brand-new chat recalls persisted verdicts via get_target_summary()

Run:  py -m pytest test_knowledge_persistence.py -q
"""
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_agent.core import Agent
from ai_agent.memory_store import GlobalKnowledge, InstitutionalMemory
from ai_agent.tools.verify import (
    REJECTED as V_REJECTED,
    UNVERIFIED as V_UNVERIFIED,
    VERIFIED as V_VERIFIED,
    STATUS_LABELS as VERIFY_LABELS,
)

TARGET = "scanme.local"


@pytest.fixture()
def stores(tmp_path):
    kb = GlobalKnowledge(str(tmp_path / "knowledge.db"))
    inst = InstitutionalMemory(str(tmp_path / "notes.db"))
    return {"kb": kb, "inst": inst}


def make_agent(stores):
    """Bare Agent instance (no heavy constructor) wired to the stores."""
    agent = object.__new__(Agent)
    agent.knowledge = stores["kb"]
    agent.institutional = stores["inst"]
    agent._kb_target = TARGET
    return agent


def _result(status, ftype="SQL injection", value="/api/login",
            method="payload", reason="time-based blind confirmed"):
    return {"status": status, "type": ftype, "value": value,
            "method": method, "reason": reason}


def _kb_rows(kb, target=TARGET):
    return kb.search_findings(target_domain=target, top_k=50)


def _inst_rows(inst):
    conn = sqlite3.connect(inst.db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT category, title, content, target, tags"
            " FROM institutional_notes").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def test_final_verdicts_persisted_to_both_stores(stores):
    """VERIFIED and REJECTED verdicts are written to both SQLite stores."""
    agent = make_agent(stores)
    results = [_result(V_VERIFIED), _result(V_REJECTED)]
    persisted = agent._persist_verdicts(results)

    assert len(persisted) == 4  # 2 verdicts x 2 stores

    kb_rows = _kb_rows(stores["kb"])
    assert len(kb_rows) == 2
    for row in kb_rows:
        assert row["target_domain"] == TARGET
        assert row["finding_type"] == "verification"
        assert "validation" in row["tags"]
        assert ("[" in row["content"]) and ("]" in row["content"])

    inst_rows = _inst_rows(stores["inst"])
    assert len(inst_rows) == 2
    for row in inst_rows:
        assert row["category"] == "findings"
        assert row["target"] == TARGET
        assert "validation" in row["tags"]


def test_unverified_never_persisted(stores):
    """UNVERIFIED findings stay chat-local (manual audit still pending)."""
    agent = make_agent(stores)
    persisted = agent._persist_verdicts([_result(V_UNVERIFIED)])

    assert persisted == []
    assert _kb_rows(stores["kb"]) == []
    assert _inst_rows(stores["inst"]) == []


def test_mixed_results_persist_only_final_verdicts(stores):
    """Out of a mixed batch, only VERIFIED/REJECTED rows are stored."""
    agent = make_agent(stores)
    agent._persist_verdicts([
        _result(V_VERIFIED),
        _result(V_UNVERIFIED),
        _result(V_REJECTED, ftype="XSS", value="/search?q="),
    ])

    kb_rows = _kb_rows(stores["kb"])
    assert len(kb_rows) == 2
    assert all(r["finding_type"] == "verification" for r in kb_rows)
    assert len(_inst_rows(stores["inst"])) == 2


def test_persisted_content_format(stores):
    """Content line embeds label, finding, method and reason."""
    agent = make_agent(stores)
    agent._persist_verdicts([_result(V_VERIFIED)])

    content = _kb_rows(stores["kb"])[0]["content"]
    assert content.startswith(VERIFY_LABELS[V_VERIFIED])
    assert "SQL injection" in content
    assert "/api/login" in content
    assert "(method: payload)" in content
    assert "time-based blind confirmed" in content


def test_storage_errors_swallowed(stores):
    """Broken stores must never break the answer pipeline."""
    class Boom:
        def save_finding(self, *a, **k):
            raise RuntimeError("db locked")

    class BoomInst:
        def add_note(self, *a, **k):
            raise RuntimeError("disk full")

    agent = object.__new__(Agent)
    agent.knowledge = Boom()
    agent.institutional = BoomInst()
    agent._kb_target = TARGET
    assert agent._persist_verdicts([_result(V_VERIFIED)]) == []


def test_new_chat_recalls_persisted_verdicts(stores):
    """Cross-chat path: a fresh session's target summary shows verdicts."""
    make_agent(stores)._persist_verdicts([_result(V_VERIFIED)])

    summary = stores["kb"].get_target_summary(TARGET)
    assert "Past knowledge for %s" % TARGET in summary
    assert "[verification]" in summary
    assert "validation" in summary
