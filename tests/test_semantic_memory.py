"""Phase 2: real semantic vector memory tests.

Covers embedding generation (dense pipeline + mocked transformer model),
semantic similarity retrieval (top-k cosine), kind filtering, the unified
brain (chats.json / notes / lessons single-index ingestion with sha dedupe),
legacy v1 sparse-store migration and persistence round-trips.
"""
import json
import os
import tempfile

import numpy as np
import pytest

from ai_agent.memory import vector_store as vs
from ai_agent.memory.vector_store import (
    EpisodicVectorMemory,
    UnifiedBrain,
    embed,
    get_embedding_engine,
)


@pytest.fixture
def store_dir():
    d = tempfile.mkdtemp(prefix="semmem_")
    yield d
    # best-effort cleanup of our own tmp artifacts
    for name in ("episodic_vectors.json", "episodic_vectors.json.tmp"):
        try:
            os.remove(os.path.join(d, name))
        except OSError:
            pass
    try:
        os.rmdir(d)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Embedding generation
# ---------------------------------------------------------------------------

def test_get_embedding_engine_is_dense():
    # numpy is a hard requirement here -> tfidf-dense is active unless a
    # heavier model got installed; hash-legacy must NOT be the engine.
    assert get_embedding_engine() in ("tfidf-dense", "sentence-transformers",
                                      "chroma")


def test_embed_returns_unit_length_dense_vector():
    vec = embed("SQL injection bypass for login forms")
    assert isinstance(vec, np.ndarray)
    assert vec.dtype.kind == "f"
    assert vec.ndim == 1
    assert vec.shape[0] > 0
    assert np.isclose(float(np.linalg.norm(vec)), 1.0, atol=1e-3)


def test_embed_is_deterministic_and_discriminating():
    a = embed("inject sql into the login form")
    b = embed("inject sql into the login form")
    c = embed("buffer overflow on windows binaries")
    assert np.allclose(a, b)
    assert not np.allclose(a, c)


def test_sentence_transformer_pipeline_wired(monkeypatch):
    """Prove the model path is genuinely integrated: when a transformer
    embedder is present the module must route through it."""
    class FakeModel:
        def encode(self, texts, normalize_embeddings=True):
            arr = np.zeros((len(texts), 8), dtype="float32")
            for i, t in enumerate(texts):
                # deterministic pseudo-embedding: distribute hash of words
                for w in str(t).split():
                    arr[i, int(vs._hash_index("w:" + w)) % 8] += 1.0
                n = float(np.linalg.norm(arr[i]))
                if n:
                    arr[i] /= n
            return arr

    monkeypatch.setattr(vs, "_HAVE_ST", True)
    monkeypatch.setattr(vs, "_HAVE_CHROMA", False)
    monkeypatch.setattr(vs, "_HAVE_NUMPY", True)
    monkeypatch.setattr(vs, "_sentence_transformer", lambda: FakeModel())
    assert get_embedding_engine() == "sentence-transformers"
    vec = embed("sql injection payload")
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (8,)
    # and a full store round-trips on the model path
    d = tempfile.mkdtemp(prefix="semmem_st_")
    try:
        s = EpisodicVectorMemory(persist_dir=d)
        s.archive("payload", "union select based sql injection", "sqli")
        s.archive("payload", "php object injection gadget chain", "php")
        hits = s.recall("sql injection union select", top_k=2)
        assert hits and hits[0]["text"].startswith("union select")
        assert hits[0]["score"] >= hits[1]["score"]
    finally:
        try:
            os.remove(os.path.join(d, "episodic_vectors.json"))
            os.rmdir(d)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Semantic similarity retrieval
# ---------------------------------------------------------------------------

def test_semantic_recall_ranks_related_hits_first(store_dir):
    s = EpisodicVectorMemory(persist_dir=store_dir)
    s.archive_lesson("SQL injection bypass techniques for login forms")
    s.archive_lesson("Buffer overflow exploitation on Windows binaries")
    s.archive_bypass("WAF bypass via chunked transfer encoding")

    hits = s.recall("how do i bypass the sql login filter", top_k=3)
    assert 2 <= len(hits) <= 3
    scores = [h["score"] for h in hits]
    assert scores == sorted(scores, reverse=True)
    assert "sql" in hits[0]["text"].lower() or "bypass" in hits[0][
        "text"].lower()
    # ordering: the unrelated buffer-overflow doc must not outrank the real
    # token matches (sql-injection lesson, waf-bypass payload).
    if len(hits) >= 2:
        assert "buffer overflow" not in hits[0]["text"].lower()
        assert "buffer overflow" not in hits[1]["text"].lower()


def test_recall_empty_store_and_top_k(store_dir):
    s = EpisodicVectorMemory(persist_dir=store_dir)
    assert s.recall("anything at all") == []
    for i in range(5):
        s.archive_lesson("lesson number %d about sqli fuzzing" % i)
    assert len(s.recall("sqli fuzzing", top_k=3)) == 3
    assert len(s.recall("sqli fuzzing", top_k=100)) == 5


def test_query_result_shape_compat(store_dir):
    """reflection.py relies on [{id, text, meta, score}] result dicts."""
    s = EpisodicVectorMemory(persist_dir=store_dir)
    s.archive_methodology("subdomain enumeration: subfinder then httpx")
    hits = s.query("enumerate subdomains with subfinder", top_k=2)
    assert hits
    for h in hits:
        assert set(("id", "text", "meta", "score")) <= set(h)
        assert isinstance(h["id"], str)
        assert h["score"] >= 0.0


def test_kind_filtering(store_dir):
    s = EpisodicVectorMemory(persist_dir=store_dir)
    s.archive("chat", "user: how do i obfuscate my sqlmap requests")
    s.archive_lesson("sqlmap tamper scripts slow down the scan too much")
    only_lessons = s.query("sqlmap tamper obfuscate", kind="lesson",
                           top_k=5)
    assert only_lessons
    assert all(h["meta"]["kind"] == "lesson" for h in only_lessons)
    both = s.query("sqlmap tamper obfuscate",
                   kind={"lesson", "chat"}, top_k=5)
    assert len(both) >= len(only_lessons)


# ---------------------------------------------------------------------------
# Archive dedupe + multi-file / unified-brain indexing
# ---------------------------------------------------------------------------

def test_dedupe_rejects_identical_record(store_dir):
    s = EpisodicVectorMemory(persist_dir=store_dir)
    first = s.archive_lesson("never trust client side auth checks")
    assert first
    assert s.archive_lesson("never trust client side auth checks") == ""
    assert s.count() == 1


def test_index_documents_bulk_and_dedupe(store_dir):
    s = EpisodicVectorMemory(persist_dir=store_dir)
    docs = [
        {"kind": "methodology", "text": "phase 1: passive recon via osint"},
        {"kind": "methodology", "text": "phase 2: active scanning"},
        {"kind": "payload", "text": "basic xss polyglot payload set"},
    ]
    assert s.index_documents(docs) == 3
    assert s.index_documents(docs) == 0  # sha-deduped
    assert s.count() == 3


def test_multi_file_indexing_and_rebuild_is_idempotent(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "method.md").write_text(
        "## Payloads\nXSS encoded variants bypass the filter.\n\n"
        "## Recon\nSubfinder first, then httpx probing.\n",
        encoding="utf-8")
    chats = {
        "sessions": {
            "sess-1": {"id": "sess-1", "messages": [
                {"role": "user", "content": "how to chain sqli to rce",
                 "ts": 1},
                {"role": "assistant",
                 "content": "use union select to write a webshell", "ts": 2},
            ]},
        }
    }
    chats_file = d / "chats.json"
    chats_file.write_text(json.dumps(chats), encoding="utf-8")

    brain = UnifiedBrain(
        store=EpisodicVectorMemory(persist_dir=str(tmp_path / "db")))
    res1 = brain.build(chats_path=str(chats_file), notes_dir=str(d))
    assert res1["total"] >= 4          # 2 paragraphs + 2 chat turns
    assert res1["chats"] == 2
    assert res1["notes"] >= 2

    res2 = brain.build(chats_path=str(chats_file), notes_dir=str(d))
    assert res2["total"] == 0          # fully sha-deduped on rebuild

    store = brain.store
    assert store.count("chat") == 2
    hits = store.recall("write a webshell through sqli", top_k=3)
    assert any("union select" in h["text"] for h in hits)


def test_index_file_dispatch_json_vs_markdown(tmp_path):
    s = EpisodicVectorMemory(persist_dir=str(tmp_path / "db"))
    md = tmp_path / "notes.md"
    md.write_text("para one about ldap injection.\n\npara two about ssrf.\n",
                  encoding="utf-8")
    assert s.index_file(str(md), kind="note") == 2
    jf = tmp_path / "list.json"
    jf.write_text(json.dumps([{"text": "smb relay attack notes"}]),
                  encoding="utf-8")
    assert s.index_file(str(jf), kind="methodology") == 1
    kinds = {r["meta"]["kind"] for r in s._docs}
    assert "note" in kinds and "methodology" in kinds


# ---------------------------------------------------------------------------
# Legacy v1 migration + persistence
# ---------------------------------------------------------------------------

def test_legacy_v1_sparse_store_migrates_and_searches(store_dir):
    path = os.path.join(store_dir, "episodic_vectors.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({
            "version": 1, "backend": "local",
            "docs": [{
                "id": "em-000001",
                "text": "legacy note: sql injection in search params",
                "meta": {"kind": "lesson", "tags": [], "target": "",
                         "outcome": "", "ts": 1.0},
                "vec": {"123": 1.0, "45": 0.5},
            }],
        }, fh)
    s = EpisodicVectorMemory(persist_dir=store_dir)
    assert s.count() == 1
    hits = s.query("sql injection search parameter", top_k=3)
    assert hits and hits[0]["id"] == "em-000001"
    # re-embedded into the dense space (no sparse dicts left)
    assert all(not isinstance(r.get("vec"), dict) for r in s._docs)


def test_persistence_round_trip(store_dir):
    p1 = os.path.join(store_dir, "sub")
    os.makedirs(p1, exist_ok=True)
    s1 = EpisodicVectorMemory(persist_dir=p1)
    s1.archive_payload("reflect xss in the referer header", tags=["xss"],
                       target="demo.local")
    del s1
    s2 = EpisodicVectorMemory(persist_dir=p1)
    assert s2.count() == 1
    hit = s2.query("stored xss via referer", top_k=1)
    assert hit and hit[0]["text"].startswith("reflect xss")
    assert hit[0]["meta"]["tags"] == ["xss"]


def test_unified_brain_recall_prefers_technical_kinds(tmp_path):
    chats = {"sessions": {"s1": {"messages": [
        {"role": "user", "content": "help me fix my python script", "ts": 1},
    ]}}}
    cj = tmp_path / "chats.json"
    cj.write_text(json.dumps(chats), encoding="utf-8")
    store = EpisodicVectorMemory(persist_dir=str(tmp_path / "db"))
    store.archive_methodology(
        "python: use requests.Session for authenticated fuzzing loops")
    brain = UnifiedBrain(store=store)
    brain.build(chats_path=str(cj))
    hits = brain.recall("python authenticated request fuzzing", top_k=5)
    assert hits
    assert any(h["meta"]["kind"] == "methodology" for h in hits[:3])
