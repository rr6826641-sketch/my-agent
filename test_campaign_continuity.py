"""CAMPAIGN CONTINUITY tests (issue #2).

1. Episodic store: transient WinError 32 -> retry saves the file.
2. Episodic store: permanent lock -> sidecar backup + auto-merge on the
   next load so zero memory is lost.
3. PayloadMemory auto-rank: hits rank above misses and seed() returns
   only payloads that worked.
4. mission_payloads wrapper surfaces the ranked memory readably.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

from ai_agent.memory.vector_store import EpisodicVectorMemory
from ai_agent.tools.payload_memory import PayloadMemory
from ai_agent.tools.auto_pilot import tool_mission_payloads


def _replace_calls(monkeypatch, flaky):
    import os as _os
    real_replace = _os.replace
    calls = [0]

    def wrapper(src, dst):
        s = str(src)
        if "episodic_vectors" in s:
            calls[0] += 1
            return flaky(src, dst, real_replace, calls)
        return real_replace(src, dst)

    monkeypatch.setattr("ai_agent.memory.vector_store.os.replace", wrapper)
    return calls


def test_episodic_retry_survives_transient_lock(tmp_path, monkeypatch):
    calls = [0]

    def flaky(src, dst, real, c):
        if c[0] < 3:
            raise PermissionError(32, "file locked (transient)")
        return real(src, dst)

    _replace_calls(monkeypatch, flaky)
    store = EpisodicVectorMemory(persist_dir=str(tmp_path))
    doc = store.archive("episode", "test retry hello world")
    assert doc, "archive failed"
    assert os.path.exists(store._local_path), "main file not written"
    # no sidecar needed when retry succeeds
    sidecars = [f for f in os.listdir(str(tmp_path))
                if f.startswith("episodic_vectors.locked-")]
    assert not sidecars, "sidecar should not exist after successful retry"


def test_episodic_sidecar_fallback_and_automerge(tmp_path, monkeypatch):
    def flaky(src, dst, real, c):
        raise PermissionError(32, "file locked permanently (webui open)")

    _replace_calls(monkeypatch, flaky)
    store = EpisodicVectorMemory(persist_dir=str(tmp_path))
    doc = store.archive("episode", "test sidecar hello world")
    assert doc, "archive failed (first store)"

    sidecars = [f for f in os.listdir(str(tmp_path))
                if f.startswith("episodic_vectors.locked-")
                and f.endswith(".json")]
    assert sidecars, "expected a locked sidecar backup"

    # lock clears -> new instance must merge the sidecar record back
    store2 = EpisodicVectorMemory(persist_dir=str(tmp_path))
    texts = [d.get("text", "") for d in store2._docs]
    assert any("test sidecar hello world" in t for t in texts), \
        "sidecar record was not auto-merged"


def test_payload_memory_ranks_hits_over_misses(tmp_path):
    pm = PayloadMemory(path=str(tmp_path / "pm.json"))
    pm.record("10.0.0.7", "sqli-payload-A", True, vuln_class="sqli")
    pm.record("10.0.0.7", "sqli-payload-A", True, vuln_class="sqli")
    pm.record("10.0.0.7", "sqli-payload-B", False, vuln_class="sqli")
    pm.record("10.0.0.7", "xss-payload-X", True, vuln_class="xss")
    seed = pm.seed("10.0.0.7")
    assert "sqli-payload-A" in seed
    assert "sqli-payload-B" not in seed, "misses must not be seeded"
    top = pm.top("10.0.0.7", vuln_class="sqli")
    assert "sqli-payload-A" in top and "sqli-payload-B" in top
    assert top.index("sqli-payload-A") < top.index("sqli-payload-B"), \
        "hits must rank above misses"


def test_mission_payloads_wrapper(tmp_path, monkeypatch):
    pm = PayloadMemory(path=str(tmp_path / "pm2.json"))
    pm.record("10.0.0.7", "dir:/admin", True, vuln_class="web:dir")
    monkeypatch.setattr(
        "ai_agent.tools.auto_pilot.tool_payload_memory_top",
        pm.top)
    out = tool_mission_payloads("10.0.0.7", 5)
    assert "dir:/admin" in out
    assert "score=" in out