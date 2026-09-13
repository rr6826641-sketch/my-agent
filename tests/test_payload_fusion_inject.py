"""Feature B (v10.4) - Payload Fusion auto-inject on new campaign.

Unit tests for the auto-inject pipeline:
  * _inject_fused_payloads - exact-once gate + cache shape + no-clobber
  * _match_fused / _fused_tags - port ranking + nuclei tag extraction
  * _phase_exploit - fused ammo fired on live web target when no CVE hits,
    idle when nothing matches
  * _phase_report - fused intel + fused ammo sections rendered
  * webui._mission_summary - payload_cache summarized for the mission list
  * tool_attack_mission - "PAYLOAD FUSION: N ..." output line

All payload memory access is redirected to tmp files; the real
PROJECT_DIR/payload_memory.json is never touched.
"""

import json
import os

import pytest

import webui
from ai_agent.memory.payload_fusion import PayloadMemory
from ai_agent.tools import auto_pilot as ap

# --- helpers ---------------------------------------------------------------

_SWARM_CAMP = {
    "kind": "swarm_campaign",
    "target": "10.0.0.7",
    "phases": {"exploit": {"targets": [
        {"host": "10.0.0.7", "service": "http", "port": 8080,
         "cves": ["CVE-2024-1001"],
         "snippet": "rce via /rpc endpoint",
         "nuclei": "poc rce sqli nuclei:default"},
        {"host": "10.0.0.7", "service": "https", "port": 443,
         "cves": ["CVE-2024-1002"],
         "nuclei": "xss lfi"},
    ]}},
}


def seed_memory(tmp_path, campaigns=2):
    """Build a temp PayloadMemory with fused records (hits>=1)."""
    mem = PayloadMemory(path=str(tmp_path / "mem.json"))
    for i in range(campaigns):
        mem.ingest(_SWARM_CAMP, campaign_key="c%d" % i)
    fused = mem.fuse(min_hits=1)
    assert fused, "test setup: seeded memory must fuse >=1 row"
    return mem, fused


def patch_fused_memory(tmp_path, monkeypatch, campaigns=2):
    mem, fused = seed_memory(tmp_path, campaigns)
    monkeypatch.setattr(ap, "_fused_memory", lambda: mem)
    return mem, fused


def make_state(tmp_path, target="10.0.0.7", extra_phases=None):
    state = ap._load(target, str(tmp_path))
    state["phases"] = extra_phases or {}
    return state


# --- gate + inject ---------------------------------------------------------

def test_inject_persists_cache(tmp_path, monkeypatch):
    _, fused = patch_fused_memory(tmp_path, monkeypatch)
    state = make_state(tmp_path)
    cache = ap._inject_fused_payloads(state, str(tmp_path))
    assert cache is not None
    assert cache["source"] == "payload_fusion"
    assert cache["count"] == len(fused)
    assert cache["injected_at"]
    assert "payloads" in cache and len(cache["payloads"]) == len(fused)
    assert state["payload_cache"] is cache
    # persisted to the campaign JSON on disk
    with open(state["campaign_file"], "r", encoding="utf-8") as fh:
        saved = json.load(fh)
    assert saved["payload_cache"]["count"] == len(fused)
    assert saved["payload_cache"]["source"] == "payload_fusion"


def test_inject_exact_once(tmp_path, monkeypatch):
    patch_fused_memory(tmp_path, monkeypatch)
    state = make_state(tmp_path)
    first = ap._inject_fused_payloads(state, str(tmp_path))
    second = ap._inject_fused_payloads(state, str(tmp_path))
    assert first is not None and second is None
    assert state["payload_cache"] is first  # untouched


def test_inject_never_clobbers_existing(tmp_path, monkeypatch):
    patch_fused_memory(tmp_path, monkeypatch)
    state = make_state(tmp_path)
    state["payload_cache"] = {"source": "manual", "count": 1,
                              "injected_at": "2020-01-01 00:00:00",
                              "payloads": [{"svc_key": "keep/1"}]}
    assert ap._inject_fused_payloads(state, str(tmp_path)) is None
    assert state["payload_cache"]["source"] == "manual"
    assert state["payload_cache"]["payloads"][0]["svc_key"] == "keep/1"


def test_inject_empty_memory_noop(tmp_path, monkeypatch):
    mem = PayloadMemory(path=str(tmp_path / "empty.json"))
    monkeypatch.setattr(ap, "_fused_memory", lambda: mem)
    state = make_state(tmp_path)
    assert ap._inject_fused_payloads(state, str(tmp_path)) is None
    assert "payload_cache" not in state
    # later run with now-seeded memory still injects (no stale cache)
    _, _ = patch_fused_memory(tmp_path, monkeypatch)
    assert ap._inject_fused_payloads(state, str(tmp_path)) is not None


# --- matching + tags -------------------------------------------------------

def test_fused_tags():
    assert ap._fused_tags({"technique": "nuclei:poc|rce|sqli"}) == "poc,rce,sqli"
    assert ap._fused_tags({"technique": "nuclei:rce"}) == "rce"
    assert ap._fused_tags({"technique": ""}) == ""
    assert ap._fused_tags({"technique": "poc|rce"}) == ""  # no nuclei: prefix


def test_match_fused_rank_order_and_cap():
    cache = {"payloads": [
        {"svc_key": "http/8080", "port": 8080, "score": 0.5},
        {"svc_key": "ssh/22", "port": None, "score": 0.9},   # rank 1 only
        {"svc_key": "https/443", "port": 443, "score": 0.9},
        {"svc_key": "mysql/3306", "port": 3306, "score": 0.1},
    ]}
    got = ap._match_fused(cache, [8080, 22, 443], top_k=20)
    keys = [r["svc_key"] for r in got]
    ranks = [r["_rank"] for r in got]
    # rank-2 rows (exact port) first, then rank-1, sorted by score desc
    assert keys == ["https/443", "http/8080", "ssh/22"]
    assert ranks == [2, 2, 1]
    # cap honored
    assert len(ap._match_fused(cache, [8080, 22, 443], top_k=2)) == 2
    # no overlap -> nothing
    assert ap._match_fused(cache, [9999]) == []
    assert ap._match_fused(None, [8080]) == []
    assert ap._match_fused(cache, []) == []


# --- exploit phase ---------------------------------------------------------

def _exploit_state(tmp_path, web_url=None):
    phases = {
        "vuln": {"status": "done", "hits": []},          # no CVE hits at all
        "recon": {"status": "done", "ports": [
            {"port": 8080, "service": "http"}]},
    }
    if web_url:
        phases["scan"] = {"status": "done", "web": {web_url: {"status": 200}}}
    return make_state(tmp_path, extra_phases=phases)


def test_exploit_idle_without_fused(tmp_path, monkeypatch):
    patch_fused_memory(tmp_path, monkeypatch)  # memory exists but...
    state = _exploit_state(tmp_path, web_url="http://10.0.0.7:8080/")
    # ...no cache injected -> nothing matched
    ctx = ap._make_ctx(str(tmp_path), budget_sec=60)
    summary = ap._phase_exploit(state, ctx)
    assert "no CVE hits, no fused ammo matched" in summary
    assert state["phases"]["exploit"]["note"].startswith(
        "no CVE hits from vuln phase and no fused ammo")


def test_exploit_idle_with_cache_but_no_port_match(tmp_path, monkeypatch):
    patch_fused_memory(tmp_path, monkeypatch)
    state = _exploit_state(tmp_path, web_url="http://10.0.0.7:8080/")
    ap._inject_fused_payloads(state, str(tmp_path))
    # open ports do not intersect cache ports (e.g. only 443 busy? no - 8080
    # is empty here because the cache needs an injected matching row)
    state["payload_cache"]["payloads"] = [
        {"svc_key": "mysql/3306", "port": 3306, "score": 0.9,
         "hits": 2, "technique": "nuclei:rce", "cves": ["CVE-2024-0001"]},
    ]
    ctx = ap._make_ctx(str(tmp_path), budget_sec=60)
    summary = ap._phase_exploit(state, ctx)
    assert "idle" in summary
    assert "fused_applied" not in state["phases"]["exploit"]


def test_exploit_fires_fused_ammo(tmp_path, monkeypatch):
    patch_fused_memory(tmp_path, monkeypatch)
    fired, records = [], []
    monkeypatch.setattr(
        ap, "tool_nuclei_scan",
        lambda url, tags="": (fired.append((url, tags)) or "nuclei: [rce] critical"))
    monkeypatch.setattr(
        ap, "tool_payload_memory_record",
        lambda *a, **kw: records.append((a, kw)))
    state = _exploit_state(tmp_path, web_url="http://10.0.0.7:8080/")
    ap._inject_fused_payloads(state, str(tmp_path))
    state["payload_cache"]["payloads"] = [
        {"svc_key": "http/8080", "port": 8080, "score": 0.9, "hits": 4,
         "technique": "nuclei:poc|rce|sqli", "cves": ["CVE-2024-1001"],
         "campaigns": ["c0", "c1"]},
    ]
    ctx = ap._make_ctx(str(tmp_path), budget_sec=60)
    summary = ap._phase_exploit(state, ctx)
    entry = state["phases"]["exploit"]
    assert "fused ammo: 1 matched / 1 fired" in summary
    assert fired == [("http://10.0.0.7:8080/", "poc,rce,sqli")]
    fa = entry["fused_applied"][0]
    assert fa["svc_key"] == "http/8080"
    assert fa["tags"] == "poc,rce,sqli"
    assert fa["attempts"][0]["url"] == "http://10.0.0.7:8080/"
    assert "rce" in fa["attempts"][0]["nuclei"]
    assert records and records[0][1]["signal"] == "fused_auto_inject"
    assert records[0][0][0] == "10.0.0.7"  # host positional
    assert records[0][1]["vuln_class"] == "fused"


def test_exploit_fused_matched_but_no_web_target(tmp_path, monkeypatch):
    patch_fused_memory(tmp_path, monkeypatch)
    called = []
    monkeypatch.setattr(ap, "tool_nuclei_scan",
                        lambda url, tags="": called.append(url) or "")
    state = _exploit_state(tmp_path)  # no scan phase -> no web targets
    ap._inject_fused_payloads(state, str(tmp_path))
    state["payload_cache"]["payloads"] = [
        {"svc_key": "http/8080", "port": 8080, "score": 0.9, "hits": 2,
         "technique": "nuclei:rce", "cves": [], "campaigns": ["c0"]},
    ]
    ctx = ap._make_ctx(str(tmp_path), budget_sec=60)
    ap._phase_exploit(state, ctx)
    fa = state["phases"]["exploit"]["fused_applied"][0]
    assert fa["note"] == "matched but no live web target"
    assert not called
    assert fa["attempts"] == []


# --- report phase ----------------------------------------------------------

def test_report_renders_fused_sections(tmp_path, monkeypatch):
    patch_fused_memory(tmp_path, monkeypatch)
    monkeypatch.setattr(ap, "tool_payload_memory_top", lambda *a, **k: "")
    state = make_state(tmp_path)
    state["phases"]["recon"] = {"status": "done", "ports": [
        {"port": 8080, "service": "http"}]}
    state["phases"]["scan"] = {"status": "done", "web": {
        "http://10.0.0.7:8080/": {"status": 200}}}
    state["phases"]["vuln"] = {"status": "done", "hits": []}
    state["payload_cache"] = {
        "source": "payload_fusion", "injected_at": "2026-09-13 12:00:00",
        "count": 1, "payloads": [
            {"svc_key": "http/8080", "port": 8080, "score": 0.9, "hits": 4,
             "technique": "nuclei:poc|rce", "cves": ["CVE-2024-1001"],
             "campaigns": ["c0", "c1"]},
        ]}
    state["phases"]["exploit"] = {"status": "done", "fused_applied": [
        {"svc_key": "http/8080", "port": 8080, "score": 0.9, "hits": 4,
         "technique": "nuclei:poc|rce", "tags": "poc,rce",
         "attempts": [{"url": "http://10.0.0.7:8080/",
                       "nuclei": "rce template matched"}]},
    ]}
    ctx = ap._make_ctx(str(tmp_path), budget_sec=60)
    summary = ap._phase_report(state, ctx)
    assert "written" in summary
    with open(state["phases"]["report"]["path"], "r", encoding="utf-8") as fh:
        md = fh.read()
    assert "## Fused payload intel (auto-injected)" in md
    assert "### Fused ammo applied (matched open ports)" in md
    assert "`http/8080`" in md
    assert "poc,rce" in md
    assert "CVE-2024-1001" in md


# --- runner wrapper (shell-level hook) -------------------------------------

def test_attack_mission_prints_fusion_line(tmp_path, monkeypatch):
    _, fused = patch_fused_memory(tmp_path, monkeypatch)
    monkeypatch.setattr(ap, "_run_one", lambda st, ph, ctx: "fake-phase-ok")
    out = ap.tool_attack_mission(target="10.0.0.7", campaign_dir=str(tmp_path))
    assert ("PAYLOAD FUSION: %d cross-campaign fused payload(s) auto-injected"
            % len(fused)) in out
    with open(os.path.join(str(tmp_path), "10.0.0.7.json"),
              "r", encoding="utf-8") as fh:
        saved = json.load(fh)
    assert saved["payload_cache"]["count"] == len(fused)


def test_run_phase_silent_hook(tmp_path, monkeypatch):
    patch_fused_memory(tmp_path, monkeypatch)
    monkeypatch.setattr(ap, "_run_one", lambda st, ph, ctx: "fake-phase-ok")
    out = ap._run_phase("10.0.0.7", "recon", campaign_dir=str(tmp_path))
    assert out == "fake-phase-ok"
    with open(os.path.join(str(tmp_path), "10.0.0.7.json"),
              "r", encoding="utf-8") as fh:
        assert "payload_cache" in json.load(fh)


# --- webui mission summary -------------------------------------------------

def test_webui_mission_summary_payload_cache(tmp_path):
    with_cache = tmp_path / "with_cache.json"
    with_cache.write_text(json.dumps({
        "target": "10.0.0.7", "phases": {},
        "payload_cache": {"source": "payload_fusion",
                          "injected_at": "2026-09-13 12:00:00",
                          "count": 3,
                          "payloads": [{"svc_key": "http/8080"}] * 3},
    }), encoding="utf-8")
    s = webui._mission_summary(str(with_cache))
    assert s["payload_cache"] == {"count": 3,
                                  "injected_at": "2026-09-13 12:00:00"}

    without = tmp_path / "without.json"
    without.write_text(json.dumps({"target": "10.0.0.8", "phases": {}}),
                       encoding="utf-8")
    assert webui._mission_summary(str(without))["payload_cache"] is None