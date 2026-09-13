# -*- coding: utf-8 -*-
"""Feature B (v10.4) - full-stack e2e: Payload Fusion auto-inject.

Proves the acceptance chain end-to-end:
  * NEW campaign is created by tool_attack_mission() against a REAL local
    mock HTTP server (real TCP connect scan + real HTTP GET probing).
  * The top fused payload rows (seeded through the REAL PayloadMemory
    ingest/fuse pipeline on a tmp store) are auto-injected into the new
    campaign's payload_cache - source "payload_fusion".
  * The exploit phase matches the injected ammo against the mock server's
    open port, fires it (tagged nuclei run), and records the
    fused_auto_inject signal.
  * The report markdown contains both fused sections.
  * The REAL Flask app exposes payload_cache through /api/missions and the
    mission template renders the fused-payload badge.

Hermetic stubs (repo-level stores / external binaries are NOT touched):
  * ap.tool_nuclei_scan        - canned output (nuclei binary is optional)
  * ap.tool_dir_fuzz           - "" (optional enhancement step, keeps fuzz fast)
  * ap.tool_tech_detect        - "" (no external fingerprint DB dependency)
  * ap.tool_cve_lookup         - "" (public NVD API not required for this path)
  * ap.tool_payload_memory_record / ap.tool_add_finding / _top - capture/
    no-op so the real payload_memory.json and findings.jsonl stay untouched.
Everything else - port scanner, HTTP probing, phase orchestration, campaign
persistence, report writer, WebUI API/templates - is the REAL code path.
"""

import http.server
import json
import os
import socketserver
import threading

import pytest

import webui
from ai_agent.memory.payload_fusion import PayloadMemory
from ai_agent.tools import auto_pilot as ap
from ai_agent.tools import network


# --- mock target server ---------------------------------------------------

class _MockHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><body>mock shop login</body></html>\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def version_string(self):
        # keep the server banner anonymous so the vuln phase has no
        # service token to feed a real NVD lookup
        return ""

    def log_message(self, *a):
        pass


@pytest.fixture
def mock_server():
    """REAL local HTTP server on an ephemeral 127.0.0.1 port.

    Returns the bound port so the seeded fused payload targets it.
    """
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _MockHandler)
    srv.allow_reuse_address = True
    port = int(srv.server_address[1])
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield port
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)


# --- fusion memory seeding -------------------------------------------------

def _swarm_camp(host, service, port, cves, nuclei, snippet):
    """Mirror the war-room campaign dict format PayloadMemory ingests."""
    return {
        "kind": "swarm_campaign",
        "target": host,
        "phases": {"exploit": {"targets": [
            {"host": host, "service": service, "port": port,
             "cves": cves, "nuclei": nuclei, "snippet": snippet},
        ]}},
    }


def seed_fused_memory(store_path, open_port):
    """Real PayloadMemory ingest/fuse pipeline on a tmp store.

    Plants two fused rows: one targeting the mock server's open port
    (http/<open_port>, proven nuclei rce tag chain) and a decoy row for a
    port that is NOT open (https/443) so matching/filtering is proven.
    """
    pm = PayloadMemory(path=str(store_path))
    pm.ingest(_swarm_camp(
        "10.0.0.7", "http", open_port,
        ["CVE-2024-1001"], "poc rce sqli nuclei:rce",
        "rce via /rpc endpoint (proven in campaign c0)"),
        campaign_key="campA")
    pm.ingest(_swarm_camp(
        "10.0.0.9", "https", 443,
        ["CVE-2024-2001"], "poc nuclei:default",
        "default-cred probe on ssl admin"),
        campaign_key="campB")
    fused = pm.fuse(min_hits=1)
    assert len(fused) == 2, "expected both seeded rows to fuse"
    return pm


# --- engine stubs ---------------------------------------------------------

def _patch_engine(monkeypatch, mock_port, records):
    """Stub the external-tool boundary; keep the rest of the engine REAL."""
    # real port scanner, pointed at the mock server's ephemeral port
    monkeypatch.setattr(ap, "tool_port_scan",
                        lambda host, **kw: network.tool_port_scan(
                            host, ports=str(mock_port), timeout=0.8))
    monkeypatch.setattr(ap, "tool_dir_fuzz", lambda *a, **k: "")
    monkeypatch.setattr(ap, "tool_tech_detect", lambda *a, **k: "")
    monkeypatch.setattr(ap, "tool_cve_lookup", lambda *a, **k: "")
    monkeypatch.setattr(ap, "tool_nuclei_scan",
                        lambda *a, **k: ("nuclei: [rce] %s - template matched"
                                         % (a[0] if a else "?")))
    monkeypatch.setattr(ap, "tool_payload_memory_top", lambda *a, **k: "")
    monkeypatch.setattr(ap, "tool_payload_memory_record",
                        lambda *a, **kw: records.append((a, kw)))
    monkeypatch.setattr(ap, "tool_add_finding", lambda *a, **k: 0)


def _campaign_json(campaign_dir, target):
    with open(os.path.join(campaign_dir, "%s.json" % target),
              "r", encoding="utf-8") as fh:
        return json.load(fh)


# --- webui mock-app helper (mirrors tests/test_webui_dock_layering.py) -----

@pytest.fixture
def webui_client(tmp_path, monkeypatch):
    """REAL Flask app in mock mode, missions served from tmp campaigns dir."""
    backup = None
    cfg = webui.CONFIG_PATH
    if os.path.exists(cfg):
        with open(cfg, "r", encoding="utf-8") as fh:
            backup = fh.read()
    monkeypatch.setattr(webui, "_CAMPAIGNS_DIR",
                        str(tmp_path / "campaigns"))
    try:
        webui._reload_state(mock_override=True)
        yield webui.app.test_client()
    finally:
        if backup is None:
            if os.path.exists(cfg):
                os.remove(cfg)
        else:
            with open(cfg, "w", encoding="utf-8") as fh:
                fh.write(backup)
        webui._reload_state(mock_override=True)


# --- the e2e walk ---------------------------------------------------------

def test_e2e_new_campaign_fused_ammo_lifecycle(tmp_path, monkeypatch,
                                               mock_server, webui_client):
    campaigns_dir = str(tmp_path / "campaigns")
    os.makedirs(campaigns_dir, exist_ok=True)
    target = "127.0.0.1"

    records = []
    _patch_engine(monkeypatch, mock_server, records)
    store = tmp_path / "payload_memory.json"
    pm = seed_fused_memory(store, mock_server)
    monkeypatch.setattr(ap, "_FUSION_MEMORY", pm)

    # 1) run the REAL kill-chain against the mock server
    out = ap.tool_attack_mission(target=target, campaign_dir=campaigns_dir,
                                 run_nuclei=False, budget_sec=150)
    state = _campaign_json(campaigns_dir, target)

    # 2) auto-inject happened on the brand-new campaign
    assert ("PAYLOAD FUSION: 2 cross-campaign fused payload(s) auto-injected"
            in out)
    pc = state["payload_cache"]
    assert pc["source"] == "payload_fusion"
    assert pc["count"] == 2
    svc_keys = [p["svc_key"] for p in pc["payloads"]]
    assert "http/%d" % mock_server in svc_keys
    assert "https/443" in svc_keys

    # 3) exploit fired the matching ammo (open port only)
    exp = state["phases"]["exploit"]
    fused_applied = exp.get("fused_applied", [])
    assert len(fused_applied) == 1, (
        "only the open-port ammo should match, decoy filtered")
    fa = fused_applied[0]
    assert fa["svc_key"] == "http/%d" % mock_server
    assert fa["tags"], "nuclei tags must be extracted"
    assert fa["attempts"][0]["url"] == "http://%s:%d/" % (target, mock_server)
    assert "nuclei" in fa["attempts"][0]
    assert "idle" not in exp.get("note", "")
    assert any(k[1].get("signal") == "fused_auto_inject" for k in records)
    fused_sig = [k for k in records if k[1].get("signal") == "fused_auto_inject"]
    assert fused_sig[0][1]["vuln_class"] == "fused"
    assert fused_sig[0][1]["payload"].startswith(
        "fused:http/%d:" % mock_server)

    # 4) report markdown carries both fused sections
    with open(state["phases"]["report"]["path"], "r",
              encoding="utf-8") as fh:
        md = fh.read()
    assert "## Fused payload intel (auto-injected)" in md
    assert "### Fused ammo applied (matched open ports)" in md
    assert "http/%d" % mock_server in md

    # 5) WebUI /api/missions surfaces the cache
    resp = webui_client.get("/api/missions")
    assert resp.status_code == 200
    missions = resp.get_json()["missions"]
    mine = next(m for m in missions if m["target"] == target)
    assert mine["payload_cache"] == {"count": 2,
                                     "injected_at": pc["injected_at"]}

    # 6) template renders the fused badge for this mission
    idx = webui_client.get("/")
    assert idx.status_code == 200
    page = idx.get_data(as_text=True)
    assert "Fused payloads" in page and "payload_cache.count" in page

    # 7) exact-once: a resume/re-run must NOT re-inject or clobber
    before = pc["injected_at"]
    ap._run_phase(target, "recon", campaign_dir=campaigns_dir,
                  run_nuclei=False, budget_sec=150)
    state2 = _campaign_json(campaigns_dir, target)
    assert state2["payload_cache"]["injected_at"] == before
    assert state2["payload_cache"]["count"] == 2