# -*- coding: utf-8 -*-
"""Feature C (v10.5) - Auto pentest report: client-ready HTML.

Generates a self-contained dark-themed HTML report at campaign end,
alongside the markdown report.  Tests:
  * _write_html_report returns a real file path, valid HTML, all sections
  * _phase_report wires entry['html'] into the campaign state
  * webui._mission_summary exposes report_html when the file exists
  * /api/missions/<key>/report prefers the HTML file
"""

import json
import os

import pytest

import webui
from ai_agent.tools import auto_pilot as ap


def _state(tmp_path, target="10.0.0.7"):
    state = ap._load(target, str(tmp_path))
    state["phases"] = {
        "recon": {"status": "done", "ports": [
            {"port": 8080, "service": "http"}]},
        "scan": {"status": "done", "web": {
            "http://10.0.0.7:8080/": {"status": 200}}},
        "vuln": {"status": "done", "hits": [
            {"query": "nginx", "cves": ["CVE-2021-23017"],
             "snippet": "nginx alias traversal"}]},
        "exploit": {"status": "done", "attempts": [
            {"query": "nginx 1.20", "cves": ["CVE-2021-23017"]}],
            "fused_applied": [
                {"svc_key": "http/8080", "tags": "poc,rce",
                 "attempts": [{"nuclei": "rce template matched",
                               "url": "http://10.0.0.7:8080/"}]}]},
        "report": {},
    }
    state["payload_cache"] = {
        "source": "payload_fusion", "injected_at": "2026-09-13 12:00:00",
        "count": 1,
        "payloads": [{"svc_key": "http/8080", "score": 0.9, "hits": 4,
                      "campaigns": ["c0"], "technique": "nuclei:poc|rce",
                      "cves": ["CVE-2024-1001"]}]}
    return state


def test_write_html_report_file_and_sections(tmp_path):
    state = _state(tmp_path)
    ctx = ap._make_ctx(str(tmp_path), budget_sec=60)
    html_path = ap._write_html_report(state, ctx)
    assert html_path and os.path.isfile(html_path)
    assert html_path.endswith(".html") and "attack_mission_" in html_path
    with open(html_path, "r", encoding="utf-8") as fh:
        page = fh.read()
    assert page.startswith("<!DOCTYPE html>")
    assert "<style>" in page and "</html>" in page
    assert "ATTACK MISSION REPORT" in page
    assert "10.0.0.7" in page
    assert "Pentest Report" in page          # <title>
    assert "8080" in page and "http" in page  # recon table
    assert "CVE-2021-23017" in page           # vuln table
    assert "CVE-2024-1001" in page            # fused cve
    assert "Fused ammo applied" in page
    assert "poc,rce" in page
    assert "rce template matched" in page
    assert "no CVE hits" not in page


def test_html_escapes_unsafe_fields(tmp_path):
    state = _state(tmp_path)
    state["target"] = "<script>alert(1)</script>"
    ctx = ap._make_ctx(str(tmp_path), budget_sec=60)
    html_path = ap._write_html_report(state, ctx)
    with open(html_path, "r", encoding="utf-8") as fh:
        page = fh.read()
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_phase_report_wires_html_entry(tmp_path):
    state = _state(tmp_path)
    state["phases"]["report"] = {}
    ctx = ap._make_ctx(str(tmp_path), budget_sec=60)
    summary = ap._phase_report(state, ctx)
    assert "written" in summary
    entry = state["phases"]["report"]
    assert entry.get("html") and os.path.isfile(entry["html"])
    # markdown report still written
    assert entry["path"].endswith(".md") and os.path.isfile(entry["path"])


def test_webui_mission_summary_report_html(tmp_path):
    state = _state(tmp_path)
    state["campaign_file"] = os.path.join(str(tmp_path), "10.0.0.7.json")
    with open(state["campaign_file"], "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    html_path = os.path.join(str(tmp_path), "attack_mission_10_0_0_7.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write("<!DOCTYPE html><html></html>")
    state["phases"]["report"]["html"] = html_path
    with open(state["campaign_file"], "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    s = webui._mission_summary(state["campaign_file"])
    assert s["report_html"] == html_path

    # missing file -> None
    state2 = _state(tmp_path)
    state2["campaign_file"] = os.path.join(str(tmp_path), "10.0.0.8.json")
    with open(state2["campaign_file"], "w", encoding="utf-8") as fh:
        json.dump(state2, fh)
    s3 = webui._mission_summary(state2["campaign_file"])
    assert s3["report_html"] is None


@pytest.fixture
def webui_client(tmp_path, monkeypatch):
    backup = None
    cfg = webui.CONFIG_PATH
    if os.path.exists(cfg):
        with open(cfg, "r", encoding="utf-8") as fh:
            backup = fh.read()
    monkeypatch.setattr(webui, "_CAMPAIGNS_DIR", str(tmp_path / "campaigns"))
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


def test_report_route_serves_html(tmp_path, monkeypatch, webui_client):
    """HTML report is served through the existing /report endpoint."""
    campaigns = tmp_path / "campaigns"
    campaigns.mkdir(exist_ok=True)
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    html_path = reports / "attack_mission_10_0_0_7.html"
    html_path.write_text("<!DOCTYPE html><html><body>CLIENT-READY</body></html>",
                         encoding="utf-8")
    camp = {
        "target": "10.0.0.7", "phases": {"report": {"status": "done",
                                                    "html": str(html_path)}},
    }
    (campaigns / "10.0.0.7.json").write_text(json.dumps(camp), encoding="utf-8")
    resp = webui_client.get("/api/missions/10.0.0.7/report")
    assert resp.status_code == 200
    assert "CLIENT-READY" in resp.get_data(as_text=True)