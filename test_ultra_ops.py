"""Tests for the v21 Ultra capability pack (ai_agent/tools/ultra_ops.py).

Pure-logic / no-network coverage:
  * redaction + bounding helpers (evidence discipline)
  * chain_quality_score scoring maths
  * self_healthcheck registry audit
  * credential/url-required guards that return an error dict without network
  * evidence_capture / ledger / redact round-trip on a temp dir

Run:  py -m pytest test_ultra_ops.py -q
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_agent.tools import ultra_ops  # noqa: E402


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def test_split_list_variants():
    assert ultra_ops._split_list("a,b;c\nd") == ["a", "b", "c", "d"]
    assert ultra_ops._split_list(["x", " y "]) == ["x", "y"]
    assert ultra_ops._split_list(None) == []
    assert ultra_ops._split_list("") == []


def test_redact_headers_masks_secrets():
    hdrs = {"Authorization": "Bearer abc", "Cookie": "sid=1",
            "X-Api-Key": "k", "Content-Type": "text/html"}
    out = ultra_ops.redact_headers(hdrs)
    assert out["Authorization"] == "<redacted>"
    assert out["Cookie"] == "<redacted>"
    assert out["X-Api-Key"] == "<redacted>"
    assert out["Content-Type"] == "text/html"


def test_redact_text_masks_jwt_and_kv():
    jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123DEFghi456")
    text = "token=%s api_key: sekret password=pw Bearer xyz.abc" % jwt
    out = ultra_ops.redact_text(text)
    assert jwt not in out
    assert "sekret" not in out
    assert "pw" not in out.split("password")[-1]


def test_bound_result_drops_body_keeps_hash():
    r = {"status": 200, "body": "secret body", "body_len": 11,
         "headers": {"Set-Cookie": "a=b"}, "body_sha256": "deadbeef"}
    out = ultra_ops._bound_result(r)
    assert "body" not in out
    assert out["body_len"] == 11
    assert out["body_sha256"] == "deadbeef"
    assert out["headers"]["Set-Cookie"] == "<redacted>"


# --------------------------------------------------------------------------
# chain quality scorer (pure)
# --------------------------------------------------------------------------

def _good_chain():
    return {"hops": [
        {"stage": "recon", "action": "enumerate", "evidence": "nmap.txt",
         "requires": "in-scope range"},
        {"stage": "enum", "action": "fingerprint", "evidence": "whatweb.txt",
         "requires": "recon"},
        {"stage": "vuln", "action": "confirm sqli", "evidence": "sqlmap.log",
         "status": "CONFIRMED_POC", "requires": "enum"},
        {"stage": "exploit", "action": "dump users", "evidence": "dump.sql",
         "status": "VERIFIED", "impact": "critical data exposure",
         "requires": "sqli"},
        {"stage": "post", "action": "pivot to admin", "evidence": "shell.txt",
         "status": "CONFIRMED", "impact": "rce", "requires": "creds"},
    ]}


def test_chain_quality_full_chain_scores_high():
    out = json.loads(ultra_ops.chain_quality_score(_good_chain()))
    # 5/5 stages=30, 5/5 evidence=25, 5/5 prereq=15, 3/5 verified=12,
    # 2/5 impact=4  ->  86 (grade B)
    assert out["score"] == 86
    assert out["grade"] == "B"
    assert out["hops"] == 5
    assert out["stages_covered"] == ["enum", "exploit", "post", "recon", "vuln"]


def test_chain_quality_perfect_chain_grades_a():
    perfect = {"hops": [
        {"stage": s, "action": "do", "evidence": "e.txt",
         "requires": "r", "status": "VERIFIED", "impact": "critical"}
        for s in ("recon", "enum", "vuln", "exploit", "post")]}
    out = json.loads(ultra_ops.chain_quality_score(perfect))
    assert out["score"] == 100
    assert out["grade"] == "A"


def test_chain_quality_accepts_json_string():
    out = json.loads(ultra_ops.chain_quality_score(json.dumps(_good_chain())))
    assert out["grade"] == "B"


def test_chain_quality_weak_chain_scores_low():
    out = json.loads(ultra_ops.chain_quality_score(
        {"hops": [{"action": "scan"}]}))
    assert out["score"] < 40
    assert out["grade"] == "F"
    assert out["suggestions"]


def test_chain_quality_errors():
    assert "error" in json.loads(ultra_ops.chain_quality_score("{}"))
    assert "error" in json.loads(ultra_ops.chain_quality_score("{bad json"))
    assert "error" in json.loads(ultra_ops.chain_quality_score(123))


def test_chain_quality_alias_exists():
    assert ultra_ops.tool_chain_quality_score is ultra_ops.chain_quality_score


# --------------------------------------------------------------------------
# registry healthcheck (needs the assembled registry)
# --------------------------------------------------------------------------

def test_registry_contains_v21_tools_and_is_healthy():
    from ai_agent.tools import create_tools
    tools = {t.name: t for t in create_tools(None)}
    for name in ("subdomain_takeover", "cache_poison_scan",
                 "proto_pollution_test", "crlf_inject_test",
                 "host_header_inject", "rate_limit_test", "ldap_inject_test",
                 "xpath_inject_test", "http2_support_check", "param_mine",
                 "chain_quality_score", "evidence_capture",
                 "evidence_ledger", "evidence_redact", "retry_probe",
                 "self_healthcheck"):
        assert name in tools, "missing tool: %s" % name
    hc = json.loads(tools["self_healthcheck"].func())
    assert hc["ok"], "registry issues: %s" % hc["details"]
    assert hc["issues"] == 0


def test_every_registered_tool_schema_is_valid():
    from ai_agent.tools import create_tools
    for t in create_tools(None):
        assert t.name.isidentifier()
        assert t.description
        assert callable(t.func)
        assert isinstance(t.parameters, dict)
        assert t.parameters.get("type") == "object"


# --------------------------------------------------------------------------
# url/target-required guards (no network) + reliability helper
# --------------------------------------------------------------------------

@pytest.mark.parametrize("call", [
    lambda: ultra_ops.tool_cache_poison_scan(""),
    lambda: ultra_ops.tool_proto_pollution_test(""),
    lambda: ultra_ops.tool_crlf_inject_test(""),
    lambda: ultra_ops.tool_host_header_inject(""),
    lambda: ultra_ops.tool_rate_limit_test(""),
    lambda: ultra_ops.tool_ldap_inject_test(""),
    lambda: ultra_ops.tool_xpath_inject_test(""),
    lambda: ultra_ops.tool_param_mine(""),
    lambda: ultra_ops.tool_retry_probe(""),
    lambda: ultra_ops.tool_subdomain_takeover(""),
    lambda: ultra_ops.tool_http2_support_check(""),
])
def test_url_required_guards(call):
    out = json.loads(call())
    assert "error" in out


def test_is_transient_classification():
    assert ultra_ops._is_transient("Read timed out")
    assert ultra_ops._is_transient("ConnectionError: refused")
    assert ultra_ops._is_transient("HTTP 429")
    assert ultra_ops._is_transient("HTTP 503")
    assert not ultra_ops._is_transient("HTTP 404")
    assert not ultra_ops._is_transient("")


def test_rate_limit_count_is_hard_capped(monkeypatch):
    # patch the probe funnel so no real network happens
    calls = []

    def fake_probe(url, method="GET", headers=None, data=None, timeout=10,
                   allow_redirects=False, max_body=None, verify=False):
        calls.append(url)
        return {"status": 200, "headers": {}, "body": "", "body_len": 0,
                "body_sha256": "x", "elapsed": 0.0, "final_url": url,
                "error": None}

    monkeypatch.setattr(ultra_ops, "_probe", fake_probe)
    out = json.loads(ultra_ops.tool_rate_limit_test("https://t/", count=999))
    assert out["requests"] == 50
    assert len(calls) == 50


# --------------------------------------------------------------------------
# evidence discipline round-trip (temp dir, no network)
# --------------------------------------------------------------------------

def test_evidence_capture_ledger_redact(tmp_path, monkeypatch):
    monkeypatch.setattr(ultra_ops, "EVIDENCE_DIR", str(tmp_path))

    def fake_probe(url, method="GET", headers=None, data=None, timeout=10,
                   allow_redirects=False, max_body=None, verify=False):
        return {"status": 200, "headers": {"Set-Cookie": "sid=secret"},
                "body": "hello", "body_len": 5, "body_sha256": "abc",
                "elapsed": 0.0, "final_url": url, "error": None}

    monkeypatch.setattr(ultra_ops, "_probe", fake_probe)
    cap = json.loads(ultra_ops.tool_evidence_capture(
        label="demo", baseline=json.dumps({"url": "https://t/a"}),
        exploit=json.dumps({"url": "https://t/b"})))
    assert os.path.isfile(cap["baseline_path"])
    assert os.path.isfile(cap["exploit_path"])
    assert cap["diff"]["status_changed"] is False

    led = json.loads(ultra_ops.tool_evidence_ledger())
    assert led["count"] == 1
    assert led["bundles"][0]["label"] == "demo"

    red = json.loads(ultra_ops.tool_evidence_redact(path=cap["exploit_path"]))
    assert os.path.isfile(red["output"])
    with open(red["output"], "r", encoding="utf-8") as f:
        body = f.read()
    assert "sid=secret" not in body


def test_evidence_redact_missing_path():
    out = json.loads(ultra_ops.tool_evidence_redact(path="/no/such/file"))
    assert "error" in out
