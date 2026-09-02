"""End-to-end tests for the Autonomous Finding Verification Sub-Routine.

Covers:
  Part 1 - ai_agent/tools/verify.py (deterministic checks, mocked network)
  Part 2 - ai_agent/tools/reporting.py (verification field, tools, report)
  Part 3 - ai_agent/core.py (_find_finding_pos, extraction, tags, two-phase)

Run:  py test_verify_arch.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] %s %s" % (name, detail))
    else:
        FAIL += 1
        print("[FAIL] %s %s" % (name, detail))


def section(title):
    print("\n=== %s ===" % title)


# ---------------------------------------------------------------- Part 1
import ai_agent.tools.verify as verify_mod
from ai_agent.tools.verify import (
    REJECTED, UNVERIFIED, VERIFIED,
    classify_finding, classify_severity, lightweight_verify_finding,
    needs_subagent_validation, parse_host_port, payload_verify_plan,
    verify_cve, verify_open_port, verify_subdomain, verify_vuln,
)


def test_verify_module():
    section("verify.py - classification + parsing")

    check("classify CVE", classify_finding(
        "CVE-2024-1234 in Apache") == "cve")
    check("classify URL -> vuln", classify_finding(
        "SQL injection at http://10.0.0.1/login") == "vuln")
    check("classify host:port", classify_finding(
        "192.168.1.10:8080 exposed") == "open_port")
    check("classify port phrase", classify_finding(
        "port 443 open") == "open_port")
    check("classify subdomain", classify_finding(
        "api.target.com found") == "subdomain")
    check("classify plain -> vuln", classify_finding(
        "no clear claim here") == "vuln")

    check("severity critical", classify_severity(
        "critical RCE at http://x/login") == "critical")
    check("severity high", classify_severity(
        "auth bypass in login") == "high")
    check("severity medium", classify_severity(
        "XSS in search form") == "medium")
    check("severity low", classify_severity(
        "port 80 open") == "low")
    check("needs subagent high", needs_subagent_validation(
        "privilege escalation") is True)
    check("needs subagent low", needs_subagent_validation(
        "port 80 open") is False)

    h, p = parse_host_port("192.168.1.10:8080")
    check("parse host:port", h == "192.168.1.10" and p == 8080, "%s:%s" % (h, p))
    h, p = parse_host_port("port 22 open on 10.0.0.1")
    check("parse port-on-host", h == "10.0.0.1" and p == 22, "%s:%s" % (h, p))
    h, p = parse_host_port("port 443 open")
    check("parse port only", h == "" and p == 443, "%s:%s" % (h, p))
    h, p = parse_host_port("nothing here")
    check("parse no target", h == "" and p == 0, "%s:%s" % (h, p))


def test_payload_verify_plan():
    section("verify.py - payload re-verification plans")

    g = verify_mod.PAYLOAD_VERIFY_GUIDANCE
    check("sqli plan", payload_verify_plan(
        "SQL injection at http://10.0.0.1/login") == g["sqli"])
    check("xss plan", payload_verify_plan(
        "stored XSS in the profile form") == g["xss"])
    check("cmdi plan", payload_verify_plan(
        "command injection in the ping parameter") == g["cmdi"])
    check("path traversal plan", payload_verify_plan(
        "path traversal in download.php") == g["path_traversal"])
    check("ssrf plan", payload_verify_plan(
        "SSRF via the url parameter") == g["ssrf"])
    check("xxe plan", payload_verify_plan(
        "XXE in the XML upload") == g["xxe"])
    check("ssti plan", payload_verify_plan(
        "server-side template injection in name field") == g["ssti"])
    check("open redirect plan", payload_verify_plan(
        "open redirect on the login page") == g["open_redirect"])
    check("cve plan", payload_verify_plan(
        "CVE-2024-1234 affects Apache 2.4.1") == g["cve"])
    check("open port plan", payload_verify_plan(
        "port 80 open on 192.0.2.1") == g["open_port"])
    check("subdomain plan", payload_verify_plan(
        "api.example.com discovered") == g["subdomain"])
    check("header plan", payload_verify_plan(
        "missing Content-Security-Policy header") == g["header"])
    check("generic plan", payload_verify_plan(
        "something odd in the response") == g["generic"])
    check("plan demands evidence before VERIFIED",
          "VERIFIED" in g["sqli"] and "EXACT" in g["sqli"])


def test_verify_open_port(monkeypatch, tmp):
    section("verify.py - open_port verdicts")

    monkeypatch(verify_mod, "_probe_port",
                lambda host, port, timeout=3.0: (True, "open"))
    v = verify_open_port("port 80 open on 192.0.2.1")
    check("port open -> VERIFIED", v["status"] == VERIFIED, v["reason"])

    monkeypatch(verify_mod, "_probe_port",
                lambda host, port, timeout=3.0: (False, "refused"))
    v = verify_open_port("port 80 open on 192.0.2.1")
    check("port closed -> REJECTED", v["status"] == REJECTED, v["reason"])

    v = verify_open_port("port 80 open")
    check("no host -> UNVERIFIED", v["status"] == UNVERIFIED, v["reason"])

    v = verify_open_port("port 70000 open on 192.0.2.1")
    check("invalid port -> REJECTED", v["status"] == REJECTED, v["reason"])


def test_verify_subdomain(monkeypatch, tmp):
    section("verify.py - subdomain verdicts")

    monkeypatch(verify_mod, "_resolve",
                lambda domain, timeout=5.0: (True, "resolves to 1.2.3.4"))
    v = verify_subdomain("api.example.com discovered")
    check("resolves -> VERIFIED", v["status"] == VERIFIED, v["reason"])

    monkeypatch(verify_mod, "_resolve",
                lambda domain, timeout=5.0: (False, "no such host"))
    v = verify_subdomain("api.example.com discovered")
    check("no resolve -> REJECTED", v["status"] == REJECTED, v["reason"])

    v = verify_subdomain("some random text")
    check("no domain -> UNVERIFIED", v["status"] == UNVERIFIED, v["reason"])


def test_verify_cve(monkeypatch, tmp):
    section("verify.py - CVE verdicts")

    monkeypatch(verify_mod, "tool_cve_lookup",
                lambda query, max_results=5: (
                    "CVE-2024-1234 exists in NVD. version 2.4.1 affected."))
    v = verify_cve("CVE-2024-1234 affects Apache 2.4.1")
    check("cve found -> VERIFIED", v["status"] == VERIFIED, v["reason"])

    monkeypatch(verify_mod, "tool_cve_lookup",
                lambda query, max_results=5: (
                    "no CVEs found for 'CVE-2024-9999'"))
    v = verify_cve("CVE-2024-9999 affects Apache")
    check("fabricated cve -> REJECTED", v["status"] == REJECTED, v["reason"])

    monkeypatch(verify_mod, "tool_cve_lookup",
                lambda query, max_results=5: "cve_lookup: api unavailable")
    v = verify_cve("CVE-2024-1234 affects Apache")
    check("lookup error -> UNVERIFIED", v["status"] == UNVERIFIED, v["reason"])

    monkeypatch(verify_mod, "tool_cve_lookup",
                lambda query, max_results=5: (_ for _ in ()).throw(
                    RuntimeError("network down")))
    v = verify_cve("CVE-2024-1234 affects Apache")
    check("lookup exception -> UNVERIFIED", v["status"] == UNVERIFIED,
          v["reason"])

    v = verify_cve("no cve id here")
    check("no cve id -> UNVERIFIED", v["status"] == UNVERIFIED, v["reason"])


def test_verify_vuln(monkeypatch, tmp):
    section("verify.py - web vuln verdicts")

    monkeypatch(verify_mod, "tool_http_request",
                lambda url, method="GET", max_body=1500: (
                    "STATUS: 200\nX-Frame-Options: DENY"))
    monkeypatch(verify_mod, "tool_check_headers",
                lambda url, timeout=20: (
                    "[OK] X-Frame-Options : DENY"))

    v = verify_vuln("X-Frame-Options missing on http://10.0.0.1/")
    check("header present -> REJECTED", v["status"] == REJECTED, v["reason"])

    monkeypatch(verify_mod, "tool_check_headers",
                lambda url, timeout=20: (
                    "[MISSING] X-Frame-Options : not sent"))
    v = verify_vuln("X-Frame-Options missing on http://10.0.0.1/")
    check("header absent -> VERIFIED", v["status"] == VERIFIED, v["reason"])

    monkeypatch(verify_mod, "tool_http_request",
                lambda url, method="GET", max_body=1500: (
                    "http_request error: connection refused"))
    v = verify_vuln("XSS at http://10.0.0.1/search")
    check("unreachable -> REJECTED", v["status"] == REJECTED, v["reason"])

    monkeypatch(verify_mod, "tool_http_request",
                lambda url, method="GET", max_body=1500: (_ for _ in ()).throw(
                    RuntimeError("timeout")))
    v = verify_vuln("XSS at http://10.0.0.1/search")
    check("request exception -> UNVERIFIED", v["status"] == UNVERIFIED,
          v["reason"])

    monkeypatch(verify_mod, "tool_http_request",
                lambda url, method="GET", max_body=1500: "STATUS: 200 OK")
    v = verify_vuln("XSS at http://10.0.0.1/search")
    check("reachable generic -> UNVERIFIED", v["status"] == UNVERIFIED,
          v["reason"])

    monkeypatch(verify_mod, "tool_http_request",
                lambda url, method="GET", max_body=1500: "STATUS: 404")
    v = verify_vuln("XSS at http://10.0.0.1/search")
    check("http 404 -> REJECTED", v["status"] == REJECTED, v["reason"])

    v = verify_vuln("some vague claim with no url")
    check("no url -> UNVERIFIED", v["status"] == UNVERIFIED, v["reason"])


def test_verify_dispatch(monkeypatch, tmp):
    section("verify.py - lightweight_verify_finding dispatch")

    monkeypatch(verify_mod, "_probe_port",
                lambda host, port, timeout=3.0: (True, "open"))
    v = lightweight_verify_finding(
        {"type": "open_port", "value": "port 80 open on 192.0.2.1"})
    check("dispatch open_port", v["status"] == VERIFIED)

    monkeypatch(verify_mod, "tool_cve_lookup",
                lambda query, max_results=5: "no CVEs found for 'CVE-2024-1'")
    v = lightweight_verify_finding(
        {"value": "CVE-2024-1234 affects Apache 2.4.1"})
    check("auto-classify cve", v["status"] == REJECTED, v["reason"])

    monkeypatch(verify_mod, "tool_http_request",
                lambda url, method="GET", max_body=1500: (_ for _ in ()).throw(
                    RuntimeError("boom")))
    v = lightweight_verify_finding(
        {"type": "vuln", "value": "SQLi at http://10.0.0.1/q"})
    check("vuln exception safe -> UNVERIFIED", v["status"] == UNVERIFIED,
          v["reason"])

    v = lightweight_verify_finding(None)
    check("empty finding safe", v["status"] == UNVERIFIED, v["reason"])


# ---------------------------------------------------------------- Part 2
import ai_agent.tools.reporting as report_mod
from ai_agent.tools.reporting import (
    tool_add_finding, tool_verify_all_findings, tool_verify_finding,
    tool_write_report,
)


def test_reporting(monkeypatch, tmp):
    section("reporting.py - verification field + tools + report")
    monkeypatch(report_mod, "FINDINGS_PATH",
                os.path.join(tmp, "findings.jsonl"))
    monkeypatch(report_mod, "REPORTS_DIR", os.path.join(tmp, "reports"))

    out = tool_add_finding("http://10.0.0.1", "SQL injection in login",
                           severity="high", description="q param injectable",
                           verification="verified",
                           verification_reason="manual confirm",
                           verification_status="CONFIRMED_POC",
                           evidence="' OR 1=1-- -> auth bypass confirmed")
    check("add_finding verified accepted", "added" in out.lower()
          or "F-" in out, out)
    rows = report_mod._read_all()
    check("verified -> status confirmed",
          rows and rows[0]["status"] == "confirmed",
          rows[0]["status"] if rows else "no rows")
    check("verification stored", rows and rows[0]["verification"] == "verified")

    out = tool_add_finding("x", "bad verification value", verification="bogus")
    check("add_finding rejects bogus verification",
          "must be one of" in out.lower(), out)

    out = tool_add_finding("http://10.0.0.2", "Fake open port",
                           verification="false-positive")
    rows = report_mod._read_all()
    check("false-positive -> status filtered",
          rows[1]["status"] == "false-positive", rows[1]["status"])

    out = tool_add_finding("http://10.0.0.3", "Header missing",
                           severity="medium")
    rows = report_mod._read_all()
    check("default verification unverified",
          rows[2]["verification"] == "unverified", rows[2]["verification"])


def test_verify_finding_tool(monkeypatch, tmp):
    section("reporting.py - verify_finding / verify_findings tools")
    monkeypatch(report_mod, "FINDINGS_PATH",
                os.path.join(tmp, "findings2.jsonl"))
    monkeypatch(report_mod, "REPORTS_DIR", os.path.join(tmp, "reports2"))

    tool_add_finding("192.0.2.9", "Port 443 open on 192.0.2.9",
                     severity="high", description="port 443 open on 192.0.2.9",
                     verification_status="CONFIRMED_POC",
                     evidence="nmap -sV output: 443/tcp open")
    tool_add_finding("192.0.2.10", "Port 22 open on 192.0.2.10",
                     severity="medium", description="port 22 open on 192.0.2.10")
    rows = report_mod._read_all()
    fid1, fid2 = rows[0]["id"], rows[1]["id"]

    monkeypatch(report_mod, "lightweight_verify_finding",
                lambda finding: {"status": VERIFIED,
                                 "reason": "probe confirmed",
                                 "method": "deterministic"})
    out = tool_verify_finding(fid1)
    check("verify_finding verified", "re-verified" in out.lower()
          and "VERIFIED TRUE POSITIVE" in out, out)
    rows = report_mod._read_all()
    r1 = next(r for r in rows if r["id"] == fid1)
    check("verify tool sets verification", r1["verification"] == "verified")
    check("verify tool sets status confirmed", r1["status"] == "confirmed",
          r1["status"])

    monkeypatch(report_mod, "lightweight_verify_finding",
                lambda finding: {"status": REJECTED,
                                 "reason": "probe refused",
                                 "method": "deterministic"})
    out = tool_verify_finding(fid2)
    rows = report_mod._read_all()
    r2 = next(r for r in rows if r["id"] == fid2)
    check("verify tool rejected -> filtered",
          r2["verification"] == "false-positive"
          and r2["status"] == "false-positive", out)

    out = tool_verify_finding("F-NOTREAL")
    check("verify_finding unknown id", "not found" in out.lower(), out)

    tool_add_finding("10.9.9.9", "Port 3306 open on 10.9.9.9", severity="low",
                     description="port 3306 open on 10.9.9.9")
    monkeypatch(report_mod, "lightweight_verify_finding",
                lambda finding: {"status": VERIFIED,
                                 "reason": "probe confirmed",
                                 "method": "deterministic"})
    out = tool_verify_all_findings(only_unverified=True)
    check("verify_all ran", "verified" in out.lower(), out)
    rows = report_mod._read_all()
    r3 = next(r for r in rows if r["id"] != fid1 and r["id"] != fid2)
    check("verify_all touched unverified only",
          r3["verification"] == "verified" and r1["verification"] == "verified"
          and r2["verification"] == "false-positive", out)


def test_write_report(monkeypatch, tmp):
    section("reporting.py - report FP filtering + tags")
    monkeypatch(report_mod, "FINDINGS_PATH",
                os.path.join(tmp, "findings3.jsonl"))
    monkeypatch(report_mod, "REPORTS_DIR", os.path.join(tmp, "reports3"))

    tool_add_finding("192.0.2.20", "Real SQL injection", severity="critical",
                     description="SQLi in login form",
                     verification="verified",
                     verification_reason="confirm")
    tool_add_finding("192.0.2.21", "Fake CVE", severity="critical",
                     description="CVE-2024-9999", verification="false-positive",
                     verification_reason="not in NVD")
    tool_add_finding("192.0.2.22", "Possible header issue", severity="medium",
                     description="HSTS missing")

    out_path = os.path.join(tmp, "reports3", "test.md")
    out = tool_write_report(target="10.0.0.1", output_path=out_path)
    check("write_report saved", "Report saved" in out, out)
    with open(out_path, encoding="utf-8") as f:
        report = f.read()

    check("report totals exclude FP", "**1** finding(s)" in report
          or "**2** finding(s)" in report, "")
    check("verified tag in summary table",
          "[VERIFIED TRUE POSITIVE]" in report)
    check("unverified tag in summary table",
          "[UNVERIFIED / REQUIRES MANUAL AUDIT]" in report)
    check("exec summary verified count",
          "verified as true positives" in report)
    check("FP appendix section",
          "Filtered False Positives" in report)
    check("FP reason in appendix", "not in NVD" in report)

    out = tool_write_report(target="x", output_path=os.path.join(
        tmp, "reports3", "all_fp.md"), include_open_only=True)
    check("report all verified kept", "Report saved" in out, out)

    tool_add_finding("192.0.2.30", "Only FP", severity="high",
                     description="port 1 open on 192.0.2.30",
                     verification="false-positive")
    out = tool_write_report(target="x", output_path=os.path.join(
        tmp, "reports3", "empty.md"))
    check("report with only FPs handled",
          "Report saved" in out, out)


# ---------------------------------------------------------------- Part 3
import ai_agent.core as core_mod
from ai_agent.core import Agent, _find_finding_pos
from ai_agent.llm import MockClient


def test_find_finding_pos():
    section("core.py - _find_finding_pos")

    pos = _find_finding_pos("found port 80 open on 10.0.0.1 now",
                            "port 80 open on 10.0.0.1")
    check("exact match found", pos == 6, pos)

    pos = _find_finding_pos("found port 80 open on\n10.0.0.1 now",
                            "port 80 open on 10.0.0.1")
    check("whitespace-tolerant match", pos != -1, pos)

    pos = _find_finding_pos("completely different text",
                            "port 80 open on 10.0.0.1")
    check("no match -> -1", pos == -1, pos)

    pos = _find_finding_pos("", "needle")
    check("empty haystack -> -1", pos == -1, pos)


def test_extract_findings():
    section("core.py - _extract_findings")

    agent = Agent(llm=MockClient(), auto_verify=False)
    text = ("Port scan found port 80 open on 192.0.2.1 and port 443 open. "
            "Subdomain admin.api.example.com was discovered via enumeration. "
            "Apache 2.4.1 is vulnerable to CVE-2024-1234. "
            "SQL injection risk in the login form at http://192.0.2.1/login")
    found = agent._extract_findings(text)
    values = [f["value"] for f in found]
    check("extracted >= 4 findings", len(found) >= 4, str(found))
    check("port 80 with host", any("80" in v and "192.0.2.1" in v
                                   for v in values), str(values))
    check("cve extracted", any("CVE-2024-1234" in v for v in values),
          str(values))
    check("subdomain extracted",
          any("admin.api.example.com" in v for v in values), str(values))
    check("vuln extracted", any("sql injection" in v for v in values),
          str(values))


def test_apply_tags():
    section("core.py - _apply_verification_tags")

    agent = Agent(llm=MockClient(), auto_verify=False)
    agent._verification_results = [
        {"type": "open_port", "value": "port 80 open on 192.0.2.1",
         "status": VERIFIED, "reason": "probe ok", "method": "deterministic"},
        {"type": "cve", "value": "CVE-2024-9999 affects Apache",
         "status": REJECTED, "reason": "not in NVD", "method": "deterministic"},
        {"type": "vuln", "value": "SQLi at http://10.0.0.1/q",
         "status": UNVERIFIED, "reason": "manual audit",
         "method": "sub-agent"},
    ]
    content = ("Assessment: port 80 open on 192.0.2.1 is exposed. "
               "SQLi at http://10.0.0.1/q needs review.")
    out = agent._apply_verification_tags(content)

    check("verified tag inline",
          "[VERIFIED TRUE POSITIVE]" in out)
    check("unverified tag inline",
          "[UNVERIFIED / REQUIRES MANUAL AUDIT]" in out)
    check("verification report block", "## Verification Report" in out)
    check("report table header", "| Finding | Status | Method | Reason |" in out)
    check("filtered FP listed", "Filtered false positives" in out
          and "CVE-2024-9999" in out)
    check("original content kept", "Assessment:" in out)


def test_parse_validator_output():
    section("core.py - _parse_validator_output")

    agent = Agent(llm=MockClient(), auto_verify=False)
    verdicts = agent._parse_validator_output(
        "FINDING VERDICTS:\n"
        "- VERIFIED: port 80 open on 192.0.2.1\n"
        "- FALSE_POSITIVE: fake cve\n"
        "- UNVERIFIED: odd claim\n"
        "VERDICT: VERIFIED\nREASON: evidence confirms")
    check("per-finding verdicts parsed", len(verdicts) == 3, str(verdicts))
    check("verified status mapped",
          any(v["status"] == "verified" for v in verdicts))
    check("false positive mapped",
          any(v["status"] == "rejected" for v in verdicts))

    verdicts = agent._parse_validator_output(
        "VERDICT: FALSE_POSITIVE\nREASON: nothing matches")
    check("overall verdict fallback",
          verdicts and verdicts[0]["status"] == "rejected"
          and verdicts[0]["finding"] == "(overall)", str(verdicts))


def test_verify_findings_severity_trigger(monkeypatch, tmp):
    section("core.py - severity trigger spawns independent validator")

    monkeypatch(verify_mod, "_probe_port",
                lambda host, port, timeout=3.0: (True, "open"))
    monkeypatch(core_mod, "execute_tool",
                lambda name, args, **kw: (
                    "port_scan: no open ports found on 192.0.2.1"))

    agent = Agent(llm=MockClient(), auto_verify=False)
    text = ("High-severity auth bypass in the login flow. "
            "Port scan: port 80 open on 192.0.2.1.")
    events = list(agent._verify_findings(text))
    types = [e.get("type") for e in events]
    check("deterministic phase ran", "validation" in types, str(types))
    spawns = [e for e in events if e.get("type") == "validation_spawned"]
    check("validator spawned on high severity", len(spawns) == 1,
          str(spawns))
    if spawns:
        check("spawn reason cites severity",
              "severity" in spawns[0].get("reason", "").lower(),
              spawns[0].get("reason", ""))
    check("sub-agent tool events flowed", "validation_tool_call" in types,
          str(types))
    by_value = {r["value"].lower(): r for r in agent._verification_results}
    port = by_value.get("port 80 open on 192.0.2.1") or {}
    check("severity-flagged finding re-checked by sub-agent",
          port.get("method") == "sub-agent", str(port))
    check("sub-agent verdict overrides deterministic",
          port.get("status") == REJECTED, str(port))


def test_verify_findings_complex_bug_trigger(monkeypatch, tmp):
    section("core.py - complex-bug trigger spawns validator")

    monkeypatch(verify_mod, "_probe_port",
                lambda host, port, timeout=3.0: (True, "open"))

    agent = Agent(llm=MockClient(), auto_verify=False)
    text = ("The code audit found a race condition in the payment module. "
            "Port 80 open on 192.0.2.1.")
    events = list(agent._verify_findings(text))
    types = [e.get("type") for e in events]
    spawns = [e for e in events if e.get("type") == "validation_spawned"]
    check("validator spawned on complex bug", len(spawns) == 1, str(spawns))
    if spawns:
        check("spawn reason cites complex bug",
              "complex bug" in spawns[0].get("reason", "").lower(),
              spawns[0].get("reason", ""))
    by_value = {r["value"].lower(): r for r in agent._verification_results}
    bug = by_value.get("race condition") or {}
    check("bug finding validated by sub-agent",
          bug.get("method") == "sub-agent", str(bug))
    check("bug finding kept in results", bug.get("type") == "bug",
          str(bug))


def test_verify_findings_subagent_override_fp(monkeypatch, tmp):
    section("core.py - false-positive rejection net (validator override)")

    monkeypatch(verify_mod, "_probe_port",
                lambda host, port, timeout=3.0: (True, "open"))
    monkeypatch(core_mod, "execute_tool",
                lambda name, args, **kw: (
                    "port_scan: no open ports found on 192.0.2.1"))

    agent = Agent(llm=MockClient(), auto_verify=False)
    text = ("Critical RCE at http://192.0.2.1/login. "
            "Port 80 open on 192.0.2.1.")
    events = list(agent._verify_findings(text))
    done = next(e for e in events if e.get("type") == "validation_done")
    check("rejected counted in summary", done.get("rejected") >= 1,
          str(done))
    by_value = {r["value"].lower(): r for r in agent._verification_results}
    port = by_value.get("port 80 open on 192.0.2.1") or {}
    check("deterministic-verified finding rejected by validator",
          port.get("status") == REJECTED, str(port))
    rce = by_value.get("rce") or {}
    check("unresolved finding re-verified by sub-agent",
          rce.get("method") == "sub-agent" and rce.get("status") == REJECTED,
          str(rce))
    methods = {r.get("method") for r in agent._verification_results}
    check("all findings via sub-agent", methods == {"sub-agent"},
          str(methods))


def test_run_stream_critical_spawn_validation(monkeypatch, tmp):
    section("core.py - run_stream automated validation loop")

    monkeypatch(verify_mod, "_probe_port",
                lambda host, port, timeout=3.0: (True, "open"))
    monkeypatch(core_mod, "execute_tool",
                lambda name, args, **kw: (
                    "High-severity auth bypass in login. "
                    "Port 80 open on 192.0.2.1."))

    agent = Agent(llm=MockClient(), auto_verify=True)
    events = list(agent.run_stream(
        "port scan 192.0.2.1 and report"))
    types = [e.get("type") for e in events]
    check("validation_spawned emitted in run_stream",
          "validation_spawned" in types, str(types))
    spawns = [e for e in events if e.get("type") == "validation_spawned"]
    if spawns:
        check("spawn reason cites severity",
              "severity" in spawns[0].get("reason", "").lower(),
              spawns[0].get("reason", ""))
    finals = [e for e in events if e.get("type") == "final"]
    check("final answer emitted", len(finals) == 1, str(finals))
    if finals:
        content = finals[0]["content"]
        check("verification summary appended to final",
              "VERIFICATION" in content, content[:300])
        check("verification report present",
              "Verification Report" in content, content[:300])


def test_verify_findings_deterministic_only(monkeypatch, tmp):
    section("core.py - _verify_findings phase 1 (deterministic only)")

    monkeypatch(verify_mod, "_probe_port",
                lambda host, port, timeout=3.0: (True, "open"))
    monkeypatch(verify_mod, "tool_cve_lookup",
                lambda query, max_results=5: "no CVEs found for 'CVE-2024-9999'")

    agent = Agent(llm=MockClient(), auto_verify=False)
    text = ("Port scan: port 80 open on 192.0.2.1. "
            "CVE-2024-9999 was mentioned in the banners.")
    events = list(agent._verify_findings(text))
    types = [e.get("type") for e in events]
    check("validation_start fired", "validation_start" in types, str(types))
    check("validation events fired", "validation" in types, str(types))
    check("validation_done fired", "validation_done" in types, str(types))
    check("no sub-agent phase", "validation_tool_call" not in types,
          str(types))
    done = next(e for e in events if e.get("type") == "validation_done")
    check("summary counts present", done.get("count") == 2
          and done.get("verified") >= 1 and done.get("rejected") >= 1,
          str(done))
    check("verification_results persisted",
          len(agent._verification_results) == 2, str(
              agent._verification_results))
    by_value = {r["value"].lower(): r for r in agent._verification_results}
    check("port verdict stored verified",
          by_value["port 80 open on 192.0.2.1"]["status"] == VERIFIED)
    check("cve verdict stored rejected",
          by_value["cve-2024-9999"]["status"] == REJECTED)
    check("all methods deterministic",
          all(r["method"] == "deterministic"
              for r in agent._verification_results))


def test_verify_findings_with_subagent(monkeypatch, tmp):
    section("core.py - _verify_findings phase 2 (validation sub-agent)")

    monkeypatch(verify_mod, "_probe_port",
                lambda host, port, timeout=3.0: (True, "open"))
    monkeypatch(verify_mod, "tool_cve_lookup",
                lambda query, max_results=5: (_ for _ in ()).throw(
                    RuntimeError("offline")))
    monkeypatch(core_mod, "execute_tool",
                lambda name, args, **kw: (
                    "cve_lookup: no CVEs found for 'CVE-2024-1234' - "
                    "not found in NVD"))

    agent = Agent(llm=MockClient(), auto_verify=False)
    text = ("Port scan: port 80 open on 192.0.2.1. "
            "Apache 2.4.1 vulnerable to CVE-2024-1234.")
    events = list(agent._verify_findings(text))
    types = [e.get("type") for e in events]
    check("sub-agent phase ran", "validation_start" in types
          and "validation_done" in types, str(types))
    methods = [e.get("method") for e in events if e.get("type") == "validation"]
    check("both methods used", "deterministic" in methods
          and "sub-agent" in methods, str(methods))
    done = next(e for e in events if e.get("type") == "validation_done")
    check("rejected counted", done.get("rejected") >= 1, str(done))
    by_value = {r["value"].lower(): r for r in agent._verification_results}
    check("cve verdict from sub-agent",
          by_value["cve-2024-1234"]["method"] == "sub-agent",
          str(by_value))


def test_run_stream_tags_final(monkeypatch, tmp):
    section("core.py - run_stream auto_verify + final tagging")

    monkeypatch(verify_mod, "_probe_port",
                lambda host, port, timeout=3.0: (True, "open"))
    monkeypatch(verify_mod, "tool_http_request",
                lambda url, method="GET", max_body=1500: (_ for _ in ()).throw(
                    RuntimeError("offline")))
    monkeypatch(core_mod, "execute_tool",
                lambda name, args, **kw: "port 80 open on 192.0.2.1")

    agent = Agent(llm=MockClient(), auto_verify=True)
    events = list(agent.run_stream(
        "port scan 192.0.2.1 and report"))
    finals = [e for e in events if e.get("type") == "final"]
    check("final answer emitted", len(finals) == 1, str(finals))
    if finals:
        content = finals[0]["content"]
        check("verification report appended to final",
              "Verification Report" in content
              or "VERIFICATION" in content, content[:200])
    check("no run_stream crash", True)


# ------------------------------------------------------------------ runner
def run_all():
    tests = [
        test_verify_module, test_payload_verify_plan,
        test_verify_open_port, test_verify_subdomain,
        test_verify_cve, test_verify_vuln, test_verify_dispatch,
        test_reporting, test_verify_finding_tool, test_write_report,
        test_find_finding_pos, test_extract_findings, test_apply_tags,
        test_parse_validator_output, test_verify_findings_severity_trigger,
        test_verify_findings_complex_bug_trigger,
        test_verify_findings_subagent_override_fp,
        test_run_stream_critical_spawn_validation,
        test_verify_findings_deterministic_only,
        test_verify_findings_with_subagent, test_run_stream_tags_final,
    ]

    def monkeypatch(mod, name, replacement):
        setattr(mod, name, replacement)

    tmp = tempfile.mkdtemp(prefix="verify_arch_test_")
    for t in tests:
        try:
            t(monkeypatch, tmp) if t in (
                test_verify_open_port, test_verify_subdomain,
                test_verify_cve, test_verify_vuln, test_verify_dispatch,
                test_reporting, test_verify_finding_tool, test_write_report,
                test_verify_findings_severity_trigger,
                test_verify_findings_complex_bug_trigger,
                test_verify_findings_subagent_override_fp,
                test_run_stream_critical_spawn_validation,
                test_verify_findings_deterministic_only,
                test_verify_findings_with_subagent,
                test_run_stream_tags_final,
            ) else t()
        except Exception as exc:
            check("%s exception" % t.__name__, False,
                  "%s: %s" % (type(exc).__name__, exc))
    print("\n%d passed, %d failed" % (PASS, FAIL))
    return FAIL == 0


if __name__ == "__main__":
    sys.exit(0 if run_all() else 1)
