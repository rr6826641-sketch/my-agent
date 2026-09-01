"""Findings tracker + professional pentest report generator.

The agent logs each confirmed/validated vulnerability as a structured
finding (JSONL on disk), then writes a complete Markdown penetration
test report from those findings - the same reporting workflow used in
professional engagements.

Authorized use only - targets must be in your engagement scope.
"""

import datetime
import json
import os
import threading
import uuid

from .verify import (
    REJECTED as V_REJECTED,
    UNVERIFIED as V_UNVERIFIED,
    VERIFIED as V_VERIFIED,
    lightweight_verify_finding,
)


def _coerce_findings(value):
    """Accept a JSON string or python list and return (list, error_or_None)."""
    if isinstance(value, (list, tuple)):
        return [f for f in value if isinstance(f, dict)], None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return [], "empty findings payload"
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            return [], f"invalid JSON: {exc}"
        if isinstance(data, dict) and isinstance(data.get("findings"), list):
            data = data["findings"]
        if not isinstance(data, list):
            return [], "JSON payload must be a list of finding objects"
        return [f for f in data if isinstance(f, dict)], None
    return [], f"unsupported payload type {type(value).__name__}"

FINDINGS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "findings.jsonl",
)
REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "reports",
)

_lock = threading.Lock()

SEVERITIES = ["critical", "high", "medium", "low", "info"]
STATUSES = ["open", "confirmed", "validated", "false-positive", "fixed", "needs-validation", "hypothesis"]
VERIFICATION_STATUSES = ["verified", "unverified", "false-positive"]

CVSS_FALLBACK = {
    "critical": 9.8, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0,
}


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _read_all():
    out = []
    try:
        with open(FINDINGS_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except FileNotFoundError:
        pass
    return out


def _write_all(rows):
    os.makedirs(os.path.dirname(FINDINGS_PATH) or ".", exist_ok=True)
    with open(FINDINGS_PATH, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _clean_text(v, limit=2000):
    v = "" if v is None else str(v)
    return v.strip()[:limit]


def _verification_label(verification):
    """Display tag for a finding's verification state."""
    v = (verification or "").lower()
    if v == V_VERIFIED:
        return "[VERIFIED TRUE POSITIVE]"
    if v == "false-positive":
        return "[FALSE POSITIVE - FILTERED]"
    return "[UNVERIFIED / REQUIRES MANUAL AUDIT]"


def tool_add_finding(asset="", title="", severity="medium", cwe="",
                     description="", evidence="", impact="", remediation="",
                     confidence="medium", status="open",
                     verification="", verification_reason=""):
    """Log a vulnerability finding for the current engagement.

    asset       - affected URL/host/endpoint (required)
    title       - short finding title (required)
    severity    - critical | high | medium | low | info
    cwe         - CWE identifier, e.g. 'CWE-89' (optional)
    confidence  - low | medium | high | confirmed
    status      - open | confirmed | needs-validation | hypothesis |
                  false-positive | fixed
    """
    asset = _clean_text(asset)
    title = _clean_text(title, 300)
    if not asset or not title:
        return ("add_finding: both 'asset' and 'title' are required "
                "(e.g. asset='https://app.example.com/login' "
                "title='SQL injection in user parameter')")
    severity = (severity or "medium").strip().lower()
    if severity not in SEVERITIES:
        return "add_finding: severity must be one of %s" % SEVERITIES
    confidence = (confidence or "medium").strip().lower()
    status = (status or "open").strip().lower()
    if status not in STATUSES:
        return "add_finding: status must be one of %s" % STATUSES
    verification = (verification or "").strip().lower()
    if verification and verification not in VERIFICATION_STATUSES:
        return ("add_finding: verification must be one of %s"
                % VERIFICATION_STATUSES)
    # Keep the finding's status consistent with its verification state:
    # verified -> confirmed, false-positive -> filtered, unverified -> audit.
    if verification == V_VERIFIED and status in ("open", "needs-validation",
                                                 "hypothesis"):
        status = "confirmed"
    elif verification == "false-positive":
        status = "false-positive"
    elif verification == V_UNVERIFIED and status == "open":
        status = "needs-validation"

    fid = "F-" + uuid.uuid4().hex[:8].upper()
    finding = {
        "id": fid,
        "ts": _now(),
        "asset": asset,
        "title": title,
        "severity": severity,
        "cwe": _clean_text(cwe, 100),
        "description": _clean_text(description),
        "evidence": _clean_text(evidence),
        "impact": _clean_text(impact),
        "remediation": _clean_text(remediation),
        "confidence": confidence,
        "status": status,
        "verification": verification or V_UNVERIFIED,
        "verification_reason": _clean_text(verification_reason, 500),
    }
    with _lock:
        rows = _read_all()
        rows.append(finding)
        _write_all(rows)
    return ("Finding logged: %s | %s | %s | %s\n"
            "Run 'write_report' at the end to generate the full pentest report."
            % (fid, severity.upper(), title, asset))


def tool_list_findings(severity="", status="", sort_by="severity"):
    """List all logged findings. Optional filters: severity, status.
    sort_by: severity | asset | ts"""
    rows = _read_all()
    if severity:
        sevs = [s.strip().lower() for s in severity.split(",") if s.strip()]
        rows = [r for r in rows if r.get("severity") in sevs]
    if status:
        sts = [s.strip().lower() for s in status.split(",") if s.strip()]
        rows = [r for r in rows if r.get("status") in sts]
    if not rows:
        return ("(no findings logged - use add_finding to record "
                "confirmed vulnerabilities)")
    order = {s: i for i, s in enumerate(SEVERITIES)}
    if sort_by == "asset":
        rows.sort(key=lambda r: r.get("asset", ""))
    elif sort_by == "ts":
        rows.sort(key=lambda r: r.get("ts", ""))
    else:
        rows.sort(key=lambda r: order.get(r.get("severity"), 99))
    lines = ["Findings (%d):" % len(rows)]
    for r in rows:
        lines.append("- [%s] [%s] %s %s | %s | %s"
                     % (r.get("status", "?"),
                        (r.get("severity") or "?").upper(),
                        _verification_label(r.get("verification")),
                        r.get("id"), r.get("title"), r.get("asset")))
    return "\n".join(lines)


def tool_update_finding(finding_id="", severity="", status="", title="",
                        remediation="", confidence="",
                        verification="", verification_reason=""):
    """Update a logged finding by id (F-XXXXXXXX)."""
    finding_id = (finding_id or "").strip().upper()
    if not finding_id:
        return "update_finding: finding_id is required (e.g. F-1A2B3C4D)"
    with _lock:
        rows = _read_all()
        target = next((r for r in rows
                       if r.get("id", "").upper() == finding_id), None)
        if target is None:
            return "update_finding: finding '%s' not found" % finding_id
        if severity:
            sev = severity.strip().lower()
            if sev not in SEVERITIES:
                return "update_finding: severity must be one of %s" % SEVERITIES
            target["severity"] = sev
        if status:
            st = status.strip().lower()
            if st not in STATUSES:
                return "update_finding: status must be one of %s" % STATUSES
            target["status"] = st
        if title:
            target["title"] = _clean_text(title, 300)
        if remediation:
            target["remediation"] = _clean_text(remediation)
        if confidence:
            target["confidence"] = _clean_text(confidence, 50)
        if verification:
            v = verification.strip().lower()
            if v not in VERIFICATION_STATUSES:
                return ("update_finding: verification must be one of %s"
                        % VERIFICATION_STATUSES)
            target["verification"] = v
            if v == V_VERIFIED and target.get("status") in (
                    "open", "needs-validation", "hypothesis"):
                target["status"] = "confirmed"
            elif v == "false-positive":
                target["status"] = "false-positive"
            elif v == V_UNVERIFIED and target.get("status") == "open":
                target["status"] = "needs-validation"
        if verification_reason:
            target["verification_reason"] = _clean_text(
                verification_reason, 500)
        target["ts"] = _now()
        _write_all(rows)
    return "Finding %s updated." % finding_id


def tool_delete_finding(finding_id=""):
    """Delete a finding by id."""
    finding_id = (finding_id or "").strip().upper()
    if not finding_id:
        return "delete_finding: finding_id is required"
    with _lock:
        rows = _read_all()
        before = len(rows)
        rows = [r for r in rows if r.get("id", "").upper() != finding_id]
        if len(rows) == before:
            return "delete_finding: finding '%s' not found" % finding_id
        _write_all(rows)
    return "Finding %s deleted." % finding_id


def tool_verify_finding(finding_id="", method="auto"):
    """Deterministically re-verify one logged finding (benign checks only).

    Runs lightweight_verify_finding against the finding's claim (title +
    description + asset) and updates its verification state + status:
      verified   -> status 'confirmed'        [VERIFIED TRUE POSITIVE]
      rejected   -> status 'false-positive'   [FALSE POSITIVE - FILTERED]
      unverified -> status 'needs-validation' [UNVERIFIED / REQUIRES MANUAL AUDIT]
    """
    finding_id = (finding_id or "").strip().upper()
    if not finding_id:
        return "verify_finding: finding_id is required (e.g. F-1A2B3C4D)"
    with _lock:
        rows = _read_all()
        target = next((r for r in rows
                       if r.get("id", "").upper() == finding_id), None)
        if target is None:
            return "verify_finding: finding '%s' not found" % finding_id
        claim = "%s %s %s" % (target.get("title", ""),
                               target.get("description", ""),
                               target.get("asset", ""))
        verdict = lightweight_verify_finding({"value": claim.strip()})
        status = verdict.get("status")
        reason = (verdict.get("reason") or "").strip()
        evidence = verdict.get("evidence") or ""
        if status == V_VERIFIED:
            target["verification"] = V_VERIFIED
            target["status"] = "confirmed"
            target["confidence"] = "confirmed"
        elif status == V_REJECTED:
            target["verification"] = "false-positive"
            target["status"] = "false-positive"
        else:
            target["verification"] = V_UNVERIFIED
            if target.get("status") not in ("validated", "fixed"):
                target["status"] = "needs-validation"
        target["verification_reason"] = reason
        target["verification_method"] = verdict.get(
            "method", "deterministic")
        target["ts"] = _now()
        _write_all(rows)
    label = _verification_label(target["verification"])
    return ("Finding %s re-verified: %s\n"
            "Verification: %s %s\n"
            "Status: %s\n%s"
            % (finding_id, target.get("title", "?"), label, reason,
               target.get("status"), evidence[:400]))


def tool_verify_all_findings(only_unverified=True):
    """Re-verify every logged finding with benign deterministic checks.

    only_unverified - only touch findings not already marked verified.
    False positives found here are filtered from reports automatically.
    """
    with _lock:
        rows = _read_all()
        if not rows:
            return "verify_findings: no findings logged yet"
        todo = [r for r in rows
                if not only_unverified
                or (r.get("verification") or V_UNVERIFIED) != V_VERIFIED]
    if not todo:
        return "verify_findings: nothing to verify (all findings verified)"
    results = []
    for r in todo:
        claim = "%s %s %s" % (r.get("title", ""),
                               r.get("description", ""),
                               r.get("asset", ""))
        try:
            verdict = lightweight_verify_finding({"value": claim.strip()})
        except Exception as exc:
            verdict = {"status": V_UNVERIFIED,
                       "reason": "verification error: %s" % exc}
        results.append((r.get("id"), r.get("title"), verdict))
    with _lock:
        rows = _read_all()
        by_id = {r["id"]: r for r in rows if r.get("id")}
        done = []
        for fid, title, verdict in results:
            cur = by_id.get(fid)
            if cur is None:
                continue
            status = verdict.get("status")
            reason = (verdict.get("reason") or "").strip()
            if status == V_VERIFIED:
                cur["verification"] = V_VERIFIED
                cur["status"] = "confirmed"
                cur["confidence"] = "confirmed"
            elif status == V_REJECTED:
                cur["verification"] = "false-positive"
                cur["status"] = "false-positive"
            else:
                cur["verification"] = V_UNVERIFIED
                if cur.get("status") not in ("validated", "fixed"):
                    cur["status"] = "needs-validation"
            cur["verification_reason"] = reason
            cur["verification_method"] = verdict.get(
                "method", "deterministic")
            cur["ts"] = _now()
            done.append((fid, title, _verification_label(
                cur["verification"]), reason))
        _write_all(rows)
    if not done:
        return "verify_findings: no findings could be re-verified"
    verified_n = sum(1 for d in done if d[2] == _verification_label(V_VERIFIED))
    fp_n = sum(1 for d in done if d[2] == _verification_label("false-positive"))
    lines = ["Verified %d finding(s): %d confirmed, %d filtered as false "
             "positives, %d unverified." % (
                 len(done), verified_n, fp_n, len(done) - verified_n - fp_n)]
    for fid, title, label, reason in done:
        lines.append("- %s %s | %s - %s" % (label, fid, title, reason))
    return "\n".join(lines)


def tool_write_report(target="", author="HackerAI Agent",
                      output_path="", include_open_only=False,
                      include_remediation=True):
    """Generate a complete Markdown penetration test report from the
    logged findings. Returns the saved file path.

    target              - assessed asset / engagement name
    output_path         - optional file path (default: reports/pentest_<ts>.md)
    include_open_only   - only include findings with status open/confirmed/
                          validated/needs-validation/hypothesis
    include_remediation - include remediation sections in the report
    """
    target = _clean_text(target, 300) or "Untitled Engagement"
    author = _clean_text(author, 100) or "HackerAI Agent"
    rows = _read_all()
    if not rows:
        return ("write_report: no findings logged yet - use add_finding "
                "to record vulnerabilities first")

    # Autonomous verification filtering: findings marked as false positives
    # (by status or verification) are excluded from the assessment and listed
    # in the appendix instead of the finding totals.
    filtered = [r for r in rows
                if r.get("status") == "false-positive"
                or r.get("verification") == "false-positive"]
    rows = [r for r in rows if r not in filtered]
    if include_open_only:
        keep = {"open", "confirmed", "validated",
                "needs-validation", "hypothesis"}
        rows = [r for r in rows if r.get("status") in keep]

    if not rows:
        if filtered:
            return ("write_report: all findings were filtered as false "
                    "positives (%d) - nothing to report" % len(filtered))
        return "write_report: no findings match the requested filter"

    sev_order = {s: i for i, s in enumerate(SEVERITIES)}
    rows.sort(key=lambda r: sev_order.get(r.get("severity"), 99))

    counts = {s: 0 for s in SEVERITIES}
    for r in rows:
        counts[r.get("severity", "info")] = counts.get(r.get("severity", "info"), 0) + 1

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    L = []
    L.append("# Penetration Test Report")
    L.append("")
    L.append("**Target:** %s  " % target)
    L.append("**Date:** %s  " % now)
    L.append("**Author:** %s  " % author)
    L.append("")
    L.append("---")
    L.append("")
    L.append("## 1. Executive Summary")
    L.append("")
    L.append("This report documents the security assessment of **%s**. " % target)
    L.append("A total of **%d** finding(s) were identified." % len(rows))
    L.append("")
    L.append("| Severity | Count |")
    L.append("|----------|-------|")
    for s in SEVERITIES:
        L.append("| %s | %d |" % (s.capitalize(), counts[s]))
    L.append("")
    if counts.get("critical") or counts.get("high"):
        L.append("> **Critical/High severity issues require immediate attention.**")
        L.append("")
    verified_n = sum(1 for r in rows
                     if (r.get("verification") or "") == V_VERIFIED)
    unverified_n = len(rows) - verified_n
    L.append("**%d** finding(s) verified as true positives "
             "([VERIFIED TRUE POSITIVE]); **%d** unverified "
             "([UNVERIFIED / REQUIRES MANUAL AUDIT] - manual audit "
             "recommended)." % (verified_n, unverified_n))
    if filtered:
        L.append("**%d** false positive(s) automatically filtered "
                 "([FALSE POSITIVE - FILTERED] - see Section 5)."
                 % len(filtered))
    L.append("")
    L.append("## 2. Scope")
    L.append("")
    L.append("- **Engagement target:** %s" % target)
    L.append("- **Assessment type:** Penetration test / vulnerability assessment")
    L.append("")
    L.append("## 3. Findings Summary")
    L.append("")
    L.append("| ID | Severity | Title | Asset | Status | Verification |")
    L.append("|----|----------|-------|-------|--------|--------------|")
    for r in rows:
        L.append("| %s | %s | %s | %s | %s | %s |"
                 % (r.get("id"), (r.get("severity") or "?").capitalize(),
                    (r.get("title") or "?")[:80],
                    (r.get("asset") or "?")[:60],
                    r.get("status", "?"),
                    _verification_label(r.get("verification"))))
    L.append("")
    L.append("## 4. Detailed Findings")
    L.append("")
    for i, r in enumerate(rows, 1):
        sev = (r.get("severity") or "info").capitalize()
        L.append("### 4.%d %s - %s" % (i, sev, r.get("title")))
        L.append("")
        L.append("| Field | Value |")
        L.append("|-------|-------|")
        L.append("| Finding ID | %s |" % r.get("id"))
        L.append("| Severity | %s |" % sev)
        L.append("| Asset | `%s` |" % r.get("asset"))
        L.append("| CWE | %s |" % (r.get("cwe") or "N/A"))
        L.append("| Status | %s |" % r.get("status"))
        L.append("| Verification | %s |"
                 % _verification_label(r.get("verification")))
        L.append("| Confidence | %s |" % r.get("confidence"))
        L.append("")
        if r.get("description"):
            L.append("**Description:**")
            L.append("")
            L.append(r["description"])
            L.append("")
        if r.get("evidence"):
            L.append("**Evidence:**")
            L.append("")
            L.append("```")
            L.append(r["evidence"])
            L.append("```")
            L.append("")
        if r.get("impact"):
            L.append("**Impact:**")
            L.append("")
            L.append(r["impact"])
            L.append("")
        if r.get("verification_reason"):
            L.append("**Verification note:** %s"
                     % r["verification_reason"])
            L.append("")
        if include_remediation and r.get("remediation"):
            L.append("**Remediation:**")
            L.append("")
            L.append(r["remediation"])
            L.append("")
        L.append("---")
        L.append("")
    if filtered:
        L.append("## 5. Filtered False Positives (excluded from assessment)")
        L.append("")
        L.append("These findings were automatically filtered or downgraded "
                 "because the autonomous verification routine could not "
                 "confirm them. They do **not** count toward the finding "
                 "totals above.")
        L.append("")
        L.append("| ID | Title | Asset | Verification Reason |")
        L.append("|----|-------|-------|---------------------|")
        for r in filtered:
            L.append("| %s | %s | %s | %s |"
                     % (r.get("id"), (r.get("title") or "?")[:80],
                        (r.get("asset") or "?")[:60],
                        (r.get("verification_reason")
                         or "marked as false positive")[:120]))
        L.append("")
    L.append("## 6. Methodology")
    L.append("")
    L.append("1. **Reconnaissance** - subdomain enumeration, port scanning, service fingerprinting")
    L.append("2. **Enumeration** - web fuzzing, tech detection, HTTP method / header analysis")
    L.append("3. **Vulnerability testing** - SQLi, XSS, SSRF, CMDi, path traversal, auth checks")
    L.append("4. **Exploitation / validation** - payload testing, proof-of-concept confirmation")
    L.append("5. **Reporting** - findings consolidation, severity calibration, remediation")
    L.append("")
    L.append("## 7. Remediation Priorities")
    L.append("")
    for s, advice in [
        ("Critical", "Patch or mitigate immediately; active exploitation is likely."),
        ("High", "Remediate as a top priority in the next release cycle."),
        ("Medium", "Schedule remediation; strengthen defenses where feasible."),
        ("Low", "Address during routine hardening."),
    ]:
        L.append("- **%s:** %s" % (s, advice))
    L.append("")
    L.append("---")
    L.append("")
    L.append("*Report generated by HackerAI Agent on %s*" % now)

    report = "\n".join(L)

    if not output_path:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_target = "".join(c for c in target if c.isalnum() or c in "-_")[:40]
        output_path = os.path.join(REPORTS_DIR,
                                   "pentest_%s_%s.md" % (safe_target or "target", ts))
    output_path = os.path.abspath(os.path.expanduser(output_path))
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
    except OSError as exc:
        return "write_report: could not save report: %s" % exc
    return ("Report saved: %s\n"
            "Findings: %d | Critical: %d | High: %d | Medium: %d | Low: %d"
            % (output_path, len(rows), counts.get("critical", 0),
               counts.get("high", 0), counts.get("medium", 0),
               counts.get("low", 0)))


# ---------------------------------------------------------------------------
# Correlation, CVSS scoring and standalone report generation
# ---------------------------------------------------------------------------

# field aliases used by nmap / nuclei / nikto / http probe outputs
_ALIAS_HOST = ("host", "target", "ip", "ip_address", "address", "asset", "hostname")
_ALIAS_TITLE = ("title", "name", "vuln", "vulnerability", "issue", "id", "plugin_id", "template_id", "message", "banner")
_ALIAS_SEV = ("severity", "risk", "risk_factor", "impact", "level", "cvss_severity")
_ALIAS_PORT = ("port", "port_id", "port_number")
_ALIAS_SERVICE = ("service", "protocol", "service_name", "scheme")
_ALIAS_EVIDENCE = ("evidence", "output", "matched_at", "description", "data", "excerpt", "method")
_ALIAS_CVE = ("cve", "cves", "references", "cwe")
_ALIAS_TOOL = ("scanner", "tool", "source", "engine")
_ALIAS_URL = ("url", "site", "endpoint", "path", "matched_at", "location", "matched")

_SEV_ALIASES = {
    "crit": "critical", "critical": "critical", "c": "critical",
    "high": "high", "h": "high", "important": "high",
    "med": "medium", "medium": "medium", "m": "medium", "moderate": "medium", "warning": "medium",
    "low": "low", "l": "low", "informational": "info", "info": "info", "i": "info", "log": "info", "none": "info",
}

SEV_ORDER = {s: i for i, s in enumerate(["critical", "high", "medium", "low", "info"])}

# unified risk vectors: severity -> (score band, vector template)
RISK_VECTORS = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    "low": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
    "info": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
}


def _fget(f, aliases):
    for key in aliases:
        v = f.get(key)
        if v not in (None, ""):
            return v
    return ""


def _norm_sev(v):
    s = str(v or "").strip().lower()
    for frag, norm in (("criti", "critical"), ("high", "high"),
                       ("med", "medium"), ("low", "low"), ("info", "info")):
        if frag in s:
            return norm
    return "info"


def _norm_host(v):
    s = str(v or "").strip()
    if not s:
        return ""
    if "://" in s:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(s)
            host = parsed.hostname or ""
            if parsed.port:
                host = "%s:%d" % (host, parsed.port)
            if not _fget({}, _ALIAS_PORT) and parsed.port:
                return "%s:%d%s" % (host, parsed.port, parsed.path) if parsed.path not in ("", "/") else host
            return host
        except Exception:
            pass
    return s.split("/")[0] if "/" in s and not s.startswith("/") else s


def _unwrap_nuclei_info(f):
    """Nuclei JSON puts name/severity/description/cve inside a nested 'info'
    object - hoist them to top level so the alias lookup finds them."""
    info = f.get("info")
    if isinstance(info, dict):
        f.setdefault("title", info.get("name") or "")
        f.setdefault("severity", info.get("severity") or "")
        if info.get("description") and not f.get("evidence"):
            f["evidence"] = info["description"]
        refs = info.get("reference") or info.get("references") or info.get("classification", {}).get("cve-id")
        if refs and not f.get("cve"):
            f["cve"] = ", ".join(refs) if isinstance(refs, list) else str(refs)
    elif isinstance(info, str):
        f.setdefault("title", info)
    return f


def _title_from_finding(f):
    f = _unwrap_nuclei_info(f)
    title = str(_fget(f, _ALIAS_TITLE)).strip()
    if not title:
        service = _fget(f, _ALIAS_SERVICE)
        port = _fget(f, _ALIAS_PORT)
        title = "open service %s%s" % (str(service or "tcp"), (" /%s" % port) if port else "")
    return title[:200]


def correlate_findings(findings_list=""):
    """Aggregate raw scanner output, deduplicate and map to unified risk vectors.

    findings_list - JSON string (or list) of finding dicts from Nmap, Nuclei,
                    Nikto, HTTP probes, or any mix of the above. Field names
                    are normalized via aliases.
    Returns a dict (never raises). In addition to the flat deduped
    findings list it now constructs linked attack paths (chains):
      {ok, total_input, unique, duplicates, by_severity, findings,
       risk_matrix, attack_chains, chain_graph}
    attack_chains carries the structured chain dicts from
    build_attack_chains(); chain_graph is the ready-to-embed ASCII/Markdown
    visualization block for reports.
    """
    try:
        items, err = _coerce_findings(findings_list)
        if err:
            return {"ok": False, "error": err}
    except Exception as exc:  # absolute safety net
        return {"ok": False, "error": str(exc)}

    def _norm_title(t):
        return "".join(ch for ch in str(t or "").lower() if ch.isalnum())

    def _same_vuln(t1, t2):
        n1, n2 = _norm_title(t1), _norm_title(t2)
        if not n1 or not n2:
            return False
        return n1 == n2 or (len(n1) >= 5 and n1 in n2) or (len(n2) >= 5 and n2 in n1)

    def _url_path(u):
        s = str(u or "").strip()
        if "://" in s:
            try:
                from urllib.parse import urlparse
                return (urlparse(s).path or "").rstrip("/").lower()
            except Exception:
                return ""
        return (s if s.startswith("/") else "").rstrip("/").lower()

    seen = []
    for f in items:
        raw_url = _fget(f, _ALIAS_URL)
        host = _norm_host(_fget(f, _ALIAS_HOST))
        if not host and raw_url:
            host = _norm_host(raw_url)
        title = _title_from_finding(f)
        sev = _norm_sev(_fget(f, _ALIAS_SEV))
        port = str(_fget(f, _ALIAS_PORT) or "")
        path = _url_path(_fget(f, _ALIAS_URL))
        existing = next((r for r in seen
                         if r["asset"].lower() == host.lower()
                         and _same_vuln(r["title"], title)
                         and (not path or not r.get("path")
                              or path == r["path"])), None)
        if existing is not None:
            src = str(_fget(f, _ALIAS_TOOL) or "unknown")
            if src and src not in existing["corroborated_by"]:
                existing["corroborated_by"].append(src)
            existing["duplicate_count"] += 1
            if SEV_ORDER[sev] < SEV_ORDER[existing["severity"]]:
                existing["severity"] = sev
                existing["risk_vector"] = RISK_VECTORS[sev]
                existing["cvss_base"] = calc_cvss_score(RISK_VECTORS[sev])["base_score"]
            continue
        rec = {
            "asset": host or "unknown",
            "title": title,
            "severity": sev,
            "risk_vector": RISK_VECTORS[sev],
            "cvss_base": calc_cvss_score(RISK_VECTORS[sev])["base_score"],
            "port": port,
            "path": path,
            "service": str(_fget(f, _ALIAS_SERVICE) or ""),
            "url": str(_fget(f, _ALIAS_URL) or ""),
            "cve": _fget(f, _ALIAS_CVE),
            "evidence": str(_fget(f, _ALIAS_EVIDENCE) or "")[:500],
            "scanner": str(_fget(f, _ALIAS_TOOL) or "unknown"),
            "corroborated_by": [],
            "duplicate_count": 0,
        }
        src = rec["scanner"]
        if src and src != "unknown":
            rec["corroborated_by"].append(src)
        seen.append(rec)

    out = sorted(seen, key=lambda r: (SEV_ORDER[r["severity"]], r["asset"]))
    counts = {s: 0 for s in SEVERITIES}
    for r in out:
        counts[r["severity"]] += 1
    dupes = sum(r["duplicate_count"] for r in out)

    # Attack-Chain Graph Correlator: reconstruct linked attack paths from
    # the deduped findings instead of returning only a flat list. Each
    # chain carries chain_id / entry_point / intermediate_pivots /
    # final_impact / composite_risk_score / remediation_choke_point.
    # Deferred import avoids a circular import (attack_chains imports
    # correlate_findings from this module).
    try:
        from .attack_chains import build_attack_chains
        chains_result = build_attack_chains(items)
        chains = chains_result.get("chains", []) if chains_result.get("ok") else []
        chain_graph = ""
        if chains:
            from .attack_chains import render_chain_graph
            chain_graph = render_chain_graph(chains_result)
    except Exception:
        chains = []
        chain_graph = ""

    return {
        "ok": True,
        "total_input": len(items),
        "unique": len(out),
        "duplicates_removed": dupes,
        "by_severity": counts,
        "risk_matrix": {s: counts[s] for s in SEVERITIES},
        "findings": out,
        "attack_chains": chains,
        "chain_graph": chain_graph,
    }


# --- CVSS v3.1 base score (FIRST CVSS v3.1 specification, section 7.1) ---
_CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS_NAMES = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
}
_CVSS_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _parse_cvss_vector(vector):
    metrics = {}
    _optional = {"E": "HFPU", "RL": "OTWU", "RC": "CRU",
                 "CR": "LMH", "IR": "LMH", "AR": "LMH",
                 "MAV": "NALP", "MAC": "LH", "MPR": "NLH", "MUI": "NR",
                 "MS": "UC", "MC": "NLH", "MI": "NLH", "MA": "NLH"}
    for part in str(vector or "").strip().split("/"):
        part = part.strip()
        if not part or part.upper().startswith("CVSS"):
            continue
        if ":" in part:
            k, v = part.split(":", 1)
            k, v = k.strip().upper(), v.strip().upper()
            if k in _CVSS_REQUIRED and v in _CVSS_NAMES.get(k, {}):
                metrics[k] = v
            elif k in _optional and v in _optional[k]:
                metrics[k] = v
    return metrics


def _roundup(x):
    # official CVSS v3.1 spec Appendix A rounding
    int_input = int(round(x * 100000))
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0


def _cvss_severity_label(score):
    if score == 0.0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def calc_cvss_score(vector_string_or_metrics=""):
    """CVSS v3.1 base score from a vector string or a metrics dict.

    vector_string_or_metrics - e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                or {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                                    "S": "U", "C": "H", "I": "H", "A": "H"}
                                or a JSON string of the same dict.
    Returns {ok, base_score, severity, ratings, vector_string, missing_metrics}.
    """
    try:
        raw = vector_string_or_metrics
        if isinstance(raw, str):
            text = raw.strip()
            if not text:
                return {"ok": False, "error": "empty vector string"}
            if text.startswith("{"):
                raw = json.loads(text)
            else:
                raw = _parse_cvss_vector(text)
        if not isinstance(raw, dict):
            return {"ok": False, "error": "metrics must be a dict or vector string"}
        m = {k.strip().upper(): str(v).strip().upper()
             for k, v in raw.items() if v not in (None, "")}
        missing = [k for k in _CVSS_REQUIRED if m.get(k) not in _CVSS_NAMES.get(k, {})]
        if missing:
            return {"ok": False, "error": "missing or invalid metrics",
                    "missing_metrics": missing,
                    "required_format": "CVSS:3.1/AV:L|A|N|P/AC:L|H/PR:L|H|N/UI:N|R/S:U|C/C:L|H|N/I:L|H|N/A:L|H|N"}
        if "CVSS" not in m and "3.1" not in m:
            pass  # base metrics imply v3.1; version prefix is optional

        scope = m["S"]
        av, ac, pr, ui = m["AV"], m["AC"], m["PR"], m["UI"]
        c, i, a = m["C"], m["I"], m["A"]

        iss = 1.0 - (1 - _CVSS_WEIGHTS["CIA"][c]) * (1 - _CVSS_WEIGHTS["CIA"][i]) * (1 - _CVSS_WEIGHTS["CIA"][a])
        impact = (6.42 * iss) if scope == "U" else (7.52 * (iss - 0.029)) - (3.25 * ((iss - 0.02) ** 15))
        expl = 8.22 * _CVSS_WEIGHTS["AV"][av] * _CVSS_WEIGHTS["AC"][ac] * _CVSS_WEIGHTS["PR"][scope][pr] * _CVSS_WEIGHTS["UI"][ui]

        if impact <= 0:
            score = 0.0
        elif scope == "U":
            score = _roundup(min(impact + expl, 10.0))
        else:
            score = _roundup(min(1.08 * (impact + expl), 10.0))

        vector = "CVSS:3.1/" + "/".join("%s:%s" % (k, m[k]) for k in _CVSS_REQUIRED)
        ratings = {}
        for k in _CVSS_REQUIRED:
            val = m[k]
            if k in ("C", "I", "A"):
                name = {"H": "High", "L": "Low", "N": "None"}[val]
            else:
                name = _CVSS_NAMES[k][val]
            ratings[k.lower()] = "%s (%s)" % (name, val)
        ratings["scope"] = _CVSS_NAMES["S"][scope]

        # --- temporal metrics (optional, v3.1 spec section 8.1) ---
        e, rl, rc = m.get("E", "X"), m.get("RL", "X"), m.get("RC", "X")
        _t_weights = {"E": {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91},
                      "RL": {"X": 1.0, "O": 1.0, "T": 0.96, "W": 0.97, "U": 1.0},
                      "RC": {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}}
        temporal = _roundup(score * _t_weights["E"][e] * _t_weights["RL"][rl] * _t_weights["RC"][rc]) if score > 0 else 0.0

        # --- environmental metrics (optional, v3.1 spec section 8.2) ---
        cr, ir, ar = m.get("CR", "X"), m.get("IR", "X"), m.get("AR", "X")
        mav, mac, mpr, mui = m.get("MAV", av), m.get("MAC", ac), m.get("MPR", pr), m.get("MUI", ui)
        msc, mci, mii, mai = m.get("MS", scope), m.get("MC", c), m.get("MI", i), m.get("MA", a)
        env_modified = any(m.get(k) for k in ("CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI",
                                              "MS", "MC", "MI", "MA"))
        _req_w = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
        if not env_modified:
            environmental = temporal
        else:
            miss = 1.0 - (_CVSS_WEIGHTS["CIA"].get(mci, 0.0) or 0.0) * \
                        (_CVSS_WEIGHTS["CIA"].get(mii, 0.0) or 0.0) * \
                        (_CVSS_WEIGHTS["CIA"].get(mai, 0.0) or 0.0)
            if miss == 1.0 and (mci == "N" and mii == "N" and mai == "N"):
                miss = 0.0
            m_impact = (6.42 * miss) if msc == "U" else (7.52 * (miss - 0.029)) - (3.25 * ((miss - 0.02) ** 15))
            m_expl = 8.22 * _CVSS_WEIGHTS["AV"][mav] * _CVSS_WEIGHTS["AC"][mac] * \
                     _CVSS_WEIGHTS["PR"][msc][mpr] * _CVSS_WEIGHTS["UI"][mui]
            if m_impact <= 0:
                environmental = 0.0
            else:
                min_impact = min(m_impact * (1 - (1 - _req_w[cr]) * (1 - _req_w[ir]) * (1 - _req_w[ar])), 10.0)
                env_raw = (min_impact + m_expl) if msc == "U" else (1.08 * (min_impact + m_expl))
                environmental = _roundup(min(_roundup(env_raw), 10.0))

        full_vector = vector
        if e != "X" or rl != "X" or rc != "X":
            full_vector += "/" + "/".join("%s:%s" % (k, v) for k, v in (("E", e), ("RL", rl), ("RC", rc)) if v != "X")
        if env_modified:
            env_parts = ["%s:%s" % (k, m[k]) for k in ("CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA") if k in m]
            full_vector += "/" + "/".join(env_parts)

        return {
            "ok": True,
            "base_score": score,
            "temporal_score": temporal,
            "environmental_score": environmental,
            "severity": _cvss_severity_label(score),
            "ratings": ratings,
            "temporal_metrics": {"exploitability": e, "remediation_level": rl, "report_confidence": rc},
            "vector_string": full_vector,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def generate_markdown_report(target_name="", executive_summary="", findings_json="",
                             report_title="", author="HackerAI Agent",
                             organization="", logo_url="", classification="Confidential"):
    """Standalone Markdown pentest report from a supplied findings payload.

    target_name       - assessed target / engagement name
    executive_summary - author-provided summary paragraph
    findings_json     - JSON list (or JSON string) of finding dicts; accepts
                        raw scanner output (auto-correlated via
                        correlate_findings) or pre-correlated output.
    report_title      - custom cover/heading title (default: 'Penetration Test Report')
    author            - report author line
    organization      - client/organization name shown on the cover
    logo_url          - markdown image URL rendered at the top of the report
    classification    - data classification label (e.g. Confidential / Public)
    Returns the full Markdown text; also saves to reports/ directory.
    """
    try:
        target_name = str(target_name or "").strip() or "Untitled Target"
        executive_summary = str(executive_summary or "").strip()
        report_title = str(report_title or "").strip() or "Penetration Test Report"
        author = str(author or "").strip() or "HackerAI Agent"
        organization = str(organization or "").strip()
        classification = str(classification or "").strip() or "Confidential"
        logo_url = str(logo_url or "").strip()

        items, err = _coerce_findings(findings_json)
        if err:
            return "generate_markdown_report: %s" % err

        correlated = correlate_findings(items)
        if not correlated.get("ok"):
            return "generate_markdown_report: correlation failed: %s" % correlated.get("error")
        findings = correlated["findings"]
        counts = correlated["by_severity"]

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        if not executive_summary:
            worst = findings[0]["severity"].capitalize() if findings else "None"
            executive_summary = ("An assessment of %s identified %d unique finding(s); "
                                 "the highest severity observed is %s."
                                 % (target_name, len(findings), worst))

        L = []
        if logo_url:
            L.append("![logo](%s)" % logo_url)
            L.append("")
        L.append("# %s - %s" % (report_title, target_name))
        L.append("")
        L.append("> **Classification:** %s" % classification)
        L.append("")
        L.append("**Date:** %s  " % now)
        L.append("**Prepared by:** %s  " % author)
        if organization:
            L.append("**Prepared for:** %s  " % organization)
        L.append("")
        L.append("---")
        L.append("")
        L.append("## 1. Executive Summary")
        L.append("")
        L.append(executive_summary)
        L.append("")
        L.append("## 2. Risk Matrix")
        L.append("")
        L.append("| Severity | Count | Score band (CVSS v3.1) |")
        L.append("|----------|-------|------------------------|")
        bands = {"Critical": "9.0 - 10.0", "High": "7.0 - 8.9",
                 "Medium": "4.0 - 6.9", "Low": "0.1 - 3.9", "Info": "0.0"}
        for s in SEVERITIES:
            L.append("| %s | %d | %s |" % (s.capitalize(), counts[s], bands[s.capitalize()]))
        L.append("")
        L.append("## 3. Findings Summary")
        L.append("")
        if findings:
            L.append("| # | Severity | CVSS | Title | Asset |")
            L.append("|---|----------|------|-------|-------|")
            for n, r in enumerate(findings, 1):
                L.append("| %d | %s | %.1f | %s | `%s` |"
                         % (n, r["severity"].capitalize(), r["cvss_base"],
                            r["title"][:80], r["asset"][:60]))
            L.append("")
            L.append("## 4. Detailed Findings")
            L.append("")
            for n, r in enumerate(findings, 1):
                L.append("### 4.%d [%s] %s" % (n, r["severity"].upper(), r["title"]))
                L.append("")
                L.append("| Field | Value |")
                L.append("|-------|-------|")
                L.append("| Severity | %s |" % r["severity"].capitalize())
                L.append("| CVSS v3.1 Base | %.1f (%s) |"
                         % (r["cvss_base"], calc_cvss_score(r["risk_vector"])["severity"]))
                L.append("| Vector | `%s` |" % r["risk_vector"])
                L.append("| Asset | `%s` |" % r["asset"])
                if r["port"]:
                    L.append("| Port | %s |" % r["port"])
                if r["url"]:
                    L.append("| URL | %s |" % r["url"])
                if r["cve"]:
                    L.append("| CVE / Refs | %s |" % r["cve"])
                L.append("| Source scanner(s) | %s |" % ", ".join(r["corroborated_by"]) or "n/a")
                L.append("")
                if r["evidence"]:
                    L.append("**Proof of Concept / Evidence:**")
                    L.append("")
                    L.append("```")
                    L.append(r["evidence"])
                    L.append("```")
                    L.append("")
                L.append("**Remediation strategy:** %s"
                         % _REMEDIATION_BY_SEV[r["severity"]])
                L.append("")
        else:
            L.append("_No findings were supplied._")
            L.append("")
        if correlated.get("chain_graph"):
            L.append("## 5. Attack-Chain Graph")
            L.append("")
            L.append(correlated["chain_graph"].rstrip())
            L.append("")
            L.append("## 6. Remediation Priorities")
        else:
            L.append("## 5. Remediation Priorities")
        L.append("")
        L.append("1. **Critical:** patch immediately; active exploitation likely.")
        L.append("2. **High:** fix in the next release cycle as top priority.")
        L.append("3. **Medium:** schedule remediation and harden configurations.")
        L.append("4. **Low:** address during routine hardening and maintenance.")
        if correlated.get("chain_graph"):
            L.append("")
            L.append("**Single highest-leverage fix:** remediate the choke "
                     "point hops flagged in the Attack-Chain Graph above - "
                     "they collapse every downstream attack path.")
        L.append("")
        L.append("---")
        L.append("")
        L.append("*Report generated by %s on %s*" % (author, now))

        report = "\n".join(L)

        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        safe = "".join(c for c in target_name if c.isalnum() or c in "-_")[:40] or "target"
        out_path = os.path.join(REPORTS_DIR, "report_%s_%s.md" % (safe, ts))
        try:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(report)
        except OSError:
            out_path = ""
        return "%s\n\n[Report saved: %s]" % (report, out_path) if out_path else report
    except Exception as exc:
        return "generate_markdown_report: error: %s" % exc


_REMEDIATION_BY_SEV = {
    "critical": "Immediate patching and containment; if a patch is unavailable, apply virtual patching / WAF rules and restrict exposure until fixed.",
    "high": "Patch or reconfigure the affected component as top priority; validate fix with retesting.",
    "medium": "Schedule remediation in the next maintenance window; apply vendor guidance and least-privilege hardening.",
    "low": "Address during routine hardening; monitor for changes in exploitability.",
    "info": "No direct action required; note for awareness and future reviews.",
}
