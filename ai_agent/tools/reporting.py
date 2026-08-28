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


def tool_add_finding(asset="", title="", severity="medium", cwe="",
                     description="", evidence="", impact="", remediation="",
                     confidence="medium", status="open"):
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
        lines.append("- [%s] [%s] %s | %s | %s"
                     % (r.get("status", "?"),
                        (r.get("severity") or "?").upper(),
                        r.get("id"), r.get("title"), r.get("asset")))
    return "\n".join(lines)


def tool_update_finding(finding_id="", severity="", status="", title="",
                        remediation="", confidence=""):
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

    if include_open_only:
        keep = {"open", "confirmed", "validated",
                "needs-validation", "hypothesis"}
        rows = [r for r in rows if r.get("status") in keep]

    if not rows:
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
    L.append("## 2. Scope")
    L.append("")
    L.append("- **Engagement target:** %s" % target)
    L.append("- **Assessment type:** Penetration test / vulnerability assessment")
    L.append("")
    L.append("## 3. Findings Summary")
    L.append("")
    L.append("| ID | Severity | Title | Asset | Status |")
    L.append("|----|----------|-------|-------|--------|")
    for r in rows:
        L.append("| %s | %s | %s | %s | %s |"
                 % (r.get("id"), (r.get("severity") or "?").capitalize(),
                    (r.get("title") or "?")[:80],
                    (r.get("asset") or "?")[:60],
                    r.get("status", "?")))
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
        if include_remediation and r.get("remediation"):
            L.append("**Remediation:**")
            L.append("")
            L.append(r["remediation"])
            L.append("")
        L.append("---")
        L.append("")
    L.append("## 5. Methodology")
    L.append("")
    L.append("1. **Reconnaissance** - subdomain enumeration, port scanning, service fingerprinting")
    L.append("2. **Enumeration** - web fuzzing, tech detection, HTTP method / header analysis")
    L.append("3. **Vulnerability testing** - SQLi, XSS, SSRF, CMDi, path traversal, auth checks")
    L.append("4. **Exploitation / validation** - payload testing, proof-of-concept confirmation")
    L.append("5. **Reporting** - findings consolidation, severity calibration, remediation")
    L.append("")
    L.append("## 6. Remediation Priorities")
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
