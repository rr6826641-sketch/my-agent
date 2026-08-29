"""Lightweight deterministic finding verification (no LLM required).

Runs cheap, benign, single-request checks to confirm or reject candidate
security findings BEFORE they are presented as final in the UI / report:

  open_port  -> single TCP connect probe to host:port
  subdomain  -> single DNS resolution check
  cve        -> vulnerability-database lookup + optional version cross-check
  vuln       -> single benign HTTP GET + security-header validation when a
                URL is embedded in the claim

Verdicts (see STATUS_LABELS for display tags):
  verified   - evidence confirms the claim   -> [VERIFIED TRUE POSITIVE]
  rejected   - evidence contradicts the claim-> filtered/downgraded
  unverified - not enough evidence           -> [UNVERIFIED / REQUIRES MANUAL AUDIT]

These checks are deliberately non-destructive: read-only probes, no payloads,
no data modification. Authorized use only - targets must be in your
engagement scope.
"""

import re
import socket

from .recon import tool_cve_lookup
from .web import tool_check_headers, tool_http_request

VERIFIED = "verified"
REJECTED = "rejected"
UNVERIFIED = "unverified"

STATUS_LABELS = {
    VERIFIED: "[VERIFIED TRUE POSITIVE]",
    REJECTED: "[FALSE POSITIVE - FILTERED]",
    UNVERIFIED: "[UNVERIFIED / REQUIRES MANUAL AUDIT]",
}

# Display form used in reports and UI output.
VERIFIED_TAG = STATUS_LABELS[VERIFIED]
UNVERIFIED_TAG = STATUS_LABELS[UNVERIFIED]
REJECTED_TAG = STATUS_LABELS[REJECTED]

_RE_URL = re.compile(r"https?://[^\s\)\]\"'>]+", re.I)
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_RE_HOST_PORT = re.compile(
    r"\b(\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9.-]*\.[a-z]{2,24}):(\d{1,5})\b",
    re.I)
_RE_HOST_PHRASE = re.compile(
    r"\b(?:on|of|at|from)\s+"
    r"((?:\d{1,3}(?:\.\d{1,3}){3})|(?:[a-z0-9][a-z0-9.-]*\.[a-z]{2,24}))\b",
    re.I)
_RE_DOMAIN = re.compile(
    r"(?<![\w.])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|"
    r"dev|co|info|biz|me|xyz|tech|cloud|app|[a-z]{2,24})\b", re.I)
_RE_PORT_PHRASE = re.compile(r"\bport\s+(\d{1,5})\b", re.I)

# Headers that appear in "missing header" style claims.
_RE_HEADER_CLAIM = re.compile(
    r"\b(Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|"
    r"X-Content-Type-Options|Referrer-Policy|Permissions-Policy|"
    r"X-XSS-Protection)\b", re.I)


def _verdict(status, reason, evidence=""):
    return {"status": status, "reason": reason, "evidence": evidence,
            "method": "deterministic"}


def parse_host_port(value):
    """Best-effort (host, port) extraction from a finding value.

    Accepts 'host:port', 'port N open on host', 'port N open' and 'port N'
    phrasings. Returns (host or '', port or 0)."""
    value = value or ""
    m = _RE_HOST_PORT.search(value)
    if m:
        try:
            return m.group(1).lower(), int(m.group(2))
        except ValueError:
            pass
    host = ""
    hm = _RE_HOST_PHRASE.search(value)
    if hm:
        host = hm.group(1).lower()
    pm = _RE_PORT_PHRASE.search(value)
    port = int(pm.group(1)) if pm else 0
    return host, port


def _probe_port(host, port, timeout=3.0):
    """Single TCP connect probe. Returns (open_bool, detail)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return True, "TCP connect to %s:%d succeeded" % (host, port)
    except socket.timeout:
        return False, "TCP connect to %s:%d timed out" % (host, port)
    except ConnectionRefusedError:
        return False, "TCP connect to %s:%d refused" % (host, port)
    except OSError as exc:
        return False, "TCP connect to %s:%d failed (%s)" % (host, port, exc)


def _resolve(domain, timeout=5.0):
    """Single DNS A/AAAA resolution. Returns (resolved_bool, detail)."""
    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyname, domain)
            ip = fut.result(timeout=timeout)
        return True, "%s resolves to %s" % (domain, ip)
    except socket.gaierror as exc:
        return False, "%s does not resolve (%s)" % (domain, exc)
    except Exception as exc:
        return False, "DNS check for %s failed (%s)" % (domain, exc)


def verify_open_port(value):
    """Confirm/reject an open-port claim with one TCP connect probe."""
    host, port = parse_host_port(value)
    if not host or not port:
        return _verdict(
            UNVERIFIED,
            "no host:port target in claim - cannot re-check without a target")
    if not (1 <= port <= 65535):
        return _verdict(REJECTED,
                        "port %s is not a valid TCP/UDP port" % port)
    open_ok, detail = _probe_port(host, port)
    if open_ok:
        return _verdict(VERIFIED, detail, detail)
    # A closed port directly contradicts "port N is open".
    return _verdict(REJECTED, detail, detail)


def verify_subdomain(value):
    """Confirm/reject a subdomain discovery claim with one DNS lookup."""
    m = _RE_DOMAIN.search(value or "")
    domain = m.group(0).lower() if m else ""
    if not domain:
        return _verdict(UNVERIFIED,
                        "no domain in claim - cannot re-check without a host")
    resolved, detail = _resolve(domain)
    if resolved:
        return _verdict(VERIFIED, detail, detail)
    return _verdict(REJECTED, detail, detail)


def verify_cve(value):
    """Confirm/reject a CVE claim via the vulnerability databases (NVD/OSV).

    A CVE identifier that does not exist in the databases is strong evidence
    of a false positive. A version string in the claim is cross-checked
    against the advisory text when available."""
    m = _RE_CVE.search(value or "")
    cve = m.group(0).upper() if m else ""
    if not cve:
        return _verdict(UNVERIFIED, "no CVE identifier in claim")
    try:
        out = tool_cve_lookup(cve, max_results=5)
    except Exception as exc:
        return _verdict(UNVERIFIED,
                        "CVE database lookup failed: %s" % exc)
    if not out:
        return _verdict(UNVERIFIED, "CVE database lookup returned no data")
    if out.lower().startswith("cve_lookup:"):
        return _verdict(UNVERIFIED, "CVE database lookup failed: %s" % out)
    # "(no CVEs found for 'CVE-...')" contains the CVE id itself, so a plain
    # substring check would wrongly VERIFY a fabricated CVE. Detect the
    # no-results marker explicitly first.
    if re.search(r"\bno\s+CVEs?\s+found\b", out, re.I):
        return _verdict(REJECTED,
                        "%s not found in NVD/OSV databases - likely "
                        "fabricated or mis-typed" % cve)
    if cve.lower() not in out.lower():
        return _verdict(REJECTED,
                        "%s not found in NVD/OSV databases - likely "
                        "fabricated or mis-typed" % cve)
    reason = "%s confirmed present in vulnerability databases" % cve
    vm = re.search(r"\bv?(\d+(?:\.\d+){1,3})\b", value)
    if vm and vm.group(1) in out:
        reason += "; version %s appears in the advisory data" % vm.group(1)
    return _verdict(VERIFIED, reason, out[:400])


def verify_vuln(value):
    """Benign single-request validation of a web vulnerability claim.

    - No URL in the claim -> cannot re-check deterministically.
    - 'missing <security header>' claim -> one GET, header audit.
    - Any other web claim -> one benign GET; reachability confirms the
      endpoint exists, which supports (but does not fully prove) the claim.
    """
    value = value or ""
    um = _RE_URL.search(value)
    if not um:
        return _verdict(UNVERIFIED,
                        "no URL in claim - requires manual audit")
    url = um.group(0).rstrip(".,;")
    try:
        resp = tool_http_request(url, method="GET", max_body=1500)
    except Exception as exc:
        return _verdict(UNVERIFIED,
                        "benign GET failed (%s) - requires manual audit" % exc,
                        str(exc)[:300])
    if resp.startswith("http_request error") or resp.startswith(
            "http_request SSL error"):
        return _verdict(REJECTED,
                        "endpoint not reachable (%s)" % resp[:120], resp[:400])

    hm = _RE_HEADER_CLAIM.search(value)
    if hm:
        header = hm.group(1)
        try:
            hdr = tool_check_headers(url, timeout=20)
        except Exception as exc:
            return _verdict(UNVERIFIED,
                            "header validation failed: %s" % exc)
        present = re.search(
            r"\[OK\]\s+%s\s*:" % re.escape(header), hdr, re.I)
        if present:
            return _verdict(REJECTED,
                            "%s IS present on %s - missing-header claim "
                            "contradicted by live check" % (header, url),
                            hdr[:400])
        return _verdict(VERIFIED,
                        "%s is missing on %s (confirmed by live header "
                        "audit)" % (header, url), hdr[:400])

    # Generic web claim: endpoint answers, so the claim is plausible.
    m = re.search(r"STATUS:\s*(\d+)", resp)
    status = m.group(1) if m else "?"
    if status.startswith(("2", "3")):
        return _verdict(UNVERIFIED,
                        "endpoint reachable (HTTP %s) but the claimed "
                        "condition needs a manual audit to confirm" % status,
                        resp[:400])
    if status.startswith(("4", "5")):
        return _verdict(REJECTED,
                        "endpoint returned HTTP %s - claim does not match "
                        "live behavior" % status, resp[:400])
    return _verdict(UNVERIFIED,
                    "no clear evidence - requires manual audit", resp[:400])


def classify_finding(value):
    """Best-guess finding type from the claim text."""
    value = value or ""
    if _RE_CVE.search(value):
        return "cve"
    if _RE_URL.search(value):
        return "vuln"
    if _RE_HOST_PORT.search(value) or re.search(r"\bport\s+\d+\b", value,
                                                re.I):
        return "open_port"
    if _RE_DOMAIN.search(value):
        return "subdomain"
    return "vuln"


def lightweight_verify_finding(finding):
    """Dispatch one candidate finding to its benign deterministic check.

    finding: dict with at least {'value': '<claim text>'}; an optional
    'type' (cve|vuln|open_port|subdomain) overrides auto-classification.
    Returns a verdict dict:
      {status, reason, evidence, method}
    """
    value = (finding or {}).get("value") or ""
    ftype = (finding or {}).get("type") or classify_finding(value)
    try:
        if ftype == "open_port":
            return verify_open_port(value)
        if ftype == "subdomain":
            return verify_subdomain(value)
        if ftype == "cve":
            return verify_cve(value)
        return verify_vuln(value)
    except Exception as exc:
        return _verdict(UNVERIFIED,
                        "deterministic check error: %s" % exc)
