"""ultra_ops.py - HackerAI Ultra capability pack (v21).

Add-only module. It does NOT modify or replace any pre-existing tool; it
adds new capabilities in four areas the v20 build left thin:

1. NEW PENTEST TOOLS (web/API coverage gaps)
   - subdomain_takeover      dangling-CNAME / unclaimed-service detection
   - cache_poison_scan       web cache poisoning + cache deception probes
   - proto_pollution_test    client/server-side prototype pollution
   - crlf_inject_test        CRLF / response-header injection
   - host_header_inject      Host-header poisoning (reset/cache/routing)
   - rate_limit_test         throttle / lockout behaviour mapping
   - ldap_inject_test        LDAP injection probes
   - xpath_inject_test       XPath injection probes
   - http2_support_check     HTTP/2 negotiation + rapid-reset exposure recon
   - param_mine              hidden-parameter discovery via response diffing

2. CHAIN QUALITY
   - chain_quality_score     scores an exploit chain on evidence depth,
                             prerequisite realism, verification and impact.

3. EVIDENCE DISCIPLINE
   - evidence_capture        bounded baseline+exploit request/response pair,
                             saved and redacted, with a diff summary.
   - evidence_ledger         index of saved evidence bundles.
   - evidence_redact         scrub a saved artifact in place.

4. RELIABILITY
   - retry_probe             transient-aware HTTP probe with jittered backoff.
   - self_healthcheck        registry integrity audit of the live tool set.

Design notes
------------
* All HTTP goes through one bounded helper (`_probe`); bodies are truncated
  and hashed so evidence stays small and reproducible.
* Nothing here performs destructive or high-volume actions: probes are single
  requests (rate_limit_test is the only loop and is bounded + documented).
* Every tool returns a JSON string so the agent can chain on structured data.
"""

import datetime
import hashlib
import json
import os
import re
import socket
import subprocess
import time

try:  # requests is a hard dep of the project, but stay import-safe.
    import requests
except Exception:  # pragma: no cover - only when deps are missing
    requests = None

try:  # keep TLS-probe noise out of the operator's console
    import urllib3
    urllib3.disable_warnings()
except Exception:  # pragma: no cover
    pass


USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
EVIDENCE_DIR = os.path.join(PROJECT_DIR, "evidence")

MAX_BODY = 8000


def _json(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)


def _now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _split_list(value):
    """Accept a comma/newline/semicolon separated string or a list."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [p.strip() for p in re.split(r"[\n,;]+", str(value)) if p.strip()]


# --------------------------------------------------------------------------
# Bounded HTTP helper
# --------------------------------------------------------------------------

def _probe(url, method="GET", headers=None, data=None, timeout=10,
           allow_redirects=False, max_body=MAX_BODY, verify=False):
    """One bounded HTTP request -> normalised dict (never raises)."""
    if requests is None:
        return {"error": "requests library not installed"}
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update({str(k): str(v) for k, v in headers.items()})
    t0 = time.time()
    try:
        resp = requests.request(
            (method or "GET").upper(), url, headers=hdrs,
            data=data if data not in (None, "") else None,
            timeout=timeout, allow_redirects=allow_redirects, verify=verify)
        raw = resp.content or b""
        return {
            "status": resp.status_code,
            "headers": {k: v for k, v in resp.headers.items()},
            "body": resp.text[:max_body],
            "body_len": len(raw),
            "body_sha256": hashlib.sha256(raw).hexdigest(),
            "elapsed": round(time.time() - t0, 3),
            "final_url": resp.url,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - single funnel, stay alive
        return {"error": "%s: %s" % (type(exc).__name__, exc),
                "elapsed": round(time.time() - t0, 3)}


def _lower_headers(headers):
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


# --------------------------------------------------------------------------
# Secret redaction (evidence discipline)
# --------------------------------------------------------------------------

_SECRET_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token", "x-csrf-token",
    "x-session-token",
})

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/=]+")
_KV_RE = re.compile(
    r"(?i)\b(authorization|cookie|api[_-]?key|token|secret|password|passwd)"
    r"\s*[:=]\s*\S+")


def redact_headers(headers):
    out = {}
    for k, v in (headers or {}).items():
        if str(k).lower() in _SECRET_HEADERS:
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


def redact_text(text):
    text = _JWT_RE.sub("<jwt-redacted>", text or "")
    text = _BEARER_RE.sub("Bearer <redacted>", text)
    text = _KV_RE.sub(lambda m: "%s: <redacted>" % m.group(1), text)
    return text


def _bound_result(result, redact=True):
    """Drop the raw body from a saved probe result, keep the hash/summary."""
    if not isinstance(result, dict):
        return result
    out = dict(result)
    body = out.pop("body", "")
    out["body_len"] = out.get("body_len", len(body or ""))
    if out.get("headers"):
        out["headers"] = redact_headers(out["headers"]) if redact \
            else out["headers"]
    return out


# ==========================================================================
# 1. NEW PENTEST TOOLS
# ==========================================================================

# --- subdomain takeover ----------------------------------------------------

# (cname_suffix, service, unclaimed_body_signatures)
TAKEOVER_FINGERPRINTS = (
    ("s3.amazonaws.com", "AWS S3",
     ("nosuchbucket", "the specified bucket does not exist")),
    ("amazonaws.com", "AWS (generic)",
     ("nosuchbucket", "the specified bucket does not exist")),
    ("cloudfront.net", "AWS CloudFront",
     ("bad request", "error: the request could not be satisfied")),
    ("github.io", "GitHub Pages",
     ("there isn't a github pages site here", "for root urls")),
    ("herokuapp.com", "Heroku",
     ("no such app", "herokucdn.com/error-pages/no-such-app")),
    ("herokudns.com", "Heroku", ("no such app",)),
    ("azurewebsites.net", "Azure Web Apps",
     ("404 web site not found", "microsoft azure")),
    ("cloudapp.azure.com", "Azure CloudApp", ("not found",)),
    ("blob.core.windows.net", "Azure Blob", ("blobnotfound",)),
    ("trafficmanager.net", "Azure Traffic Manager", ("not found",)),
    ("fastly.net", "Fastly",
     ("fastly error: unknown domain",)),
    ("netlify.app", "Netlify", ("not found - request id",)),
    ("netlify.com", "Netlify", ("not found - request id",)),
    ("surge.sh", "Surge", ("project not found",)),
    ("bitbucket.io", "Bitbucket", ("repository not found",)),
    ("readthedocs.io", "Read the Docs",
     ("unknown to read the docs",)),
    ("readme.io", "ReadMe", ("project doesnt exist",)),
    ("myshopify.com", "Shopify",
     ("sorry, this shop is currently unavailable",)),
    ("shopify.com", "Shopify",
     ("sorry, this shop is currently unavailable",)),
    ("wordpress.com", "WordPress", ("doesn't exist", "do you want to register")),
    ("tumblr.com", "Tumblr", ("there's nothing here", "whatever you were looking for")),
    ("pantheonsite.io", "Pantheon", ("the gods are wise", "404 error unknown site")),
    ("ghost.io", "Ghost", ("the thing you were looking for is no longer here",)),
    ("helpjuice.com", "Helpjuice", ("we could not find what you're looking for",)),
    ("helpscoutdocs.com", "Help Scout", ("no settings were found",)),
    ("zendesk.com", "Zendesk", ("help center closed",)),
    ("statuspage.io", "Statuspage", ("status page is not found",)),
    ("uservoice.com", "UserVoice", ("this uservoice subdomain is currently available",)),
    ("pingdom.com", "Pingdom", ("this research page is not available",)),
    ("smugmug.com", "SmugMug", ("smugmug.com", "page not found")),
    ("teamwork.com", "Teamwork", ("oops - we didn't find your project",)),
    ("unbounce.com", "Unbounce", ("the requested url was not found",)),
    ("wpengine.com", "WP Engine", ("the site you were looking for couldn't be found",)),
    ("agilecrm.com", "Agile CRM", ("sorry, this page is no longer available",)),
    ("airee.ru", "Airee", ("this website is not configured",)),
    ("anima.io", "Anima", ("the site you are looking for could not be found",)),
    ("campaignmonitor.com", "Campaign Monitor", ("trying to access your account",)),
)


def _resolve_cname(host, timeout=8):
    """Resolve the first CNAME target for `host` (dnspython, else nslookup)."""
    try:
        import dns.resolver  # type: ignore
        ans = dns.resolver.resolve(host, "CNAME")
        return str(ans[0].target).rstrip(".")
    except Exception:
        pass
    try:
        proc = subprocess.run(
            ["nslookup", "-type=CNAME", host], capture_output=True,
            text=True, timeout=timeout)
        m = re.search(r"canonical name\s*=\s*(\S+?)\.?\s*$",
                      proc.stdout, re.I | re.M)
        if m:
            return m.group(1).rstrip(".")
    except Exception:
        pass
    return None


def tool_subdomain_takeover(targets="", timeout=10, probe_http=True):
    """Detect dangling CNAMEs pointing at unclaimed third-party services.

    For each hostname: resolve the CNAME chain, match it against a
    fingerprint table of takeover-prone providers (S3, GitHub Pages,
    Heroku, Azure, Fastly, Netlify, Shopify, ...), then optionally fetch
    the host and look for the provider's 'unclaimed' body signature.
    Returns a per-host verdict plus a small remediation note.
    """
    hosts = _split_list(targets)
    if not hosts:
        return _json({"error": "no targets supplied"})
    results = []
    for host in hosts:
        host = host.strip().lstrip("*.").lower()
        entry = {"host": host, "cname": None, "service": None,
                 "http_status": None, "signature": None, "verdict": "no-cname"}
        cname = _resolve_cname(host, timeout=timeout)
        entry["cname"] = cname
        if cname:
            low = cname.lower()
            for suffix, service, sigs in TAKEOVER_FINGERPRINTS:
                if low.endswith(suffix) or suffix in low:
                    entry["service"] = service
                    entry["verdict"] = "dangling-cname"
                    entry["fingerprints"] = list(sigs)
                    break
            else:
                entry["verdict"] = "cname-external"
        if probe_http and entry["verdict"] in ("dangling-cname", "cname-external"):
            for scheme in ("https", "http"):
                r = _probe("%s://%s/" % (scheme, host), timeout=timeout)
                if r.get("error"):
                    continue
                entry["http_status"] = r.get("status")
                body = (r.get("body") or "").lower()
                sigs = entry.get("fingerprints") or []
                for sig in sigs:
                    if sig in body:
                        entry["signature"] = sig
                        entry["verdict"] = "POTENTIAL_TAKEOVER"
                        break
                break
        entry["next_step"] = (
            "Confirm the provider still serves an unclaimed resource, then "
            "claim it under an authorized account to prove control."
            if entry["verdict"] == "POTENTIAL_TAKEOVER" else
            "Verify manually; provider bodies change over time.")
        results.append(entry)
    taken = [r for r in results if r["verdict"] == "POTENTIAL_TAKEOVER"]
    return _json({"checked": len(results),
                  "potential_takeovers": len(taken),
                  "results": results})


# --- web cache poisoning / deception --------------------------------------

_UNKEYED_HEADERS = (
    ("X-Forwarded-Host", "evil.example.com"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Host", "evil.example.com"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-Server", "evil.example.com"),
    ("Forwarded", "host=evil.example.com"),
)

_CACHE_HEADERS = ("x-cache", "cf-cache-status", "age", "cache-control",
                  "x-cache-hits", "vary", "x-served-by", "x-proxy-cache")


def _cache_state(headers):
    lh = _lower_headers(headers)
    return {h: lh[h] for h in _CACHE_HEADERS if h in lh}


def tool_cache_poison_scan(url="", method="GET", timeout=10, deception=True):
    """Probe for web cache poisoning and cache-deception exposure.

    Sends unkeyed-header payloads (X-Forwarded-Host, X-Host, X-Original-URL,
    Forwarded, ...) and flags any whose value is reflected into the response
    body, redirect Location, or a cache-identifying header. Optionally adds a
    cache-deception path probe (static extension on a dynamic route).
    Read-only: one request per probe, no payload is cached destructively.
    """
    if not url:
        return _json({"error": "url is required"})
    base = _probe(url, method=method, timeout=timeout)
    out = {"url": url, "baseline": {"status": base.get("status"),
                                    "cache": _cache_state(base.get("headers")),
                                    "body_sha256": base.get("body_sha256"),
                                    "error": base.get("error")},
           "probes": [], "cache_deception": None}

    for hname, hval in _UNKEYED_HEADERS:
        r = _probe(url, method=method, headers={hname: hval}, timeout=timeout)
        if r.get("error"):
            out["probes"].append({"header": hname, "error": r["error"]})
            continue
        body = r.get("body") or ""
        loc = _lower_headers(r.get("headers")).get("location", "")
        reflected = (hval in body) or (hval in loc)
        out["probes"].append({
            "header": hname,
            "status": r.get("status"),
            "reflected": reflected,
            "reflect_in": ("location" if hval in loc else
                           ("body" if hval in body else None)),
            "cache": _cache_state(r.get("headers")),
            "verdict": "candidate" if reflected else "no-signal",
        })

    if deception:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(url)
        decoy = urlunsplit((parts.scheme, parts.netloc,
                            parts.path.rstrip("/") + "/nonexistent.css",
                            "", ""))
        r = _probe(decoy, method="GET", timeout=timeout)
        b = base.get("status")
        out["cache_deception"] = {
            "url": decoy,
            "status": r.get("status"),
            "same_as_baseline": r.get("status") == b,
            "cache": _cache_state(r.get("headers")),
            "verdict": ("candidate" if (r.get("status") == 200 and b == 200
                                        and r.get("body_sha256")
                                        == base.get("body_sha256"))
                        else "no-signal"),
        }

    out["candidates"] = sum(1 for p in out["probes"]
                            if p.get("verdict") == "candidate")
    return _json(out)


# --- prototype pollution ---------------------------------------------------

_PROTO_PAYLOADS = (
    "__proto__[polluted]=hxptest",
    "constructor[prototype][polluted]=hxptest",
    "__proto__.polluted=hxptest",
    "constructor.prototype.polluted=hxptest",
    '{"__proto__":{"polluted":"hxptest"}}',
    '{"constructor":{"prototype":{"polluted":"hxptest"}}}',
)


def tool_proto_pollution_test(url="", param="", method="GET", timeout=10):
    """Probe for client/server-side prototype pollution.

    Injects __proto__ / constructor[prototype] payloads carrying a unique
    marker and flags any response that echoes the marker (or the polluted
    key), which indicates the parser merged an attacker-controlled
    prototype. Marker is unique per call so caching cannot false-positive.
    """
    if not url:
        return _json({"error": "url is required"})
    marker = "hxpp%d" % (int(time.time()) % 100000)
    base = _probe(url, method=method, timeout=timeout)
    out = {"url": url, "marker": marker,
           "baseline": {"status": base.get("status"),
                        "body_sha256": base.get("body_sha256"),
                        "error": base.get("error")},
           "probes": []}
    for payload in _PROTO_PAYLOADS:
        p = payload.replace("hxptest", marker)
        if param:
            joiner = "&" if "?" in url else "?"
            target = "%s%s%s=%s" % (url.split("#")[0], joiner, param, p)
        else:
            target = url
        r = _probe(target, method=method,
                   data=(p if method.upper() in ("POST", "PUT", "PATCH")
                         else None),
                   timeout=timeout)
        body = r.get("body") or ""
        out["probes"].append({
            "payload": p,
            "status": r.get("status"),
            "reflected": marker in body,
            "error": r.get("error"),
        })
    out["candidates"] = sum(1 for p in out["probes"] if p["reflected"])
    out["note"] = ("Reflection alone is a signal, not proof: confirm the "
                   "polluted property is actually consumed downstream "
                   "(e.g. a header, a gadget, or a DOM sink).")
    return _json(out)


# --- CRLF injection --------------------------------------------------------

_CRLF_PAYLOADS = (
    "%0d%0aX-Injected: hxcrlf",
    "%0aX-Injected: hxcrlf",
    "%0d%0a%0d%0a<hxcrlf>",
    "\\r\\nX-Injected: hxcrlf",
    "%23%0d%0aX-Injected: hxcrlf",
)


def tool_crlf_inject_test(url="", param="", method="GET", data="", timeout=10):
    """Probe for CRLF / HTTP response-header injection.

    Injects %0d%0a sequences carrying a canary header (X-Injected) and
    flags responses where the canary appears as a real header or in the
    body, which indicates the value reached the response header block.
    """
    if not url:
        return _json({"error": "url is required"})
    out = {"url": url, "canary": "X-Injected", "probes": []}
    for payload in _CRLF_PAYLOADS:
        if param:
            joiner = "&" if "?" in url else "?"
            target = "%s%s%s=%s" % (url.split("#")[0], joiner, param, payload)
            r = _probe(target, method=method, timeout=timeout)
        else:
            r = _probe(url, method=method, data=(data or payload),
                       timeout=timeout)
        if r.get("error"):
            out["probes"].append({"payload": payload, "error": r["error"]})
            continue
        lh = _lower_headers(r.get("headers"))
        header_hit = "x-injected" in lh
        body_hit = "x-injected" in (r.get("body") or "").lower() \
            or "<hxcrlf>" in (r.get("body") or "")
        out["probes"].append({
            "payload": payload,
            "status": r.get("status"),
            "header_injected": header_hit,
            "body_reflected": body_hit,
            "verdict": "candidate" if (header_hit or body_hit) else "no-signal",
        })
    out["candidates"] = sum(1 for p in out["probes"]
                            if p.get("verdict") == "candidate")
    return _json(out)


# --- host header injection -------------------------------------------------

_HOST_PAYLOADS = (
    ("Host", "evil.example.com"),
    ("X-Forwarded-Host", "evil.example.com"),
    ("X-Forwarded-Server", "evil.example.com"),
    ("X-HTTP-Host-Override", "evil.example.com"),
    ("Forwarded", "host=evil.example.com"),
)


def tool_host_header_inject(url="", method="GET", timeout=10):
    """Probe for Host-header poisoning (password-reset / cache / routing).

    Sends attacker-controlled Host variants and flags reflection into the
    body, a redirect Location, or link/script tags. High-value when a reset
    or invite flow echoes the host into an emailed URL.
    """
    if not url:
        return _json({"error": "url is required"})
    from urllib.parse import urlsplit
    real_host = urlsplit(url).netloc
    out = {"url": url, "real_host": real_host, "probes": []}
    for hname, hval in _HOST_PAYLOADS:
        r = _probe(url, method=method, headers={hname: hval},
                   timeout=timeout)
        if r.get("error"):
            out["probes"].append({"header": hname, "error": r["error"]})
            continue
        body = r.get("body") or ""
        loc = _lower_headers(r.get("headers")).get("location", "")
        out["probes"].append({
            "header": hname,
            "status": r.get("status"),
            "reflect_in_body": hval in body,
            "reflect_in_location": hval in loc,
            "verdict": ("candidate" if (hval in body or hval in loc)
                        else "no-signal"),
        })
    out["candidates"] = sum(1 for p in out["probes"]
                            if p.get("verdict") == "candidate")
    return _json(out)


# --- rate limiting / lockout ----------------------------------------------

def tool_rate_limit_test(url="", method="GET", data="", count=15,
                         timeout=10, delay=0.0):
    """Map throttle / lockout behaviour with a small bounded burst.

    Sends `count` requests (hard-capped at 50) with an optional inter-request
    delay, records status codes and latency, and reports whether 429/403/503
    throttling or account lockout appeared. Keep count modest and only run
    against in-scope targets.
    """
    if not url:
        return _json({"error": "url is required"})
    n = max(1, min(int(count or 15), 50))
    statuses = []
    t0 = time.time()
    first_throttle = None
    for i in range(n):
        r = _probe(url, method=method, data=(data or None), timeout=timeout)
        st = r.get("status")
        statuses.append(st)
        if st in (429, 403, 503, 502) and first_throttle is None:
            first_throttle = i + 1
        elif r.get("error") and first_throttle is None:
            first_throttle = i + 1
        if delay:
            time.sleep(delay)
    elapsed = round(time.time() - t0, 2)
    uniq = sorted({s for s in statuses if s is not None})
    out = {
        "url": url, "requests": n, "elapsed_s": elapsed,
        "statuses": statuses, "distinct_status": uniq,
        "throttled": first_throttle is not None,
        "first_throttle_at": first_throttle,
        "rate_per_s": round(n / elapsed, 2) if elapsed else None,
        "verdict": ("throttling/lockout observed" if first_throttle is not None
                    else "no throttling observed in burst"),
        "note": "A negative result only means the burst was too small or the "
                "limit is above it; it is not proof of a missing control.",
    }
    return _json(out)


# --- LDAP injection --------------------------------------------------------

_LDAP_PAYLOADS = (
    "*",
    "*)(uid=*",
    "*)(|(uid=*",
    "admin*",
    "*)(&",
    ")(cn=*",
    "x)(|(objectClass=*",
)


def tool_ldap_inject_test(url="", param="", method="GET", data="", timeout=10):
    """Probe an input for LDAP injection.

    Injects LDAP metacharacter payloads and compares response length/status
    against a benign baseline. A wildcard '*' that yields a materially
    larger/smaller result set is the classic signal of an unsanitised filter.
    """
    if not url:
        return _json({"error": "url is required"})
    base = _probe(url, method=method, timeout=timeout)
    out = {"url": url, "baseline": {"status": base.get("status"),
                                    "len": base.get("body_len"),
                                    "sha": base.get("body_sha256")},
           "probes": []}
    for payload in _LDAP_PAYLOADS:
        if param:
            joiner = "&" if "?" in url else "?"
            target = "%s%s%s=%s" % (url.split("#")[0], joiner, param,
                                    requests.utils.quote(payload, safe="")
                                    if requests else payload)
        else:
            target = url
        r = _probe(target, method=method, data=(data or payload),
                   timeout=timeout)
        changed = (r.get("status") != base.get("status")
                   or r.get("body_sha256") != base.get("body_sha256"))
        out["probes"].append({
            "payload": payload,
            "status": r.get("status"),
            "len": r.get("body_len"),
            "delta_len": (r.get("body_len") or 0) - (base.get("body_len") or 0),
            "changed_vs_baseline": changed,
            "verdict": "candidate" if changed else "no-signal",
        })
    out["candidates"] = sum(1 for p in out["probes"]
                            if p.get("verdict") == "candidate")
    out["note"] = ("Response differences can be normal; confirm a hit with "
                   "a blind/boolean oracle or a time-delay payload before "
                   "reporting.")
    return _json(out)


# --- XPath injection -------------------------------------------------------

_XPATH_PAYLOADS = (
    "' or '1'='1",
    "' or 1=1 or ''='",
    "x' or name()='username' or 'x'='y",
    "' or count(/*)>0 or 'a'='b",
    "1 or 1=1",
)


def tool_xpath_inject_test(url="", param="", method="GET", data="", timeout=10):
    """Probe an input for XPath injection.

    Injects boolean/tautology payloads and flags responses that diverge from
    the baseline (typical of an unsanitised XPath query returning all nodes).
    """
    if not url:
        return _json({"error": "url is required"})
    base = _probe(url, method=method, timeout=timeout)
    out = {"url": url, "baseline": {"status": base.get("status"),
                                    "len": base.get("body_len"),
                                    "sha": base.get("body_sha256")},
           "probes": []}
    for payload in _XPATH_PAYLOADS:
        if param:
            joiner = "&" if "?" in url else "?"
            enc = requests.utils.quote(payload, safe="") if requests else payload
            target = "%s%s%s=%s" % (url.split("#")[0], joiner, param, enc)
        else:
            target = url
        r = _probe(target, method=method, data=(data or payload),
                   timeout=timeout)
        changed = (r.get("status") != base.get("status")
                   or r.get("body_sha256") != base.get("body_sha256"))
        out["probes"].append({
            "payload": payload,
            "status": r.get("status"),
            "len": r.get("body_len"),
            "changed_vs_baseline": changed,
            "verdict": "candidate" if changed else "no-signal",
        })
    out["candidates"] = sum(1 for p in out["probes"]
                            if p.get("verdict") == "candidate")
    return _json(out)


# --- HTTP/2 support + rapid-reset exposure recon ---------------------------

def tool_http2_support_check(target="", port=443, timeout=8):
    """Recon whether a TLS endpoint negotiates HTTP/2 (ALPN 'h2').

    Rapid Reset (CVE-2023-44487) is abused at connection level; a full proof
    needs an h2 client and is intentionally NOT performed here (it is a DoS
    primitive). This tool only reports whether h2 is offered and whether the
    server advertises SETTINGS_MAX_CONCURRENT_STREAMS, so the operator can
    decide on a bounded, in-scope test.
    """
    target = (target or "").strip()
    if not target:
        return _json({"error": "target is required"})
    target = target.replace("https://", "").replace("http://", "").split("/")[0]
    host = target.split(":")[0]
    p = int(target.split(":")[1]) if ":" in target else int(port or 443)
    out = {"target": "%s:%d" % (host, p), "http2_offered": False,
           "alpn": None, "error": None}
    try:
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((host, p), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                out["alpn"] = ssock.selected_alpn_protocol()
                out["http2_offered"] = ssock.selected_alpn_protocol() == "h2"
    except Exception as exc:  # noqa: BLE001
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    out["verdict"] = ("HTTP/2 offered - test Rapid Reset only in isolation, "
                      "bounded, and with written scope"
                      if out["http2_offered"] else
                      "HTTP/2 not negotiated at this endpoint")
    return _json(out)


# --- hidden parameter discovery -------------------------------------------

_COMMON_PARAMS = (
    "id", "debug", "test", "admin", "redirect", "url", "next", "return",
    "callback", "file", "path", "page", "view", "lang", "format", "token",
    "key", "api_key", "user", "username", "email", "role", "isAdmin",
    "access", "preview", "hidden", "source", "ref", "utm_source",
    "include", "template", "action", "cmd",
)


def tool_param_mine(url="", method="GET", timeout=8, params="", max_params=40):
    """Discover hidden parameters by response-diffing against a baseline.

    Requests the URL once as-is, then once per candidate parameter
    (a supplied list or a built-in common set) with a benign marker value,
    flagging params whose response length/status/sha diverges from the
    baseline. Bounded to `max_params` requests.
    """
    if not url:
        return _json({"error": "url is required"})
    cand = _split_list(params) or list(_COMMON_PARAMS)
    cap = max(1, min(int(max_params or 40), 80))
    base = _probe(url, method=method, timeout=timeout)
    out = {"url": url, "baseline_len": base.get("body_len"),
           "baseline_status": base.get("status"),
           "baseline_sha": base.get("body_sha256"), "candidates": [],
           "tested": 0}
    joiner = "&" if "?" in url else "?"
    for name in cand[:cap]:
        target = "%s%s%s=hxpm%d" % (url.split("#")[0], joiner, name,
                                    int(time.time()) % 1000)
        r = _probe(target, method=method, timeout=timeout)
        out["tested"] += 1
        changed = (r.get("status") != base.get("status")
                   or r.get("body_sha256") != base.get("body_sha256"))
        if changed:
            out["candidates"].append({
                "param": name,
                "status": r.get("status"),
                "len": r.get("body_len"),
                "delta_len": (r.get("body_len") or 0)
                - (base.get("body_len") or 0),
            })
    out["found"] = len(out["candidates"])
    return _json(out)


# ==========================================================================
# 2. CHAIN QUALITY
# ==========================================================================

_CHAIN_STAGE_ORDER = ("recon", "enum", "vuln", "exploit", "post")


def _hop_blob(hop):
    return json.dumps(hop, ensure_ascii=False, default=str).lower()


def chain_quality_score(chain):
    """Score a chain dict {hops:[...]} or a bare list of hop dicts.

    Returns {score 0-100, grade, breakdown, suggestions}. Scoring rewards
    stage coverage, per-hop evidence, prerequisite realism, PoC-confirmed
    verification and demonstrated impact - i.e. it pushes chains toward the
    evidence discipline the report stage requires.

    Recognised hop keys (all optional, matched case-insensitively):
      stage, action, evidence, verification_status|status, requires|prereq,
      impact, severity.
    """
    if isinstance(chain, str):
        try:
            chain = json.loads(chain)
        except ValueError as exc:
            return _json({"error": "invalid chain JSON: %s" % exc})
    if isinstance(chain, dict):
        hops = chain.get("hops") or chain.get("chain") or []
    elif isinstance(chain, list):
        hops = chain
    else:
        return _json({"error": "chain must be a list or {hops: [...]}"})
    hops = [h for h in hops if isinstance(h, dict)]
    if not hops:
        return _json({"error": "chain has no hops"})

    stages = set()
    evidence = 0
    prereq = 0
    confirmed = 0
    impact = 0
    for h in hops:
        blob = _hop_blob(h)
        for s in _CHAIN_STAGE_ORDER:
            if s in blob:
                stages.add(s)
        if h.get("evidence"):
            evidence += 1
        if h.get("requires") or h.get("prereq") or "requires" in blob:
            prereq += 1
        if str(h.get("verification_status", h.get("status", ""))).upper() \
                in ("CONFIRMED_POC", "VERIFIED", "CONFIRMED"):
            confirmed += 1
        if h.get("impact") or "rce" in blob or "critical" in blob:
            impact += 1

    n = len(hops)
    coverage = round(30 * len(stages) / len(_CHAIN_STAGE_ORDER))
    ev_score = round(25 * evidence / n)
    pre_score = round(15 * prereq / n)
    ver_score = round(20 * confirmed / n)
    imp_score = round(10 * min(impact / n, 1.0))
    score = coverage + ev_score + pre_score + ver_score + imp_score
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 60 else "D" if score >= 40 else "F")

    suggestions = []
    missing = [s for s in _CHAIN_STAGE_ORDER if s not in stages]
    if missing:
        suggestions.append("Add hops covering: %s" % ", ".join(missing))
    if evidence < n:
        suggestions.append("Attach bounded evidence to %d/%d hops."
                           % (n - evidence, n))
    if confirmed < n:
        suggestions.append("Confirm %d/%d hops with a non-destructive PoC."
                           % (n - confirmed, n))
    if prereq < n:
        suggestions.append("State prerequisites per hop so impact is credible.")
    if not impact:
        suggestions.append("Articulate demonstrated impact for the terminal hop.")
    return _json({"score": score, "grade": grade, "hops": n,
                  "breakdown": {"stage_coverage": coverage,
                                "evidence": ev_score,
                                "prerequisites": pre_score,
                                "verification": ver_score,
                                "impact": imp_score},
                  "stages_covered": sorted(stages),
                  "suggestions": suggestions})


# legacy-style alias (some callers expect a `tool_` prefix)
tool_chain_quality_score = chain_quality_score


# ==========================================================================
# 3. EVIDENCE DISCIPLINE
# ==========================================================================

def _safe_label(label):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", (label or "evidence"))[:60]


def _parse_req_spec(spec):
    if isinstance(spec, dict):
        return spec
    try:
        return json.loads(spec or "{}")
    except ValueError:
        return {}


def _run_req_spec(spec, timeout=10):
    spec = _parse_req_spec(spec)
    url = spec.get("url") or ""
    if not url:
        return {"error": "spec missing url", "request": spec}
    r = _probe(url, method=spec.get("method", "GET"),
               headers=spec.get("headers"), data=spec.get("data"),
               timeout=timeout)
    r["request"] = {"url": url, "method": (spec.get("method") or "GET").upper(),
                    "headers": redact_headers(spec.get("headers")),
                    "data": redact_text(str(spec.get("data") or ""))}
    return r


def tool_evidence_capture(label="", baseline="", exploit="", timeout=10,
                          redact=True):
    """Capture a bounded, redacted baseline+exploit request/response pair.

    `baseline` and `exploit` are JSON request specs, e.g.
    {"url":"https://t/x?a=1","method":"GET","headers":{...},"data":"..."}.
    Saves both to evidence/<label>/ (baseline.json, exploit.json, index.json)
    with secret headers/JWTs redacted, and returns the save paths plus a
    behavioural diff (status, length, body hash) that documents the impact.
    """
    b = _run_req_spec(baseline, timeout=timeout)
    e = _run_req_spec(exploit, timeout=timeout)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = "%s_%s" % (_safe_label(label), stamp)
    folder = os.path.join(EVIDENCE_DIR, name)
    os.makedirs(folder, exist_ok=True)

    def _save(tag, r):
        payload = {
            "captured": _now_iso(),
            "request": r.get("request"),
            "response": _bound_result(
                {k: r.get(k) for k in
                 ("status", "headers", "body", "body_len", "body_sha256",
                  "elapsed", "final_url", "error")}, redact=redact),
        }
        path = os.path.join(folder, "%s.json" % tag)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return path

    b_path = _save("baseline", b)
    e_path = _save("exploit", e)
    diff = {
        "status_changed": b.get("status") != e.get("status"),
        "baseline_status": b.get("status"),
        "exploit_status": e.get("status"),
        "length_delta": (e.get("body_len") or 0) - (b.get("body_len") or 0),
        "body_changed": b.get("body_sha256") != e.get("body_sha256"),
    }
    index = {"label": _safe_label(label), "captured": _now_iso(),
             "baseline_path": b_path, "exploit_path": e_path, "diff": diff,
             "redacted": bool(redact)}
    with open(os.path.join(folder, "index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    index["folder"] = folder
    return _json(index)


def tool_evidence_ledger(limit=50):
    """List saved evidence bundles (newest first) for report traceability."""
    if not os.path.isdir(EVIDENCE_DIR):
        return _json({"evidence_dir": EVIDENCE_DIR, "bundles": []})
    rows = []
    for name in sorted(os.listdir(EVIDENCE_DIR), reverse=True):
        idx = os.path.join(EVIDENCE_DIR, name, "index.json")
        if os.path.isfile(idx):
            try:
                with open(idx, "r", encoding="utf-8") as f:
                    rows.append(json.load(f))
            except ValueError:
                rows.append({"folder": os.path.join(EVIDENCE_DIR, name),
                             "label": name, "error": "unreadable index"})
        if len(rows) >= max(1, int(limit or 50)):
            break
    return _json({"evidence_dir": EVIDENCE_DIR, "count": len(rows),
                  "bundles": rows})


def tool_evidence_redact(path="", extra_patterns=""):
    """Scrub secrets from a saved evidence file, writing <name>.redacted.

    Redacts known secret headers (Authorization/Cookie/...), JWTs, Bearer
    tokens and key=value secrets, plus any extra regex patterns supplied.
    Returns the output path and how many substitutions were made.
    """
    if not path or not os.path.isfile(path):
        return _json({"error": "path not found: %s" % path})
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    before = text
    try:
        data = json.loads(text)
        if isinstance(data, dict) and isinstance(data.get("response"), dict):
            data["response"]["headers"] = redact_headers(
                data["response"].get("headers"))
            data["response"] = _bound_result(data["response"], redact=True)
            text = json.dumps(data, ensure_ascii=False, indent=2)
    except ValueError:
        pass
    text = redact_text(text)
    for pat in _split_list(extra_patterns):
        text = re.sub(pat, "<redacted>", text)
    out_path = path + ".redacted"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    return _json({"input": path, "output": out_path,
                  "changed": text != before,
                  "input_len": len(before), "output_len": len(text)})


# ==========================================================================
# 4. RELIABILITY
# ==========================================================================

_TRANSIENT = (
    "timeout", "timed out", "connectionerror", "connection error",
    "connection refused", "connection reset", "reset by peer",
    "temporary failure", "temporarily unavailable", "getaddrinfo",
    "max retries", "remote end closed", "read timed out",
)


def _is_transient(err):
    e = (err or "").lower()
    return any(m in e for m in _TRANSIENT) or "http 429" in e \
        or "http 5" in e


def tool_retry_probe(url="", method="GET", attempts=3, base_delay=0.5,
                     headers=None, data=None, timeout=8):
    """Transient-aware HTTP probe with jittered exponential backoff.

    Retries only on connection/timeout/5xx/429-style errors (never on a
    definitive 4xx answer), uses full-jitter backoff, and reports the attempt
    timeline. Improves reliability against flaky links without hammering.
    """
    if not url:
        return _json({"error": "url is required"})
    import random
    n = max(1, min(int(attempts or 3), 8))
    timeline = []
    last = None
    for i in range(n):
        r = _probe(url, method=method, headers=headers, data=data,
                   timeout=timeout)
        last = r
        err = r.get("error")
        trans = bool(err) and _is_transient(err)
        timeline.append({"attempt": i + 1, "status": r.get("status"),
                         "error": err, "transient": trans})
        if not err or not trans:
            break
        if i < n - 1:
            delay = random.uniform(0, base_delay * (2 ** i))
            time.sleep(delay)
    return _json({"url": url, "attempts_made": len(timeline),
                  "final_status": (last or {}).get("status"),
                  "final_error": (last or {}).get("error"),
                  "recovered": bool(timeline and timeline[-1].get("status")
                                    and not timeline[-1].get("error")),
                  "timeline": timeline})


def tool_self_healthcheck():
    """Audit the live tool registry for integrity problems.

    Checks: duplicate names, empty descriptions, non-callable handlers,
    malformed JSON-schema, and non-identifier names across the built-in
    registry plus any synthesized tools. Reliability guard so one bad tool
    registration cannot silently break tool discovery.
    """
    try:
        from . import _REGISTRY as registry, _BUILTIN_NAMES  # noqa: F401
        from . import synthesized_tool_catalog
    except Exception as exc:  # pragma: no cover
        return _json({"error": "registry unavailable: %r" % exc})
    tools = list(registry or []) + list(synthesized_tool_catalog().values())
    issues = []
    seen = {}
    for t in tools:
        name = getattr(t, "name", None)
        if not name or not isinstance(name, str) or not name.isidentifier():
            issues.append({"tool": name, "issue": "invalid name"})
        elif name in seen:
            issues.append({"tool": name, "issue": "duplicate name"})
        else:
            seen[name] = True
        if not getattr(t, "description", ""):
            issues.append({"tool": name, "issue": "empty description"})
        if not callable(getattr(t, "func", None)):
            issues.append({"tool": name, "issue": "non-callable handler"})
        params = getattr(t, "parameters", None)
        if not isinstance(params, dict) or params.get("type") != "object":
            issues.append({"tool": name, "issue": "invalid parameter schema"})
    return _json({"checked": len(tools), "unique": len(seen),
                  "issues": len(issues), "ok": not issues,
                  "details": issues[:50]})
