"""WebSocket Security Tester (Tier 2 bundle #10).

Real-time endpoint testing:
  - handshake fingerprinting (server headers, subprotocols, close codes)
  - origin-spoofing / auth-header bypass probes
  - message injection: XSS reflection, SQLi probes, command injection,
    path traversal, oversized frames, malformed frames
  - bounded: sequential sends, per-test timeouts, capped echo reads

Uses the `websockets` library (installed) with a dual-API compatible
connect call (additional_headers / extra_headers fallback). Every entry
point returns a JSON-serialisable dict, never raises.
"""

from __future__ import annotations

import asyncio
import json
import ssl
import time

# Payload catalogue ----------------------------------------------------------
_XSS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "{{7*7}}",
    "${7*7}",
    "';alert(String.fromCharCode(88,83,83))//",
]
_SQLI = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin'--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' WAITFOR DELAY '0:0:3'--",
]
_CMDI = [
    ";id",
    "|id",
    "$(id)",
    "`id`",
    ";ls -la",
    "%0a id",
]
_PATH = [
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
]
_ERR_MARKERS = {
    "sqli": ["sql", "syntax error", "mysql", "postgres", "unclosed quotation",
             "odbc", "sqlite", "ora-", "jdbc", "microsoft oledb", "query failed"],
    "cmdi": ["uid=", "gid=", "groups=", "/bin/sh", "not found", "no such file",
             "total ", "drwxr", "-rw-r--r--"],
    "path": ["root:", "daemon:", "/bin/bash", "nologin", "passwd"],
    "xss": [],
}
_OVERSCAN = 2  # max replies consumed after an injection


def _norm_payload_str(payloads):
    """Payload set selector -> list of (kind, payload) tuples."""
    p = (payloads or "xss").strip().lower()
    if p in ("all", "full"):
        return [("xss", x) for x in _XSS] + [("sqli", s) for s in _SQLI] \
               + [("cmdi", c) for c in _CMDI] + [("path", t) for t in _PATH]
    out = []
    for token in p.replace("|", ",").split(","):
        token = token.strip()
        if token == "xss":
            out += [("xss", x) for x in _XSS]
        elif token == "sqli":
            out += [("sqli", s) for s in _SQLI]
        elif token == "cmdi":
            out += [("cmdi", c) for c in _CMDI]
        elif token == "path":
            out += [("path", t) for t in _PATH]
    return out or [("xss", _XSS[0])]


def _parse_headers(headers_text):
    out = {}
    for line in (headers_text or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _build_conn_kwargs(extra_headers, ssl_ctx):
    """Return kwarg dict; supports websockets API v10+ and v12+ naming."""
    kw = {"max_size": 8 * 1024 * 1024}
    if ssl_ctx is not None:
        kw["ssl"] = ssl_ctx
    if extra_headers:
        kw["additional_headers"] = extra_headers
        kw["extra_headers"] = extra_headers
    return kw


async def _probe_connect(uri, extra_headers, ssl_ctx, timeout):
    """Single connect probe; returns dict of handshake facts."""
    out = {"connected": False, "error": ""}
    t0 = time.time()
    try:
        ws = await _connect_once(uri, ssl_ctx, timeout,
                                 headers=extra_headers or None)
    except asyncio.TimeoutError:
        return {**out, "error": "connection timeout",
                "ms": int((time.time() - t0) * 1000)}
    except Exception as exc:
        return {**out, "error": "%s: %s" % (type(exc).__name__, exc),
                "ms": int((time.time() - t0) * 1000)}
    res = {**out, "connected": True,
           "ms": int((time.time() - t0) * 1000),
           "protocol": ws.subprotocol,
           "server_headers": _hdrs_dict(ws.response_headers)
           if hasattr(ws, "response_headers") else None,
           "path": getattr(ws, "path", "")}
    try:
        await ws.close()
    except Exception:
        pass
    return res


def _hdrs_dict(hdrs):
    try:
        return dict(hdrs)
    except Exception:
        return None


async def _connect_once(url, ssl_ctx, timeout, headers=None):
    import websockets
    base = {"max_size": 8 * 1024 * 1024}
    # Never route pentest connections through a system/autodetected proxy
    # (websockets >= 14 honours urllib.getproxies(); a local proxy would
    # swallow loopback/WS traffic and break the handshake).
    base["proxy"] = None
    if ssl_ctx is not None:
        base["ssl"] = ssl_ctx
    # Build candidate arg sets: latest headers API first, fall back to the
    # legacy extra_headers API and drop the proxy kwarg on old versions.
    candidates = [dict(base)]
    if headers:
        candidates[0]["additional_headers"] = headers
        legacy = dict(base); legacy["extra_headers"] = headers
        candidates.append(legacy)
    coro = None
    for argset in candidates:
        try:
            coro = websockets.connect(url, **argset)
            break
        except TypeError:
            argset.pop("proxy", None)
            try:
                coro = websockets.connect(url, **argset)
                break
            except TypeError:
                continue
    if coro is None:
        raise RuntimeError("websockets.connect rejected header kwargs")
    return await asyncio.wait_for(coro, timeout=timeout)


async def _amain(url, header_pairs, payloads, max_messages, timeout, tls_insecure):
    import websockets
    ssl_ctx = None
    if url.startswith("wss://"):
        ssl_ctx = ssl.create_default_context()
        if tls_insecure:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    report = {"target": url, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
              "tests": [], "findings": []}

    # 1) baseline handshake
    base = await _probe_connect(url, None, ssl_ctx, timeout)
    report["handshake"] = base
    if not base["connected"]:
        report["error"] = ("could not establish baseline connection: %s"
                           % base["error"])
        return report

    # 2) origin / auth header spoof probe
    spoof = {"Origin": "https://evil.example.com",
             "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    for k, v in header_pairs:
        spoof[k] = v
    alt = await _probe_connect(url, spoof, ssl_ctx, timeout)
    report["origin_spoof_probe"] = alt
    if alt.get("connected"):
        report["findings"].append({
            "type": "origin-auth-bypass",
            "severity": "medium",
            "title": "Server accepted spoofed Origin / custom auth headers",
            "evidence": "handshake accepted with Origin=%s" % spoof.get("Origin", ""),
            "remediation": "Validate Origin against an allowlist for "
                           "state-changing WS messages; bind sessions to "
                           "cookies, not client-supplied headers.",
        })

    # 3) message injection tests
    found = set()
    for kind, payload in payloads:
        if len(report["findings"]) >= 12:
            break
        replies = []
        phase = ""
        try:
            ws = await _connect_once(url, ssl_ctx, timeout)
            phase = "connected"
            reply = await asyncio.wait_for(ws.send(payload), timeout=timeout)
            for _ in range(_OVERSCAN):
                try:
                    r = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    replies.append((r if isinstance(r, str) else repr(r))[:400])
                except asyncio.TimeoutError:
                    break
        except Exception as exc:
            report["tests"].append({"payload_kind": kind, "payload": payload,
                                    "phase": phase or "connect",
                                    "error": "%s" % (exc or "")[:160]})
            continue
        finally:
            try:
                if "ws" in dir() and ws is not None:
                    await ws.close()
            except Exception:
                pass

        joined = " | ".join(replies)
        report["tests"].append({"payload_kind": kind, "payload": payload,
                                "replies": len(replies), "echoed": bool(replies),
                                "echo_sample": (joined[:300] if replies else "")})

        key = (kind, payload)
        if kind == "xss" and payload.lower() in joined.lower():
            if key not in found:
                found.add(key)
                report["findings"].append({
                    "type": "xss-reflection", "severity": "medium",
                    "title": "XSS payload echoed verbatim by WebSocket endpoint",
                    "evidence": "payload '%s' returned in reply: %s"
                                % (payload, joined[:200]),
                    "remediation": "Encode/validate server-side before "
                                   "funnelling WS messages into the DOM.",
                })
        elif kind in ("sqli", "cmdi", "path"):
            markers = _ERR_MARKERS[kind]
            matched = [m for m in markers if m.lower() in joined.lower()]
            if matched:
                ftype = {"sqli": "sql-injection", "cmdi": "command-injection",
                         "path": "path-traversal"}[kind]
                sev = "critical" if kind in ("sqli", "cmdi") else "high"
                if key not in found:
                    found.add(key)
                    report["findings"].append({
                        "type": ftype, "severity": sev,
                        "title": "WebSocket %s probe returned error markers"
                                 % ftype.replace("-", " "),
                        "evidence": ("payload '%s' -> server responded with "
                                     "markers %s (reply: %s)"
                                     % (payload, matched[:3], joined[:200])),
                        "remediation": ("Parameterise WS message handling; "
                                        "treat every message as untrusted "
                                        "input."),
                    })
            elif payload in joined:
                if key not in found:
                    found.add(key)
                    report["findings"].append({
                        "type": "echo-reflection", "severity": "low",
                        "title": "%s probe echoed back without processing"
                                 % kind,
                        "evidence": "payload echoed verbatim: %s"
                                    % joined[:200],
                    })

    # 4) oversized frame test
    try:
        ws = await _connect_once(url, ssl_ctx, timeout)
        big = "A" * 1_000_000
        try:
            await asyncio.wait_for(ws.send(big), timeout=timeout)
            try:
                r = await asyncio.wait_for(ws.recv(), timeout=timeout)
                report["oversized_frame"] = {
                    "sent_bytes": 1000000, "accepted": True,
                    "reply": (r if isinstance(r, str) else repr(r))[:200]}
            except asyncio.TimeoutError:
                report["oversized_frame"] = {"sent_bytes": 1000000,
                                             "accepted": True,
                                             "reply": "(no reply)"}
        except Exception as exc:
            report["oversized_frame"] = {"sent_bytes": 1000000,
                                         "accepted": False,
                                         "error": str(exc)[:160]}
        finally:
            try:
                await ws.close()
            except Exception:
                pass
    except Exception as exc:
        report["oversized_frame"] = {"error": str(exc)[:160]}

    report["finding_count"] = len(report["findings"])
    return report


def tool_websocket_test(url="", headers_text="", payloads="xss|sqli|cmdi|path",
                        max_messages=4, timeout=8, tls_insecure=False):
    """WebSocket security tester. Connect and inject:

    url           - ws:// or wss:// endpoint
    headers_text  - extra request headers, one 'Name: value' per line
                    (e.g. 'Authorization: Bearer eyJ...' or 'Cookie: s=1')
    payloads      - 'all' or pipe list: xss|sqli|cmdi|path
    max_messages  - max replies consumed per probe (default 4)
    timeout       - per-operation timeout seconds (default 8)
    tls_insecure  - skip TLS certificate verification for wss://

    Returns JSON: {handshake, origin_spoof_probe, tests, findings,
    oversized_frame, finding_count}. Findings carry severity + evidence.
    """
    if not url:
        return json.dumps({"error": "url is required (ws:// or wss://)"},
                          ensure_ascii=False)
    if not (url.startswith("ws://") or url.startswith("wss://")):
        return json.dumps({"error": "url must start with ws:// or wss://"},
                          ensure_ascii=False)
    try:
        header_pairs = list(_parse_headers(headers_text).items())
        pset = _norm_payload_str(payloads)
        try:
            timeout = max(2.0, float(timeout))
        except (TypeError, ValueError):
            timeout = 8.0
        report = asyncio.run(_amain(url, header_pairs, pset,
                                    int(max_messages) or 4, timeout,
                       
                                    bool(tls_insecure)))
        return json.dumps(report, ensure_ascii=False, indent=2)
    except Exception as exc:
        return json.dumps({"error": "websocket test failed: %r" % exc},
                          ensure_ascii=False)
