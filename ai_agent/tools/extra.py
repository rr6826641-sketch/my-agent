"""Extra security & utility tools: HTTP methods, CORS, WAF, redirects,
DNS AXFR, IOC extraction, cookie audit, local listeners, sqlite, password
strength, MAC vendor lookup, subnet calculator."""

import ipaddress
import math
import re
import socket
import sqlite3
import string
import subprocess

import requests

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def _get_session():
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def tool_http_methods(url, timeout=15):
    """Probe which HTTP methods a server allows (GET, POST, PUT, DELETE,
    PATCH, HEAD, OPTIONS, TRACE, CONNECT). TRACE enabled = XST risk."""
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
               "OPTIONS", "TRACE", "CONNECT"]
    s = _get_session()
    out = ["HTTP method probe: %s" % url, ""]
    try:
        r = s.request("OPTIONS", url, timeout=timeout)
        allow = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods")
        if allow:
            out.append("Server Allow header: %s" % allow)
        else:
            out.append("No Allow header returned (methods below are probes).")
        out.append("")
    except requests.exceptions.RequestException as exc:
        out.append("OPTIONS probe failed: %s" % exc)
        out.append("")
    for m in methods:
        try:
            r = s.request(m, url, timeout=timeout)
            flag = ""
            if m == "TRACE" and r.status_code in (200, 201):
                if "TRACE" in r.text[:200] or "Method: TRACE" in r.text[:200]:
                    flag = "  <-- TRACE enabled (XST risk!)"
            out.append("%-8s -> %s (len=%d)%s" % (m, r.status_code, len(r.content), flag))
        except requests.exceptions.RequestException as exc:
            out.append("%-8s -> error: %s" % (m, exc))
    return "\n".join(out)


def tool_cors_check(url, timeout=15):
    """Test CORS configuration by sending attacker-controlled origins and
    checking if Access-Control-Allow-Origin is reflected/trusted."""
    evil_origins = [
        "https://evil.com",
        "https://attacker.example.com",
        "https://sub.attacker.example.com",
        "null",
        "https://evil.com.evil.org",
    ]
    s = _get_session()
    out = ["CORS check: %s" % url, ""]
    for origin in evil_origins:
        try:
            r = s.get(url, timeout=timeout,
                      headers={"Origin": origin, "Cookie": "session=test123"})
            acao = r.headers.get("Access-Control-Allow-Origin", "(none)")
            acac = r.headers.get("Access-Control-Allow-Credentials", "(none)")
            reflected = acao.strip().lower() == origin.strip().lower()
            if reflected:
                status = "VULNERABLE: origin reflected"
                if acac.lower() == "true":
                    status += " + credentials allowed (account takeover risk)"
            elif acao == "*":
                status = "wildcard ACAO (no credentials; lower risk)"
            elif acao != "(none)":
                status = "specific origin allowed: %s" % acao
            else:
                status = "no ACAO header (safe)"
            out.append("Origin: %s\n  ACAO=%s ACAC=%s -> %s"
                       % (origin, acao, acac, status))
        except requests.exceptions.RequestException as exc:
            out.append("Origin: %s -> error: %s" % (origin, exc))
        out.append("")
    return "\n".join(out)


def tool_waf_detect(url, timeout=15):
    """Detect a WAF by fingerprinting headers and sending common
    attack-triggering payloads to compare responses."""
    s = _get_session()
    out = ["WAF detection: %s" % url, ""]
    try:
        r = s.get(url, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        return "waf_detect error: %s" % exc
    hdrs = r.headers
    out.append("Baseline: status=%d len=%d" % (r.status_code, len(r.content)))
    out.append("")
    signals = []
    for h in ("Server", "Via", "X-Powered-By", "CF-RAY", "x-amzn-RequestId",
              "X-Sucuri-ID", "X-CDN", "X-Frame-Options", "Cdn-Cache"):
        if hdrs.get(h):
            signals.append("%s: %s" % (h, hdrs[h]))
    if signals:
        out.append("Fingerprint headers:")
        out.extend("  " + s_ for s_ in signals)
    else:
        out.append("No WAF/CDN fingerprint headers found.")
    out.append("")
    probes = [
        ("sqli", "?id=1' OR '1'='1"),
        ("xss", "?q=<script>alert(1)</script>"),
        ("path_traversal", "?f=../../../../etc/passwd"),
        ("sqli_union", "?id=1 UNION SELECT 1,2,3--"),
        ("cmdi", "?cmd=;id"),
    ]
    out.append("Payload probes (status/len vs baseline):")
    base_len = len(r.content)
    for name, suffix in probes:
        try:
            sep = "&" if "?" in url else "?"
            p = s.get(url + sep + suffix.split("?", 1)[1], timeout=timeout)
            blocked = ""
            if p.status_code in (403, 406, 429) or len(p.content) != base_len:
                blocked = "  <-- possible block/anomaly"
            out.append("  %-16s -> %d (len=%d)%s"
                       % (name, p.status_code, len(p.content), blocked))
        except requests.exceptions.RequestException as exc:
            out.append("  %-16s -> error: %s" % (name, exc))
    return "\n".join(out)


def tool_redirect_chain(url, timeout=15, max_hops=10):
    """Follow the redirect chain of a URL and show every hop with its
    status code, location header, and host."""
    s = _get_session()
    out = ["Redirect chain: %s" % url, ""]
    current = url
    seen = set()
    for i in range(int(max_hops or 10)):
        if current in seen:
            out.append("  loop detected at %s" % current)
            break
        seen.add(current)
        try:
            r = s.request("GET", current, timeout=timeout, allow_redirects=False)
            loc = r.headers.get("Location", "")
            out.append("  hop %d: %d %s -> %s" % (i + 1, r.status_code, current, loc))
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                current = requests.compat.urljoin(r.url, loc)
                continue
            out.append("")
            out.append("Final: %s" % current)
            return "\n".join(out)
        except requests.exceptions.RequestException as exc:
            out.append("  hop %d: error: %s" % (i + 1, exc))
            return "\n".join(out)
    return "\n".join(out) + "\n(stopped at max hops)"


def tool_dns_axfr(domain, nameserver="", timeout=15):
    """Attempt a DNS zone transfer (AXFR). Zone transfer = full DNS record
    dump, a serious misconfiguration if allowed."""
    cmd = ["nslookup", "-type=axfr", domain]
    if nameserver:
        cmd.append(nameserver)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return "dns_axfr error: nslookup not found"
    except subprocess.TimeoutExpired:
        return "dns_axfr: timed out"
    out = r.stdout + r.stderr
    lines = [l for l in out.splitlines() if l.strip()]
    text = "\n".join(lines)
    if "Transfer failed" in text or "Can't find" in text or "server can't find" in text:
        return "AXFR refused or failed (server is properly configured):\n" + text[:1500]
    if len(lines) > 2:
        return ("AXFR returned records (zone transfer ALLOWED!):\n"
                + text[:6000])
    return "AXFR: no usable output:\n" + text[:1500]


def tool_extract_iocs(text):
    """Extract indicators of compromise from text: URLs, emails, IPv4/IPv6,
    domains, and hashes (MD5/SHA1/SHA256/SHA512)."""
    if not text:
        return "extract_iocs: empty input"
    iocs = {}
    iocs["urls"] = sorted(set(re.findall(
        r"https?://[^\s<>\"']+", text, re.I)))
    iocs["emails"] = sorted(set(re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)))
    iocs["ipv4"] = sorted(set(re.findall(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        text)))
    iocs["domains"] = sorted(set(re.findall(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|net|org|io|info|biz|dev|xyz|ai|pk|uk|us|de|ru|cn|in)\b",
        text, re.I)))
    hashes = []
    for hlen in (32, 40, 64, 128):
        hashes.extend(re.findall(r"\b[a-fA-F0-9]{%d}\b" % hlen, text))
    iocs["hashes"] = sorted(set(hashes))
    lines = ["Extracted IOCs", ""]
    total = 0
    for kind in ("urls", "emails", "ipv4", "domains", "hashes"):
        vals = iocs[kind]
        total += len(vals)
        lines.append("%s (%d):" % (kind, len(vals)))
        for v in vals[:40]:
            lines.append("  " + v)
        lines.append("")
    lines.append("Total: %d indicators" % total)
    return "\n".join(lines)


def tool_http_cookies(url, timeout=15):
    """Fetch a URL and audit its cookies: name, domain, path, flags
    (HttpOnly, Secure, SameSite), and expiry."""
    s = _get_session()
    try:
        r = s.get(url, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        return "http_cookies error: %s" % exc
    cookies = list(r.cookies)
    out = ["Cookie audit: %s (status %d)" % (r.url, r.status_code), ""]
    if not cookies:
        return "\n".join(out) + "No cookies set by this response."
    issues = []
    for c in cookies:
        flags = []
        if c.get_nonstandard_attr("HttpOnly") or "httponly" in str(c._rest).lower():
            flags.append("HttpOnly")
        else:
            flags.append("NO-HttpOnly")
            issues.append("%s: missing HttpOnly (XSS can steal it)" % c.name)
        if c.secure:
            flags.append("Secure")
        else:
            flags.append("NO-Secure")
            issues.append("%s: missing Secure (sent over plain HTTP)" % c.name)
        ss = c.get_nonstandard_attr("SameSite")
        if ss:
            flags.append("SameSite=%s" % ss)
        else:
            flags.append("SameSite=None?")
            issues.append("%s: no SameSite attribute" % c.name)
        out.append("  %s = %s" % (c.name, (c.value or "")[:40]))
        out.append("    domain=%s path=%s [%s]" % (c.domain, c.path, " ".join(flags)))
        if c.expires:
            out.append("    expires=%s" % c.expires)
        out.append("")
    out.append("Issues found: %d" % len(issues))
    for i in issues:
        out.append("  - " + i)
    return "\n".join(out)


def tool_local_listeners():
    """List locally listening TCP/UDP ports with owning process names
    (Windows: netstat + tasklist; Linux: ss)."""
    try:
        r = subprocess.run(["netstat", "-ano"], capture_output=True,
                           text=True, timeout=30)
        text = r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        try:
            r = subprocess.run(["ss", "-tulnp"], capture_output=True,
                               text=True, timeout=30)
            return "Listening sockets (ss):\n" + r.stdout[:6000]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return "local_listeners error: neither netstat nor ss available"
    lines = [l for l in text.splitlines()
             if "LISTENING" in l or "UDP" in l[:3]]
    if not lines:
        return "No listening sockets found (netstat parse issue)."
    pids = {}
    for l in lines:
        parts = l.split()
        if parts and parts[-1].isdigit():
            pids[parts[-1]] = True
    pid_names = {}
    for pid in pids:
        try:
            r = subprocess.run(["tasklist", "/FI", "PID eq %s" % pid],
                               capture_output=True, text=True, timeout=15)
            for row in r.stdout.splitlines():
                cols = row.split()
                if len(cols) >= 2 and cols[1] == pid:
                    pid_names[pid] = cols[0]
                    break
        except Exception:
            continue
    out = ["Local listening sockets:", ""]
    for l in lines:
        parts = l.split()
        if len(parts) >= 5:
            proto = parts[0]
            local = parts[1]
            state = parts[3] if len(parts) > 4 else ""
            pid = parts[-1]
            name = pid_names.get(pid, "?")
            out.append("  %-4s %-24s %-12s pid=%s (%s)"
                       % (proto, local, state, pid, name))
    return "\n".join(out[:120])


def tool_sqlite_query(db_path, query=".tables", timeout=15):
    """Run a read-only SQL query against a SQLite database file.
    Use '.tables' to list tables, '.schema' for CREATE statements."""
    if not db_path:
        return "sqlite_query: db_path is required"
    try:
        uri = "file:%s?mode=ro" % db_path.replace("\\", "/")
        conn = sqlite3.connect(uri, uri=True, timeout=timeout)
        cur = conn.cursor()
        q = (query or ".tables").strip()
        if q == ".tables":
            rows = cur.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view') "
                "ORDER BY name").fetchall()
            conn.close()
            return "Tables/views in %s:\n%s" % (
                db_path, "\n".join("  " + r[0] for r in rows) or "  (none)")
        if q.lower().startswith(".schema"):
            target = q.split(None, 1)[1] if " " in q else "%"
            rows = cur.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE sql IS NOT NULL AND (name LIKE ? OR type='table')",
                ("%" + target.strip("%") + "%",)).fetchall()
            conn.close()
            return "\n\n".join("-- %s\n%s" % (r[0], r[1]) for r in rows[:20]) \
                or "No schema found."
        cur.execute(q)
        if q.strip().lower().startswith(("select", "pragma", "with")):
            cols = [d[0] for d in cur.description or []]
            rows = cur.fetchmany(50)
            conn.close()
            if not cols:
                return "(query returned no columns)"
            w = [max(len(str(c)), max((len(str(r[i])) for r in rows),
                                      default=0)) for i, c in enumerate(cols)]
            lines = ["  ".join(str(c).ljust(w[i]) for i, c in enumerate(cols))]
            lines.append("  ".join("-" * w[i] for i in range(len(cols))))
            for row in rows:
                lines.append("  ".join(str(v).ljust(w[i])
                                       for i, v in enumerate(row)))
            lines.append("")
            lines.append("(%d rows shown)" % len(rows))
            return "\n".join(lines)
        conn.commit()
        affected = cur.rowcount
        conn.close()
        return "Query OK, %s rows affected." % affected
    except sqlite3.Error as exc:
        return "sqlite_query error: %s" % exc
    except Exception as exc:
        return "sqlite_query error: %s: %s" % (type(exc).__name__, exc)


def tool_password_strength(password):
    """Analyze a password: length, charset variety, entropy, crack-time
    estimate, and a strength score (0-4)."""
    if not password:
        return "password_strength: password is required"
    pw = str(password)
    n = len(pw)
    pools = 0
    kinds = []
    if re.search(r"[a-z]", pw):
        pools += 26
        kinds.append("lowercase")
    if re.search(r"[A-Z]", pw):
        pools += 26
        kinds.append("uppercase")
    if re.search(r"[0-9]", pw):
        pools += 10
        kinds.append("digits")
    if re.search(r"[^A-Za-z0-9]", pw):
        pools += 33
        kinds.append("symbols")
    entropy = n * math.log2(max(pools, 1)) if n else 0
    if entropy < 28:
        score, label = 0, "Very weak"
    elif entropy < 36:
        score, label = 1, "Weak"
    elif entropy < 60:
        score, label = 2, "Fair"
    elif entropy < 80:
        score, label = 3, "Strong"
    else:
        score, label = 4, "Very strong"
    common = pw.lower() in {"password", "123456", "12345678", "qwerty",
                            "abc123", "admin", "letmein", "welcome",
                            "iloveyou", "monkey", "dragon", "password123"}
    if common:
        score, label = 0, "Very weak (commonly used password)"
    out = ["Password strength analysis", ""]
    out.append("  Length      : %d chars" % n)
    out.append("  Charset     : %s" % ", ".join(kinds) or "none")
    out.append("  Pool size   : %d possible chars" % pools)
    out.append("  Entropy     : %.1f bits" % entropy)
    out.append("  Score       : %d/4 - %s" % (score, label))
    if common:
        out.append("  NOTE        : found in common password lists!")
    return "\n".join(out)


def tool_mac_vendor(mac_address, timeout=15):
    """Look up the NIC vendor (OUI) for a MAC address via macvendors.com,
    with a small offline fallback table for common OUIs."""
    mac = (mac_address or "").strip().lower()
    if not mac:
        return "mac_vendor: MAC address is required"
    oui = re.sub(r"[^0-9a-f]", "", mac)[:6]
    if len(oui) != 6:
        return "mac_vendor: invalid MAC address format"
    offline = {
        "000c29": "VMware",
        "005056": "VMware",
        "001c14": "VMware",
        "080027": "Oracle VirtualBox",
        "00155d": "Microsoft Hyper-V",
        "0003ff": "Microsoft (Hyper-V/Xbox)",
        "525400": "QEMU/KVM",
        "f8ffc2": "Wistron (common on Windows boards)",
        "a0369f": "Espressif (ESP32)",
        "b827eb": "Raspberry Pi Foundation",
    }
    off = offline.get(oui)
    if off:
        return "MAC %s (OUI %s) -> %s (offline table)" % (mac, oui, off)
    try:
        r = requests.get("https://api.macvendors.com/%s" % oui,
                         timeout=timeout, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200 and r.text.strip():
            return "MAC %s (OUI %s) -> %s" % (mac, oui, r.text.strip())
        return "MAC %s: OUI %s not found (or lookup rate-limited)" % (mac, oui)
    except requests.exceptions.RequestException as exc:
        return "mac_vendor lookup error: %s" % exc


def tool_subnet_calc(cidr):
    """Calculate network details for a CIDR block: mask, network,
    broadcast, usable hosts, and first/last addresses."""
    if not cidr:
        return "subnet_calc: CIDR is required (e.g. 192.168.1.0/24)"
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        return "subnet_calc error: %s" % exc
    hosts = list(net.hosts())
    total = net.num_addresses
    if net.prefixlen == 32:
        usable = 1
        first = last = str(net.network_address)
    elif net.prefixlen == 31:
        usable = 2
        first, last = str(hosts[0]), str(hosts[-1])
    else:
        usable = len(hosts)
        first = str(hosts[0]) if hosts else "-"
        last = str(hosts[-1]) if hosts else "-"
    return ("CIDR         : %s\n"
            "Network      : %s\n"
            "Netmask      : %s\n"
            "Wildcard     : %s\n"
            "Broadcast    : %s\n"
            "Total addrs  : %d\n"
            "Usable hosts : %d\n"
            "First usable : %s\n"
            "Last usable  : %s"
            % (cidr, net.network_address, net.netmask, net.hostmask,
               net.broadcast_address, total, usable, first, last))
