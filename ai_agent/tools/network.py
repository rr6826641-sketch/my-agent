"""Network tools: DNS, port scan, RDAP whois, geoip, SSL, ping."""

import concurrent.futures
import datetime
import os
import socket
import ssl
import subprocess

import requests

DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,2375,3000,3306,3389,5432,5900,6379,8000,8080,8443,8888,9000,9090,9200,11211,27017"

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def _parse_port_list(spec):
    ports = set()
    if isinstance(spec, int):
        ports.add(spec)
    elif isinstance(spec, str):
        for part in spec.replace(" ", "").split(","):
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                try:
                    ports.update(range(int(a), int(b) + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    continue
    return sorted(ports)


def tool_dns_lookup(hostname, record_type="A"):
    """DNS lookup: A/AAAA/CNAME via socket; MX/NS/TXT via nslookup."""
    record_type = (record_type or "A").upper()
    if record_type in ("MX", "NS", "TXT", "SOA", "SRV"):
        if os.name == "nt":
            try:
                out = subprocess.run(["nslookup", "-type=%s" % record_type, hostname],
                                     capture_output=True, text=True, timeout=20,
                                     errors="replace").stdout
                return out.strip()[:4000] or "(no output)"
            except Exception as exc:
                return "dns_lookup error: %s" % exc
        try:
            out = subprocess.run(["dig", record_type, hostname],
                                 capture_output=True, text=True, timeout=20).stdout
            return out.strip()[:4000]
        except Exception as exc:
            return "dns_lookup error: %s" % exc
    try:
        if record_type == "A":
            results = socket.getaddrinfo(hostname, None, socket.AF_INET)
            ips = sorted({info[4][0] for info in results})
        elif record_type == "AAAA":
            results = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            ips = sorted({info[4][0] for info in results if "%" not in info[4][0]})
        elif record_type == "CNAME":
            out = subprocess.run(["nslookup", "-type=CNAME", hostname],
                                 capture_output=True, text=True, timeout=20,
                                 errors="replace").stdout
            return out.strip()[:3000] or "(no CNAME found)"
        else:
            return "dns_lookup: unsupported type %s (use A/AAAA/CNAME/MX/NS/TXT)" % record_type
        if not ips:
            return "(no %s records found for %s)" % (record_type, hostname)
        lines = ["%s records for %s:" % (record_type, hostname)]
        lines += ["  " + ip for ip in ips]
        return "\n".join(lines)
    except socket.gaierror:
        return "(DNS resolution failed for %s)" % hostname
    except Exception as exc:
        return "dns_lookup error: %s" % exc


def tool_reverse_dns(ip):
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        out = ["PTR: %s" % host]
        if aliases:
            out.append("aliases: %s" % ", ".join(aliases))
        return "\n".join(out)
    except socket.herror:
        return "(no reverse DNS record for %s)" % ip
    except Exception as exc:
        return "reverse_dns error: %s" % exc


def _grab_banner(sock):
    try:
        sock.settimeout(3)
        data = sock.recv(1024)
        return data.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


def _probe_port(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = _grab_banner(s)
            return port, True, banner
    except Exception:
        return port, False, ""


def tool_port_scan(host, ports=DEFAULT_PORTS, timeout=1.5, concurrency=150):
    """TCP connect port scan with banner grabbing (pure Python)."""
    port_list = _parse_port_list(ports)
    if not port_list:
        return "port_scan: no valid ports"
    if len(port_list) > 2000:
        return "port_scan: too many ports (max 2000)"
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(_probe_port, host, p, timeout): p for p in port_list}
        for fut in concurrent.futures.as_completed(futures):
            port, ok, banner = fut.result()
            if ok:
                open_ports.append((port, banner))
    open_ports.sort()
    if not open_ports:
        return "No open ports found on %s (scanned %d ports)" % (host, len(port_list))
    lines = ["Open ports on %s (scanned %d):" % (host, len(port_list))]
    for port, banner in open_ports:
        try:
            service = socket.getservbyport(port)
        except Exception:
            service = "unknown"
        line = "  %-5d %-12s" % (port, service)
        if banner:
            line += " banner: %s" % banner[:120]
        lines.append(line)
    return "\n".join(lines)


def tool_whois_rdap(domain_or_ip):
    """WHOIS-style lookup via RDAP (rdap.org) - no external dependency."""
    target = domain_or_ip.strip()
    try:
        url = "https://rdap.org/domain/" + target
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=25)
        if resp.status_code == 404:
            url = "https://rdap.org/ip/" + target
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=25)
        if resp.status_code != 200:
            return "whois: RDAP lookup failed (status %d) for %s" % (resp.status_code, target)
        data = resp.json()
    except requests.exceptions.RequestException as exc:
        return "whois error: %s" % exc
    except ValueError:
        return "whois: RDAP returned invalid JSON"
    lines = ["RDAP lookup for %s" % target]
    if data.get("handle"):
        lines.append("handle: %s" % data["handle"])
    if data.get("name"):
        lines.append("name: %s" % data["name"])
    status = data.get("status") or []
    if status:
        lines.append("status: %s" % ", ".join(status))
    events = data.get("events") or []
    for ev in events:
        if ev.get("eventAction") in ("registration", "last changed", "expiration"):
            lines.append("%s: %s" % (ev["eventAction"], ev.get("eventDate", "?")))
    ns = data.get("nameservers") or []
    if ns:
        lines.append("nameservers: %s" % ", ".join(n.get("ldhName", "?") for n in ns))
    entities = data.get("entities") or []
    for ent in entities[:6]:
        roles = ent.get("roles") or []
        vcard = ent.get("vcardArray", [])
        email = ""
        if len(vcard) > 1:
            for item in vcard[1]:
                if item[0] == "email":
                    email = item[3]
        if roles or email:
            lines.append("entity: roles=%s email=%s" % (",".join(roles), email or "n/a"))
    return "\n".join(lines) if len(lines) > 1 else "whois: no RDAP data for %s" % target


def tool_geoip_lookup(ip):
    """IP geolocation via ip-api.com (free, no key, HTTP)."""
    try:
        resp = requests.get("http://ip-api.com/json/%s" % ip.strip(),
                            headers={"User-Agent": USER_AGENT}, timeout=15)
        data = resp.json()
    except Exception as exc:
        return "geoip_lookup error: %s" % exc
    if data.get("status") != "success":
        return "geoip: lookup failed: %s" % data.get("message", "?")
    lines = ["IP: %s" % data.get("query"),
             "country: %s (%s)" % (data.get("country", "?"), data.get("countryCode", "?")),
             "region: %s" % data.get("regionName", "?"),
             "city: %s" % data.get("city", "?"),
             "zip: %s" % data.get("zip", "?"),
             "lat/lon: %s, %s" % (data.get("lat", "?"), data.get("lon", "?")),
             "timezone: %s" % data.get("timezone", "?"),
             "isp: %s" % data.get("isp", "?"),
             "org: %s" % data.get("org", "?"),
             "as: %s" % data.get("as", "?")]
    return "\n".join(lines)


def tool_ssl_info(host, port=443, timeout=15):
    """Inspect the TLS certificate of a host:port."""
    host = host.strip()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                cipher_str = "%s (%s, %d bits)" % cipher if isinstance(cipher, tuple) else str(cipher)
                lines = ["Host: %s:%d" % (host, port),
                         "TLS version: %s" % tls.version(),
                         "cipher: %s" % cipher_str]
                if not cert:
                    lines.append("certificate: (self-signed or unverifiable)")
                    return "\n".join(lines)
                lines.append("subject: %s" % _fmt_dn(cert.get("subject", [])))
                lines.append("issuer: %s" % _fmt_dn(cert.get("issuer", [])))
                lines.append("notBefore: %s" % cert.get("notBefore", "?"))
                lines.append("notAfter: %s" % cert.get("notAfter", "?"))
                sans = cert.get("subjectAltName", [])
                if sans:
                    lines.append("SANs: %s" % ", ".join("%s:%s" % s for s in sans[:20]))
                serial = cert.get("serialNumber")
                if serial:
                    lines.append("serial: %s" % serial)
                now = datetime.datetime.now(datetime.timezone.utc)
                try:
                    exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    exp = exp.replace(tzinfo=datetime.timezone.utc)
                    days = (exp - now).days
                    lines.append("expires in: %d days" % days)
                except Exception:
                    pass
                return "\n".join(lines)
    except ssl.SSLError as exc:
        return "ssl_info error: %s" % exc
    except socket.error as exc:
        return "ssl_info: connection failed: %s" % exc
    except Exception as exc:
        return "ssl_info error: %s" % exc


def _fmt_dn(dn_parts):
    parts = []
    for item in dn_parts:
        for key, val in item:
            parts.append("%s=%s" % (key, val))
    return ", ".join(parts)


def tool_ping_host(host, count=3, timeout=2000):
    """Ping a host (ICMP via system ping; 3 attempts default)."""
    host = host.strip()
    try:
        if os.name == "nt":
            cmd = ["ping", "-n", str(count), "-w", str(timeout), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout // 1000), host]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                              errors="replace")
        out = (proc.stdout or proc.stderr or "").strip()
        if not out:
            return "(ping returned no output)"
        return out[:3000]
    except subprocess.TimeoutExpired:
        return "(ping timed out)"
    except Exception as exc:
        return "ping_host error: %s" % exc
