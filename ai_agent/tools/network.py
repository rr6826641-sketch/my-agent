"""Network tools: DNS, port scan, RDAP whois, geoip, SSL, ping."""

import concurrent.futures
import datetime
import os
import socket
import ssl
import subprocess

import requests

DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,2375,3000,3306,3389,5432,5900,6379,8000,8080,8443,8888,9000,9090,9200,11211,27017"

# DEEP-SCAN POSTURE: full well-known range (1-1024) + the default set +
# high-value service ports commonly hidden above 1024 (admin UIs, DBs,
# caches, CI/CD, IoT, backdoors).  Built at import time, deduped + sorted,
# stays under the tool_port_scan 2000-port cap (~1100 ports total).
_DEEP_EXTRA_PORTS = (
    # legacy / alternate web + proxies
    81, 82, 83, 84, 85, 88, 90, 98, 100, 108, 250, 300, 400, 500, 600,
    808, 888, 900, 1080, 1111, 1234, 2000, 2001, 2080, 2096, 2323,
    3001, 3128, 3333, 4000, 4040, 4080, 4444, 4445, 4567, 5000, 5001,
    5050, 5555, 5556, 5601, 5666, 5800, 5810, 5901, 5984, 5985, 6080,
    6112, 6666, 6667, 7000, 7001, 7070, 7071, 7080, 7081, 7090, 7100,
    7144, 7173, 7200, 7272, 7443, 7474, 7478, 7500, 7547, 7575, 7777,
    # web tier / app servers / dev tooling
    8000, 8001, 8002, 8005, 8008, 8009, 8010, 8020, 8021, 8030, 8042,
    8060, 8069, 8070, 8072, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
    8088, 8089, 8090, 8091, 8095, 8098, 8100, 8111, 8112, 8120, 8123,
    8125, 8161, 8172, 8180, 8181, 8200, 8222, 8243, 8280, 8300, 8333,
    8383, 8400, 8444, 8500, 8530, 8531, 8600, 8649, 8686, 8765, 8787,
    8800, 8834, 8843, 8850, 8881, 8882, 8888, 8899, 8910, 8983, 8990,
    8999, 9001, 9002, 9003, 9005, 9009, 9010, 9030, 9040, 9042, 9043,
    9050, 9060, 9080, 9081, 9091, 9092, 9093, 9095, 9099, 9100, 9102,
    9111, 9152, 9191, 9201, 9210, 9300, 9312, 9418, 9443, 9500, 9530,
    9595, 9600, 9696, 9876, 9898, 9900, 9950, 9999, 10000, 10001,
    10080, 10082, 10100, 10180, 10250, 10443, 10566, 10600, 11000,
    11001, 11010, 11100, 11111, 11211, 11212, 11300, 11400, 11443,
    11500, 11600, 11700, 12000, 12174, 12201, 12321, 12345, 12445,
    12500, 12700, 12800, 12888, 12990, 13000, 13001, 13100, 13200,
    13300, 13500, 13600, 13700, 13800, 14000, 14100, 14200, 14300,
    14400, 14444, 14500, 14600, 14700, 14800, 15000, 15001, 15100,
    15200, 15300, 15400, 15500, 15600, 15672, 15800, 15900, 16000,
    16113, 16544, 16600, 16700, 16800, 17000, 17100, 17200, 17300,
    17400, 17500, 17600, 17700, 17800, 17900, 18000, 18080, 18100,
    18200, 18300, 18400, 18500, 18600, 18700, 18800, 18900,
    19000, 19100, 19200, 19300, 19400, 19500, 19600, 19700, 19800,
    19900, 20000, 20001, 20002, 20005, 20100, 20200, 20300, 20400,
    20500, 20600, 20700, 20800, 20900, 21000, 21100, 21200, 21300,
    21400, 21500, 21600, 21700, 21800, 21900, 22000, 22100, 22200,
    22222, 22300, 22400, 22500, 22600, 22700, 22800, 22900, 23000,
    23100, 23200, 23300, 23400, 23500, 23600, 23700, 2375, 23800,
    23900, 24000, 24100, 24200, 24300, 24400, 24500, 24600, 24700,
    24800, 24900, 25000, 25100, 25200, 25300, 25400, 25500, 25565,
    25600, 25700, 25800, 25900, 26000, 26100, 26200, 26300, 26379,
    26400, 26500, 26600, 26700, 26800, 26900, 27000, 27017, 27018,
    27100, 27200, 27300, 27400, 27500, 27600, 27700, 27800, 27900,
    28000, 28017, 28100, 28200, 28300, 28400, 28500, 28600, 28700,
    28800, 28900, 29000, 29100, 29200, 29300, 29400, 29500, 29600,
    29700, 29800, 29900, 30000, 30100, 30200, 30300, 30400, 30500,
    30600, 30700, 30800, 30900, 31000, 31100, 31200, 31300, 31337,
    31400, 31500, 31600, 31700, 31800, 31900, 32000, 32100, 32200,
    32300, 32400, 32500, 32600, 32700, 32768, 32800, 32900, 33000,
    33060, 33100, 33200, 33300, 33333, 33400, 33500, 33600, 33700,
    33800, 33900, 34000, 34100, 34200, 34300, 34400, 34500, 34600,
    34700, 34800, 34900, 35000, 35100, 35200, 35300, 35400, 35500,
    35600, 35700, 35800, 35900, 36000, 36100, 36200, 36300, 36400,
    36500, 36600, 36700, 36800, 36900, 37000, 37100, 37200, 37300,
    37400, 37500, 37600, 37700, 37800, 37900, 38000, 38100, 38200,
    38300, 38400, 38500, 38600, 38700, 38800, 38900, 39000, 39100,
    39200, 39300, 39400, 39500, 39600, 39700, 39800, 39900, 40000,
    40443, 41000, 42000, 43000, 44000, 44443, 45000, 46000, 47000,
    48000, 49000, 50000, 51000, 52000, 53000, 54000, 55000, 56000,
    57000, 58000, 59000, 60000,
)

_DEEP_PORTS_SET = set(range(1, 1025))
_DEEP_PORTS_SET |= set(int(x) for x in DEFAULT_PORTS.split(","))
_DEEP_PORTS_SET |= set(_DEEP_EXTRA_PORTS)
DEEP_PORTS = ",".join(str(p) for p in sorted(_DEEP_PORTS_SET))

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
