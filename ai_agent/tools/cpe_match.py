# -*- coding: utf-8 -*-
"""CPE -> NUCLEI AUTO-TEMPLATE MATCH.

Sniper approach, not a blind full-scan: pull real banners with
nmap -sV, normalise them into CPE strings, index the local
nuclei-templates directory once (cached), and run ONLY the templates
that actually match the detected product / version / CVE list.

Less noise, less detection surface, faster passes.

Public tools:
    cpe_scan            - nmap -sV banner -> per-port CPE table (live host)
    cpe_extract         - parse free-text nmap output into CPE rows
    cpe_match           - CPE string / product keyword -> matched template paths
    cpe_nuclei_scan     - full pipeline on one URL (banner -> CPE -> templates -> nuclei)
    cpe_template_index  - inspect / rebuild the local template index

NO FILTERS: whatever matches is reported. The pin system upstream
keeps the whole chain 100% uncensored-tier.
"""

import io
import json
import os
import re
import time

from .pentest import _which, _run, tool_nuclei_scan

_SV_LINE_RE = re.compile(
    r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+([^\s]+)\s*"
    r"(?:([A-Za-z][A-Za-z0-9_\-\./]*?)\s+)?([^\r\n]*)$")
_CVE_TAG_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CPE_META_RE = re.compile(
    r"cpe\s*[:=]\s*[\"']?(cpe:2\.3:[aho][^\"'\s,}]+)", re.IGNORECASE)
_VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,3}[a-z0-9\-]*)", re.IGNORECASE)

# product-name aliases so a banner token maps to canonical keywords used
# by nuclei template names / cpe metadata.
_ALIASES = {
    "httpd": "apache",
    "apache_http_server": "apache",
    "apache-http-server": "apache",
    "apache http server": "apache",
    "opendistro": "opendistro",
    "microsoft-httpd": "iis",
    "iis": "iis",
    "openssh": "openssh",
    "open_ssh": "openssh",
    "nginx": "nginx",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "wordpress": "wordpress",
    "joomla": "joomla",
    "drupal": "drupal",
    "tomcat": "tomcat",
    "apache_tomcat": "tomcat",
    "jboss": "jboss",
    "wildfly": "wildfly",
    "php": "php",
    "nodejs": "node",
    "node.js": "node",
    "express": "express",
    "ruby": "ruby",
    "rails": "rails",
    "python": "python",
    "django": "django",
    "flask": "flask",
    "asp.net": "aspnet",
    "angularjs": "angular",
    "angular": "angular",
    "react": "react",
    "vite": "vite",
    "svelte": "svelte",
    "elixir": "elixir",
    "phoenix": "phoenix",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "docker": "docker",
    "traefik": "traefik",
    "caddy": "caddy",
    "haproxy": "haproxy",
    "envoy": "envoy",
    "istio": "istio",
    "varnish": "varnish",
    "squid": "squid",
    "miniupnp": "miniupnp",
    "sslip": "sslip",
    "openssl": "openssl",
    "awk": "awk",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "exim": "exim",
    "postfix": "postfix",
    "sendmail": "sendmail",
    "dovecot": "dovecot",
    "opensmtpd": "opensmtpd",
    "smtp": "smtp",
    "pop3": "pop3",
    "imap": "imap",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgres",
    "postgres": "postgres",
    "mongodb": "mongodb",
    "mongod": "mongodb",
    "redis": "redis",
    "memcached": "memcached",
    "rabbitmq": "rabbitmq",
    "elasticsearch": "elasticsearch",
    "kibana": "kibana",
    "logstash": "logstash",
    "solr": "solr",
    "cassandra": "cassandra",
    "couchdb": "couchdb",
    "sqlite": "sqlite",
    "mssql": "mssql",
    "oracle": "oracle",
    "db2": "db2",
    "firebird": "firebird",
    "cockroachdb": "cockroachdb",
    "grafana": "grafana",
    "prometheus": "prometheus",
    "zabbix": "zabbix",
    "nagios": "nagios",
    "centreon": "centreon",
    "phpmyadmin": "phpmyadmin",
    "adminer": "adminer",
    "cacti": "cacti",
    "librenms": "librenms",
    "openvpn": "openvpn",
    "wireguard": "wireguard",
    "strongswan": "strongswan",
    "ipsec": "ipsec",
    "openswan": "openswan",
    "kerberos": "kerberos",
    "ntp": "ntp",
    "mdns": "mdns",
    "snmp": "snmp",
    "samba": "samba",
    "smb": "smb",
    "nfs": "nfs",
    "ftp": "ftp",
    "telnet": "telnet",
    "rsh": "rsh",
    "ssh": "ssh",
    "rdp": "rdp",
    "vnc": "vnc",
}

# canonical product -> likely nuclei template directory keywords
_CATEGORY_HINTS = {
    "apache": ["apache", "http_server", "httpd"],
    "iis": ["iis", "microsoft"],
    "nginx": ["nginx"],
    "tomcat": ["tomcat", "apache"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "wordpress": ["wordpress", "wp-"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "php": ["php"],
    "node": ["nodejs", "node"],
    "express": ["express"],
    "flask": ["flask", "python"],
    "django": ["django", "python"],
    "ruby": ["ruby", "rails"],
    "mysql": ["mysql"],
    "mariadb": ["mariadb"],
    "postgres": ["postgres"],
    "mongodb": ["mongodb"],
    "redis": ["redis"],
    "elasticsearch": ["elastic", "kibana"],
    "kibana": ["kibana", "elastic"],
    "grafana": ["grafana"],
    "phpmyadmin": ["phpmyadmin"],
    "cacti": ["cacti"],
    "openvpn": ["openvpn"],
    "openssh": ["openssh", "ssh"],
    "samba": ["samba", "smb"],
    "vsftpd": ["vsftpd", "ftp"],
    "proftpd": ["proftpd", "ftp"],
    "exim": ["exim", "smtp"],
    "postfix": ["postfix", "smtp"],
    "dovecot": ["dovecot", "imap"],
}

_INDEX_CACHE_NAME = "cpe_template_index.json"


def _canonical(product):
    p = (product or "").strip().lower()
    if not p:
        return ""
    return _ALIASES.get(p, p)


def _find_templates_dir():
    """Locate local nuclei-templates directory (checked candidates)."""
    env = os.environ.get("NUCLEI_TEMPLATES", "").strip()
    if env and os.path.isdir(env):
        return env
    home = os.path.expanduser("~")
    candidates = []
    for base in (home,
                 os.environ.get("APPDATA", ""),
                 os.environ.get("LOCALAPPDATA", ""),
                 os.environ.get("NUCLEI_CONFIG", "")):
        if not base:
            continue
        candidates.append(os.path.join(base, "nuclei-templates"))
        candidates.append(os.path.join(base, "nuclei", "nuclei-templates"))
        candidates.append(os.path.join(base, ".nuclei", "nuclei-templates"))
    seen = set()
    for c in candidates:
        c = os.path.normpath(c)
        if c in seen or not c:
            continue
        seen.add(c)
        if os.path.isdir(c) and any(
                os.path.isdir(os.path.join(c, d))
                for d in ("http", "network", "dns", "ssl")):
            return c
    return ""


def _CACHE_PATH():
    cdir = os.path.join(os.getcwd(), "data")
    try:
        os.makedirs(cdir, exist_ok=True)
    except Exception:
        cdir = os.getcwd()
    return os.path.join(cdir, _INDEX_CACHE_NAME)


def _build_index(templates_dir):
    """Walk templates once and index 'cpe:' metadata + CVE ids.

    Returns {products: {keyword: [paths]}, cves: {CVE: [paths]},
             templates: total, entries: [ {path, cpe, cves, id} ]}
    """
    root = templates_dir.rstrip("\\/")
    walk_dirs = [os.path.join(root, "http", "cves"),
                 os.path.join(root, "http", "technologies"),
                 os.path.join(root, "http", "vulnerabilities"),
                 os.path.join(root, "http", "exposures"),
                 os.path.join(root, "network", "cves"),
                 os.path.join(root, "network", "detect")]
    seen_dirs = set()
    products, cves = {}, {}
    entries = []
    total = 0
    for start in walk_dirs:
        if not os.path.isdir(start):
            continue
        for dirpath, dirnames, filenames in os.walk(start):
            dn = os.path.normpath(dirpath)
            if dn in seen_dirs:
                del dirnames[:]
                continue
            seen_dirs.add(dn)
            for fn in filenames:
                if not fn.lower().endswith((".yaml", ".yml")):
                    continue
                if fn.startswith((".", "_")):
                    continue
                path = os.path.join(dirpath, fn)
                total += 1
                try:
                    size = os.path.getsize(path)
                    if size > 6 * 1024 * 1024:
                        continue
                    with io.open(path, "r", encoding="utf-8",
                                 errors="replace") as fh:
                        head = fh.read(4096)
                    cpes = _CPE_META_RE.findall(head)
                    cve_ids = sorted(set(_CVE_TAG_RE.findall(head)))[:6]
                    tpl_id = ""
                    m = re.search(r"^id\s*:\s*([\w\-\d]+)",
                                  head, re.MULTILINE | re.IGNORECASE)
                    if m:
                        tpl_id = m.group(1).strip()
                    # product keywords from cpe metadata + path
                    keys = set()
                    for c in cpes:
                        parts = c.split(":")
                        if len(parts) >= 5:
                            keys.add(parts[4].replace("_", " "))
                    lpath = path.lower().replace("\\", "/")
                    if "/cves/" in lpath or "/technologies/" in lpath:
                        stem = os.path.splitext(fn)[0].lower()
                        keys.update(stem.split("-"))
                    for k in keys:
                        k = k.strip()
                        if not k or len(k) < 3:
                            continue
                        products.setdefault(k, []).append(path)
                    for cvid in cve_ids:
                        cves.setdefault(cvid.upper(), []).append(path)
                    entries.append({
                        "path": path, "id": tpl_id, "cpe": cpes[:3],
                        "cves": cve_ids})
                except Exception:
                    continue
    return {"products": products, "cves": cves,
            "templates": total, "entries": entries[:2000],
            "built_at": time.strftime("%Y-%m-%d %H:%M:%S")}


def _load_index(rebuild=False):
    tdir = _find_templates_dir()
    if not tdir:
        return {"error": ("nuclei-templates directory not found. Run: "
                          "nuclei -update-templates first")}
    cache = _CACHE_PATH()
    if not rebuild and os.path.exists(cache):
        try:
            with io.open(cache, "r", encoding="utf-8") as fh:
                idx = json.load(fh)
            if idx.get("source") == tdir and \
               abs(time.time() - idx.get("ts", 0)) < 6 * 3600:
                return idx
        except Exception:
            pass
    idx = _build_index(tdir)
    idx["source"] = tdir
    idx["ts"] = time.time()
    try:
        with io.open(cache, "w", encoding="utf-8") as fh:
            json.dump(idx, fh, ensure_ascii=False)
    except Exception:
        pass
    return idx


def _match_templates(products, index):
    """Given a list of canonical product keywords, return template paths
    that reference any of them (deduped, capped)."""
    hits, seen = [], set()
    src = index.get("products", {})
    for prod in products:
        prod = (prod or "").strip().lower()
        if not prod:
            continue
        cats = _CATEGORY_HINTS.get(prod, [prod])
        # also expand aliases in reverse
        for alias, canon in _ALIASES.items():
            if canon == prod:
                cats.append(alias)
        words = set()
        for c in cats:
            for tok in re.split(r"[\s_\-.]+", c):
                tok = tok.strip()
                if len(tok) >= 3:
                    words.add(tok)
        for w in words:
            for path in src.get(w, []):
                if path not in seen:
                    seen.add(path)
                    hits.append(path)
    return hits[:120]


def _match_cve_templates(cve_ids, index):
    """Template paths whose metadata / filename reference given CVEs."""
    hits, seen = [], set()
    src = index.get("cves", {})
    for cid in cve_ids or []:
        cid = str(cid).upper()
        for path in src.get(cid, []):
            if path not in seen:
                seen.add(path)
                hits.append(path)
    return hits


# --------------------------------------------------------------------------
# banner parsing
# --------------------------------------------------------------------------

def _parse_sv(text):
    """Parse nmap -sV output into rows:
    {port, proto, service, product, version, cpe}"""
    rows = []
    for line in (text or "").splitlines():
        m = _SV_LINE_RE.match(line)
        if not m:
            continue
        port, proto, service = m.group(1), m.group(2), m.group(3)
        product_raw = (m.group(4) or "").strip()
        trailer = (m.group(5) or "").strip()
        product = product_raw
        version = ""
        if product_raw:
            vm = _VERSION_RE.search(trailer) if trailer else None
            if vm:
                version = vm.group(1)
                trailer = trailer.replace(vm.group(1), "", 1).strip()
        else:
            # "open http Apache httpd 2.4.49" -> product from trailer
            parts = trailer.split()
            product = parts[0] if parts else ""
            rest = parts[1:] if len(parts) > 1 else []
            if rest:
                vm = _VERSION_RE.search(" ".join(rest))
                if vm:
                    version = vm.group(1)
        cpe = ""
        c = _CPE_META_RE.search(line) if _CPE_META_RE.search(text) else None
        if c:
            cpe = c.group(1)
        elif product:
            canon = _canonical(product)
            prod_token = canon.replace(" ", "_") or product.lower()
            cpe = "cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*" % (
                prod_token.split("_")[0] if "_" in prod_token else prod_token,
                prod_token, version or "*")
        rows.append({
            "port": port, "proto": proto, "service": service,
            "product": product, "version": version, "cpe": cpe})
    return rows


def tool_cpe_extract(banner_text=""):
    """Parse raw nmap -sV / banner text into CPE rows."""
    if not (banner_text or "").strip():
        return ("cpe_extract: provide nmap -sV output text, e.g. "
                "'80/tcp open http Apache httpd 2.4.49'")
    rows = _parse_sv(banner_text)
    if not rows:
        return ("(no service/version lines matched - raw banner must look like "
                "'80/tcp open http Apache httpd 2.4.49')")
    lines = ["cpe_extract: %d services parsed" % len(rows)]
    for r in rows:
        lines.append("- %s/%s %s | %s %s | %s" % (
            r["port"], r["proto"], r["service"], r["product"] or "?",
            r["version"] or "", r["cpe"]))
    return "\n".join(lines)


def tool_cpe_scan(host="", ports=""):
    """Run nmap -sV against a host and return CPE rows per open port."""
    exe = _which("nmap")
    if not exe:
        return ("nmap is not installed - cannot pull banners. "
                "Use cpe_extract with existing nmap output, or "
                "tool_nmap_scan first.")
    host = (host or "").strip()
    if not host:
        return "cpe_scan: provide a host"
    cmd = [exe, "-Pn", "-sV", "-T4", "--open"]
    if ports:
        cmd += ["-p", str(ports).strip()]
    cmd.append(host)
    out = _run(cmd, timeout=480)
    if "[exit code" in out and "0]" not in out.split("]")[1][:3]:
        return "cpe_scan: nmap failed.\n%s" % out[:800]
    rows = _parse_sv(out)
    if not rows:
        return "cpe_scan: no version rows in nmap output.\n%s" % out[:800]
    lines = ["cpe_scan: %s -> %d services" % (host, len(rows))]
    for r in rows:
        lines.append("- %s/%s %s | %s %s | %s" % (
            r["port"], r["proto"], r["service"], r["product"] or "?",
            r["version"] or "", r["cpe"]))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# template match + nuclei run
# --------------------------------------------------------------------------

def tool_cpe_match(cpe_or_product="", rebuild=False):
    """Resolve a CPE string or product keyword to matched nuclei
    template paths from the local index."""
    query = (cpe_or_product or "").strip()
    if not query:
        return ("cpe_match: provide a CPE string (cpe:2.3:a:apache:...) "
                "or product keyword (apache, nginx, tomcat ...)")
    index = _load_index(rebuild=bool(rebuild))
    if index.get("error"):
        return "cpe_match: %s" % index["error"]
    products = []
    if query.lower().startswith("cpe:"):
        parts = query.split(":")
        if len(parts) >= 5:
            products.append(_canonical(parts[4].replace("_", " ")))
    products.append(_canonical(query))
    hits = _match_templates(products, index)
    if not hits:
        return ("cpe_match: no template matched %r (index: %d templates, "
                "products=%d)" % (query, index.get("templates", 0),
                                  len(index.get("products", {}))))
    lines = ["cpe_match: %r -> %d templates" % (query, len(hits))]
    for h in hits[:40]:
        lines.append("- %s" % h)
    return "\n".join(lines)


def tool_cpe_nuclei_scan(url="", banner="", ports="", rebuild=False,
                         extra_cves=""):
    """SNIPER PIPELINE: banner/CPE -> matched templates -> nuclei run.

    Prefer explicit `banner` text (nmap -sV output). If banner is empty,
    runs cpe_scan against the URL's host automatically.
    """
    url = (url or "").strip()
    if not url:
        return ("cpe_nuclei_scan: provide a URL. Example: "
                "cpe_nuclei_scan(url='http://10.0.0.7:8080/', "
                "banner='80/tcp open http Apache httpd 2.4.49')")
    host = url.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
    rows = []
    if (banner or "").strip():
        rows = _parse_sv(banner)
    if not rows and host:
        scan_out = tool_cpe_scan(host, ports)
        if "->" in scan_out:
            for ln in scan_out.splitlines():
                mm = re.match(r"^-\s+(\d+)/(tcp|udp)\s+(\S+)\s*\|\s*([^|]*)\s*\|\s*(cpe:.*)$", ln)
                if mm:
                    rows.append({"port": mm.group(1), "proto": mm.group(2),
                                 "service": mm.group(3),
                                 "product": mm.group(4).split()[0] if mm.group(4).split() else "",
                                 "version": mm.group(4).split()[-1] if len(mm.group(4).split()) > 1 else "",
                                 "cpe": mm.group(5)})
    index = _load_index(rebuild=bool(rebuild))
    if index.get("error"):
        return "cpe_nuclei_scan: %s" % index["error"]
    products, cve_ids = [], []
    for r in rows:
        if r.get("product"):
            products.append(_canonical(r["product"]))
    for c in (extra_cves or "").split(","):
        c = c.strip()
        if c and re.match(r"^CVE-\d{4}-\d{4,7}$", c, re.IGNORECASE):
            cve_ids.append(c)
    hits = _match_templates(products, index)
    hits += _match_cve_templates(cve_ids, index)
    seen = set()
    hits = [h for h in hits if not (h in seen or seen.add(h))]
    if not hits:
        return ("cpe_nuclei_scan: no templates matched for %r (banner had "
                "%d service rows). Run with rebuild=true after "
                "nuclei -update-templates." % (banner or url, len(rows)))
    parts = []
    out_lines = ["cpe_nuclei_scan: sniper run on %s" % url,
                 "  products: %s" % (", ".join(sorted(set(products))) or "-"),
                 "  cves: %s" % (", ".join(cve_ids) or "-"),
                 "  matched templates: %d" % len(hits)]
    for h in hits:
        parts.append("-t")
        parts.append(h)
    cmd = [_which("nuclei") or "nuclei", "-u", url, "-silent",
           "-severity", "low,medium,high,critical"] + parts
    res = _run(cmd, timeout=480)
    out_lines.append(res[:2500])
    return "\n".join(out_lines)


def tool_cpe_template_index(rebuild=False):
    """Inspect (or rebuild with rebuild=true) the local template index."""
    index = _load_index(rebuild=bool(rebuild))
    if index.get("error"):
        return "cpe_template_index: %s" % index["error"]
    return (
        "cpe_template_index: source=%s\n"
        "  templates indexed: %d\n"
        "  product keys: %d\n"
        "  cve keys: %d\n"
        "  built: %s" % (
            index.get("source", "?"), index.get("templates", 0),
            len(index.get("products", {})), len(index.get("cves", {})),
            index.get("built_at", "?")))