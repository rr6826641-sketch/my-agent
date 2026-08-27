"""Web & HTTP tools: requests, header audit, robots, links, tech detect."""

import re

import requests

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS - HTTPS enforcement; missing = risk"),
    ("Content-Security-Policy", "CSP - XSS protection; missing = risk"),
    ("X-Frame-Options", "Clickjacking protection; missing = risk"),
    ("X-Content-Type-Options", "MIME sniffing protection; missing = risk"),
    ("Referrer-Policy", "Referrer leakage control; missing = low risk"),
    ("Permissions-Policy", "Browser feature control; missing = low risk"),
]


def _get(url, timeout=20, headers=None):
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    return requests.get(url, headers=hdrs, timeout=timeout,
                        allow_redirects=True)


def tool_http_request(url, method="GET", headers=None, data=None, timeout=20,
                      max_body=4000):
    """Send a raw HTTP request and return status, headers, and body."""
    method = (method or "GET").upper()
    try:
        hdrs = {"User-Agent": USER_AGENT}
        if headers:
            hdrs.update(headers)
        resp = requests.request(method, url, headers=hdrs, data=data,
                                timeout=timeout, allow_redirects=True)
        body = resp.text[:max_body]
        hdr_lines = ["%s: %s" % (k, v) for k, v in resp.headers.items()]
        return ("URL: %s\nMETHOD: %s\nSTATUS: %d\nTIME: %.2fs\n"
                "FINAL URL: %s\n\n--- headers ---\n%s\n\n--- body (%d bytes) ---\n%s"
                % (url, method, resp.status_code, resp.elapsed.total_seconds(),
                   resp.url, "\n".join(hdr_lines), len(resp.content), body))
    except requests.exceptions.SSLError as exc:
        return "http_request SSL error: %s" % exc
    except requests.exceptions.RequestException as exc:
        return "http_request error: %s" % exc


def tool_check_headers(url, timeout=20):
    """Audit a URL's HTTP security headers."""
    try:
        resp = _get(url, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        return "check_headers error: %s" % exc
    lines = ["Target: %s (status %d)" % (resp.url, resp.status_code), ""]
    issues = 0
    for hname, note in SECURITY_HEADERS:
        val = resp.headers.get(hname)
        if val:
            lines.append("[OK]   %s: %s" % (hname, val[:80]))
        else:
            lines.append("[MISS] %s - %s" % (hname, note))
            issues += 1
    server = resp.headers.get("Server")
    if server:
        lines.append("\nServer: %s" % server)
    powered = resp.headers.get("X-Powered-By")
    if powered:
        lines.append("X-Powered-By: %s (may reveal tech stack)" % powered)
    cookies = resp.headers.get("Set-Cookie", "")
    if cookies:
        flags = [f.strip().lower() for f in cookies.split(";")[1:]]
        lines.append("Cookies set: %s" % cookies[:120])
        if "secure" not in flags:
            lines.append("[WARN] cookie missing Secure flag")
            issues += 1
        if "httponly" not in flags:
            lines.append("[WARN] cookie missing HttpOnly flag")
            issues += 1
    lines.append("\n%d header issue(s) found" % issues)
    return "\n".join(lines)


def tool_robots_txt(url, timeout=15):
    """Fetch a site's robots.txt."""
    base = url.rstrip("/")
    try:
        resp = _get(base + "/robots.txt", timeout=timeout)
        if resp.status_code == 404:
            return "robots.txt not found (404) on %s" % base
        body = resp.text[:4000]
        return ("Status: %d\n\n%s" % (resp.status_code, body)) if body.strip() \
            else "robots.txt is empty (status %d)" % resp.status_code
    except requests.exceptions.RequestException as exc:
        return "robots_txt error: %s" % exc


def tool_extract_links(url, timeout=20, max_links=60):
    """Extract all unique links (a href + script/img src) from a page."""
    try:
        resp = _get(url, timeout=timeout)
        html = resp.text
    except requests.exceptions.RequestException as exc:
        return "extract_links error: %s" % exc
    from urllib.parse import urljoin, urlparse
    found = []
    for tag in ("href", "src"):
        found += re.findall(r'%s=["\']([^"\']+)["\']' % tag, html, re.I)
    links = []
    seen = set()
    for link in found:
        if link.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        abs_url = urljoin(resp.url, link)
        if abs_url in seen:
            continue
        seen.add(abs_url)
        links.append(abs_url)
        if len(links) >= max_links:
            break
    host = urlparse(resp.url).netloc
    internal = [l for l in links if urlparse(l).netloc == host]
    external = [l for l in links if urlparse(l).netloc != host]
    out = ["Page: %s (status %d)" % (resp.url, resp.status_code),
           "Total unique links found: %d" % len(links), "",
           "--- internal (%d) ---" % len(internal)]
    out += internal[:40]
    out += ["", "--- external (%d, first 20) ---" % len(external)]
    out += external[:20]
    return "\n".join(out)


TECH_MARKERS = [
    ("WordPress", ["wp-content", "wp-includes", "generator\">WordPress"]),
    ("Joomla", ["/media/system/js/", "com_content"]),
    ("Drupal", ["/sites/default/files", "Drupal.settings"]),
    ("nginx", ["server: nginx", "nginx/"]),
    ("Apache", ["server: apache", "apache/"]),
    ("IIS", ["server: microsoft-iis", "x-powered-by: asp.net"]),
    ("Express/Node", ["x-powered-by: express"]),
    ("PHP", ["x-powered-by: php", "PHPSESSID"]),
    ("ASP.NET", ["viewstate", "__requestverificationtoken"]),
    ("jQuery", ["jquery"]),
    ("Bootstrap", ["bootstrap"]),
    ("React", ["_reactrootcontainer", "react.production"]),
    ("Vue.js", ["vue@", "data-v-"]),
    ("Google Analytics", ["google-analytics.com/analytics"]),
    ("Cloudflare", ["cf-ray", "cloudflare"]),
    ("GitHub Pages", ["github.com/.*/.*/blob/", "github pages"]),
    ("S3/Static Hosting", ["s3.amazonaws", "x-amz-bucket-region"]),
]


def tool_tech_detect(url, timeout=20):
    """Detect web technologies from response headers + page markers."""
    try:
        resp = _get(url, timeout=timeout)
        html = (resp.text or "")[:500000].lower()
    except requests.exceptions.RequestException as exc:
        return "tech_detect error: %s" % exc
    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
    found = []
    for tech, markers in TECH_MARKERS:
        for marker in markers:
            m = marker.lower()
            if m.startswith(("server:", "x-powered-by:")):
                if m.split(":")[0] in headers and m.split(":", 1)[1].strip() in headers.get(m.split(":")[0], ""):
                    found.append(tech)
                    break
            elif re.search(m, html) or m in html:
                found.append(tech)
                break
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                          resp.text, re.I)
    lines = ["Target: %s (status %d)" % (resp.url, resp.status_code)]
    if generator:
        lines.append("Generator meta: %s" % generator.group(1))
    lines.append("Server: %s" % resp.headers.get("Server", "(not disclosed)"))
    lines.append("X-Powered-By: %s" % resp.headers.get("X-Powered-By", "(none)"))
    lines.append("Detected: %s" % (", ".join(dict.fromkeys(found)) if found else "(none detected)"))
    return "\n".join(lines)


def tool_url_status(urls, timeout=10):
    """Check HTTP status of a comma-separated list of URLs."""
    if isinstance(urls, str):
        urls = [u.strip() for u in urls.split(",") if u.strip()]
    if not urls:
        return "url_status: provide at least one URL"
    out = []
    for url in urls:
        try:
            r = requests.get(url, headers={"User-Agent": USER_AGENT},
                             timeout=timeout, allow_redirects=False)
            out.append("%-8s %s" % (r.status_code, url))
        except requests.exceptions.RequestException as exc:
            out.append("%-8s %s (error: %s)" % ("ERR", url, exc.__class__.__name__))
    return "\n".join(out)
