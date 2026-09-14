"""OSINT tools: open-source intelligence gathering.

All tools use free, keyless public endpoints (crt.sh, Wayback Machine CDX,
emailrep.io, rdap.org) or pure-Python local parsing (EXIF/PNG/PDF/Office
metadata, phone prefixes, dork generation). Match the codebase convention:
UC browser User-Agent, defensive try/except, human-readable text responses.
"""

import concurrent.futures
import datetime
import json
import os
import re
import struct
import zipfile

import requests

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
HTTP_TIMEOUT = 20

# ---------------------------------------------------------------------------
# 1. Certificate Transparency (extended) - subdomains + issuer + validity
# ---------------------------------------------------------------------------

def tool_osint_ct_subdomains(domain, max_results=150):
    """Enumerate subdomains from Certificate Transparency logs via crt.sh,
    including the issuing CA and certificate validity window for each name.
    Great for discovering shadow/hidden subdomains before they are indexed."""
    domain = (domain or "").strip().lower().lstrip("*.")
    if not domain or "." not in domain:
        return "osint_ct_subdomains: invalid domain"
    try:
        resp = requests.get(
            "https://crt.sh/?q=%25.%s&output=json" % domain,
            headers={"User-Agent": USER_AGENT}, timeout=40)
    except requests.exceptions.RequestException as exc:
        return "osint_ct_subdomains: crt.sh request failed: %r" % exc
    if resp.status_code != 200:
        return "osint_ct_subdomains: crt.sh status %d" % resp.status_code
    try:
        data = resp.json()
    except ValueError:
        return "osint_ct_subdomains: crt.sh returned invalid JSON"
    subs = {}
    for entry in data:
        for n in (entry.get("name_value") or "").split("\n"):
            n = n.strip().lower().lstrip("*").strip()
            if not n or not n.endswith("." + domain):
                continue
            rec = subs.setdefault(n, {"issuer": set(), "not_before": None,
                                      "not_after": None, "certs": 0})
            issuer = entry.get("issuer_name") or ""
            if issuer:
                rec["issuer"].add(issuer.split(",")[0])
            nb = entry.get("not_before") or ""
            na = entry.get("not_after") or ""
            if nb and (not rec["not_before"] or nb < rec["not_before"]):
                rec["not_before"] = nb
            if na and (not rec["not_after"] or na > rec["not_after"]):
                rec["not_after"] = na
            rec["certs"] += 1
    if not subs:
        return "osint_ct_subdomains: no certificates found for %s" % domain
    lines = ["osint_ct_subdomains: %d unique subdomains for %s "
             "(issuer / valid window):" % (len(subs), domain)]
    for name in sorted(subs)[:max_results]:
        r = subs[name]
        issuer = ", ".join(sorted(r["issuer"])) or "?"
        window = "%s -> %s" % (r["not_before"][:10], r["not_after"][:10]) \
            if r["not_before"] and r["not_after"] else "?"
        lines.append("  %-45s %-28s %s  (%d certs)" %
                     (name, issuer[:26], window, r["certs"]))
    if len(subs) > max_results:
        lines.append("  ... %d more" % (len(subs) - max_results))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 2. Wayback Machine - historical URLs, status codes, interesting files
# ---------------------------------------------------------------------------

_INTERESTING_EXT = (".env", ".sql", ".bak", ".conf", ".config", ".json",
                    ".git", ".svn", ".yaml", ".yml", ".pem", ".key",
                    ".htpasswd", ".htaccess", ".log", ".tar", ".zip",
                    ".gz", ".pdf", ".xls", ".xlsx", ".doc", ".docx")

def tool_osint_wayback_urls(domain, limit=200):
    """Query the Wayback Machine CDX API for the target domain's URL
    history: every archived URL with timestamp and HTTP status code.
    Flags interesting file extensions (.env/.sql/.bak/.git/...) and login
    panels so the agent can pivot to exposed artifacts."""
    domain = (domain or "").strip().lower()
    if not domain or "." not in domain:
        return "osint_wayback_urls: invalid domain"
    cdx = ("https://web.archive.org/cdx/search/cdx"
           "?url=%s/*&output=json&fl=timestamp,original,statuscode"
           "&collapse=urlkey&filter=statuscode:200&limit=%d"
           % (domain, int(limit) + 50))
    try:
        resp = requests.get(cdx, headers={"User-Agent": USER_AGENT},
                            timeout=40)
    except requests.exceptions.RequestException as exc:
        return "osint_wayback_urls: CDX request failed: %r" % exc
    if resp.status_code != 200:
        return "osint_wayback_urls: CDX status %d" % resp.status_code
    try:
        rows = resp.json()
    except ValueError:
        return "osint_wayback_urls: CDX returned invalid JSON"
    if not rows or len(rows) < 2:
        return "osint_wayback_urls: no archived URLs for %s" % domain
    rows = rows[1:]  # header row
    interesting, normal = [], []
    for ts, url, code in rows:
        low = url.lower()
        if any(low.endswith(e) or ("." + e[1:] + "/") in low for e in _INTERESTING_EXT) \
                or any(k in low for k in ("/admin", "/login", "/api", "/upload",
                                          "/backup", "/.git", "/console")):
            interesting.append((ts, url, code))
        else:
            normal.append((ts, url, code))
    lines = ["osint_wayback_urls: %d archived URLs for %s "
             "(%d interesting)" % (len(rows), domain, len(interesting))]
    if interesting:
        lines.append("[interesting]  %s  %s  %s" %
                     ("timestamp".ljust(14), "code", "url"))
        for ts, url, code in interesting[:30]:
            lines.append("  %s  %s  %s" % (ts, code, url))
        if len(interesting) > 30:
            lines.append("  ... %d more interesting URLs "
                         "(use limit to widen)" % (len(interesting) - 30))
    lines.append("[recent]")
    for ts, url, code in normal[:10]:
        lines.append("  %s  %s  %s" % (ts, code, url))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 3. Username OSINT - cross-platform profile presence (sherlock-style)
# ---------------------------------------------------------------------------

# platform -> (label, URL template, check method)
#   status   : clean 200/404 semantics (trustworthy)
#   content  : page always 200, verify by body content
#   heuristic: login walls / bot protection, report as "possibly present"
_USER_SITES = [
    ("GitHub",        "https://github.com/{u}",                "status"),
    ("GitLab",        "https://gitlab.com/{u}",                "status"),
    ("Reddit",        "https://www.reddit.com/user/{u}/about.json", "status"),
    ("Medium",        "https://medium.com/@{u}",               "status"),
    ("Pastebin",      "https://pastebin.com/u/{u}",            "status"),
    ("Docker Hub",    "https://hub.docker.com/u/{u}",          "status"),
    ("PyPI",          "https://pypi.org/user/{u}/",            "status"),
    ("npm",           "https://www.npmjs.com/~{u}",            "status"),
    ("Replit",        "https://replit.com/@{u}",               "status"),
    ("Keybase",       "https://keybase.io/{u}",                "status"),
    ("Bitbucket",     "https://bitbucket.org/{u}/",            "status"),
    ("HackerNews",    "https://news.ycombinator.com/user?id={u}", "status"),
    ("Gravatar",      "https://www.gravatar.com/{u}.json",     "status"),
    ("Spotify",       "https://open.spotify.com/user/{u}",     "status"),
    ("About.me",      "https://about.me/{u}",                  "status"),
    ("Dribbble",      "https://dribbble.com/{u}",              "status"),
    ("Behance",       "https://www.behance.net/{u}",           "status"),
    ("Disqus",        "https://disqus.com/by/{u}/",            "status"),
    ("Flickr",        "https://www.flickr.com/people/{u}/",    "status"),
    ("Telegram",      "https://t.me/{u}",                      "content"),
    ("VK",            "https://vk.com/{u}",                    "heuristic"),
    ("Instagram",     "https://www.instagram.com/{u}/",        "heuristic"),
]

def _check_user_site(platform, url, method):
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                            timeout=8, allow_redirects=True)
        code = resp.status_code
    except requests.exceptions.RequestException as exc:
        return (platform, url, "error", "request failed: %r" % exc)
    except Exception as exc:
        return (platform, url, "error", "exception: %r" % exc)
    if method == "status":
        if code in (200, 202, 301, 302, 303):
            return (platform, url, "FOUND", "HTTP %d" % code)
        if code in (404, 410):
            return (platform, url, "not found", "HTTP %d" % code)
        if code == 403:
            return (platform, url, "FOUND (protected)", "HTTP 403")
        if code in (429,):
            return (platform, url, "rate limited", "HTTP 429")
        return (platform, url, "unknown", "HTTP %d" % code)
    if method == "content":
        body = (resp.text or "")[:20000]
        if "tgme_page_title" in body and "This username does not exist" not in body:
            return (platform, url, "FOUND (by content)", "page title present")
        return (platform, url, "not found", "no profile marker")
    # heuristic
    if code == 200 and len(resp.text or "") > 1500:
        return (platform, url, "possibly present", "HTTP 200 (login wall)")
    if code == 404:
        return (platform, url, "not found", "HTTP 404")
    return (platform, url, "unknown", "HTTP %d" % code)

def tool_osint_username_search(username, max_workers=6):
    """Search a username across public platforms (GitHub, GitLab, Reddit,
    Telegram, Pastebin, PyPI, npm, Docker Hub, Replit, Keybase, etc.) to
    map a person's public footprint. Verified platforms report found/not
    found by HTTP semantics; heuristic platforms note login walls."""
    u = (username or "").strip()
    if not u:
        return "osint_username_search: provide a username"
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(_check_user_site, plat, url.format(u=u), method)
                for plat, url, method in _USER_SITES]
        for f in concurrent.futures.as_completed(futs):
            results.append(f.result())
    found = [r for r in results if str(r[2]).upper().startswith("FOUND")
             or r[2] == "possibly present"]
    missing = [r for r in results if r[2] in ("not found",)]
    lines = ["osint_username_search: '%s' across %d platforms - "
             "%d hit(s), %d clear miss" % (u, len(results), len(found),
                                           len(missing))]
    for r in sorted(found, key=lambda x: x[2], reverse=True):
        lines.append("  [HIT ] %-14s %-22s %s" % (r[0], r[2], r[1]))
    if found:
        lines.append("  (profile existence on heuristic platforms needs "
                     "manual confirmation)")
    for r in sorted(missing, key=lambda x: x[0]):
        lines.append("  [miss] %-14s %s" % (r[0], r[1]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 4. Email reputation / breach context (emailrep.io, keyless)
# ---------------------------------------------------------------------------

def tool_osint_email_lookup(email):
    """Query emailrep.io (keyless tier) for an email address:
    reputation score, breach/leak flags, malicious-activity history and
    the public references found. Set EMAILREP_KEY in .env for the higher
    tier. Use for validating accounts found during OSINT / phishing
    pretext research."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return "osint_email_lookup: provide a valid email"
    headers = {"User-Agent": USER_AGENT}
    key = os.environ.get("EMAILREP_KEY", "").strip()
    if key:
        headers["Key"] = key
    try:
        resp = requests.get("https://emailrep.io/%s" % email,
                            headers=headers, timeout=HTTP_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return "osint_email_lookup: request failed: %r" % exc
    if resp.status_code == 404:
        return "osint_email_lookup: no reference data for %s" % email
    if resp.status_code in (401, 403, 429):
        return ("osint_email_lookup: emailrep.io needs an API key / "
                "rate limited for keyless tier (HTTP %d) - set "
                "EMAILREP_KEY in .env" % resp.status_code)
    if resp.status_code != 200:
        return "osint_email_lookup: HTTP %d" % resp.status_code
    try:
        d = resp.json()
    except ValueError:
        return "osint_email_lookup: invalid JSON from emailrep.io"
    det = d.get("details") or {}
    flags = []
    for k, label in (("blacklisted", "blacklisted"),
                     ("malicious_activity", "malicious activity"),
                     ("credentials_leaked", "credentials leaked"),
                     ("data_breach", "in data breach"),
                     ("spam", "spam activity"),
                     ("domain_reputation", "low domain reputation")):
        if det.get(k):
            flags.append(label)
    lines = ["osint_email_lookup: %s -> reputation=%s, suspicious=%s"
             % (email, d.get("reputation"), d.get("suspicious"))]
    lines.append("  flags: %s" % (", ".join(flags) if flags else "none"))
    if d.get("details", {}).get("last_breach"):
        lines.append("  last breach reference: %s"
                     % d["details"]["last_breach"])
    refs = d.get("references") or []
    if refs:
        lines.append("  public references (%d):" % len(refs))
        for r in refs[:8]:
            lines.append("    - %s" % r.get("uri"))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 5. Phone number OSINT (phonenumbers lib optional, prefix-map fallback)
# ---------------------------------------------------------------------------

_COUNTRY_PREFIXES = [
    ("+1", "US/Canada", 10), ("+44", "UK", 10), ("+91", "India", 10),
    ("+92", "Pakistan", 10), ("+971", "UAE", 9), ("+966", "Saudi Arabia", 9),
    ("+49", "Germany", 10), ("+33", "France", 9), ("+39", "Italy", 9),
    ("+34", "Spain", 9), ("+31", "Netherlands", 9), ("+32", "Belgium", 9),
    ("+41", "Switzerland", 9), ("+43", "Austria", 9), ("+46", "Sweden", 9),
    ("+47", "Norway", 8), ("+45", "Denmark", 8), ("+358", "Finland", 9),
    ("+48", "Poland", 9), ("+420", "Czechia", 9), ("+30", "Greece", 10),
    ("+351", "Portugal", 9), ("+353", "Ireland", 9), ("+86", "China", 11),
    ("+81", "Japan", 10), ("+82", "South Korea", 9), ("+65", "Singapore", 8),
    ("+60", "Malaysia", 9), ("+66", "Thailand", 8), ("+62", "Indonesia", 10),
    ("+63", "Philippines", 10), ("+84", "Vietnam", 9), ("+61", "Australia", 9),
    ("+64", "New Zealand", 8), ("+55", "Brazil", 10), ("+52", "Mexico", 10),
    ("+54", "Argentina", 10), ("+56", "Chile", 9), ("+57", "Colombia", 10),
    ("+27", "South Africa", 9), ("+20", "Egypt", 9), ("+234", "Nigeria", 10),
    ("+7", "Russia/Kazakhstan", 10), ("+90", "Turkey", 10), ("+98", "Iran", 10),
    ("+972", "Israel", 9), ("+964", "Iraq", 9), ("+93", "Afghanistan", 9),
    ("+880", "Bangladesh", 10), ("+95", "Myanmar", 9), ("+94", "Sri Lanka", 9),
    ("+977", "Nepal", 9), ("+855", "Cambodia", 8), ("+856", "Laos", 8),
]

def tool_osint_phone_lookup(phone):
    """Validate and classify a phone number: E.164 format, country, and
    carrier/type when the `phonenumbers` library is installed (offline,
    no external API). Without the lib it uses a built-in country-prefix
    table for country + national-length validation."""
    raw = (phone or "").strip()
    if not raw:
        return "osint_phone_lookup: provide a phone number"
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder
        try:
            num = phonenumbers.parse(raw, None)
        except phonenumbers.NumberParseException:
            num = phonenumbers.parse(raw, "PK")  # best effort default
        if not phonenumbers.is_valid_number(num):
            return "osint_phone_lookup: %s is not a valid phone number" % raw
        lines = ["osint_phone_lookup: %s" % phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)]
        lines.append("  country: %s (%s)" % (geocoder.country_name_for_number(
            num, "en") or "?", phonenumbers.region_code_for_number(num)))
        if phonenumbers.is_possible_number(num):
            lines.append("  possible: yes (national length ok)")
        carrier_name = carrier.name_for_number(num, "en")
        if carrier_name:
            lines.append("  carrier: %s" % carrier_name)
        num_type = phonenumbers.number_type(num)
        lines.append("  type: %s" % num_type)
        return "\n".join(lines)
    except ImportError:
        pass
    digits = re.sub(r"\D", "", raw)
    if not raw.startswith("+"):
        return ("osint_phone_lookup: format with country code "
                "(e.g. +923001234567) for prefix detection")
    for prefix, country, nat_len in _COUNTRY_PREFIXES:
        if raw.startswith(prefix):
            if len(digits) != len(prefix[1:]) + nat_len:
                return ("osint_phone_lookup: %s -> %s, but national part "
                        "length is %d (expected ~%d) - verify manually"
                        % (raw, country, len(digits) - len(prefix[1:]),
                           nat_len))
            return ("osint_phone_lookup: %s -> %s (length checks out; "
                    "install 'pip install phonenumbers' for carrier/type "
                    "detail)" % (raw, country))
    return ("osint_phone_lookup: %s -> unknown country prefix; "
            "install 'phonenumbers' lib for full parsing" % raw)


# ---------------------------------------------------------------------------
# 6. Google dork builder - query generation for web pivots
# ---------------------------------------------------------------------------

_DORK_TEMPLATES = {
    "files": [
        "site:{t} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:ppt",
        "site:{t} filetype:csv OR filetype:tsv",
        "site:{t} inurl:download OR inurl:uploads OR inurl:files",
    ],
    "secrets": [
        "site:{t} ext:env OR ext:bak OR ext:conf OR ext:cfg",
        "site:{t} inurl:.git OR inurl:config.php OR ext:sql",
        "site:{t} \"password\" OR \"api_key\" OR \"secret\" filetype:txt "
        "OR filetype:log",
        "site:{t} inurl:phpinfo.php OR ext:ini",
    ],
    "emails": [
        "site:{t} \"@{t}\"",
        "\"@{t}\" email OR contact",
        "site:pastebin.com \"{t}\"",
        "site:linkedin.com/in \"{org}\" email",
        "{org} employees email list",
    ],
    "exposed": [
        "site:{t} inurl:admin OR inurl:login OR inurl:signin OR inurl:portal",
        "site:{t} inurl:phpmyadmin OR inurl:jenkins OR inurl:grafana",
        "site:{t} inurl:swagger OR inurl:api OR inurl:actuator",
        "site:{t} inurl:console OR inurl:terminal OR inurl:shell",
        "site:{t} intitle:\"index of\"",
        "site:{t} inurl:backup OR inurl:old OR inurl:test",
    ],
    "docs": [
        "site:{t} filetype:pdf \"confidential\" OR \"internal\" OR \"NDA\"",
        "site:{t} filetype:xlsx OR filetype:docx OR filetype:pptx",
        "site:docs.google.com \"{org}\"",
        "site:{t} \"sensitive\" OR \"restricted\" OR \"classified\"",
    ],
    "paste": [
        "site:pastebin.com OR site:paste.ee \"{t}\" OR \"{org}\"",
        "\"@{t}\" password OR passwd OR credential",
        "site:github.com \"{org}\" token OR password OR api_key",
    ],
}

def tool_osint_dork_builder(target, org="", category="all"):
    """Generate ready-to-use Google dork queries for a target domain
    (and optional company name) to uncover exposed files, secrets, emails,
    login panels, docs and paste/leak mentions. Returns grouped queries -
    the agent can then run them through web_search / open_url."""
    t = (target or "").strip().lower()
    if not t:
        return "osint_dork_builder: provide a target domain (e.g. example.com)"
    org = (org or t.split(".")[0]).strip()
    cats = list(_DORK_TEMPLATES) if category in ("all", "") else [category]
    if category not in _DORK_TEMPLATES and category != "all":
        return ("osint_dork_builder: category must be all|files|secrets|"
                "emails|exposed|docs|paste (got %r)" % category)
    lines = ["osint_dork_builder: %d dork%s for %s (org=%s):" %
             (sum(len(_DORK_TEMPLATES[c]) for c in cats),
              "s" if sum(len(_DORK_TEMPLATES[c]) for c in cats) != 1 else "",
              t, org)]
    for c in cats:
        lines.append("[%s]" % c)
        for tmpl in _DORK_TEMPLATES[c]:
            lines.append("  %s" % tmpl.format(t=t, org=org))
    lines.append("(run via web_search or paste into a search engine; "
                 "prefix with 'site:' operators as-is)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 7. Metadata extraction - EXIF / PNG / PDF / Office docs (pure Python)
# ---------------------------------------------------------------------------

_EXIF_TAGS = {
    0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
    0x0132: "DateTime", 0x010E: "ImageDescription", 0x0109: "CameraOwnerName",
    0x0112: "Orientation", 0x8827: "ISOSpeedRatings",
    0x829A: "ExposureTime", 0x829D: "FNumber", 0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized", 0x9286: "UserComment",
    0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
}

def _parse_jpeg_exif(data):
    out = []
    try:
        if data[:2] != b"\xff\xd8":
            return out
        i = 2
        while i + 4 <= len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
            body = data[i + 4:i + 2 + seg_len]
            if marker == 0xE1 and body[:6] == b"Exif\x00\x00":
                tiff = body[6:]
                order = tiff[:2]
                if order == b"II":
                    endian = "<"
                elif order == b"MM":
                    endian = ">"
                else:
                    return out
                try:
                    ifd_off = struct.unpack(endian + "I", tiff[4:8])[0]
                except struct.error:
                    return out
                if ifd_off + 2 > len(tiff):
                    return out
                n = struct.unpack(endian + "H", tiff[ifd_off:ifd_off + 2])[0]
                pos = ifd_off + 2
                for _ in range(n):
                    if pos + 12 > len(tiff):
                        break
                    tag, typ, cnt = struct.unpack(
                        endian + "HHI", tiff[pos:pos + 8])
                    val_raw = tiff[pos + 8:pos + 12]
                    name = _EXIF_TAGS.get(tag)
                    fmt = {1: "B", 2: "c", 3: "H", 4: "I", 5: "II",
                           7: "B", 9: "I", 10: "II"}.get(typ)
                    if name and fmt:
                        size = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4,
                                10: 8}[typ]
                        if cnt * size <= 4:
                            if typ == 2:
                                val = val_raw[:cnt].split(b"\x00")[0]
                                try:
                                    val = val.decode("utf-8", "ignore")
                                except Exception:
                                    val = str(val_raw)
                            elif typ in (3, 4, 9):
                                val = struct.unpack(endian + fmt, val_raw[:size])[0]
                            elif typ == 5:
                                a, b = struct.unpack(endian + "II", val_raw)
                                val = round(a / b, 4) if b else "?"
                            elif typ == 10:
                                a, b = struct.unpack(endian + "II", val_raw)
                                val = "%s sec" % (round(a / b, 4) if b else "?")
                            else:
                                val = str(val_raw[:cnt])
                            out.append("%s: %s" % (name, val))
                    pos += 12
                return out
            i += 2 + seg_len
    except Exception as exc:
        out.append("jpeg parse error: %r" % exc)
    return out


def _parse_png_meta(data):
    out = []
    try:
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            return out
        i = 8
        while i + 8 <= len(data):
            length = struct.unpack(">I", data[i:i + 4])[0]
            ctype = data[i + 4:i + 8].decode("latin1")
            chunk = data[i + 8:i + 8 + length]
            if ctype == "IHDR" and len(chunk) >= 8:
                w, h = struct.unpack(">II", chunk[:8])
                out.append("Image: %dx%d" % (w, h))
            elif ctype == "tEXt":
                if b"\x00" in chunk:
                    k, v = chunk.split(b"\x00", 1)
                    try:
                        v = v.decode("latin1").strip()
                    except Exception:
                        v = str(v)
                    if v:
                        out.append("%s: %s" % (k.decode("latin1"), v))
            elif ctype == "zTXt":
                if b"\x00" in chunk:
                    k, rest = chunk.split(b"\x00", 1)
                    out.append("%s: (compressed text)" % k.decode("latin1"))
            if ctype == "IEND":
                break
            i += 8 + length + 4
    except Exception as exc:
        out.append("png parse error: %r" % exc)
    return out


def _parse_pdf_meta(data):
    out = []
    for key in ("Title", "Author", "Creator", "Producer", "CreationDate",
                "ModDate", "Subject", "Keywords"):
        m = re.search(r"/%s\s*\(((?:[^()\\]|\\.)*)\)" % key, data[:65536])
        if m:
            out.append("%s: %s" % (key, m.group(1)[:200]))
    return out


def _parse_office_meta(path):
    out = []
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            xml = b""
            for cand in ("docProps/core.xml", "docProps/app.xml"):
                if cand in names:
                    xml += z.read(cand)
            text = xml.decode("utf-8", "ignore")
            for tag in ("title", "creator", "lastModifiedBy", "created",
                        "modified", "Application", "Company", "TotalTime"):
                m = re.search(r"<%s[^>]*>(.*?)</%s>" % (tag, tag),
                              text, re.S)
                if m and m.group(1).strip():
                    out.append("%s: %s" % (tag, m.group(1).strip()))
    except Exception as exc:
        out.append("office parse error: %r" % exc)
    return out


def tool_osint_metadata_extract(path):
    """Extract metadata from a local file: JPEG EXIF (camera, GPS-er
    fields, date, software), PNG text chunks, PDF info dict, Office
    docProps (creator/lastModified/company), plus a quick email/URL scan
    of any text-ish file. Purely local, no network."""
    path = (path or "").strip().strip('"')
    if not path or not os.path.isfile(path):
        return "osint_metadata_extract: no such file: %r" % path
    size = os.path.getsize(path)
    if size > 20 * 1024 * 1024:
        return "osint_metadata_extract: file too large (%d MB)" % (size // 1048576)
    with open(path, "rb") as fh:
        data = fh.read(1024 * 1024)
    low = path.lower()
    lines = ["osint_metadata_extract: %s (%d bytes)" % (path, size)]
    meta = []
    if low.endswith((".jpg", ".jpeg")):
        meta = _parse_jpeg_exif(data)
    elif low.endswith(".png"):
        meta = _parse_png_meta(data)
    elif low.endswith(".pdf"):
        meta = _parse_pdf_meta(data)
    elif low.endswith((".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp")):
        meta = _parse_office_meta(path)
    else:
        try:
            text = data.decode("utf-8", "ignore")
        except Exception:
            text = ""
        if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
            emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                                text)
            meta.append("emails found: %s" % ", ".join(sorted(set(emails))[:8]))
        urls = re.findall(r"https?://[^\s\"'<>]+", text)
        if urls:
            meta.append("urls found: %s" % ", ".join(sorted(set(urls))[:8]))
    if meta:
        seen = set()
        for m in meta:
            if m not in seen:
                lines.append("  " + m)
                seen.add(m)
    else:
        lines.append("  (no extractable metadata)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 8. Netblock / ASN OSINT via RDAP (rdap.org -> ARIN/RIPE/APNIC/...)
# ---------------------------------------------------------------------------

def tool_osint_netblock_lookup(ip):
    """Resolve an IP to its owning netblock, ASN, organization and abuse
    contact via the RDAP bootstrap service (rdap.org redirects to the
    correct RIR). Useful for scoping an engagement, identifying hosting
    provider, and finding the right abuse channel."""
    ip = (ip or "").strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return "osint_netblock_lookup: provide a valid IPv4"
    try:
        resp = requests.get("https://rdap.org/ip/%s" % ip,
                            headers={"User-Agent": USER_AGENT},
                            timeout=HTTP_TIMEOUT, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        return "osint_netblock_lookup: RDAP request failed: %r" % exc
    if resp.status_code != 200:
        return "osint_netblock_lookup: RDAP status %d" % resp.status_code
    try:
        d = resp.json()
    except ValueError:
        return "osint_netblock_lookup: RDAP returned invalid JSON"
    lines = ["osint_netblock_lookup: %s" % ip]
    for key, label in (("startAddress", "range start"),
                       ("endAddress", "range end"),
                       ("name", "netname"), ("handle", "handle"),
                       ("type", "network type"), ("country", "country"),
                       ("parentHandle", "parent")):
        if d.get(key):
            lines.append("  %s: %s" % (label, d[key]))
    for entity in d.get("entities") or []:
        role = (entity.get("roles") or ["?"])[0]
        vcard = entity.get("vcardArray") or ["", []]
        names = []
        for item in vcard[1] if len(vcard) > 1 else []:
            if item and len(item) > 3 and item[0] == "fn":
                names.append(str(item[3]))
        if names:
            lines.append("  %s: %s" % (role, ", ".join(names)[:200]))
    for event in d.get("events") or []:
        if event.get("eventAction") in ("last changed", "registration"):
            lines.append("  %s: %s" % (event["eventAction"], event["eventDate"]))
    links = d.get("links") or []
    if links:
        lines.append("  source: %s" % links[0].get("href"))
    return "\n".join(lines)


if __name__ == "__main__":
    print("osint.py module loaded - tools available:")
    for f in (tool_osint_ct_subdomains, tool_osint_wayback_urls,
              tool_osint_username_search, tool_osint_email_lookup,
              tool_osint_phone_lookup, tool_osint_dork_builder,
              tool_osint_metadata_extract, tool_osint_netblock_lookup):
        print("  -", f.__name__)

# ---------------------------------------------------------------------------
# 9. DNS-over-HTTPS resolution (keyless - Cloudflare / Google DoH JSON API)
# ---------------------------------------------------------------------------

def tool_osint_dns_doh(domain, record_type="A"):
    """Resolve A/AAAA/MX/TXT/NS/CNAME records via DNS-over-HTTPS (keyless).

    Tries Cloudflare 1.1.1.1 first, falls back to Google 8.8.8.8. Returns
    every answer record with TTL - great for fast passive DNS mapping,
    mail-server discovery and SPF/DMARC TXT inspection before touching the
    target with active queries.
    """
    domain = (domain or "").strip().lower()
    rtype = (record_type or "A").strip().upper()
    if not domain:
        return "osint_dns_doh: invalid domain"
    if rtype not in ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"):
        return "osint_dns_doh: unsupported record type '%s'" % rtype
    endpoints = (
        "https://cloudflare-dns.com/dns-query?name=%s&type=%s"
        % (domain, rtype),
        "https://dns.google/resolve?name=%s&type=%s" % (domain, rtype),
    )
    last_err = None
    for url in endpoints:
        try:
            resp = requests.get(url, headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/dns-json",
            }, timeout=HTTP_TIMEOUT)
            if resp.status_code != 200:
                last_err = "status %d" % resp.status_code
                continue
            data = resp.json()
            answers = data.get("Answer") or []
            if not answers:
                return "osint_dns_doh: %s %s - no records (NXDOMAIN or empty)" % (
                    rtype, domain)
            lines = ["%s records for %s:" % (rtype, domain)]
            for a in answers:
                lines.append("  %s  TTL=%s  %s" % (
                    a.get("type"), a.get("TTL"), a.get("data")))
            return "\n".join(lines)
        except requests.exceptions.RequestException as exc:
            last_err = repr(exc)
        except ValueError:
            last_err = "invalid JSON response"
    return "osint_dns_doh: both DoH endpoints failed: %s" % last_err


# ---------------------------------------------------------------------------
# 10. IP geolocation / carrier / timezone intel (keyless - ip-api.com)
# ---------------------------------------------------------------------------

def tool_osint_ip_info(ip):
    """Passive IP intelligence via ip-api.com (keyless, HTTP fallback
    supported): country, region, city, ISP, org, ASN, lat/lon, timezone.

    Useful to geo-locate infrastructure behind CDNs, spot hosting-provider
    origin IPs and confirm a target's hosting footprint before active scan.
    """
    ip = (ip or "").strip()
    if not ip:
        return "osint_ip_info: invalid IP"
    try:
        resp = requests.get(
            "http://ip-api.com/json/%s?fields=status,message,country,"
            "countryCode,regionName,city,isp,org,as,asname,lat,lon,"
            "timezone,query" % ip,
            headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return "osint_ip_info: ip-api request failed: %r" % exc
    if resp.status_code != 200:
        return "osint_ip_info: ip-api status %d" % resp.status_code
    try:
        d = resp.json()
    except ValueError:
        return "osint_ip_info: invalid JSON response"
    if d.get("status") != "success":
        return "osint_ip_info: lookup failed: %s" % (d.get("message") or "unknown")
    labels = (("query", "IP"), ("country", "country"),
              ("regionName", "region"), ("city", "city"),
              ("isp", "ISP"), ("org", "org"), ("as", "ASN"),
              ("asname", "AS name"), ("lat", "lat"), ("lon", "lon"),
              ("timezone", "timezone"))
    return "\n".join("  %s: %s" % (label, d.get(key, "-"))
                     for key, label in labels if d.get(key))


# ---------------------------------------------------------------------------
# 11. GitHub public lookup (keyless - 60 req/hr unauthenticated)
# ---------------------------------------------------------------------------

def tool_osint_github_lookup(query, kind="users"):
    """Public GitHub search via the keyless API (rate-limited ~60/hr).

    kind=users: find accounts by name/keyword (login, id, public repos,
    followers, bio, company, location, blog).
    kind=repos: find public repositories by keyword (full_name, stars,
    forks, language, description, pushed_at).

    Great for employee-account discovery, leaked-cred hunting in public
    repos, and company code footprint checks.
    """
    query = (query or "").strip()
    kind = (kind or "users").strip().lower()
    if not query:
        return "osint_github_lookup: invalid query"
    if kind not in ("users", "repos"):
        return "osint_github_lookup: kind must be users or repos"
    try:
        resp = requests.get(
            "https://api.github.com/search/%s?q=%s&per_page=10"
            % (kind, query.replace(" ", "+")),
            headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
            timeout=HTTP_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return "osint_github_lookup: request failed: %r" % exc
    if resp.status_code == 403:
        return "osint_github_lookup: rate limited (60/hr keyless) - retry later"
    if resp.status_code != 200:
        return "osint_github_lookup: status %d" % resp.status_code
    try:
        d = resp.json()
    except ValueError:
        return "osint_github_lookup: invalid JSON response"
    items = d.get("items") or []
    if not items:
        return "osint_github_lookup: no %s found for '%s'" % (kind, query)
    lines = ["GitHub %s for '%s' (%d total):" % (kind, query, d.get("total_count", 0))]
    for it in items[:10]:
        if kind == "users":
            lines.append("  @%s | id=%s | repos=%s | followers=%s | %s | %s"
                         % (it.get("login"), it.get("id"),
                            it.get("public_repos"), it.get("followers"),
                            it.get("location") or "-", it.get("html_url")))
        else:
            lines.append("  %s | stars=%s | forks=%s | %s | %s"
                         % (it.get("full_name"), it.get("stargazers_count"),
                            it.get("forks_count"),
                            it.get("language") or "-", it.get("html_url")))
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# 12. Domain RDAP WHOIS (keyless - rdap.org bootstrap, modern structured WHOIS)
# ---------------------------------------------------------------------------

def tool_osint_rdap_whois(domain):
    """Domain registration WHOIS via the RDAP bootstrap service (keyless).
    Returns registrar, created/updated/expiry dates, status codes,
    nameservers and registrant contact names - the structured replacement
    for legacy WHOIS. Great before any active engagement.
    """
    domain = (domain or "").strip().lower()
    if not domain or not re.match(
            r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$",
            domain):
        return "osint_rdap_whois: provide a valid registered domain (e.g. example.com)"
    try:
        resp = requests.get("https://rdap.org/domain/%s" % domain,
                            headers={"User-Agent": USER_AGENT},
                            timeout=HTTP_TIMEOUT, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        return "osint_rdap_whois: RDAP request failed: %r" % exc
    if resp.status_code != 200:
        return "osint_rdap_whois: RDAP status %d (no RDAP for this TLD?)" \
               % resp.status_code
    try:
        d = resp.json()
    except ValueError:
        return "osint_rdap_whois: RDAP returned invalid JSON"
    lines = ["RDAP WHOIS for %s" % domain]

    def _names(entities, role):
        out = []
        for ent in entities or []:
            if role in (ent.get("roles") or []):
                for item in ((ent.get("vcardArray") or [None, []])[1] or []):
                    if item and len(item) > 3 and item[0] == "fn":
                        out.append(str(item[3]))
        return out

    if d.get("ldhName"):
        lines.append("  domain: %s" % d["ldhName"])
    statuses = []
    for s in d.get("status") or []:
        if s:
            statuses.append(s.split()[0])
    if statuses:
        lines.append("  status: %s" % ", ".join(statuses))
    regs = _names(d.get("entities"), "registrar")
    if regs:
        lines.append("  registrar: %s" % regs[0][:120])
    regs = _names(d.get("entities"), "registrant")
    if regs:
        lines.append("  registrant: %s" % regs[0][:120])
    for ns in (d.get("nameservers") or []):
        if isinstance(ns, dict) and ns.get("ldhName"):
            lines.append("  nameserver: %s" % ns["ldhName"].rstrip("."))
    for event in d.get("events") or []:
        action = event.get("eventAction")
        if action in ("registration", "expiration", "last changed",
                      "last update of RDDS database"):
            lines.append("  %s: %s" % (action, event.get("eventDate")))
    if d.get("secureDNS"):
        lines.append("  dnssec: enabled")
    for key in ("handle",):
        if d.get(key):
            lines.append("  %s: %s" % (key, d[key]))
    links = d.get("links") or []
    if links:
        lines.append("  source: %s" % links[0].get("href"))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 13. Reverse DNS (PTR) via DNS-over-HTTPS (keyless - passive)
# ---------------------------------------------------------------------------

def tool_osint_reverse_dns(ip):
    """Reverse DNS (PTR record) for an IPv4/IPv6 address via DoH (keyless).
    Maps an IP back to its hostname - useful to confirm hosting, CDN
    fronting, or vhosts before active testing.
    """
    ip = (ip or "").strip()
    if not ip:
        return "osint_reverse_dns: provide an IP address"
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "osint_reverse_dns: invalid IP '%s'" % ip
    if addr.version == 4:
        ptr_name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    else:
        ptr_name = ".".join(reversed(list(addr.exploded.replace(":", "")))) \
            + ".ip6.arpa"
    endpoints = (
        "https://cloudflare-dns.com/dns-query?name=%s&type=PTR" % ptr_name,
        "https://dns.google/resolve?name=%s&type=PTR" % ptr_name,
    )
    last_err = None
    for url in endpoints:
        try:
            resp = requests.get(url, headers={
                "User-Agent": USER_AGENT, "Accept": "application/dns-json"},
                timeout=HTTP_TIMEOUT)
            if resp.status_code != 200:
                last_err = "status %d" % resp.status_code
                continue
            answers = (resp.json().get("Answer") or [])
            if not answers:
                return "osint_reverse_dns: %s - no PTR record" % ip
            lines = ["Reverse DNS for %s:" % ip]
            for a in answers:
                if a.get("type") == 12 and a.get("data"):
                    lines.append("  %s  (TTL=%s)"
                                 % (a["data"].rstrip("."), a.get("TTL")))
            return "\n".join(lines)
        except requests.exceptions.RequestException as exc:
            last_err = repr(exc)
        except ValueError:
            last_err = "invalid JSON response"
    return "osint_reverse_dns: both DoH endpoints failed: %s" % last_err


# ---------------------------------------------------------------------------
# 14. TLS certificate fingerprint (stdlib only - passive connection)
# ---------------------------------------------------------------------------

def tool_osint_ssl_cert_scan(host, port=443):
    """Grab a remote host's TLS certificate and summarize subject, SANs,
    issuer, validity window, days-until-expiry, TLS version and cipher.
    Purely passive service connection - no exploitation. Works for public
    and self-signed/untrusted certificates (cryptography parse fallback).
    """
    host = (host or "").strip()
    if not host:
        return "osint_ssl_cert_scan: provide a hostname or IP"
    host = host.replace("https://", "").replace("http://", "").split("/")[0]
    host = host.split(":")[0]
    try:
        port = int(port or 443)
    except (TypeError, ValueError):
        return "osint_ssl_cert_scan: invalid port"

    def _rdn(items):
        pairs = []
        for ent in items or []:
            if (isinstance(ent, (list, tuple)) and len(ent) == 2
                    and isinstance(ent[1], str)):
                pairs.append((ent[0], ent[1]))
            elif isinstance(ent, (list, tuple)):
                for sub in ent:
                    if (isinstance(sub, (list, tuple)) and len(sub) == 2):
                        pairs.append((sub[0], sub[1]))
        return ", ".join("%s=%s" % (k, v) for k, v in pairs)

    tls_version = cipher = None
    cert = {}
    der = None
    try:
        import socket
        import ssl
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                tls_version = sock.version()
                cipher = sock.cipher()
    except Exception as first_err:
        try:
            import socket
            import ssl
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port),
                                          timeout=HTTP_TIMEOUT) as raw:
                with ctx2.wrap_socket(raw, server_hostname=host) as sock:
                    der = sock.getpeercert(binary_form=True)
                    tls_version = sock.version()
                    cipher = sock.cipher()
        except Exception as exc:
            return "osint_ssl_cert_scan: connect/TLS failed for %s:%s: %r" \
                   % (host, port, exc)

    lines = ["TLS certificate for %s:%s (TLS %s)" % (host, port, tls_version)]
    if cipher:
        lines.append("  cipher: %s" % cipher[0])

    # ---- untrusted/self-signed: parse DER with cryptography ----------------
    if not cert and der:
        try:
            from cryptography import x509
            c = x509.load_der_x509_certificate(der)
            cn = c.subject.rfc4514_string()
            if cn:
                lines.append("  subject: %s" % cn[:200])
            iss = c.issuer.rfc4514_string()
            if iss:
                lines.append("  issuer: %s" % iss[:200])
            try:
                alt = c.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
                if alt:
                    lines.append("  SANs (%d): %s"
                                 % (len(alt), ", ".join(alt[:20])))
            except Exception:
                pass
            nb = c.not_valid_before_utc
            na = c.not_valid_after_utc
            lines.append("  valid from: %s" % nb.isoformat())
            lines.append("  valid to:   %s" % na.isoformat())
            days = (na - datetime.datetime.now(datetime.timezone.utc)).days
            lines.append("  expires in: %d days" % days)
            lines.append("  serial: %s" % c.serial_number)
            return "\n".join(lines)
        except Exception as parse_exc:
            return "\n".join(lines) + \
                "\n  (cert parse fallback failed: %r)" % parse_exc

    # ---- verified path: populated getpeercert() dict -----------------------
    subject = cert.get("subject") or []
    issuer = cert.get("issuer") or []
    if subject:
        lines.append("  subject: %s" % _rdn(subject)[:200])
    if issuer:
        lines.append("  issuer: %s" % _rdn(issuer)[:200])
    sans = cert.get("subjectAltName") or []
    if sans:
        lines.append("  SANs (%d):" % len(sans))
        for typ, val in sans[:20]:
            lines.append("    %s: %s" % (typ, val))
    lines.append("  valid from: %s" % cert.get("notBefore", "?"))
    lines.append("  valid to:   %s" % cert.get("notAfter", "?"))
    try:
        exp = datetime.strptime(cert.get("notAfter", ""),
                                "%b %d %H:%M:%S %Y GMT")
        lines.append("  expires in: %d days" % (exp - datetime.datetime.utcnow()).days)
    except Exception:
        pass
    if cert.get("serialNumber"):
        lines.append("  serial: %s" % cert["serialNumber"])
    return "\n".join(lines)



# ---------------------------------------------------------------------------
# 15. HTTP header / security posture scan (keyless - passive GET)
# ---------------------------------------------------------------------------

def tool_osint_http_headers(url):
    """Fetch a URL and report server fingerprint plus security headers:
    Server, X-Powered-By, HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    cookie security flags, and which hardening headers are missing.
    Passive recon of a web target's hardening posture.
    """
    url = (url or "").strip()
    if not url:
        return "osint_http_headers: provide a URL or hostname"
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                            timeout=HTTP_TIMEOUT, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        return "osint_http_headers: request failed: %r" % exc
    lines = ["HTTP header scan: %s -> %d %s"
             % (url, resp.status_code, resp.reason or "")]
    wanted = ["Server", "X-Powered-By", "Via", "Strict-Transport-Security",
              "Content-Security-Policy", "X-Frame-Options",
              "X-Content-Type-Options", "Referrer-Policy",
              "Permissions-Policy", "X-XSS-Protection", "Location"]
    for h in wanted:
        v = resp.headers.get(h)
        if v:
            if h == "Set-Cookie":
                continue
            lines.append("  %s: %s" % (h, v[:220]))
    cookies = resp.headers.get("Set-Cookie")
    if cookies:
        parts = cookies.split(";")
        lines.append("  Set-Cookie: %s; secure=%s httponly=%s samesite=%s"
                     % (parts[0][:80],
                        "Y" if "secure" in cookies.lower() else "N",
                        "Y" if "httponly" in cookies.lower() else "N",
                        [p.strip().split("=")[1] for p in parts[1:]
                         if p.strip().lower().startswith("samesite")] or "-"))
    missing = [h for h in ("Strict-Transport-Security",
                           "Content-Security-Policy", "X-Frame-Options",
                           "X-Content-Type-Options")
               if h.lower() not in {k.lower() for k in resp.headers}]
    if missing:
        lines.append("  MISSING hardening: %s" % ", ".join(missing))
    lines.append("  total headers: %d" % len(resp.headers))
    return "\n".join(lines)
