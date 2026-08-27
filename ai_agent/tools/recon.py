"""Recon tools: subdomain enum (crt.sh), dir fuzzing, CVE lookup, wordlists."""

import concurrent.futures
import itertools
import json
import re
import time

import requests

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

DEFAULT_WORDLIST = [
    "admin", "login", "wp-admin", "wp-login.php", "api", "v1", "v2", "graphql",
    "swagger", "api-docs", "docs", "health", "status", "robots.txt", "sitemap.xml",
    ".well-known/security.txt", ".git/config", ".git/HEAD", ".env", "config",
    "config.php", "config.json", "db", "database", "backup", "bak", "old", "test",
    "dev", "staging", "phpmyadmin", "adminer", "uploads", "images", "assets",
    "static", "css", "js", "download", "files", "data", "dump", "logs", "log",
    "error", "debug", "info", "user", "users", "profile", "settings", "install",
    "readme", "license", "changelog", "server-status", "server-info", "shell",
    "cmd", "console", "manage", "panel", "cpanel", "webmail", "mail", "ftp",
]


def tool_subdomain_enum(domain, max_results=80):
    """Enumerate subdomains via Certificate Transparency (crt.sh)."""
    domain = domain.strip().lower()
    try:
        resp = requests.get(
            "https://crt.sh/?q=%25.%s&output=json" % domain,
            headers={"User-Agent": USER_AGENT}, timeout=40)
        if resp.status_code != 200:
            return "subdomain_enum: crt.sh returned status %d" % resp.status_code
        data = resp.json()
    except requests.exceptions.RequestException as exc:
        return "subdomain_enum error: %s" % exc
    except ValueError:
        return "subdomain_enum: crt.sh returned invalid JSON"
    subs = set()
    for entry in data:
        names = entry.get("name_value", "")
        for n in names.split("\n"):
            n = n.strip().strip("*").strip().lower()
            if n and n.endswith("." + domain):
                subs.add(n)
    subs = sorted(subs)
    if not subs:
        return "(no subdomains found for %s)" % domain
    out = ["%d unique subdomains found for %s:" % (len(subs), domain)]
    out += ["  " + s for s in subs[:max_results]]
    if len(subs) > max_results:
        out.append("  ... %d more" % (len(subs) - max_results))
    return "\n".join(out)


def tool_dir_fuzz(base_url, wordlist=None, max_results=40, timeout=8,
                  threads=12, method="GET"):
    """Brute-force common paths on a web server. Provide your own comma-separated
    wordlist to override the default one."""
    base = base_url.rstrip("/")
    words = wordlist or DEFAULT_WORDLIST
    if isinstance(words, str):
        words = [w.strip() for w in words.split(",") if w.strip()]
    if not words:
        return "dir_fuzz: empty wordlist"
    found = []

    def probe(path):
        url = base + "/" + path
        try:
            r = requests.request(method, url,
                                 headers={"User-Agent": USER_AGENT},
                                 timeout=timeout, allow_redirects=False)
            return path, r.status_code, len(r.content), r.headers.get("Location", "")[:60]
        except Exception:
            return path, 0, 0, ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(probe, p) for p in words]
        for fut in concurrent.futures.as_completed(futures):
            path, code, size, loc = fut.result()
            if code in (200, 301, 302, 303, 307, 308, 401, 403, 405, 500):
                found.append((path, code, size, loc))
    found.sort(key=lambda x: (x[1] not in (200, 301, 302), x[0]))
    if not found:
        return "No interesting paths found on %s (tested %d paths)" % (base, len(words))
    lines = ["Interesting paths on %s (tested %d):" % (base, len(words))]
    for path, code, size, loc in found[:max_results]:
        line = "  %-5s %-22s %8d bytes" % (code, path, size)
        if loc:
            line += " -> %s" % loc
        lines.append(line)
    if len(found) > max_results:
        lines.append("  ... %d more" % (len(found) - max_results))
    return "\n".join(lines)


def _nvd_cve_search(query, max_results):
    """Search CVEs via the NVD API 2.0 (no key required)."""
    params = {"keywordSearch": query, "resultsPerPage": max_results}
    last_err = None
    for attempt in range(3):
        try:
            resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                params=params, headers={"User-Agent": USER_AGENT},
                                timeout=30)
            if resp.status_code == 200:
                return resp.json()
            last_err = "NVD status %d" % resp.status_code
        except requests.exceptions.RequestException as exc:
            last_err = str(exc)
        time.sleep(3 * (attempt + 1))
    return {"error": last_err or "NVD unavailable"}


def tool_cve_lookup(query, max_results=15):
    """Search known CVEs by keyword/product/version (NVD API 2.0)."""
    data = _nvd_cve_search(query, max_results)
    if isinstance(data, dict) and data.get("error"):
        # fall back to CIRCL (deprecated but sometimes reachable)
        try:
            url = "https://cve.circl.lu/api/search/" + requests.utils.quote(query)
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=25)
            if resp.status_code == 200:
                data = resp.json()
        except requests.exceptions.RequestException:
            pass
    if isinstance(data, dict) and data.get("error"):
        return "cve_lookup: %s (NVD is rate-limited; wait ~30s and retry)" % data["error"]
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else data
    if not vulns:
        return "(no CVEs found for '%s')" % query
    lines = ["%d CVEs found for '%s' (showing up to %d):"
             % (len(vulns), query, max_results)]
    for entry in vulns[:max_results]:
        cve = entry.get("cve") if isinstance(entry, dict) else entry
        if not isinstance(cve, dict):
            continue
        cid = cve.get("id", "?")
        cvss_str = ""
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            rows = metrics.get(key) or []
            if rows:
                cvss_data = rows[0].get("cvssData") or {}
                score = cvss_data.get("baseScore")
                if isinstance(score, (int, float)):
                    cvss_str = "CVSS %.1f" % score
                break
        desc = ""
        for d in cve.get("descriptions") or []:
            if d.get("lang") == "en":
                desc = d.get("value", "")[:180]
                break
        lines.append("- %s %s\n    %s" % (cid, cvss_str, desc))
    return "\n".join(lines)


def tool_wordlist_gen(keywords, numbers="0-9", years="2015-2026", specials="!@#",
                      max_lines=300):
    """Generate a wordlist from keywords + numbers + years + special chars."""
    if isinstance(keywords, str):
        keywords = [k.strip() for k in keywords.split(",") if k.strip()]
    if not keywords:
        return "wordlist_gen: provide at least one keyword"
    try:
        nums = [n for n in range(int(numbers.split("-")[0]), int(numbers.split("-")[1]) + 1)]
    except Exception:
        nums = list(range(10))
    try:
        yrs = list(range(int(years.split("-")[0]), int(years.split("-")[1]) + 1))
    except Exception:
        yrs = []
    words = set()
    for k in keywords:
        words.add(k)
        words.add(k.lower())
        words.add(k.upper())
        words.add(k.capitalize())
        for n in list(nums[:5]) + list(yrs[-3:]):
            words.add(k + str(n))
            words.add(str(n) + k)
        for s in specials:
            words.add(k + s)
            words.add(k + s + "1")
            words.add(k.capitalize() + s + "1")
    words = [w for w in words if len(w) >= 3][:max_lines]
    if not words:
        return "(wordlist empty)"
    return "%d entries generated:\n%s" % (len(words), "\n".join(sorted(words)))
