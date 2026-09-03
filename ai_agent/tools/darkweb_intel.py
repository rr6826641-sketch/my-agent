"""Dark Web Threat Intelligence & Onion Research Engine.

Tools:
  * scrape_onion_service(onion_url, ...) -> dict (never raises)
      Fetches ONE .onion page through the local Tor SOCKS5 proxy and
      safely extracts: title, meta metadata, readable text excerpt,
      leaked e-mail patterns, hash candidates (md5/sha1/sha256) and
      every .onion link on the page. Dead/offline onion nodes return a
      structured error within a bounded time - a tool thread can never
      hang the agent loop on a dead node.
  * search_darkweb_leaks(query, ...) -> dict (never raises)
      Queries a public dark-web search index (Ahmia clearnet mirror by
      default; Ahmia .onion via Tor when use_tor=true) for onion pages
      matching a target domain / breach indicator. Structured hits:
      onion_url, title, snippet, first_seen_timestamp.

Operational rules (self-managed doctrine):
  * TOR PROXY: requests route through socks5h://127.0.0.1:9050 (remote
    DNS - .onion names must be resolved BY Tor, never the local
    resolver). Override with the TOR_PROXY env var.
  * NO BLOCKING: bounded timeouts, hard download cap, graceful offline
    fallbacks, structured errors on every failure mode.
  * CLEARNET FALLBACK: search works even without a local Tor daemon.
  * AUTHORIZED OSINT: only publicly indexed .onion content for targets
    you are allowed to hunt.

Network code sits behind module-level helpers so tests monkeypatch
them; nothing touches the network at import time.
"""

from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.parse
import warnings
from html import unescape

import requests
from bs4 import BeautifulSoup

DEFAULT_TOR_PROXY = "socks5h://127.0.0.1:9050"
DEFAULT_TOR_HOST = "127.0.0.1"
DEFAULT_TOR_PORT = 9050

AHMIA_CLEARNET_SEARCH = "https://ahmia.fi/search/?q={q}"
AHMIA_ONION_SEARCH = ("http://juhanurmihxlp77nkq76byazcldxy2hl43fwsa2icpv3"
                      "kqon4m5c5b2yd.onion/search/?q={q}")

MAX_BODY_BYTES = 3_000_000           # hard download cap per page
MAX_EMAILS = 100                     # never dump an infinite mailbox
MAX_ONION_LINKS = 60
EXCERPT_CHARS = 3000                 # readable-text excerpt cap
SNIPPET_CHARS = 400

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Label-guided hash patterns keep random 32/40/64-hex noise out of the
# top-level report; a generic scan is exposed separately.
LABELED_HASH_RE = re.compile(
    r"\b(?:md5|sha[-_]?1|sha[-_]?256|ntlm)\b[^a-f0-9]{0,24}"
    r"([a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-f0-9])", re.I)
GENERIC_HASH_RE = re.compile(r"\b(?<![a-f0-9])([a-f0-9]{32,})(?![a-f0-9])")

_DATE_RE = re.compile(
    r"(?P<iso>20\d{2}[-/.]\d{1,2}[-/.]\d{1,2})|"
    r"(?P<day>\d{1,2})[\s-]+(?P<mon>jan|feb|mar|apr|may|jun|jul|aug|sep|"
    r"oct|nov|dec)[a-z]*[\s-]+(?P<year>20\d{2})", re.I)
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun",
     "jul", "aug", "sep", "oct", "nov", "dec"])}

_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
               "AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/126.0.0.0 Safari/537.36")

_SKIP_TAGS = ("script", "style", "noscript", "svg", "iframe", "template",
              "form", "nav", "header", "footer", "aside", "select",
              "textarea", "canvas", "audio", "video", "button")


def _env(name, default):
    v = os.environ.get(name)
    return v if v else default


def tor_proxy():
    """SOCKS5 proxy URL (remote DNS via the 'h' suffix), env-overridable."""
    return _env("TOR_PROXY", DEFAULT_TOR_PROXY)


def _tor_proxy_parts():
    m = re.match(r"socks5h?://([^:/]+):(\d+)", tor_proxy())
    if m:
        return m.group(1), int(m.group(2))
    return DEFAULT_TOR_HOST, DEFAULT_TOR_PORT


def _dumps(data):
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


def tor_is_available(timeout=2.0):
    """Quick TCP probe of the Tor SOCKS5 endpoint. Never raises.

    Returns (ok, detail). Refused connect = Tor not running; a successful
    connect means the port is up (real SOCKS negotiation happens on the
    actual request, which classifies deeper failures).
    """
    host, port = _tor_proxy_parts()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        return False, ("Tor proxy at %s:%d did not answer within %.0fs - "
                       "start Tor or check TOR_PROXY" % (host, port, timeout))
    except OSError as exc:
        return False, ("Tor proxy at %s:%d unreachable (%s) - is the Tor "
                       "daemon running? TOR_PROXY=%s"
                       % (host, port, exc, tor_proxy()))
    try:
        sock.close()
    except Exception:
        pass
    return True, "Tor proxy reachable at %s:%d" % (host, port)


def _http_get(url, *, timeout, proxies=None, headers=None, verify=True,
              max_bytes=MAX_BODY_BYTES):
    """GET with bounded connect/read timeouts + a hard download cap.

    Raises requests.RequestException subclasses on transport failure so
    callers can classify them; returns the response on success. Streamed
    reads enforce the size cap without buffering a hostile page in RAM.
    """
    hdrs = {"User-Agent": _USER_AGENT,
            "Accept": ("text/html,application/xhtml+xml,application/xml;"
                       "q=0.9,*/*;q=0.8")}
    if headers:
        hdrs.update(headers)
    connect_timeout = min(8.0, max(1.0, timeout))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # self-signed onion TLS noise
        resp = requests.get(url, proxies=proxies, headers=hdrs,
                            timeout=(connect_timeout, timeout),
                            stream=True, verify=verify)
    chunks, total, truncated = [], 0, False
    for chunk in resp.iter_content(chunk_size=65536):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            truncated = True
            break
        chunks.append(chunk)
    resp._hackerai_truncated = truncated
    resp._hackerai_body = b"".join(chunks)
    return resp


def _absolute(base_url, href):
    if not href:
        return None
    try:
        return urllib.parse.urljoin(base_url, href.strip())
    except ValueError:
        return None


def _is_onion_url(url):
    try:
        host = urllib.parse.urlparse(url).netloc.split(":")[0].lower()
    except ValueError:
        return False
    return host.endswith(".onion")


def _onion_links(soup, base_url):
    """Deduplicated absolute .onion hrefs discovered on the page."""
    seen, order = set(), []
    for a in soup.find_all("a", href=True):
        full = _absolute(base_url, a["href"])
        if full and _is_onion_url(full) and full not in seen:
            seen.add(full)
            order.append(full)
            if len(order) >= MAX_ONION_LINKS:
                break
    return order


def _extract_emails(text):
    out, seen = [], set()
    for raw in EMAIL_RE.findall(text):
        em = raw.strip().lower().strip(".").strip("-").strip("_")
        if len(em) < 6 or not em[0].isalnum():
            continue
        if em not in seen:
            seen.add(em)
            out.append(em)
        if len(out) >= MAX_EMAILS:
            break
    return out


def _classify_hashes(text):
    """Label-guided hashes (high confidence) + generic hex scan (noise)."""
    labeled, seen_l = [], set()
    for m in LABELED_HASH_RE.finditer(text):
        h = m.group(1).lower()
        if h not in seen_l:
            seen_l.add(h)
            labeled.append(h)
    generic, seen_g = [], set(labeled)
    for m in GENERIC_HASH_RE.finditer(text):
        h = m.group(1).lower()
        if h not in seen_g:
            seen_g.add(h)
            generic.append(h[:128])
    buckets = {"md5": [], "sha1": [], "sha256": [], "other": []}
    for h in labeled:
        kind = ("md5" if len(h) == 32 else "sha1" if len(h) == 40 else
                "sha256" if len(h) == 64 else "other")
        buckets[kind].append(h)
    return {"labeled": labeled,
            "generic_hex_candidates": generic[:50],
            "by_type": {k: v[:20] for k, v in buckets.items()},
            "counts": {k: len(v) for k, v in buckets.items()}}


def _readable_text(soup):
    for tag in soup.find_all(_SKIP_TAGS):
        tag.decompose()
    text = soup.get_text(" ", strip=True)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()


def _meta(soup, key):
    tag = soup.find("meta", attrs={"name": key}) or \
        soup.find("meta", attrs={"property": key})
    if tag and tag.get("content"):
        return re.sub(r"\s+", " ", tag["content"]).strip()[:500]
    return None


def _decode_body(resp):
    """Best-effort text decode honoring response/charset/utf-8.

    Tolerates both bytes (real requests.Response.content) and already
    decoded str bodies (test doubles / cached responses).
    """
    content = resp.content
    if isinstance(content, str):
        return content
    encoding = getattr(resp, "encoding", None)
    if encoding:
        try:
            return content.decode(encoding, errors="replace")
        except Exception:
            pass
    try:
        head = content[:2048].decode("latin-1", errors="ignore")
        m = re.search(r"charset=([\w\-]+)", head, re.I)
        if m:
            return content.decode(m.group(1).strip('"'),
                                  errors="replace")
    except (LookupError, Exception):
        pass
    return content.decode("utf-8", errors="replace")


def _clean_snippet(text):
    text = re.sub(r"\s+", " ", unescape(text)).strip()
    if len(text) > SNIPPET_CHARS:
        return text[:SNIPPET_CHARS] + "..."
    return text


def _extract_first_seen(text):
    """First date-looking string in a hit block, normalized to ISO."""
    m = _DATE_RE.search(text)
    if not m:
        return None
    if m.group("iso"):
        return re.sub(r"[/.]", "-", m.group("iso"))
    mon = _MONTHS.get((m.group("mon") or "").lower()[:3])
    if mon:
        return "%s-%02d-%02d" % (m.group("year"), mon,
                                 int(m.group("day")))
    return None


def scrape_onion_service(onion_url, timeout=15, ignore_ssl=False,
                         include_text=True):
    """Fetch one .onion page through Tor and extract intel safely.

    Returns a structured dict, never raises. Failure modes are classified
    (tor-off, node-offline, http-error, parse) so the caller can tell a
    dead market from a dead Tor daemon.
    """
    started = time.time()
    url = (onion_url or "").strip().strip('"').strip("'").strip()
    if not url:
        return {"status": "error",
                "error": "onion_url is required (e.g. "
                         "http://<56-char>.onion/page)"}
    if "://" not in url:
        url = "http://" + url           # .onion pages are plain http
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as exc:
        return {"status": "error", "error": "invalid url: %s" % exc}
    if parsed.scheme not in ("http", "https"):
        return {"status": "error",
                "error": "scheme must be http/https (onion pages are "
                         "usually http), got %r" % parsed.scheme}
    host = (parsed.netloc or "").split(":")[0].lower()
    if not host.endswith(".onion"):
        return {"status": "error",
                "error": "only .onion hosts are routable through Tor; got "
                         "%r (use search_darkweb_leaks for clearnet hits)"
                         % parsed.netloc}
    onion_label = host[:-6]
    if (len(onion_label) < 16
            or re.fullmatch(r"[a-z0-9]+", onion_label) is None):
        return {"status": "error",
                "error": "unrecognized .onion hostname %r - expected a "
                         "v2 (16-char) or v3 (56-char) base32 address"
                         % host}

    # Tor gate: fail fast instead of hanging on a dead proxy
    ok, detail = tor_is_available()
    if not ok:
        return {"status": "error", "error": "Tor proxy offline",
                "detail": detail,
                "hint": "start Tor (default socks5h://127.0.0.1:9050) or "
                        "set TOR_PROXY to your SOCKS5 endpoint",
                "elapsed_ms": int((time.time() - started) * 1000)}

    proxies = {"http": tor_proxy(), "https": tor_proxy()}
    try:
        resp = _http_get(url, timeout=float(timeout or 15), proxies=proxies,
                         headers={"Accept-Language": "en-US,en;q=0.9"},
                         verify=not ignore_ssl)
    except requests.exceptions.SSLError as exc:
        return {"status": "error", "error": "TLS error from onion node",
                "detail": str(exc)[:300],
                "hint": "self-signed onion TLS is common - retry with "
                        "ignore_ssl=true",
                "elapsed_ms": int((time.time() - started) * 1000)}
    except requests.exceptions.Timeout:
        return {"status": "error",
                "error": "onion node offline or too slow",
                "detail": "no response within %ss via %s"
                          % (timeout, tor_proxy()),
                "hint": "onion services are frequently down; retry later "
                        "or probe a mirror",
                "elapsed_ms": int((time.time() - started) * 1000)}
    except requests.exceptions.ProxyError as exc:
        return {"status": "error", "error": "Tor proxy failed mid-request",
                "detail": str(exc)[:300],
                "hint": "is Tor still running? proxy: %s" % tor_proxy(),
                "elapsed_ms": int((time.time() - started) * 1000)}
    except requests.exceptions.RequestException as exc:
        return {"status": "error",
                "error": "request failed while reaching onion service",
                "detail": str(exc)[:300],
                "elapsed_ms": int((time.time() - started) * 1000)}

    body = resp._hackerai_body
    out = {"status": "ok", "url": url, "onion_host": host,
           "http_status": resp.status_code,
           "downloaded_bytes": len(body),
           "download_truncated": bool(getattr(resp, "_hackerai_truncated",
                                              False)),
           "elapsed_ms": int((time.time() - started) * 1000)}
    text_html = _decode_body(resp) if body else ""
    soup = None
    if text_html.strip():
        try:
            soup = BeautifulSoup(text_html, "html.parser")
        except Exception:
            soup = None

    if resp.status_code >= 400:
        out["status"] = "http_error"
        out["error"] = "onion node answered HTTP %d" % resp.status_code

    if soup is not None:
        title = soup.title.get_text(strip=True) if soup.title else None
        out["title"] = _clean_snippet(title)[:300] if title else None
        out["page_meta"] = {
            "description": _meta(soup, "description"),
            "keywords": _meta(soup, "keywords"),
            "generator": _meta(soup, "generator"),
            "og_title": _meta(soup, "og:title"),
        }
        out["onion_links"] = _onion_links(soup, url)
        out["onion_link_count"] = len(out["onion_links"])
        if include_text:
            text = _readable_text(soup)
            emails = _extract_emails(text)
            out["text_length"] = len(text)
            out["word_count"] = len(text.split())
            out["text_excerpt"] = (text[:EXCERPT_CHARS] + "..."
                                   if len(text) > EXCERPT_CHARS else text)
            out["emails_found"] = emails[:MAX_EMAILS]
            out["email_count"] = len(emails)
            out["hash_analysis"] = _classify_hashes(text)
        if include_text and not out.get("emails_found"):
            # 2nd pass over raw HTML catches mailto:/attribute leaks
            emails = _extract_emails(text_html)
            out["emails_found"] = emails[:MAX_EMAILS]
            out["email_count"] = len(emails)
    else:
        out["title"] = None
        out["body_preview"] = _clean_snippet(text_html[:1000])
        if include_text:
            emails = _extract_emails(text_html)
            out["emails_found"] = emails[:MAX_EMAILS]
            out["email_count"] = len(emails)
            out["hash_analysis"] = _classify_hashes(text_html)

    out["elapsed_ms"] = int((time.time() - started) * 1000)
    return out


def _json_results_from_body(body, limit):
    """Ahmia mirrors sometimes answer JSON: {"results": [...]}."""
    try:
        if isinstance(body, str):
            payload = json.loads(body)
        else:
            payload = json.loads(body.decode("utf-8", errors="ignore"))
    except Exception:
        return None
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return None
    hits = []
    for item in results:
        if not isinstance(item, dict):
            continue
        url = (item.get("url") or item.get("link") or "").strip()
        if not url or not _is_onion_url(url):
            continue
        first_seen = (item.get("first_seen") or item.get("timestamp")
                      or item.get("date") or None)
        if isinstance(first_seen, (int, float)):
            secs = first_seen / 1000.0 if first_seen > 1e12 else first_seen
            first_seen = time.strftime("%Y-%m-%d", time.gmtime(secs))
        title = item.get("title") or url
        snippet = (item.get("snippet") or item.get("description")
                   or item.get("text") or "")
        hits.append({"onion_url": _clean_snippet(url),
                     "title": (_clean_snippet(title)[:300]
                               if title else None),
                     "snippet": _clean_snippet(snippet) or None,
                     "first_seen_timestamp": first_seen})
        if len(hits) >= limit:
            break
    return hits


def _parse_ahmia_html(text_html, limit):
    """Format-tolerant BS4 parse of an Ahmia results HTML page.

    Preferred rows are <li class="result">; older/newer layouts degrade
    to any <li> or <div class="result">, then to a flat .onion-anchor
    scan. One hit per onion page URL, deduplicated.
    """
    soup = BeautifulSoup(text_html, "html.parser")
    rows = (soup.find_all("li", class_="result")
            or soup.find_all("li")
            or soup.find_all("div", class_="result"))
    if not rows:
        rows = [a.parent or a for a in soup.find_all("a", href=True)
                if ".onion" in (a.get("href") or "")]

    def _first_onion_anchor(container):
        for a in container.find_all("a", href=True):
            href = (a.get("href") or "").strip()
            if ".onion" in href:
                return a, href
        return None, None

    hits, seen = [], set()
    for container in rows:
        a, href = _first_onion_anchor(container)
        if a is None or href in seen:
            continue
        seen.add(href)
        title = a.get_text(" ", strip=True) or href
        block_text = container.get_text(" ", strip=True)
        snippet = _clean_snippet(block_text)
        for needle in (title, href):
            if needle and snippet.startswith(needle[:120]):
                snippet = snippet[len(needle[:120]):].strip()
        ts = _extract_first_seen(block_text)
        hits.append({"onion_url": _clean_snippet(href),
                     "title": (_clean_snippet(title)[:300]
                               if title else None),
                     "snippet": _clean_snippet(snippet) or None,
                     "first_seen_timestamp": ts})
        if len(hits) >= limit:
            break
    return hits


def _ahmia_search(query, limit=8, use_tor=False, timeout=20):
    """Core Ahmia query. Returns a dict with status + parsed hits.

    use_tor=False hits the clearnet mirror https://ahmia.fi (works with
    no local Tor). use_tor=True queries the .onion index through the Tor
    SOCKS proxy so no clearnet request ever leaves this host.
    """
    started = time.time()
    query = (query or "").strip()
    if not query:
        return {"status": "error", "error": "query is required",
                "elapsed_ms": int((time.time() - started) * 1000)}
    limit = max(1, min(int(limit or 8), 25))
    via_tor = bool(use_tor)
    if via_tor:
        ok, detail = tor_is_available()
        if not ok:
            return {"status": "error", "error": "Tor proxy offline",
                    "detail": detail,
                    "hint": "start Tor (socks5h://127.0.0.1:9050), set "
                            "TOR_PROXY, or call with use_tor=false",
                    "elapsed_ms": int((time.time() - started) * 1000)}
        url = AHMIA_ONION_SEARCH.format(q=urllib.parse.quote_plus(query))
        proxies = {"http": tor_proxy(), "https": tor_proxy()}
    else:
        url = AHMIA_CLEARNET_SEARCH.format(q=urllib.parse.quote_plus(query))
        proxies = None
    try:
        resp = _http_get(url, timeout=float(timeout or 20), proxies=proxies)
    except requests.exceptions.Timeout:
        return {"status": "error", "error": "search index timed out",
                "detail": "no response within %ss" % timeout,
                "hint": ("retry later, or use_tor=true"
                         if not via_tor else "retry later, or use_tor=false "
                         "to reach the clearnet mirror"),
                "elapsed_ms": int((time.time() - started) * 1000)}
    except requests.exceptions.SSLError as exc:
        return {"status": "error", "error": "TLS error contacting index",
                "detail": str(exc)[:300],
                "elapsed_ms": int((time.time() - started) * 1000)}
    except requests.exceptions.RequestException as exc:
        return {"status": "error", "error": "search request failed",
                "detail": str(exc)[:300],
                "elapsed_ms": int((time.time() - started) * 1000)}
    body = resp._hackerai_body
    if not body:
        return {"status": "error",
                "error": "search index returned an empty body",
                "elapsed_ms": int((time.time() - started) * 1000)}

    text_html = _decode_body(resp)
    hits = _json_results_from_body(body, limit)
    if hits is None:
        hits = _parse_ahmia_html(text_html, limit)
    return {"status": "ok", "query": query, "engine": "ahmia",
            "via_tor": via_tor, "result_count": len(hits),
            "results": hits, "search_url": url,
            "elapsed_ms": int((time.time() - started) * 1000)}


def search_darkweb_leaks(query, limit=8, use_tor=False, timeout=20):
    """Search public dark-web indexes for leaks about a domain/indicator.

    Clearnet-safe by default (Ahmia mirror). Returns structured hits
    {onion_url, title, snippet, first_seen_timestamp} plus the full
    result dict. Never raises; every failure mode is classified.
    """
    out = _ahmia_search(query=query, limit=limit, use_tor=use_tor,
                        timeout=timeout)
    return out


def tool_scrape_onion_service(onion_url, timeout=15, ignore_ssl=False,
                              include_text=True):
    """Tool entry point - same behavior, JSON-serialized result string."""
    return _dumps(scrape_onion_service(onion_url, timeout=timeout,
                                       ignore_ssl=ignore_ssl,
                                       include_text=include_text))


def tool_search_darkweb_leaks(query, limit=8, use_tor=False, timeout=20):
    """Tool entry point - same behavior, JSON-serialized result string."""
    return _dumps(search_darkweb_leaks(query, limit=limit, use_tor=use_tor,
                                       timeout=timeout))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(tool_scrape_onion_service(sys.argv[1]))
    else:
        print(tool_scrape_onion_service("http://example.invalid"))
