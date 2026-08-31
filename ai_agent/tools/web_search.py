"""DuckDuckGo web search tool module (no API key required).

Backends (in order):
  1. `duckduckgo_search` / `ddgs` library  — structured results via DDGS().text()
  2. Built-in fallback scraper             — https://lite.duckduckgo.com/lite/

Public API:
  search_web(query, max_results=5) -> dict with structured results:
      {"query": ..., "backend": ..., "count": n,
       "results": [{"title": ..., "url": ..., "snippet": ...}, ...]}

On total failure the dict carries an "error" key and an empty results list —
it never raises, so a bad search can never crash the agent loop.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, quote_plus, urlparse

import requests

try:  # preferred: current `ddgs` package (multi-engine backends)
    from ddgs import DDGS  # type: ignore
except ImportError:
    try:  # legacy alias: duckduckgo_search package
        from duckduckgo_search import DDGS  # type: ignore
    except ImportError:
        DDGS = None  # type: ignore[assignment]

# Engines tried in order by the library backend (new ddgs API).
# brave omitted: often DNS-blocked on some resolvers.
_DDGS_BACKENDS = ("duckduckgo", "google", "bing")

REQUEST_TIMEOUT = 15       # per-HTTP-request timeout (seconds)
MAX_RESULTS_CAP = 20       # hard upper bound regardless of caller input
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def _clamp(max_results) -> int:
    try:
        n = int(max_results)
    except (TypeError, ValueError):
        n = 5
    return max(1, min(n, MAX_RESULTS_CAP))

# --------------------------------------------------------------------------
# Tiny TTL cache: avoids hammering search backends on repeated queries.
# --------------------------------------------------------------------------

import threading, time as _time

_CACHE_TTL = 300  # seconds
_cache = {}
_cache_lock = threading.Lock()


def _cache_get(key):
    with _cache_lock:
        hit = _cache.get(key)
        if not hit:
            return None
        ts, val = hit
        if _time.monotonic() - ts > _CACHE_TTL:
            del _cache[key]
            return None
        return val


def _cache_put(key, value):
    with _cache_lock:
        if len(_cache) > 256:
            oldest = min(_cache, key=lambda k: _cache[k][0])
            del _cache[oldest]
        _cache[key] = (_time.monotonic(), value)


# --------------------------------------------------------------------------
# Backend 1: duckduckgo_search / ddgs library
# --------------------------------------------------------------------------

def _ddgs_search(query: str, max_results: int) -> list[dict]:
    if DDGS is None:
        raise RuntimeError("ddgs / duckduckgo_search library not installed")
    try:  # newer versions accept a timeout on the constructor
        ddgs = DDGS(timeout=REQUEST_TIMEOUT)
    except TypeError:
        ddgs = DDGS()
    raw = None
    last_err = None
    for backend in _DDGS_BACKENDS:
        try:
            raw = ddgs.text(query, max_results=max_results,
                            backend=backend) or []
            if raw:
                break
        except TypeError:
            # legacy duckduckgo_search API has no backend kwarg
            raw = ddgs.text(query, max_results=max_results) or []
            break
        except Exception as exc:
            last_err = exc
            continue
    if not raw and last_err is not None:
        raise last_err
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append({
            "title": str(item.get("title", "")).strip()[:200],
            "url": str(item.get("href") or item.get("url") or "").strip()[:500],
            "snippet": str(item.get("body") or item.get("snippet") or "").strip()[:500],
        })
    return out


# --------------------------------------------------------------------------
# Backend 2: API-key-free fallback scraper (lite.duckduckgo.com)
# --------------------------------------------------------------------------

class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "svg", "head", "template"):
            self._skip += 1
        if tag in ("p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "svg", "head", "template") \
                and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


_CLEAN = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    return _CLEAN.sub("", text or "").strip()


def _unwrap_ddg_link(href: str) -> str:
    """DuckDuckGo wraps real URLs in a /l/?uddg= redirect; extract target."""
    try:
        if "uddg=" in href:
            parsed = parse_qs(urlparse(href).query)
            return parsed.get("uddg", [href])[0]
    except Exception:
        pass
    return href


def _scraper_search(query: str, max_results: int) -> list[dict]:
    url = "https://lite.duckduckgo.com/lite/?q=" + quote_plus(query)
    resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                        timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    page = resp.text
    anchors = re.findall(
        r'<a\b([^>]*\bclass=["\']result-link["\'][^>]*)>(.*?)</a>', page, re.S)
    snips = re.findall(r'class=["\']result-snippet["\']>(.*?)</td>', page, re.S)
    out = []
    for i, (attrs, title_html) in enumerate(anchors[:max_results]):
        m = re.search(r'\bhref=["\']([^"\']+)["\']', attrs)
        link = _unwrap_ddg_link(m.group(1).strip()) if m else ""
        snip = _strip_html(snips[i]) if i < len(snips) else ""
        out.append({
            "title": _strip_html(title_html)[:200],
            "url": link[:500],
            "snippet": snip[:500],
        })
    return out


# --------------------------------------------------------------------------
# Public tool API
# --------------------------------------------------------------------------

def search_web(query: str, max_results: int = 5) -> dict:
    """Search the web via DuckDuckGo; return structured JSON results.

    Returns:
        {"query": str, "backend": "ddgs"|"scraper", "count": int,
         "results": [{"title", "url", "snippet"}, ...]}
        plus {"error": str} when every backend failed (results == []).
    """
    query = (query or "").strip()
    if not query:
        return {"error": "query is required", "query": query,
                "results": [], "count": 0}
    max_results = _clamp(max_results)

    cache_key = "%s::%d" % (query.lower(), max_results)
    cached = _cache_get(cache_key)
    if cached is not None:
        out = dict(cached)
        out["cached"] = True
        return out

    errors = []
    # 1) library backend
    try:
        results = _ddgs_search(query, max_results)
        if results:
            out = {"query": query, "backend": "ddgs",
                   "count": len(results), "results": results}
            _cache_put(cache_key, out)
            return dict(out)
        errors.append("ddgs: no results")
    except Exception as exc:
        errors.append("ddgs: %s" % exc)
    # 2) API-key-free scraper fallbacks (lite + html endpoints)
    for name, fn in (("scraper", _scraper_search), ("html", _html_search)):
        try:
            results = fn(query, max_results)
            if results:
                out = {"query": query, "backend": name,
                       "count": len(results), "results": results}
                _cache_put(cache_key, out)
                return dict(out)
            errors.append("%s: no results" % name)
        except Exception as exc:
            errors.append("%s: %s" % (name, exc))

    return {"query": query, "error": "; ".join(errors) or "no results",
            "results": [], "count": 0}
