"""Jina AI integration — neural web search (s.jina.ai) + Reader (r.jina.ai).

Provider : https://jina.ai  (JINA_API_KEY in .env)
  * Search  : GET https://s.jina.ai/?q=<query>      -> ranked web results
  * Reader  : GET https://r.jina.ai/<url>           -> clean LLM-ready markdown
  * Grounding: GET https://g.jina.ai/<query>        -> factual grounding (opt-in)

Design notes
------------
* No hard dependency: if `requests` is missing or JINA_API_KEY is unset the
  functions degrade gracefully and return structured dicts (never raise), so a
  missing key can never crash the agent loop.
* The API key is read ONLY from the environment / .env (JINA_API_KEY), matching
  the project convention in ai_agent/config.py. It is never logged or echoed.
* Jina is registered as the *priority* search backend in web_search.search_web
  (keyed, higher quality, JSON output) while DuckDuckGo stays as the keyless
  fallback chain.

Public API:
  jina_available() -> bool
  jina_status()    -> dict
  jina_search(query, max_results=8) -> {"query","backend":"jina","count","results":[...]}
  jina_read(url, max_length=8000)   -> {"url","status","title","text",...}
  jina_ground(query)                -> {"query","facts":[...]}

Tools (registered in tools/__init__.py):
  tool_jina_search, tool_jina_read, tool_jina_status
"""

from __future__ import annotations

import os
import re
import time

try:
    import requests
except ImportError:  # pragma: no cover - requests is a hard project dep
    requests = None  # type: ignore

REQUEST_TIMEOUT = 30
SEARCH_ENDPOINT = "https://s.jina.ai/"
READER_ENDPOINT = "https://r.jina.ai/"
GROUND_ENDPOINT = "https://g.jina.ai/"

MAX_RESULTS_CAP = 20
_TAG_RE = re.compile(r"<[^>]+>")


def _key() -> str:
    """Return the Jina API key from the environment (never logged)."""
    return (os.environ.get("JINA_API_KEY") or "").strip()


def jina_available() -> bool:
    return bool(requests is not None and _key())


def jina_status() -> dict:
    return {
        "available": jina_available(),
        "requests_installed": requests is not None,
        "key_present": bool(_key()),
        "endpoints": {"search": SEARCH_ENDPOINT,
                      "reader": READER_ENDPOINT,
                      "ground": GROUND_ENDPOINT},
        "note": "set JINA_API_KEY in .env to enable; keyless reader also works at 20 RPM",
    }


def _headers(extra: dict | None = None) -> dict:
    h = {
        "Accept": "application/json",
        "User-Agent": "HackerAI-MyAgent/1.0 (+jina)",
    }
    key = _key()
    if key:
        h["Authorization"] = "Bearer " + key
    if extra:
        h.update(extra)
    return h


def _clean(text, limit=600) -> str:
    text = _TAG_RE.sub("", str(text or "")).strip()
    text = re.sub(r"\s{2,}", " ", text)
    return text[:limit]


def _clamp(max_results) -> int:
    try:
        n = int(max_results)
    except (TypeError, ValueError):
        n = 8
    return max(1, min(n, MAX_RESULTS_CAP))


def _as_text(value) -> str:
    """Flatten Jina 'description'/'content' which may be str or list."""
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value or "")


def jina_search(query: str, max_results: int = 8) -> dict:
    """Search the web via Jina's neural search (s.jina.ai).

    Returns a structured dict compatible with web_search.search_web results:
        {"query", "backend": "jina", "count", "results": [{title,url,snippet}]}
    plus {"error": str} on failure (results == []).
    """
    query = (query or "").strip()
    if not query:
        return {"query": query, "error": "query is required",
                "results": [], "count": 0}
    if requests is None:
        return {"query": query, "error": "requests library not installed",
                "results": [], "count": 0}
    max_results = _clamp(max_results)

    url = SEARCH_ENDPOINT + "?q=" + requests.utils.quote(query)
    # no-content keeps the payload small: title + url + description per hit
    headers = _headers({"X-Respond-With": "no-content"})
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        return {"query": query, "error": "jina search timeout", "results": [], "count": 0}
    except requests.exceptions.RequestException as exc:
        return {"query": query, "error": "jina search request failed: %s" % exc,
                "results": [], "count": 0}

    if resp.status_code == 401:
        return {"query": query, "error": "jina search 401 (invalid JINA_API_KEY)",
                "results": [], "count": 0}
    if resp.status_code == 429:
        return {"query": query, "error": "jina search 429 (rate limited)",
                "results": [], "count": 0}
    if resp.status_code >= 400:
        return {"query": query, "error": "jina search HTTP %d" % resp.status_code,
                "results": [], "count": 0}

    results: list[dict] = []
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "json" in ctype or resp.text.lstrip().startswith(("{", "[")):
        try:
            data = resp.json()
            items = data.get("data") if isinstance(data, dict) else data
            for item in (items or []):
                if not isinstance(item, dict):
                    continue
                results.append({
                    "title": _clean(item.get("title"), 200),
                    "url": _clean(item.get("url"), 500),
                    "snippet": _clean(_as_text(item.get("description")
                                               or item.get("content")), 500),
                })
        except ValueError:
            results = []
    if not results:
        # markdown fallback: lines like "Title: ... / URL Source: ... "
        for block in re.split(r"\n\s*\n", resp.text or ""):
            m_t = re.search(r"Title:\s*(.+)", block)
            m_u = re.search(r"URL Source:\s*(\S+)", block)
            if m_t and m_u:
                results.append({"title": _clean(m_t.group(1), 200),
                                "url": _clean(m_u.group(1), 500),
                                "snippet": ""})

    results = [r for r in results if r.get("url")][:max_results]
    if not results:
        return {"query": query, "error": "jina search: no results",
                "results": [], "count": 0}
    return {"query": query, "backend": "jina", "count": len(results),
            "results": results}


def jina_read(url: str, max_length: int = 8000) -> dict:
    """Fetch any URL and convert it to clean, LLM-ready markdown via r.jina.ai.

    Bypasses JS-rendering walls, cookie banners and anti-bot blocks that break
    plain requests. Works keyless (20 RPM) or with JINA_API_KEY (higher limits).
    """
    url = (url or "").strip()
    if not url:
        return {"url": url, "status": "error", "error": "url is required", "text": ""}
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    if requests is None:
        return {"url": url, "status": "error",
                "error": "requests library not installed", "text": ""}

    started = time.monotonic()
    # Reader must return plain markdown, NOT the JSON envelope
    headers = _headers({"X-Return-Format": "markdown", "Accept": "text/plain"})
    target = READER_ENDPOINT + url
    try:
        resp = requests.get(target, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        return {"url": url, "status": "error", "error": "jina reader timeout", "text": ""}
    except requests.exceptions.RequestException as exc:
        return {"url": url, "status": "error",
                "error": "jina reader request failed: %s" % exc, "text": ""}

    if resp.status_code >= 400:
        return {"url": url, "status": "error", "http_status": resp.status_code,
                "error": "jina reader HTTP %d" % resp.status_code, "text": ""}

    text = resp.text or ""
    # defensive: if the JSON envelope slips through, unwrap the content field
    if text.lstrip().startswith("{"):
        try:
            env = resp.json()
            node = env.get("data") if isinstance(env, dict) else None
            if isinstance(node, dict):
                text = str(node.get("content") or node.get("text") or "")
        except ValueError:
            pass
    title = ""
    m = re.search(r"^Title:\s*(.+)$", text, re.M)
    if m:
        title = _clean(m.group(1), 200)
        # strip the metadata header block (Title:/URL Source:/Markdown Content:)
        text = re.sub(r"^(Title|URL Source|Markdown Content|Published Time):.*\n?",
                      "", text, flags=re.M)
    text = text.strip()
    truncated = False
    try:
        lim = max(500, int(max_length))
    except (TypeError, ValueError):
        lim = 8000
    if len(text) > lim:
        text = text[:lim].rstrip() + "\n...[truncated]"
        truncated = True
    return {"url": url, "status": "ok", "http_status": resp.status_code,
            "title": title, "text": text, "truncated": truncated,
            "original_length": None if truncated else len(text),
            "elapsed_ms": int((time.monotonic() - started) * 1000)}


def jina_ground(query: str) -> dict:
    """Factual grounding via g.jina.ai — returns verified statements + sources."""
    query = (query or "").strip()
    if not query or requests is None:
        return {"query": query, "error": "query required / requests missing",
                "facts": []}
    url = GROUND_ENDPOINT + requests.utils.quote(query)
    try:
        resp = requests.get(url, headers=_headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"query": query, "error": "jina ground failed: %s" % exc, "facts": []}
    facts = data.get("data") if isinstance(data, dict) else data
    return {"query": query, "facts": facts or [], "count": len(facts or [])}


# --------------------------------------------------------------------------
# Tool wrappers (registered as agent tools)
# --------------------------------------------------------------------------

def tool_jina_search(query: str = "", max_results: int = 8) -> dict:
    return jina_search(query, max_results)


def tool_jina_read(url: str = "", max_length: int = 8000) -> dict:
    return jina_read(url, max_length)


def tool_jina_status() -> dict:
    return jina_status()
