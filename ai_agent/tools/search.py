"""Advanced web research & source citation engine.

Generates 1-3 targeted query variants per research intent (technical jargon,
acronym and non-English variations), runs them, and returns structured,
citation-ready results: title, URL and snippet context per hit.

Tools:
  tool_generate_queries(intent, lang="")
  tool_web_search_v2(query, max_results=6, variant="")
  tool_research(intent, lang="", max_results=6)  -- full loop: variants + search
  tool_build_citation(title, url, snippet="")    -- markdown citation line
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, quote_plus, urlparse

import requests

from .base import truncate

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

# Technical jargon / acronym expansions (lowercased source -> variants)
_JARGON = {
    "sql injection": ["sqli", "SQL injection attack", "inyección SQL", "SQL注入"],
    "cross-site scripting": ["xss", "XSS payload", "cross site scripting"],
    "xss": ["cross-site scripting", "XSS payload", "reflected xss", "DOM xss"],
    "sql injection attack": ["sqli", "sql injection", "inyección SQL"],
    "path traversal": ["directory traversal", "LFI", "path traversal CVE"],
    "directory traversal": ["path traversal", "LFI", "../ traversal"],
    "server-side request forgery": ["ssrf", "SSRF exploitation"],
    "cross-site request forgery": ["csrf", "xsrf", "CSRF token bypass"],
    "command injection": ["RCE", "os command injection", "injection de comandos"],
    "file upload": ["webshell upload", "malicious file upload"],
    "privilege escalation": ["privesc", "local privilege escalation"],
    "brute force": ["credential stuffing", "password spraying"],
    "denial of service": ["dos", "ddos", "resource exhaustion"],
    "authentication bypass": ["auth bypass", "authentication flaw"],
    "zero day": ["0day", "zero-day exploit"],
    "security": ["cybersecurity", "信息安全和", "seguridad informática"],
}
# Roman-Urdu / non-English topical glosses for common research intents
_NON_EN = {
    "hack": "hacking tools kali linux",
    "vulnerability": "vulnerability scanner",
    "exploit": "exploit database",
    "cve": "CVE database NVD",
    "hacking": "hacking",
    "security": "security",
    "penetration testing": "penetration testing pentest",
    "browser": "browser automation",
    "playwright": "playwright automation",
}

_CITE_BAD = re.compile(r"[^A-Za-z0-9 /._:&#()\-,%'\"+=]")


def _sanitize(text: str, limit: int = 300) -> str:
    return _CITE_BAD.sub("", (text or "")).strip()[:limit]


def tool_generate_queries(intent: str, lang: str = "") -> dict:
    """Expand a research intent into 1-3 targeted query variants."""
    intent = (intent or "").strip()
    if not intent:
        return {"error": "intent is required", "queries": []}
    variants: list[str] = [intent]
    low = intent.lower()
    # jargon / acronym variation
    for key, reps in _JARGON.items():
        if key in low:
            pat = re.compile(re.escape(key), re.IGNORECASE)
            variants.append(pat.sub(reps[0], intent))
            if len(variants) < 3 and len(reps) > 1:
                variants.append(pat.sub(reps[1], intent))
            break
    # generic non-Latin fallback -> english security gloss
    if len(variants) < 2 and not intent.isascii():
        variants.append(intent + " vulnerability security CVE")
    # CVE-number variation -> authoritative databases
    if len(variants) < 3 and re.search(r"\bcve-\d{4}-\d+\b", low):
        for rep in ("NVD vulnerability details", "cve.mitre.org database"):
            if len(variants) < 3:
                variants.append((intent + " " + rep).strip())
    # non-English variation (lang hint or glossed)
    hint = (lang or "").lower()
    if not variants or len(variants) < 3:
        for key, rep in _NON_EN.items():
            if key in low:
                suffix = f" ({rep})" if lang and lang.lower().startswith(("ur", "hi")) else " " + rep
                if len(variants) < 3:
                    variants.append((intent + suffix).strip())
                break
    uniq, seen2 = [], set()
    for v in variants:
        key = v.lower()
        if key not in seen2:
            seen2.add(key)
            uniq.append(v)
    return {"queries": uniq[:3], "count": len(uniq[:3]), "lang": lang}


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
        if tag in ("script", "style", "noscript", "svg", "head", "template") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def _html_to_text(raw, limit=8000):
    parser = _TextExtractor()
    try:
        parser.feed(raw or "")
    except Exception:
        pass
    text = re.sub(r"\n{3,}", "\n\n", "".join(parser.parts))
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()[:limit]


def _unwrap_ddg_link(href):
    try:
        if "uddg=" in href:
            return parse_qs(urlparse(href).query).get("uddg", [href])[0]
    except Exception:
        pass
    return href


def _fetch_lite(query):
    url = "https://lite.duckduckgo.com/lite/?q=" + quote_plus(query)
    resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=25)
    resp.raise_for_status()
    return resp.text


def _parse_lite(page, max_results):
    """Extract structured results: (title, url, snippet)."""
    anchors = re.findall(
        r'<a\b([^>]*\bclass=["\']result-link["\'][^>]*)>(.*?)</a>', page, re.S)
    snips = re.findall(r'class=["\']result-snippet["\']>(.*?)</td>', page, re.S)
    out = []
    for i, (attrs, title_html) in enumerate(anchors[:max_results]):
        m = re.search(r'\bhref=["\']([^"\']+)["\']', attrs)
        link = _unwrap_ddg_link(m.group(1).strip()) if m else ""
        title = re.sub(r"<[^>]+>", "", title_html).strip()
        snip = re.sub(r"<[^>]+>", "", snips[i]).strip() if i < len(snips) else ""
        out.append({"title": _sanitize(title, 200), "url": link, "snippet": _sanitize(snip, 500)})
    return out

def tool_web_search_v2(query: str, max_results: int = 6, variant: str = "") -> dict:
    """Search with one query; return structured {title, url, snippet} results."""
    if not query:
        return {"error": "query is required", "results": []}
    try:
        page = _fetch_lite(query)
        results = _parse_lite(page, max(1, min(int(max_results), 10)))
        return {
            "query": query, "variant": variant, "count": len(results),
            "results": results,
        }
    except Exception as exc:
        return {"query": query, "variant": variant, "error": str(exc), "results": []}


def tool_research(intent: str, lang: str = "", max_results: int = 6) -> dict:
    """Full research loop: expand intent to 1-3 variants, run each, merge hits."""
    gen = tool_generate_queries(intent, lang)
    queries = gen.get("queries", [])
    if not queries:
        return {"error": "intent is required", "sources": []}
    merged, seen = [], set()
    for q in queries:
        res = tool_web_search_v2(q, max_results=max(1, int(max_results) // max(len(queries), 1) + 1))
        for r in res.get("results", []):
            if not r.get("url"):
                continue
            key = r.get("url") or r.get("title")
            if key and key not in seen:
                seen.add(key)
                r["query_variant"] = q
                merged.append(r)
    merged = merged[:max(1, int(max_results))]
    return {
        "intent": intent, "lang": lang, "query_variants": queries,
        "sources": merged, "count": len(merged),
    }


def tool_build_citation(title: str = "", url: str = "", snippet: str = "") -> dict:
    """Build a strict markdown citation line from a validated source."""
    title = _sanitize(title, 200)
    url = _sanitize(url, 500)
    snippet = _sanitize(snippet, 300)
    if not url:
        return {"error": "url is required", "citation": ""}
    if not title:
        title = url
    citation = f"Source: {title} — {url}"
    if snippet:
        citation += f" (\"{truncate(snippet, 200)}\")"
    return {"citation": citation, "title": title, "url": url, "snippet": snippet}


def tool_open_url(url):
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
        return _html_to_text(resp.text)
    except Exception as exc:
        return "open_url error: %s" % exc
