"""Web search (DuckDuckGo, no API key) and page text extraction."""

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, quote_plus, urlparse

import requests

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


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
    """DuckDuckGo wraps real URLs in a redirect; extract the target."""
    try:
        if "uddg=" in href:
            parsed = parse_qs(urlparse(href).query)
            return parsed.get("uddg", [href])[0]
    except Exception:
        pass
    return href


def tool_web_search(query, max_results=6):
    url = "https://lite.duckduckgo.com/lite/?q=" + quote_plus(query)
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=25)
        resp.raise_for_status()
        page = resp.text
        titles = re.findall(r'class=["\']result-link["\'][^>]*>(.*?)</a>', page, re.S)
        links = re.findall(
            r'<a[^>]*class=["\']result-link["\'][^>]*href=["\']([^"\']+)["\']',
            page)
        snips = re.findall(r'class=["\']result-snippet["\']>(.*?)</td>', page, re.S)
        results = []
        count = max(len(titles), len(links))
        for i in range(min(max_results, count)):
            title = re.sub(r"<[^>]+>", "", titles[i]).strip() if i < len(titles) else ""
            link = _unwrap_ddg_link(links[i].strip()) if i < len(links) else ""
            snip = re.sub(r"<[^>]+>", "", snips[i]).strip() if i < len(snips) else ""
            results.append("%d. %s\n   %s\n   %s" % (i + 1, title, link, snip))
        return "\n\n".join(results) if results else "No results found."
    except Exception as exc:
        return "web_search error: %s" % exc


def tool_open_url(url):
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
        return _html_to_text(resp.text)
    except Exception as exc:
        return "open_url error: %s" % exc
