"""Web page scraping & main-content extraction engine.

Public API:
  fetch_url(url, max_length=4000) -> dict (structured, never raises)
      {"url", "status", "http_status", "title", "text", "content_type",
       "truncated", "original_length", "elapsed_ms", ...}

Pipeline:
  requests GET (rotating user-agent, timeout, size-capped stream)
    -> BeautifulSoup parse
    -> junk stripping (script/style/nav/header/footer/aside/forms/ads)
    -> readability heuristics (best <article>/<main>/densest text container)
    -> whitespace cleanup + clean truncation on sentence/word boundaries

Errors (404/403/timeouts/SSL/DNS/etc.) come back as structured dicts with
an "error" key and status="error" — a bad URL can never crash the agent
loop or hang a tool thread.
"""

from __future__ import annotations

import random
import re
import socket
import ssl
import time
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

REQUEST_TIMEOUT = 20          # seconds per HTTP request
MAX_DOWNLOAD_BYTES = 3_000_000  # hard cap on response body (3 MB)
DEFAULT_MAX_LENGTH = 4000     # default text cap (keeps tool output token-safe)
MAX_LENGTH_CAP = 50_000

# Rotating user-agents (desktop Chrome / Firefox / Edge on Windows & Linux)
USER_AGENTS = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 "
     "Firefox/127.0"),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0"),
]

_REQUEST_HEADERS = {
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,*/*;q=0.8"),
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "close",
}

# Tags whose entire content is noise for readability purposes
_JUNK_TAGS = (
    "script", "style", "noscript", "svg", "iframe", "template", "form",
    "nav", "header", "footer", "aside", "button", "select", "textarea",
    "canvas", "audio", "video",
)
# Common ad/tracking containers matched by class/id substring
_JUNK_CLASS_HINTS = re.compile(
    r"(cookie|consent|banner|advert|ads?-|ads$|tracking|newsletter|"
    r"subscribe|popup|modal|overlay|sidebar|breadcrumb|pagination|"
    r"social-share|share-buttons|related-posts|comments?|footer|"
    r"nav[-_ ]?(menu|bar)?|topbar|byline|promo|sponsor)", re.I)

_WHITESPACE = re.compile(r"[ \t]+")
_MANY_NEWLINES = re.compile(r"\n{3,}")


def _clamp(max_length) -> int:
    try:
        n = int(max_length)
    except (TypeError, ValueError):
        n = DEFAULT_MAX_LENGTH
    return max(200, min(n, MAX_LENGTH_CAP))


def _pick_ua() -> str:
    return random.choice(USER_AGENTS)


def _error(url: str, message: str, http_status=None, **extra) -> dict:
    out = {"url": url, "status": "error", "error": message,
           "http_status": http_status, "title": "", "text": "",
           "truncated": False}
    out.update(extra)
    return out


def _clean_truncate(text: str, max_length: int) -> tuple[str, bool]:
    """Truncate on a sentence, then word, boundary; return (text, truncated)."""
    text = _MANY_NEWLINES.sub("\n\n", text).strip()
    if len(text) <= max_length:
        return text, False
    cut = text[:max_length]
    # prefer last sentence end inside the cut window
    best = -1
    for sep in (". ", "! ", "? ", ".\n", "!\n", "?\n"):
        idx = cut.rfind(sep)
        if idx > best:
            best = idx
    if best > max_length * 0.5:
        return cut[:best + 1].rstrip() + "\n...[truncated]", True
    # fall back to a word boundary
    sp = cut.rfind(" ")
    if sp > max_length * 0.5:
        return cut[:sp].rstrip() + " ...[truncated]", True
    return cut.rstrip() + " ...[truncated]", True


# --------------------------------------------------------------------------
# HTML -> readable main text
# --------------------------------------------------------------------------

def _strip_junk(soup: BeautifulSoup) -> None:
    for tag in soup.find_all(_JUNK_TAGS):
        tag.decompose()
    # drop ad/nav/comment/social containers by class/id hints
    for el in soup.find_all(class_=_JUNK_CLASS_HINTS):
        el.decompose()
    for el in soup.find_all(id=_JUNK_CLASS_HINTS):
        el.decompose()
    # drop tiny fragmented inline nodes that only carry layout text
    for el in soup.find_all(
            lambda t: t.name in ("div", "span", "p") and not t.get_text(strip=True)
            and not t.find(["p", "li", "td", "h1", "h2", "h3", "h4"])):
        el.decompose()


def _score_container(el) -> int:
    """Rough text-density score used to pick the main content container."""
    score = 0
    for p in el.find_all("p"):
        score += len(p.get_text(" ", strip=True))
    if el.name in ("article", "main"):
        score = int(score * 1.25)
    return score


def _extract_main_text(soup: BeautifulSoup) -> str:
    # explicit semantic containers first
    candidates = soup.find_all(["article", "main"])
    if not candidates:
        # fall back to densest generic container (div/section/body)
        candidates = soup.find_all(["div", "section", "body"])
    best, best_score = None, 0
    for c in candidates:
        score = _score_container(c)
        if score > best_score:
            best, best_score = c, score
    # <pre>/<code> blocks (docs, raw dumps) deserve preservation
    pres = soup.find_all(["pre", "code"])
    root = best if best is not None else soup.body or soup
    if best_score < 300 and pres:
        # text-thin pages: treat pre blocks as first-class content
        blocks = [p.get_text("\n", strip=True) for p in pres]
        body_text = root.get_text("\n", strip=True)
        return (body_text + "\n\n" + "\n\n".join(blocks)).strip() \
            if body_text else "\n\n".join(blocks).strip()
    return root.get_text("\n", strip=True)


def _clean_text(raw: str) -> str:
    raw = raw or ""
    raw = _WHITESPACE.sub(" ", raw)
    raw = re.sub(r" ?\n ?", "\n", raw)
    raw = _MANY_NEWLINES.sub("\n\n", raw)
    # drop junk lines that are pure UI noise
    junk_line = re.compile(
        r"^(cookie|accept all|manage preferences|share (this|on)|follow us|"
        r"subscribe|sign in|log in|advertisement|skip to (main )?content)\b.*$",
        re.I | re.M)
    raw = junk_line.sub("", raw)
    return raw.strip()


# --------------------------------------------------------------------------
# Public tool API
# --------------------------------------------------------------------------

def fetch_url(url: str, max_length: int = DEFAULT_MAX_LENGTH) -> dict:
    """Fetch a web page and extract readable main text.

    Returns a structured dict; on failure returns status="error" with a
    human-readable "error" message instead of raising.
    """
    started = time.monotonic()
    url = (url or "").strip()
    if not url:
        return _error(url, "url is required")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("invalid URL")
        # uncensored build: any http(s) URL is fetchable, including
        # localhost/loopback/internal hosts (local app testing, post-exploitation
        # pivots, intranet recon). The operator's machine runs this tool, so no
        # destination is out of bounds.
    except ValueError:
        return _error(url, "invalid URL format")
    max_length = _clamp(max_length)

    headers = dict(_REQUEST_HEADERS)
    headers["User-Agent"] = _pick_ua()
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT,
                            allow_redirects=True, stream=True)
        status = resp.status_code
        ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip()
        # stream with a size cap so huge/binary responses can't eat memory
        content = b""
        for chunk in resp.iter_content(chunk_size=65536):
            content += chunk
            if len(content) >= MAX_DOWNLOAD_BYTES:
                content = content[:MAX_DOWNLOAD_BYTES]
                break
        resp.close()
    except requests.exceptions.Timeout:
        return _error(url, "timeout after %ds" % REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError as exc:
        msg = str(getattr(exc, "reason", None) or exc)
        if "NameResolutionError" in msg or "getaddrinfo failed" in msg or "Name or service not known" in msg:
            return _error(url, "DNS resolution failed for host")
        return _error(url, "connection failed: %s" % msg.split("(" )[0].strip())
    except ssl.SSLError as exc:
        return _error(url, "SSL error: %s" % exc)
    except socket.gaierror:
        return _error(url, "DNS resolution failed for host")
    except requests.exceptions.RequestException as exc:
        return _error(url, "request failed: %s" % exc)

    if status >= 400:
        msgs = {401: "unauthorized (401)", 403: "forbidden (403)",
                404: "not found (404)", 410: "gone (410)",
                429: "rate limited (429)",
                500: "server error (500)", 502: "bad gateway (502)",
                503: "service unavailable (503)"}
        return _error(url, msgs.get(status, "HTTP error %d" % status),
                      http_status=status,
                      content_type=ctype)

    if "html" in ctype or "xml" in ctype or not ctype:
        try:
            soup = BeautifulSoup(
                content[:MAX_DOWNLOAD_BYTES],
                "html.parser")
            if not soup.body and b"<html" not in content[:512].lower():
                pass  # parser still produced something; keep it
            title = (soup.title.get_text(strip=True)
                     if soup.title else "")[:200]
            _strip_junk(soup)
            text = _extract_main_text(soup)
            text = _clean_text(text)
        except Exception as exc:
            return _error(url, "HTML parse failed: %s" % exc,
                          http_status=status, content_type=ctype)
    else:
        # plain text / json / binary-ish: only serve text-like content
        title = ""
        if any(t in ctype for t in ("text/", "json", "javascript")) or ctype == "":
            try:
                text = content.decode(resp.encoding or "utf-8", "replace")
            except Exception as exc:
                return _error(url, "decode failed: %s" % exc,
                              http_status=status, content_type=ctype)
        else:
            return _error(url, "unsupported content type: %s" % (ctype or "unknown"),
                          http_status=status)

    if not text.strip():
        return _error(url, "no readable text extracted (page may be JS-rendered)",
                      http_status=status, content_type=ctype, title=title)

    text, truncated = _clean_truncate(text, max_length)
    return {
        "url": url,
        "final_url": getattr(resp, "url", url),
        "status": "ok",
        "http_status": status,
        "content_type": ctype,
        "title": title,
        "text": text,
        "truncated": truncated,
        "original_length": None if truncated else len(text),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
