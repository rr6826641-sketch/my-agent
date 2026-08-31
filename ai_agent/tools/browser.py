"""Playwright / Chromium headless browser automation engine.

Real-browser execution for verifying DOM-based XSS, client-side auth
bypasses, CSRF flows and complex JavaScript single-page applications
(SPAs).

Tools:
  browse_page(uri, wait_ms=2500, capture_js_errors=True)
  click_element(selector, wait_ms=1200)
  fill_form(fields_json, submit_selector="")
  take_screenshot(path="", full_page=False)
  capture_network_traffic(uri="", wait_ms=3000, filter_substring="", max_entries=250)

Requires:  py -m pip install playwright  &&  py -m playwright install chromium
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any, Dict, List

try:
    from .base import truncate
except Exception:  # pragma: no cover - fallback for isolated imports
    def truncate(text: str, n: int) -> str:
        text = text or ""
        return text if len(text) <= n else text[:n] + f"... (truncated {len(text) - n} chars)"

try:  # pragma: no cover - optional dependency
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
    _PW_OK = True
except Exception:  # pragma: no cover
    sync_playwright = None
    _PW_OK = False

_browser = None
_context = None
_page = None
_console_msgs: List[Dict[str, str]] = []
_requests: List[Dict[str, Any]] = []
_last_status_code: int | None = None
_user_agent: str | None = None


def _pw_missing() -> str:
    return (
        "Playwright is not installed in this Python environment. "
        "Install it with:  py -m pip install playwright  &&  py -m playwright install chromium"
    )


def _reset_capture() -> None:
    global _console_msgs, _requests, _last_status_code
    _console_msgs = []
    _requests = []
    _last_status_code = None


def _ensure_page():
    global _browser, _context, _page
    if _page is not None and not _page.is_closed():
        return _page
    if not _PW_OK:
        return None
    if _browser is None or not _browser.is_connected():
        pw = sync_playwright().start()
        _browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-blink-features=AutomationControlled"],
        )
    ctx_kwargs: Dict[str, Any] = {"ignore_https_errors": True}
    if _user_agent:
        ctx_kwargs["user_agent"] = _user_agent
    _context = _browser.new_context(**ctx_kwargs)
    _page = _context.new_page()

    def _on_request(req):
        if len(_requests) < 500:
            _requests.append({"url": req.url, "method": req.method, "type": req.resource_type})

    def _on_response(resp):
        global _last_status_code
        try:
            if resp.request.is_navigation_request():
                _last_status_code = resp.status
        except Exception:
            if resp.url == _page.url:
                _last_status_code = resp.status
        for entry in _requests:
            if entry["url"] == resp.url and "status" not in entry:
                entry["status"] = resp.status
                try:
                    entry["size"] = len(resp.body())
                except Exception:
                    entry["size"] = 0
                break

    def _on_console(msg):
        _console_msgs.append({"type": msg.type, "text": msg.text[:400]})

    def _on_pageerror(err):
        _console_msgs.append({"type": "pageerror", "text": str(err)[:400]})

    _page.on("request", _on_request)
    _page.on("response", _on_response)
    _page.on("console", _on_console)
    _page.on("pageerror", _on_pageerror)
    return _page


def _close_browser() -> None:
    global _browser, _context, _page
    try:
        if _page is not None and not _page.is_closed():
            _page.close()
        if _context is not None:
            _context.close()
        if _browser is not None and _browser.is_connected():
            _browser.close()
    except Exception:
        pass
    _browser = _context = _page = None


def tool_browse_page(uri: str, wait_ms: int = 2500, capture_js_errors: bool = True,
                     user_agent: str = "") -> Dict[str, Any]:
    global _user_agent
    if user_agent and user_agent != _user_agent:
        _close_browser()
        _user_agent = user_agent
    if not isinstance(uri, str) or not uri.startswith(("http://", "https://", "file://")):
        return {"error": "uri must start with http://, https:// or file://"}
    page = _ensure_page()
    if page is None:
        return {"error": _pw_missing()}
    # Same-document (hash-only) navigation does not re-fetch the document, so
    # keep the previous HTTP status instead of resetting it to None.
    same_doc = False
    try:
        cur = page.url
        same_doc = bool(cur and uri.startswith(("http://", "https://")) and cur.split("#")[0] == uri.split("#")[0])
    except Exception:
        pass
    if not same_doc:
        _reset_capture()
    try:
        page.goto(uri, wait_until="domcontentloaded", timeout=max(int(wait_ms), 1000))
        page.wait_for_timeout(int(wait_ms))
    except PlaywrightTimeoutError:
        pass
    except Exception as exc:
        return {"error": f"navigation failed: {exc}"}
    title, content, body = "", "", ""
    try:
        title = page.title() or ""
        content = page.content() or ""
        body = page.inner_text("body") or ""
    except Exception:
        pass
    return {
        "final_url": page.url,
        "title": title,
        "http_status": _last_status_code,
        "html_size": len(content),
        "body_preview": truncate(body, 1500),
        "console_js_errors": _console_msgs[-30:] if capture_js_errors else [],
    }


def tool_click_element(selector: str, wait_ms: int = 1200) -> Dict[str, Any]:
    page = _ensure_page()
    if page is None:
        return {"error": _pw_missing()}
    if not selector:
        return {"error": "selector is required"}
    try:
        element = page.wait_for_selector(selector, timeout=5000)
        if element is None:
            return {"error": f"element not found: {selector}"}
        element.click()
        page.wait_for_timeout(int(wait_ms))
        return {"clicked": selector, "url": page.url, "title": page.title() or ""}
    except PlaywrightTimeoutError:
        return {"error": f"element not found after 5s: {selector}"}
    except Exception as exc:
        return {"error": str(exc)}


def tool_fill_form(fields: str, submit_selector: str = "") -> Dict[str, Any]:
    page = _ensure_page()
    if page is None:
        return {"error": _pw_missing()}
    if isinstance(fields, str):
        try:
            data = json.loads(fields)
        except Exception:
            return {"error": 'fields must be a JSON object like {"#username": "admin", "[name=pass]": "x"}'}
    else:
        data = fields
    if not isinstance(data, dict):
        return {"error": "fields must be a JSON object"}
    filled, failed = [], []
    for sel, value in data.items():
        try:
            page.fill(str(sel), str(value))
            filled.append(str(sel))
        except Exception as exc:
            failed.append({"selector": sel, "error": str(exc)})
    out: Dict[str, Any] = {"filled": filled, "failed": failed}
    if submit_selector:
        try:
            page.click(submit_selector)
            page.wait_for_timeout(1200)
            out["submitted"] = submit_selector
            out["url"] = page.url
        except Exception as exc:
            out["submit_error"] = str(exc)
    return out


def tool_take_screenshot(path: str = "", full_page: bool = False) -> Dict[str, Any]:
    page = _ensure_page()
    if page is None:
        return {"error": _pw_missing()}
    if not path:
        path = os.path.join(tempfile.gettempdir(), f"agent_shot_{int(time.time())}.png")
    try:
        page.screenshot(path=path, full_page=bool(full_page))
        return {"saved": os.path.abspath(path), "bytes": os.path.getsize(path), "full_page": bool(full_page)}
    except Exception as exc:
        return {"error": str(exc)}


def tool_capture_network_traffic(
    uri: str = "",
    wait_ms: int = 3000,
    filter_substring: str = "",
    max_entries: int = 250,
) -> Dict[str, Any]:
    page = _ensure_page()
    if page is None:
        return {"error": _pw_missing()}
    if uri:
        try:
            page.goto(uri, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(int(wait_ms))
        except Exception as exc:
            return {"error": f"navigation failed: {exc}"}
    entries = _requests
    if filter_substring:
        entries = [e for e in entries if filter_substring in e["url"]]
    entries = entries[-max(1, min(int(max_entries), 500)):]
    return {"total": len(entries), "entries": entries}


def tool_close_browser() -> Dict[str, Any]:
    _close_browser()
    return {"closed": True}
