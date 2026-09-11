"""STEP 1 UI verification: gatekeeper full-screen lockscreen overlay.

* Static asset checks (no Flask import, always fast):
    - ai_agent/webui/templates/gatekeeper_lockscreen.html exposes the
      full-screen overlay entry point, master-password input and the
      fingerprint/biometric button.
    - ai_agent/webui/static/gatekeeper_lockscreen.css forces
      z-index: 9999, fixed full-viewport coverage and backdrop blur.
    - ai_agent/webui/static/gatekeeper_lockscreen.js wires password +
      fingerprint unlock handlers.
* Render check (mock mode): loading the WebUI shows the lockscreen
  overlay first (GET / contains the overlay) and both static assets
  are served without error.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WEBUI_DIR = REPO_ROOT / "ai_agent" / "webui"
TPL = WEBUI_DIR / "templates" / "gatekeeper_lockscreen.html"
CSS = WEBUI_DIR / "static" / "gatekeeper_lockscreen.css"
JS = WEBUI_DIR / "static" / "gatekeeper_lockscreen.js"


def test_assets_exist():
    assert TPL.is_file(), "lockscreen template missing"
    assert CSS.is_file(), "lockscreen stylesheet missing"
    assert JS.is_file(), "lockscreen script missing"


def test_overlay_markup_blocks_webui():
    html = TPL.read_text(encoding="utf-8")
    assert 'id="gatekeeper-lockscreen"' in html
    assert 'class="gatekeeper-lockscreen"' in html
    assert 'role="dialog"' in html and 'aria-modal="true"' in html
    assert 'id="gk-password"' in html and 'type="password"' in html
    assert 'id="gk-submit"' in html
    assert 'id="gk-fingerprint"' in html  # fingerprint / biometric icon button


def test_css_is_full_screen_topmost():
    css = CSS.read_text(encoding="utf-8")
    assert "z-index: 9999" in css
    assert "position: fixed" in css
    assert "backdrop-filter: blur" in css or "-webkit-backdrop-filter: blur" in css
    assert ".gk-hidden" in css  # overlay only hides after unlock


def test_js_wires_unlock_ceremonies():
    js = JS.read_text(encoding="utf-8")
    assert "/api/gatekeeper/status" in js
    assert "/api/gatekeeper/unlock" in js
    assert "/api/gatekeeper/webauthn/assert" in js
    assert 'addEventListener("submit"' in js or 'addEventListener(\'submit\'' in js
    assert 'addEventListener("click"' in js


@pytest.fixture()
def app_client():
    import webui

    backup = None
    if os.path.exists(webui.CONFIG_PATH):
        with open(webui.CONFIG_PATH, "r", encoding="utf-8") as f:
            backup = f.read()
    webui._reload_state(mock_override=True)
    yield webui.app.test_client()
    if backup is None:
        try:
            os.remove(webui.CONFIG_PATH)
        except FileNotFoundError:
            pass
    else:
        with open(webui.CONFIG_PATH, "w", encoding="utf-8") as f:
            f.write(backup)


def test_webui_renders_lockscreen_first(app_client):
    resp = app_client.get("/")
    assert resp.status_code == 200
    page = resp.get_data(as_text=True)
    # The overlay must appear before the main app markup; it is included
    # immediately after <body> and blocks everything behind it.
    assert "gatekeeper-lockscreen" in page
    assert "AGENT LOCKED" in page
    assert page.find("gatekeeper-lockscreen") < page.find("<div class=\"app\">")


def test_lockscreen_assets_served(app_client):
    css_resp = app_client.get("/gatekeeper/lockscreen.css")
    assert css_resp.status_code == 200
    assert "z-index: 9999" in css_resp.get_data(as_text=True)
    js_resp = app_client.get("/gatekeeper/lockscreen.js")
    assert js_resp.status_code == 200
    assert "/api/gatekeeper/unlock" in js_resp.get_data(as_text=True)
