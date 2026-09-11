"""STEP 1 UI verification: gatekeeper full-screen lockscreen overlay.

* Static asset checks (no Flask import, always fast):
    - ai_agent/webui/templates/gatekeeper_lockscreen.html exposes the
      full-screen overlay entry point, master-password input and the
      fingerprint/biometric button.
    - ai_agent/webui/static/gatekeeper_lockscreen.css forces
      z-index: 9999, fixed full-viewport coverage, crisp HD styling
      (explicitly no backdrop blur - blur-free by design).
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
    # HD TURBO lockscreen (v0.8.3+): razor-sharp by design - blur must
    # never come back, otherwise the password screen turns blurry again.
    assert "backdrop-filter" not in css
    assert "-webkit-backdrop-filter" not in css
    assert ".gk-blur-layer" in css  # sharp HD ambient glow layer (no blur)
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


def test_gatekeeper_status_endpoint(app_client):
    resp = app_client.get("/api/gatekeeper/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "setup" in data and "locked" in data


def test_gatekeeper_setup_unlock_endpoints(app_client):
    r1 = app_client.post("/api/gatekeeper/setup", json={"password": "Master-Pass-2026"})
    assert r1.status_code == 200 and r1.get_json()["ok"] is True
    r2 = app_client.post("/api/gatekeeper/unlock", json={"password": "Master-Pass-2026"})
    assert r2.status_code == 200 and r2.get_json()["ok"] is True
    assert "token" in r2.get_json()
    r3 = app_client.post("/api/gatekeeper/unlock", json={"password": "wrong-pass"})
    assert r3.status_code == 401


def test_gatekeeper_lock_and_status_flow(app_client):
    app_client.post("/api/gatekeeper/setup", json={"password": "Master-Pass-2026"})
    app_client.post("/api/gatekeeper/unlock", json={"password": "Master-Pass-2026"})
    st = app_client.get("/api/gatekeeper/status").get_json()
    assert st["locked"] is False
    app_client.post("/api/gatekeeper/lock", json={})
    st2 = app_client.get("/api/gatekeeper/status").get_json()
    assert st2["locked"] is True


def test_gatekeeper_webauthn_assert_not_registered(app_client):
    app_client.post("/api/gatekeeper/setup", json={"password": "Master-Pass-2026"})
    resp = app_client.post("/api/gatekeeper/webauthn/assert", json={})
    assert resp.status_code == 400
# --------------------------------------------------------------------------
# STEP 4 integration: Lock Screen UI -> Auth Engine -> OS Notification
# --------------------------------------------------------------------------

def test_unlock_success_hides_overlay_contract():
    """Unlock ceremony must hide `.gatekeeper-lockscreen` (gk-hidden)."""
    js = JS.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    # success path of the password ceremony calls hideOverlay()
    assert "function hideOverlay()" in js
    assert 'root.classList.add("gk-hidden")' in js
    # ...and hideOverlay is invoked on the unlock success chain
    assert ".then(function () { hideOverlay(); })" in js
    # CSS: gk-hidden state makes the overlay disappear
    assert ".gatekeeper-lockscreen.gk-hidden" in css
    assert "display: none" in css


def test_auto_lock_cleanup_contract():
    """After lock/auto-lock the UI keeps the overlay mounted for re-check."""
    js = JS.read_text(encoding="utf-8")
    assert "has-gatekeeper" in js
    assert 'fetch("/api/gatekeeper/status"' in js
    assert "markReady" in js and "markNotSetup" in js


def test_ui_unlock_fires_desktop_notification(app_client, monkeypatch):
    """Seamless flow: UI unlock (password) -> auth engine -> OS notification."""
    import webui
    calls = []
    monkeypatch.setattr(webui, "_login_notify", lambda m: calls.append(m))
    r1 = app_client.post("/api/gatekeeper/setup",
                         json={"password": "Master-Pass-2026"})
    assert r1.status_code == 200 and r1.get_json()["ok"] is True
    r2 = app_client.post("/api/gatekeeper/unlock",
                         json={"password": "Master-Pass-2026"})
    assert r2.status_code == 200 and r2.get_json()["ok"] is True
    assert r2.get_json()["token"]
    assert calls == ["Password"], "successful unlock must fire the Password notification"


def test_failed_ui_unlock_fires_no_notification(app_client, monkeypatch):
    """Wrong password: 401 and NO desktop notification may be emitted."""
    import webui
    calls = []
    monkeypatch.setattr(webui, "_login_notify", lambda m: calls.append(m))
    app_client.post("/api/gatekeeper/setup",
                    json={"password": "Master-Pass-2026"})
    r3 = app_client.post("/api/gatekeeper/unlock", json={"password": "wrong-pass"})
    assert r3.status_code == 401
    assert calls == []


def test_ui_webauthn_complete_fires_notification(app_client, monkeypatch):
    """Seamless flow: fingerprint unlock -> auth engine -> OS notification."""
    import webui
    from ai_agent.webui.gatekeeper import Gatekeeper
    calls = []
    monkeypatch.setattr(webui, "_login_notify", lambda m: calls.append(m))
    monkeypatch.setattr(
        Gatekeeper, "webauthn_complete_assert",
        lambda self, *a, **k: {"ok": True, "token": "tok-bio"})
    r = app_client.post("/api/gatekeeper/webauthn/assert",
                        json={"credential_id": "c", "client_data": "x",
                              "auth_data": "y", "signature": "z"})
    assert r.status_code == 200 and r.get_json()["ok"] is True
    assert calls == ["Fingerprint"]