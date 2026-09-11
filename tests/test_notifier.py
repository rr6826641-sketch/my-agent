"""tests/test_notifier.py - STEP 3: OS desktop notifications on login.

Verifies the notification payload contract for successful login events
(password unlock and biometric/WebAuthn flows), graceful degradation of
the cross-platform backends, and the auth-route wiring.
"""

import datetime as _dt

import pytest

from ai_agent.core import notifier as mod


def _utc(*args):
    return _dt.datetime(*args, tzinfo=_dt.timezone.utc)


# --------------------------------------------------------------------------
# Payload construction contract
# --------------------------------------------------------------------------

def test_payload_password_exact_contract():
    payload = mod.build_payload("Password", at=_utc(2026, 9, 11, 10, 30, 5))
    assert payload == (
        "🚨 [HACKERAI SECURITY ALERT] Agent session opened via "
        "Password at 2026-09-11T10:30:05+00:00"
    )


def test_payload_fingerprint_contract():
    payload = mod.build_payload("Fingerprint", at=_utc(2026, 9, 11, 12, 0, 0))
    assert payload.startswith("🚨 [HACKERAI SECURITY ALERT]")
    assert "via Fingerprint at " in payload
    assert "2026-09-11T12:00:00+00:00" in payload


def test_payload_normalizes_common_method_spellings():
    assert "via Password" in mod.build_payload("password")
    assert "via Fingerprint" in mod.build_payload("windows hello")
    assert "via Fingerprint" in mod.build_payload("WEBAUTHN")
    assert "via Fingerprint" in mod.build_payload("biometric")
    assert "via Biometric Key" in mod.build_payload("Biometric Key")


def test_payload_default_timestamp_is_recent_iso():
    payload = mod.build_payload("Password")
    ts = payload.rsplit(" at ", 1)[1]
    parsed = _dt.datetime.fromisoformat(ts)
    now = _dt.datetime.now().astimezone()
    assert abs((now - parsed).total_seconds()) < 2.0


# --------------------------------------------------------------------------
# notify() - never raises, degrades gracefully
# --------------------------------------------------------------------------

def test_dry_run_returns_true_without_touching_os(monkeypatch):
    calls = []

    monkeypatch.setattr(mod, "_run_backend",
                        lambda *a, **k: calls.append(a) or True)
    assert mod.notify("Password", dry_run=True) is True
    assert calls == []


def test_notify_graceful_when_no_backend(monkeypatch):
    monkeypatch.setattr(mod, "_detect_backend", lambda: None)
    assert mod.notify("Password") is False


def test_notify_degrades_to_console_line(monkeypatch, capsys):
    monkeypatch.setattr(mod, "_detect_backend", lambda: "console")
    assert mod.notify("Fingerprint") is False
    assert "HACKERAI notifier" in capsys.readouterr().err


def test_run_backend_missing_binary(monkeypatch):
    monkeypatch.setattr(mod._shutil, "which", lambda name: None)
    assert mod._run_backend("notify-send", "t", "b") is False
    assert mod._detect_backend() == "console"


def test_run_backend_unknown_is_false():
    assert mod._run_backend("bespoke", "t", "b") is False


def test_run_backend_exception_swallowed(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no display")

    monkeypatch.setattr(mod._subprocess, "run", boom)
    assert mod._run_backend("notify-send", "t", "b") is False


def test_powershell_uses_wscript_popup(monkeypatch):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return True

    monkeypatch.setattr(mod._subprocess, "run", fake_run)
    ok = mod._run_backend("powershell", "HACKERAI Security Alert",
                          'body "quoted"')
    assert ok is True
    assert captured["cmd"][0] == "powershell.exe"
    joined = " ".join(captured["cmd"])
    assert "WScript.Shell" in joined
    assert "Popup(" in joined


# --------------------------------------------------------------------------
# notify_login() helper and pytest short-circuit
# --------------------------------------------------------------------------

def test_notify_login_sync_path(monkeypatch, capsys):
    monkeypatch.setattr(mod, "_in_test", lambda: False)
    monkeypatch.setattr(mod, "_detect_backend", lambda: "console")
    assert mod.notify_login("Password", async_ok=False) is False
    assert "HACKERAI notifier" in capsys.readouterr().err


def test_notify_login_async_fires_in_thread(monkeypatch):
    import threading
    fired = threading.Event()
    monkeypatch.setattr(mod, "_in_test", lambda: False)

    def fake_notify(method, at=None, dry_run=False):
        fired.set()
        return True

    monkeypatch.setattr(mod, "notify", fake_notify)
    assert mod.notify_login("Fingerprint") is True
    assert fired.wait(2.0) is True


def test_notify_login_short_circuits_under_pytest(monkeypatch):
    monkeypatch.setattr(mod, "_in_test", lambda: True)

    def fake_notify(*a, **k):
        raise AssertionError("must not run under pytest")

    monkeypatch.setattr(mod, "notify", fake_notify)
    assert mod.notify_login("Password") is True


# --------------------------------------------------------------------------
# Auth-route wiring: successful login must fire the notifier
# --------------------------------------------------------------------------

def _auth_app(auth_mod):
    import flask
    app = flask.Flask(__name__)
    app.register_blueprint(auth_mod.auth_bp)
    return app


def test_auth_unlock_wiring_fires_password_notification(monkeypatch):
    import flask
    from ai_agent.webui import auth as auth_mod

    class _GK:
        def unlock(self, password):
            return "tok-123"

        def _now(self):
            return 1234

    monkeypatch.setattr(auth_mod, "get_gatekeeper", lambda: _GK())
    calls = []
    monkeypatch.setattr(auth_mod, "_notify_login",
                        lambda method: calls.append(method))

    app = _auth_app(auth_mod)
    with app.test_request_context("/api/auth/unlock", method="POST",
                                  json={"password": "x"}):
        resp = auth_mod.auth_unlock()

    assert resp.json["ok"] is True
    assert resp.json["token"] == "tok-123"
    assert calls == ["Password"]


def test_auth_webauthn_assert_wiring_fires_fingerprint_notification(monkeypatch):
    import flask
    from ai_agent.webui import auth as auth_mod

    class _Store:
        def update_credential_sign_count(self, *a, **k):
            pass

        def save(self):
            pass

    class _WA:
        def complete_assert(self, *a, **k):
            return {"credential_id": "cred-1", "new_sign_count": 7}

    class _GK:
        _webauthn = _WA()
        _store = _Store()
        _unlocked = True
        _last_activity = 0

        def _now(self):
            return 1234

        def _mint_token(self):
            return "tok-bio"

    monkeypatch.setattr(auth_mod, "get_gatekeeper", lambda: _GK())
    calls = []
    monkeypatch.setattr(auth_mod, "_notify_login",
                        lambda method: calls.append(method))

    app = _auth_app(auth_mod)
    with app.test_request_context("/api/auth/webauthn/assert/complete",
                                  method="POST",
                                  json={"credential_id": "c",
                                        "client_data": "x",
                                        "auth_data": "y",
                                        "signature": "z"}):
        resp = auth_mod.auth_webauthn_assert_complete()

    assert resp.json["ok"] is True
    assert resp.json["token"] == "tok-bio"
    assert calls == ["Fingerprint"]