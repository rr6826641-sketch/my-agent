"""Authentication handler — ai_agent/webui/auth.py.

STEP 2 security layer on top of the Gatekeeper state machine.

Exposes a self-contained Flask Blueprint (``/api/auth``) that provides:

  * bcrypt master-password verification  -> POST /api/auth/unlock
  * WebAuthn challenge/response ceremonies (Fingerprint / Touch ID /
    Windows Hello)                       -> /api/auth/webauthn/*
  * Encrypted-LocalStorage JWT session tokens with an idle auto-lock
    timeout                              -> /api/auth/session

Mounting::

    from ai_agent.webui.auth import auth_bp
    app.register_blueprint(auth_bp)

Every request enforces the auto-lock timeout first, so an idle browser
that comes back with a stale token is transparently re-locked.
"""

from __future__ import annotations

import threading

from flask import Blueprint, current_app, jsonify, request

from ai_agent.core.notifier import notify_login as _notify_login
from ai_agent.webui.gatekeeper import DEFAULT_AUTO_LOCK_S, Gatekeeper, GatekeeperError

__all__ = ["auth_bp", "get_gatekeeper"]

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

_GATEKEEPER = None
_GATEKEEPER_LOCK = threading.RLock()


def get_gatekeeper() -> Gatekeeper:
    """Lazily build (or reuse) the process-wide Gatekeeper instance.

    The store path can be injected through the Flask app config key
    ``GATEKEEPER_STORE_PATH`` so tests can point at a tmp dir.
    """
    global _GATEKEEPER
    with _GATEKEEPER_LOCK:
        if _GATEKEEPER is None:
            store_path = None
            try:
                store_path = current_app.config.get("GATEKEEPER_STORE_PATH")
            except RuntimeError:  # no application context (standalone use)
                pass
            _GATEKEEPER = Gatekeeper(store_path=store_path)
        return _GATEKEEPER


def _authed(req, token_arg: str = "token") -> Gatekeeper | None:
    """Return the unlocked gatekeeper if an auto-locked session is live."""
    gk = get_gatekeeper()
    gk.lock_if_expired()
    payload = request.get_json(silent=True) or {}
    token = payload.get(token_arg) or request.headers.get("X-Gatekeeper-Token")
    if not token:
        return None
    if gk.authorize(token) is None:
        return None
    return gk


def _err(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


# ---------------------------------------------------------------------------
# Session / password endpoints
# ---------------------------------------------------------------------------

@auth_bp.get("/status")
def auth_status():
    gk = get_gatekeeper()
    gk.lock_if_expired()
    return jsonify({
        "ok": True,
        "setup": gk.is_setup(),
        "unlocked": gk.is_setup() and _active(),
        "auto_lock_seconds": int(gk._store.auto_lock_seconds()),
    })


def _active() -> bool:
    """Config-free 'is a session currently unlocked' probe for status."""
    try:
        return get_gatekeeper()._unlocked
    except Exception:
        return False


@auth_bp.post("/setup")
def auth_setup():
    """POST /api/auth/setup  {password, auto_lock_s?}"""
    gk = get_gatekeeper()
    body = request.get_json(silent=True) or {}
    password = body.get("password")
    if not isinstance(password, str) or not password:
        return _err("master password is required")
    try:
        gk.setup(password, int(body.get("auto_lock_s", DEFAULT_AUTO_LOCK_S)))
        token = gk.unlock(password)
    except GatekeeperError as exc:
        return _err(str(exc))
    return jsonify({"ok": True, "token": token})


@auth_bp.post("/unlock")
def auth_unlock():
    """POST /api/auth/unlock  {password}  -> encrypted session token."""
    gk = get_gatekeeper()
    body = request.get_json(silent=True) or {}
    password = body.get("password")
    if not isinstance(password, str) or not password:
        return _err("master password is required")
    try:
        token = gk.unlock(password)
    except GatekeeperError as exc:
        return _err(str(exc), 401)
    _notify_login("Password")
    return jsonify({"ok": True, "token": token})


@auth_bp.post("/lock")
def auth_lock():
    gk = get_gatekeeper()
    gk.lock()
    return jsonify({"ok": True, "locked": True})


@auth_bp.post("/touch")
def auth_touch():
    body = request.get_json(silent=True) or {}
    if not body.get("token"):
        return _err("session token required", 401)
    try:
        claims = get_gatekeeper().authorize(body["token"])
    except Exception:
        claims = None
    if claims is None:
        return _err("session expired or invalid", 401)
    return jsonify({"ok": True, "expires_in": claims.get("expires_at")})


@auth_bp.route("/session", methods=["GET", "POST"])
def auth_session():
    """GET /api/auth/session  (token in body/header) -> active claims."""
    gk = _authed(request)
    if gk is None:
        return _err("session locked or invalid", 401)
    return jsonify({"ok": True, "locked": False})


# ---------------------------------------------------------------------------
# WebAuthn ceremonies — Fingerprint / Touch ID / Windows Hello
# ---------------------------------------------------------------------------

@auth_bp.post("/webauthn/register/begin")
def auth_webauthn_register_begin():
    """Require an unlocked password session; challenge a biometric enroll."""
    gk = _authed(request)
    if gk is None:
        return _err("unlock with the master password first", 401)
    return jsonify({"ok": True, **gk._webauthn.begin_register()})


@auth_bp.post("/webauthn/register/complete")
def auth_webauthn_register_complete():
    gk = _authed(request)
    if gk is None:
        return _err("session required", 401)
    body = request.get_json(silent=True) or {}
    try:
        result = gk._webauthn.complete_register(
            body.get("client_data", ""),
            body.get("attestation", ""),
            body.get("user_handle"),
        )
        if result.get("store_and_push"):
            gk._store.put_credential(
                result["credential_id"],
                result["credential"],
            )
            gk._store.save()
    except GatekeeperError as exc:
        return _err(str(exc))
    return jsonify({"ok": True, "credential_id": result["credential_id"]})


@auth_bp.post("/webauthn/assert/begin")
def auth_webauthn_assert_begin():
    """Begin the biometric unlock challenge (no password required)."""
    gk = get_gatekeeper()
    gk.lock_if_expired()
    if not gk.is_setup():
        return _err("gatekeeper is not set up", 400)
    return jsonify({"ok": True, **gk._webauthn.begin_assert()})


@auth_bp.post("/webauthn/assert/complete")
def auth_webauthn_assert_complete():
    """Verify the biometric signature and mint a fresh session token."""
    gk = get_gatekeeper()
    body = request.get_json(silent=True) or {}
    try:
        result = gk._webauthn.complete_assert(
            body.get("credential_id", ""),
            body.get("client_data", ""),
            body.get("auth_data", ""),
            body.get("signature", ""),
        )
        gk._store.update_credential_sign_count(
            result["credential_id"], result["new_sign_count"]
        )
        gk._store.save()
        gk._unlocked = True
        gk._last_activity = gk._now()
        token = gk._mint_token()
    except GatekeeperError as exc:
        return _err(str(exc), 401)
    _notify_login("Fingerprint")
    return jsonify({"ok": True, "token": token, "credential_id": result["credential_id"]})