"""Tests for the STEP 2 authentication handler (ai_agent/webui/auth.py)."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from flask import Flask

from ai_agent.webui import auth as auth_mod
from ai_agent.webui.auth import auth_bp, get_gatekeeper

MASTER = "ultra-uncensored-master-2026!"


@pytest.fixture()
def client(tmp_path):
    app = Flask("test-auth-handler")
    app.config["TESTING"] = True
    app.config["GATEKEEPER_STORE_PATH"] = str(tmp_path / "gk.json")
    app.register_blueprint(auth_bp)
    with app.test_client() as c:
        yield c
    auth_mod._GATEKEEPER = None  # reset singleton per test


def _setup(client):
    r = client.post("/api/auth/setup", json={"password": MASTER})
    assert r.status_code == 200, r.get_json()
    return r.get_json()["token"]


class TestAuthHandlerStatus:
    def test_status_before_setup(self, client):
        assert client.get("/api/auth/status").get_json()["setup"] is False

    def test_status_after_setup(self, client):
        _setup(client)
        body = client.get("/api/auth/status").get_json()
        assert body["setup"] is True
        assert body["auto_lock_seconds"] > 0


class TestAuthHandlerPassword:
    def test_unlock_with_correct_password_mints_token(self, client):
        _setup(client)
        body = client.post(
            "/api/auth/unlock", json={"password": MASTER}
        ).get_json()
        assert body["ok"] is True and body["token"]

    def test_unlock_with_wrong_password_rejected(self, client):
        _setup(client)
        r = client.post("/api/auth/unlock", json={"password": "wrong-pass"})
        assert r.status_code == 401

    def test_session_requires_valid_token(self, client):
        _setup(client)
        assert client.post(
            "/api/auth/session", json={"token": "forged"}
        ).status_code == 401
        token = client.post(
            "/api/auth/unlock", json={"password": MASTER}
        ).get_json()["token"]
        assert client.post(
            "/api/auth/session", json={"token": token}
        ).get_json()["ok"] is True

    def test_lock_revokes_session(self, client):
        _setup(client)
        token = client.post(
            "/api/auth/unlock", json={"password": MASTER}
        ).get_json()["token"]
        client.post("/api/auth/lock")
        assert client.post(
            "/api/auth/session", json={"token": token}
        ).status_code == 401


class TestAuthHandlerWebAuthn:
    def test_register_requires_unlocked_session(self, client):
        _setup(client)
        assert client.post(
            "/api/auth/webauthn/register/begin", json={}
        ).status_code == 401

    def test_assert_begins_without_session(self, client):
        _setup(client)
        body = client.post(
            "/api/auth/webauthn/assert/begin", json={}
        ).get_json()
        assert body["ok"] is True and body["challenge"]

    def test_assert_complete_with_garbage_sig_rejected(self, client):
        _setup(client)
        r = client.post("/api/auth/webauthn/assert/complete", json={
            "credential_id": "AAAA",
            "client_data": "AAAA",
            "auth_data": "AAAA",
            "signature": "AAAA",
        })
        assert r.status_code == 401