"""Gatekeeper lock-screen auth tests (PHASE 1).

Covers:
  * PasswordHasher  - bcrypt / pbkdf2 hashing, verification, scheme-preserving rehash.
  * TokenManager    - JWTs bound to sess_v + device secret; tamper/expiry/revocation.
  * AESGCMCipher    - encrypted localStorage session envelope.
  * WebAuthnManager - full register/assert ceremonies (real ECDSA P-256 fixtures),
                      challenge single-use, origin checks, sign-count anti-rollback.
  * Gatekeeper      - setup/unlock/lock/change_password/auto-lock/authorize lifecycle
                      and the WebAuthn facade used by the web layer.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

from ai_agent.webui.gatekeeper import (
    AESGCMCipher,
    Gatekeeper,
    GatekeeperError,
    GatekeeperStore,
    PasswordHasher,
    TokenManager,
    WebAuthnManager,
    _b64d,
    _b64e,
)

RP_ID = "localhost"
ORIGIN = "http://localhost"
GOOD_PW = "Master-Pass-2026"


class Clock:
    """Deterministic fake clock for auto-lock tests."""

    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def gk(tmp_path, clock):
    g = Gatekeeper(store_path=str(tmp_path / "gk.json"), now_fn=clock,
                   rp_id=RP_ID, origin=ORIGIN)
    g.setup(GOOD_PW, auto_lock_s=300)
    return g


def _keypair():
    sk = ec.generate_private_key(ec.SECP256R1())
    nums = sk.public_key().public_numbers()
    return sk, nums.x, nums.y


def _raw_sig(sk, message: bytes) -> bytes:
    der = sk.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _auth_data(flags: int, sign_count: int, cred_id: bytes = None,
               cose: bytes = b"") -> bytes:
    rp_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
    sc = struct.pack(">I", sign_count)
    body = b""
    if flags & 0x40 and cred_id is not None:
        body = b"\x00" * 16 + struct.pack(">H", len(cred_id)) + cred_id + cose
    return rp_hash + bytes([flags]) + sc + body


def _client_data(challenge_b64: str, typ: str):
    raw = json.dumps({"type": typ, "challenge": challenge_b64,
                      "origin": ORIGIN, "crossOrigin": False}).encode("utf-8")
    return _b64e(raw), raw


def _attestation(fmt: str, auth_data: bytes, sig: bytes = None) -> bytes:
    att = {1: fmt, 2: auth_data}
    if sig is not None:
        att[3] = {"alg": -7, "sig": sig}
    return cbor2.dumps(att)


def _register_credential(g: Gatekeeper):
    """Run a full registration ceremony against *g*; return the pieces needed
    to assert later: (cred_id_b64, private_key)."""
    sk, x, y = _keypair()
    cred_id = os.urandom(32)
    info = g.webauthn_begin_register()
    client_b64, raw_cd = _client_data(info["challenge"], "webauthn.create")
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})
    auth_data = _auth_data(0x41, 1, cred_id, cose)
    sig = _raw_sig(sk, auth_data + hashlib.sha256(raw_cd).digest())
    att = _attestation("self", auth_data, sig)
    res = g.webauthn_complete_register(client_b64, _b64e(att))
    assert res["ok"] is True
    return res["credential_id"], sk


def _assert_credential(g: Gatekeeper, cred_id_b64: str, sk, sign_count: int = 2):
    info = g.webauthn_begin_assert()
    client_b64, raw_cd = _client_data(info["challenge"], "webauthn.get")
    auth_data = _auth_data(0x01, sign_count)
    sig = _raw_sig(sk, auth_data + hashlib.sha256(raw_cd).digest())
    return g.webauthn_complete_assert(cred_id_b64, client_b64,
                                      _b64e(auth_data), _b64e(sig))


# ---------------------------------------------------------------------------
# PasswordHasher
# ---------------------------------------------------------------------------


class TestPasswordHasher:
    def test_bcrypt_hash_and_verify_default(self):
        h = PasswordHasher()
        stored = h.hash_password(GOOD_PW)
        assert stored.startswith("bcrypt$")
        assert h.verify(GOOD_PW, stored) is True
        assert h.verify("wrong-password", stored) is False

    def test_pbkdf2_fallback(self):
        h = PasswordHasher(preferred="pbkdf2")
        stored = h.hash_password(GOOD_PW)
        assert stored.startswith("pbkdf2$sha256$")
        assert h.verify(GOOD_PW, stored) is True
        assert h.verify("wrong-password", stored) is False

    def test_short_password_rejected(self):
        with pytest.raises(GatekeeperError):
            PasswordHasher().hash_password("short")

    def test_verify_garbage(self):
        assert PasswordHasher().verify(GOOD_PW, "") is False
        assert PasswordHasher().verify(GOOD_PW, "not-a-hash") is False
        assert PasswordHasher().verify(GOOD_PW, "bcrypt$::::") is False

    def test_verify_is_format_agnostic(self):
        h = PasswordHasher()
        bc = h.hash_password(GOOD_PW)
        pk = PasswordHasher(preferred="pbkdf2")._pbkdf2_hash(GOOD_PW)
        assert PasswordHasher().verify(GOOD_PW, bc) is True
        assert PasswordHasher().verify(GOOD_PW, pk) is True

    def test_hash_for_verify_preserves_scheme(self):
        h = PasswordHasher()
        bc = h.hash_password(GOOD_PW)
        new_bc = h.hash_for_verify("New-Pass-2026", bc)
        assert new_bc.startswith("bcrypt$")
        assert h.verify("New-Pass-2026", new_bc) is True
        pk = PasswordHasher(preferred="pbkdf2")._pbkdf2_hash(GOOD_PW)
        new_pk = h.hash_for_verify("New-Pass-2026", pk)
        assert new_pk.startswith("pbkdf2$sha256$")
        assert h.verify("New-Pass-2026", new_pk) is True

    def test_bad_preferred_name_raises(self):
        with pytest.raises(ValueError):
            PasswordHasher(preferred="scrypt")


# ---------------------------------------------------------------------------
# TokenManager
# ---------------------------------------------------------------------------


class TestTokenManager:
    def test_mint_verify_roundtrip(self, clock):
        tm = TokenManager(b"d" * 32, "master-hash")
        tok = tm.mint(sess_v=3, ttl_s=600, now=clock())
        claims = tm.verify(tok, sess_v=3, now=clock())
        assert claims["sub"] == "gatekeeper"
        assert claims["sess_v"] == 3
        assert claims["exp"] == int(clock()) + 600

    def test_wrong_session_generation_rejected(self, clock):
        tm = TokenManager(b"d" * 32, "mh")
        tok = tm.mint(sess_v=2, ttl_s=600, now=clock())
        assert tm.verify(tok, sess_v=3, now=clock()) is None  # revoked

    def test_expired_token_rejected(self, clock):
        tm = TokenManager(b"d" * 32, "mh")
        tok = tm.mint(sess_v=1, ttl_s=10, now=clock())
        clock.advance(11)
        assert tm.verify(tok, sess_v=1, now=clock()) is None

    def test_tampered_token_rejected(self, clock):
        tm = TokenManager(b"d" * 32, "mh")
        tok = tm.mint(sess_v=1, ttl_s=600, now=clock())
        head, body, sig = tok.split(".")
        flip = "AA" if body[-2:] != "AA" else "BB"
        tampered = "%s.%s%s%s" % (head, body[:-2], flip, "." + sig)
        assert tm.verify(tampered, sess_v=1, now=clock()) is None

    def test_wrong_secret_rejected(self, clock):
        tm1 = TokenManager(b"d" * 32, "mh")
        tm2 = TokenManager(b"e" * 32, "mh")
        tok = tm1.mint(sess_v=1, ttl_s=600, now=clock())
        assert tm2.verify(tok, sess_v=1, now=clock()) is None

    def test_empty_token(self, clock):
        tm = TokenManager(b"d" * 32, "mh")
        assert tm.verify("", sess_v=1, now=clock()) is None
        assert tm.verify(None, sess_v=1, now=clock()) is None


# ---------------------------------------------------------------------------
# AESGCMCipher
# ---------------------------------------------------------------------------


class TestAESGCMCipher:
    def test_seal_open_roundtrip(self):
        c = AESGCMCipher(b"k" * 32)
        env = c.seal(b"session-jwt-payload")
        assert env.startswith("aesgcm$v1$")
        assert c.open(env) == b"session-jwt-payload"

    def test_envelopes_are_unique(self):
        c = AESGCMCipher(b"k" * 32)
        assert c.seal(b"x") != c.seal(b"x")

    def test_wrong_key_rejected(self):
        c1 = AESGCMCipher(b"k" * 32)
        env = c1.seal(b"secret")
        with pytest.raises(ValueError):
            AESGCMCipher(b"z" * 32).open(env)

    def test_tampered_envelope_rejected(self):
        c = AESGCMCipher(b"k" * 32)
        env = c.seal(b"secret")
        prefix = "aesgcm$v1$"
        iv, ct = env[len(prefix):].split(".")
        raw = bytearray(_b64d(ct))
        raw[0] ^= 1
        with pytest.raises(ValueError):
            c.open(prefix + iv + "." + _b64e(bytes(raw)))

    def test_non_envelope_rejected(self):
        with pytest.raises(ValueError):
            AESGCMCipher(b"k" * 32).open("plaintext")

    def test_bad_key_size(self):
        with pytest.raises(ValueError):
            AESGCMCipher(b"tooshort")


# ---------------------------------------------------------------------------
# GatekeeperStore
# ---------------------------------------------------------------------------


class TestGatekeeperStore:
    def test_fresh_store_not_setup(self, tmp_path, clock):
        s = GatekeeperStore(str(tmp_path / "s.json"), now_fn=clock)
        assert s.is_setup() is False
        assert s.sess_v == 0
        assert s.list_credentials() == []

    def test_persists_across_reload(self, tmp_path, clock):
        path = str(tmp_path / "s.json")
        s = GatekeeperStore(path, now_fn=clock)
        s.set_master_hash("bcrypt$abc")
        s.ensure_device_key()
        s.bump_sess_v()
        s.put_credential("cid", {"x": 1, "y": 2, "sign_count": 1})
        s2 = GatekeeperStore(path, now_fn=clock)
        assert s2.is_setup() is True
        assert s2.master_hash == "bcrypt$abc"
        assert s2.sess_v == 1
        assert s2.get_credential("cid")["sign_count"] == 1

    def test_corrupt_store_treated_as_empty(self, tmp_path, clock):
        path = tmp_path / "s.json"
        path.write_text("{not-json", encoding="utf-8")
        s = GatekeeperStore(str(path), now_fn=clock)
        assert s.is_setup() is False

    def test_update_and_remove_credential(self, tmp_path, clock):
        s = GatekeeperStore(str(tmp_path / "s.json"), now_fn=clock)
        s.put_credential("cid", {"x": 1, "y": 2, "sign_count": 1})
        s.update_credential_sign_count("cid", 7)
        assert s.get_credential("cid")["sign_count"] == 7
        s.remove_credential("cid")
        assert s.get_credential("cid") is None


# ---------------------------------------------------------------------------
# WebAuthnManager (raw ceremony level)
# ---------------------------------------------------------------------------


class TestWebAuthnManager:
    def test_challenge_single_use(self, clock):
        sk, x, y = _keypair()
        cred_id = os.urandom(32)
        w = WebAuthnManager(RP_ID, ORIGIN, now_fn=clock)
        info = w.begin_register()
        cid_b64, raw_cd = _client_data(info["challenge"], "webauthn.create")
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})
        auth_data = _auth_data(0x41, 1, cred_id, cose)
        sig = _raw_sig(sk, auth_data + hashlib.sha256(raw_cd).digest())
        att = _attestation("self", auth_data, sig)
        assert w.complete_register(cid_b64, _b64e(att))["ok"] is True
        with pytest.raises(GatekeeperError):  # replay: challenge already consumed
            w.complete_register(cid_b64, _b64e(att))

    def test_origin_mismatch_rejected(self, clock):
        w = WebAuthnManager(RP_ID, ORIGIN, now_fn=clock)
        info = w.begin_register()
        raw = json.dumps({"type": "webauthn.create",
                          "challenge": info["challenge"],
                          "origin": "http://evil.example"}).encode()
        with pytest.raises(GatekeeperError):
            w.complete_register(_b64e(raw), _b64e(_attestation("none", _auth_data(0x41, 1))))

    def test_wrong_client_data_type_rejected(self, clock):
        w = WebAuthnManager(RP_ID, ORIGIN, now_fn=clock)
        info = w.begin_register()
        cid_b64, _ = _client_data(info["challenge"], "webauthn.get")  # wrong type
        with pytest.raises(GatekeeperError):
            w.complete_register(cid_b64, _b64e(_attestation("none", _auth_data(0x41, 1))))

    def test_self_attestation_register_and_assert(self, clock):
        sk, x, y = _keypair()
        cred_id = os.urandom(32)
        w = WebAuthnManager(RP_ID, ORIGIN, now_fn=clock)
        info = w.begin_register()
        client_b64, raw_cd = _client_data(info["challenge"], "webauthn.create")
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})
        auth_data = _auth_data(0x41, 5, cred_id, cose)
        sig = _raw_sig(sk, auth_data + hashlib.sha256(raw_cd).digest())
        res = w.complete_register(client_b64, _b64e(_attestation("self", auth_data, sig)))
        assert res["ok"] is True
        assert res["credential_id"] == _b64e(cred_id)

        # assertion with UP flag + valid signature
        cred = {"x": x, "y": y, "sign_count": 5}
        w._store_lookup = lambda cid: cred if cid == res["credential_id"] else None
        info2 = w.begin_assert()
        client_b64, raw_cd = _client_data(info2["challenge"], "webauthn.get")
        ad = _auth_data(0x01, 6)
        sig = _raw_sig(sk, ad + hashlib.sha256(raw_cd).digest())
        out = w.complete_assert(res["credential_id"], client_b64, _b64e(ad), _b64e(sig))
        assert out["ok"] is True and out["new_sign_count"] == 6

    def test_bad_assertion_signature_rejected(self, clock):
        sk, x, y = _keypair()
        sk2, _, _ = _keypair()
        cred_id_b64 = _b64e(os.urandom(32))
        w = WebAuthnManager(RP_ID, ORIGIN, now_fn=clock)
        w._store_lookup = lambda cid: {"x": x, "y": y, "sign_count": 1}
        info = w.begin_assert()
        client_b64, raw_cd = _client_data(info["challenge"], "webauthn.get")
        ad = _auth_data(0x01, 2)
        sig = _raw_sig(sk2, ad + hashlib.sha256(raw_cd).digest())  # wrong key
        with pytest.raises(GatekeeperError):
            w.complete_assert(cred_id_b64, client_b64, _b64e(ad), _b64e(sig))

    def test_missing_user_presence_rejected(self, clock):
        sk, x, y = _keypair()
        w = WebAuthnManager(RP_ID, ORIGIN, now_fn=clock)
        w._store_lookup = lambda cid: {"x": x, "y": y, "sign_count": 1}
        info = w.begin_assert()
        client_b64, raw_cd = _client_data(info["challenge"], "webauthn.get")
        ad = _auth_data(0x00, 2)  # UP flag NOT set
        sig = _raw_sig(sk, ad + hashlib.sha256(raw_cd).digest())
        with pytest.raises(GatekeeperError):
            w.complete_assert(_b64e(os.urandom(32)), client_b64, _b64e(ad), _b64e(sig))

    def test_sign_count_regression_rejected(self, clock):
        sk, x, y = _keypair()
        cred_id_b64 = _b64e(os.urandom(32))
        w = WebAuthnManager(RP_ID, ORIGIN, now_fn=clock)
        w._store_lookup = lambda cid: {"x": x, "y": y, "sign_count": 20}
        info = w.begin_assert()
        client_b64, raw_cd = _client_data(info["challenge"], "webauthn.get")
        ad = _auth_data(0x01, 3)
        sig = _raw_sig(sk, ad + hashlib.sha256(raw_cd).digest())
        with pytest.raises(GatekeeperError):
            w.complete_assert(cred_id_b64, client_b64, _b64e(ad), _b64e(sig))

    def test_unknown_credential_rejected(self, clock):
        w = WebAuthnManager(RP_ID, ORIGIN, now_fn=clock)
        w._store_lookup = lambda cid: None
        info = w.begin_assert()
        client_b64, raw_cd = _client_data(info["challenge"], "webauthn.get")
        with pytest.raises(GatekeeperError):
            w.complete_assert(_b64e(os.urandom(32)), client_b64,
                              _b64e(_auth_data(0x01, 1)), _b64e(b"\x00" * 64))


# ---------------------------------------------------------------------------
# Gatekeeper lifecycle
# ---------------------------------------------------------------------------


class TestGatekeeperLifecycle:
    def test_fresh_gatekeeper_is_locked_and_unset(self, tmp_path, clock):
        g = Gatekeeper(store_path=str(tmp_path / "g.json"), now_fn=clock,
                       rp_id=RP_ID, origin=ORIGIN)
        assert g.is_setup() is False
        st = g.status()
        assert st["locked"] is True
        assert st["locked_reason"] == "not_setup"
        assert st["auto_lock_s"] == 900

    def test_setup_rejects_short_password(self, tmp_path, clock):
        g = Gatekeeper(store_path=str(tmp_path / "g.json"), now_fn=clock)
        with pytest.raises(GatekeeperError):
            g.setup("short")
        assert g.is_setup() is False

    def test_unlock_requires_setup(self, tmp_path, clock):
        g = Gatekeeper(store_path=str(tmp_path / "g.json"), now_fn=clock)
        with pytest.raises(GatekeeperError):
            g.unlock(GOOD_PW)

    def test_unlock_wrong_password(self, gk):
        with pytest.raises(GatekeeperError):
            gk.unlock("wrong-password")

    def test_unlock_mints_valid_token(self, gk):
        tok = gk.unlock(GOOD_PW)
        st = gk.status(token=tok)
        assert st["locked"] is False
        assert st["token_valid"] is True
        assert st["locked_reason"] == "unlocked"
        claims = gk.authorize(tok)
        assert claims["sub"] == "gatekeeper"
        assert claims["sess_v"] == gk._store.sess_v

    def test_lock_revokes_token(self, gk):
        tok = gk.unlock(GOOD_PW)
        gk.lock()
        st = gk.status(token=tok)
        assert st["locked"] is True
        assert gk.authorize(tok) is None

    def test_auto_lock_after_idle_timeout(self, tmp_path, clock):
        g = Gatekeeper(store_path=str(tmp_path / "g.json"), now_fn=clock,
                       rp_id=RP_ID, origin=ORIGIN)
        g.setup(GOOD_PW, auto_lock_s=60)
        tok = g.unlock(GOOD_PW)
        clock.advance(30)
        assert g.lock_if_expired() is False  # still under the timeout
        assert g.authorize(tok) is not None  # also refreshes the idle clock
        clock.advance(61)                     # 61s idle since last activity
        assert g.lock_if_expired() is True
        assert g.authorize(tok) is None

    def test_touch_refreshes_idle_clock(self, tmp_path, clock):
        g = Gatekeeper(store_path=str(tmp_path / "g.json"), now_fn=clock,
                       rp_id=RP_ID, origin=ORIGIN)
        g.setup(GOOD_PW, auto_lock_s=60)
        tok = g.unlock(GOOD_PW)
        for _ in range(10):
            clock.advance(30)
            g.touch()
        assert g.lock_if_expired() is False
        assert g.authorize(tok) is not None

    def test_change_password_invalidates_tokens(self, gk):
        tok = gk.unlock(GOOD_PW)
        assert gk.authorize(tok) is not None
        with pytest.raises(GatekeeperError):  # wrong old password
            gk.change_password("not-the-old-password", "New-Pass-2026")
        gk.change_password(GOOD_PW, "New-Pass-2026")
        assert gk.status()["locked"] is True
        assert gk.authorize(tok) is None
        with pytest.raises(GatekeeperError):  # old password no longer works
            gk.unlock(GOOD_PW)
        tok2 = gk.unlock("New-Pass-2026")
        assert gk.authorize(tok2) is not None

    def test_short_change_password_rejected(self, gk):
        gk.unlock(GOOD_PW)
        with pytest.raises(GatekeeperError):
            gk.change_password(GOOD_PW, "short")


# ---------------------------------------------------------------------------
# Gatekeeper WebAuthn facade (biometric login)
# ---------------------------------------------------------------------------


class TestGatekeeperWebAuthn:
    def test_register_requires_setup(self, tmp_path, clock):
        g = Gatekeeper(store_path=str(tmp_path / "g.json"), now_fn=clock)
        with pytest.raises(GatekeeperError):
            g.webauthn_begin_register()

    def test_full_biometric_login_flow(self, gk):
        cred_id_b64, sk = _register_credential(gk)
        assert gk.status()["webauthn_registered"] is True
        st = gk.status()
        assert st["locked"] is True  # still locked after registering

        res = _assert_credential(gk, cred_id_b64, sk, sign_count=2)
        tok = res["token"]
        st = gk.status(token=tok)
        assert st["locked"] is False
        assert st["token_valid"] is True
        assert gk.authorize(tok) is not None

    def test_duplicate_registration_rejected(self, gk):
        cred_id_b64, _ = _register_credential(gk)
        # attempt to re-register the same credential id
        sk, x, y = _keypair()
        info = gk.webauthn_begin_register()
        client_b64, raw_cd = _client_data(info["challenge"], "webauthn.create")
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})
        auth_data = _auth_data(0x41, 1, _b64d(cred_id_b64), cose)
        sig = _raw_sig(sk, auth_data + hashlib.sha256(raw_cd).digest())
        with pytest.raises(GatekeeperError):
            gk.webauthn_complete_register(client_b64,
                                          _b64e(_attestation("self", auth_data, sig)))

    def test_assert_requires_registered_credential(self, gk):
        with pytest.raises(GatekeeperError):
            gk.webauthn_begin_assert()

    def test_assert_with_replayed_challenge_rejected(self, gk):
        cred_id_b64, sk = _register_credential(gk)
        info = gk.webauthn_begin_assert()
        client_b64, raw_cd = _client_data(info["challenge"], "webauthn.get")
        auth_data = _auth_data(0x01, 2)
        sig = _raw_sig(sk, auth_data + hashlib.sha256(raw_cd).digest())
        gk.webauthn_complete_assert(cred_id_b64, client_b64,
                                    _b64e(auth_data), _b64e(sig))
        with pytest.raises(GatekeeperError):  # challenge already consumed
            gk.webauthn_complete_assert(cred_id_b64, client_b64,
                                        _b64e(auth_data), _b64e(sig))

    def test_sign_count_persists_and_rolls_forward(self, gk):
        cred_id_b64, sk = _register_credential(gk)
        _assert_credential(gk, cred_id_b64, sk, sign_count=2)
        _assert_credential(gk, cred_id_b64, sk, sign_count=3)
        cred = gk._store.get_credential(cred_id_b64)
        assert cred["sign_count"] == 3
