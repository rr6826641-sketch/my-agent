"""Gatekeeper: WebUI lock-screen security layer.

Pure-Python (no Flask dependency) implementation of:

  * GatekeeperStore      -- encrypted-adjacent JSON persistence (device key,
                            bcrypt master hash, WebAuthn credentials, auto-lock
                            configuration) with atomic writes.
  * PasswordHasher       -- bcrypt-preferred password hashing with an
                            HMAC-SHA256-PBKDF2 fallback for portability.
  * TokenManager         -- stdlib-only HS256 JWT (HMAC + base64url). Tokens
                            are bound to the session generation (sess_v) and a
                            key derived from the device key and master hash.
  * AESGCMCipher         -- authenticated encryption envelope for sealing the
                            browser-side session token in localStorage.
  * WebAuthnManager      -- minimal WebAuthn ceremony handling: challenge
                            issuance, attestation object parsing (CBOR/COSE),
                            ECDSA P-256 signature verification (fmt "none" and
                            "self"), and assertion verification with sign-count
                            anti-rollback checks.
  * Gatekeeper           -- state machine glue (setup / unlock / lock /
                            change_password / auto-lock / authorize) and the
                            WebAuthn facade used by the web layer.

The feature is opt-in: an absent or corrupt store simply means "not set up",
so the WebUI behaves exactly as before until a master password is chosen.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time

try:
    import bcrypt
except Exception:  # pragma: no cover - optional dependency
    bcrypt = None

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidSignature, InvalidTag
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - optional dependency
    _HAS_CRYPTO = False

try:
    import cbor2
except Exception:  # pragma: no cover - optional dependency
    cbor2 = None

CURRENT_STORE_VERSION = 1

# WebAuthn RP defaults (override via env/config in the web layer).
DEFAULT_RP_ID = "localhost"
DEFAULT_ORIGIN = "http://localhost"
CHALLENGE_TTL_S = 120
DEFAULT_AUTO_LOCK_S = 900  # 15 minutes


class GatekeeperError(Exception):
    """Raised for user-facing gatekeeper failures (invalid credentials etc.)."""


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = b"=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text.encode("ascii") + pad)


def _ct_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def _default_store_path() -> str:
    """Resolve the default gatekeeper store location."""
    env = os.environ.get("GATEKEEPER_STORE")
    if env:
        return env
    try:
        from ai_agent.config import PROJECT_DIR  # type: ignore
    except Exception:
        PROJECT_DIR = os.getcwd()
    return os.path.join(PROJECT_DIR, "data", "gatekeeper_store.json")


class _MemoryChallengeStore:
    """Thread-safe single-use challenge registry (in-memory by design)."""

    def __init__(self, now_fn=time.time):
        self._now = now_fn
        self._challenges = {}
        self._lock = threading.Lock()

    def issue(self, purpose: str) -> str:
        nonce = _b64e(secrets.token_bytes(32))
        with self._lock:
            self._challenges[nonce] = {
                "purpose": purpose,
                "exp": self._now() + CHALLENGE_TTL_S,
            }
        return nonce

    def consume(self, nonce: str, purpose: str):
        """Atomically pop+validate. Returns True on success (already expired
        entries are discarded). Raises GatekeeperError otherwise."""
        with self._lock:
            entry = self._challenges.pop(nonce, None)
        if entry is None:
            raise GatekeeperError("challenge not found or already used")
        if entry.get("purpose") != purpose:
            raise GatekeeperError("challenge purpose mismatch")
        if self._now() > entry.get("exp", 0):
            raise GatekeeperError("challenge expired")
        return True


# ---------------------------------------------------------------------------
# GatekeeperStore
# ---------------------------------------------------------------------------

class GatekeeperStore:
    """JSON document store with atomic, fsynced writes.

    Layout::

        {
          "v": 1,
          "created": 1234.0,
          "master_hash": "bcrypt$...",
          "device_key": "<b64url 32 bytes>",
          "auto_lock_s": 900,
          "sess_v": 3,
          "credentials": {
             "<cred_id b64url>": {
               "x": 123, "y": 456, "sign_count": 5,
               "user_handle": "<b64url>", "created": 1234.0
             }
          }
        }
    """

    def __init__(self, path=None, now_fn=time.time):
        self.path = path or _default_store_path()
        self._now = now_fn
        self._lock = threading.RLock()
        self._data = self._load()

    # -- load/save ---------------------------------------------------------
    def _load(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict) and raw.get("v") == CURRENT_STORE_VERSION:
                return _normalize_doc(raw, self._now)
        except FileNotFoundError:
            pass
        except (ValueError, TypeError, OSError):
            # Corrupt store -> treat as empty (opt-in never breaks the server).
            pass
        return _empty_doc(self._now)

    def save(self) -> None:
        doc = dict(self._data)
        if not os.path.isdir(os.path.dirname(os.path.abspath(self.path))):
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        tmp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, self.path)

    # -- accessors ----------------------------------------------------------
    def is_setup(self) -> bool:
        return bool(self._data.get("master_hash"))

    @property
    def master_hash(self):
        return self._data.get("master_hash")

    @property
    def device_key(self) -> bytes:
        return _b64d(self._data.get("device_key", ""))

    def set_master_hash(self, value) -> None:
        self._data["master_hash"] = value
        self.save()

    def ensure_device_key(self) -> bytes:
        if not self._data.get("device_key"):
            self._data["device_key"] = _b64e(secrets.token_bytes(32))
            self.save()
        return self.device_key

    def auto_lock_seconds(self) -> int:
        return int(self._data.get("auto_lock_s") or DEFAULT_AUTO_LOCK_S)

    def set_auto_lock_seconds(self, seconds: int) -> None:
        self._data["auto_lock_s"] = int(seconds)

    def bump_sess_v(self) -> int:
        self._data["sess_v"] = int(self._data.get("sess_v") or 0) + 1
        self.save()
        return self._data["sess_v"]

    @property
    def sess_v(self) -> int:
        return int(self._data.get("sess_v") or 0)

    # -- credentials --------------------------------------------------------
    def list_credentials(self) -> list:
        return list(self._data.get("credentials") or {})

    def get_credential(self, cred_id_b64: str):
        return (self._data.get("credentials") or {}).get(cred_id_b64)

    def put_credential(self, cred_id_b64: str, entry: dict) -> None:
        self._data.setdefault("credentials", {})[cred_id_b64] = entry
        self.save()

    def update_credential_sign_count(self, cred_id_b64: str, count: int) -> None:
        cred = self.get_credential(cred_id_b64)
        if cred is None:
            return
        cred["sign_count"] = int(count)
        self.save()

    def remove_credential(self, cred_id_b64: str) -> None:
        (self._data.get("credentials") or {}).pop(cred_id_b64, None)
        self.save()


def _empty_doc(now_fn) -> dict:
    return {
        "v": CURRENT_STORE_VERSION,
        "created": now_fn(),
        "master_hash": None,
        "device_key": None,
        "auto_lock_s": DEFAULT_AUTO_LOCK_S,
        "sess_v": 0,
        "credentials": {},
    }


def _normalize_doc(doc: dict, now_fn) -> dict:
    out = _empty_doc(now_fn)
    out["v"] = CURRENT_STORE_VERSION
    out["created"] = doc.get("created") or now_fn()
    out["master_hash"] = doc.get("master_hash")
    out["device_key"] = doc.get("device_key")
    out["auto_lock_s"] = int(doc.get("auto_lock_s") or DEFAULT_AUTO_LOCK_S)
    out["sess_v"] = int(doc.get("sess_v") or 0)
    creds = doc.get("credentials")
    out["credentials"] = creds if isinstance(creds, dict) else {}
    return out


# ---------------------------------------------------------------------------
# PasswordHasher
# ---------------------------------------------------------------------------

PBKDF2_SHA256_ITERATIONS = 600_000

PASSWORD_MIN_LENGTH = 8


class PasswordHasher:
    """bcrypt-preferred password hashing (``bcrypt$...``) with a portable
    HMAC-SHA256-PBKDF2 fallback (``pbkdf2$sha256$<iters>$<salt>$<dk>``)."""

    def __init__(self, preferred: str = "bcrypt"):
        if preferred not in ("bcrypt", "pbkdf2"):
            raise ValueError("preferred must be 'bcrypt' or 'pbkdf2'")
        self.preferred = preferred

    # -- hashing ------------------------------------------------------------
    def hash_password(self, password: str) -> str:
        if len(password) < PASSWORD_MIN_LENGTH:
            raise GatekeeperError(
                "password must be at least %d characters" % PASSWORD_MIN_LENGTH
            )
        if self.preferred == "bcrypt":
            if bcrypt is not None:
                try:
                    hashed = bcrypt.hashpw(
                        password.encode("utf-8"), bcrypt.gensalt(rounds=12)
                    )
                    return "bcrypt$" + hashed.decode("ascii")
                except Exception:
                    pass  # fall through to pbkdf2
            return self._pbkdf2_hash(password)
        return self._pbkdf2_hash(password)

    def _pbkdf2_hash(self, password: str) -> str:
        salt = secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_SHA256_ITERATIONS
        )
        return "pbkdf2$sha256$%d$%s$%s" % (
            PBKDF2_SHA256_ITERATIONS,
            _b64e(salt),
            _b64e(dk),
        )

    def hash_for_verify(self, password: str, expected: str) -> str:
        """Re-hash in the same scheme as ``expected`` (used by change_password
        so the stored scheme is preserved)."""
        if expected.startswith("bcrypt$"):
            if bcrypt is not None:
                return "bcrypt$" + bcrypt.hashpw(
                    password.encode("utf-8"), bcrypt.gensalt(rounds=12)
                ).decode("ascii")
            return self._pbkdf2_hash(password)
        return self._pbkdf2_hash(password)

    # -- verification -------------------------------------------------------
    def verify(self, password: str, stored: str) -> bool:
        if not stored:
            return False
        if stored.startswith("bcrypt$"):
            if bcrypt is None:
                return False
            try:
                return bcrypt.checkpw(
                    password.encode("utf-8"), stored[7:].encode("ascii")
                )
            except Exception:
                return False
        if stored.startswith("pbkdf2$"):
            scheme, iters_s, salt_b, dk_b = stored.split("$")[1:5]
            if scheme != "sha256":
                return False
            try:
                iters = int(iters_s)
                salt = _b64d(salt_b)
                expected = _b64d(dk_b)
                actual = hashlib.pbkdf2_hmac(
                    "sha256", password.encode("utf-8"), salt, iters
                )
                return _ct_eq(actual, expected)
            except Exception:
                return False
        return False


# ---------------------------------------------------------------------------
# TokenManager (stdlib HS256 JWT)
# ---------------------------------------------------------------------------

class TokenManager:
    """Minimal HS256 JWT manager (no external JWT library).

    Tokens are bound to the session generation ``sess_v`` and a secret derived
    from the device key + master hash, so a password change or an explicit
    lock revokes every previously issued token.
    """

    _HEADER = {"alg": "HS256", "typ": "JWT"}
    GRACE_SECONDS = 300  # tokens stay valid up to 5 minutes past auto-lock
    SUBJECT = "gatekeeper"

    def __init__(self, device_key: bytes, master_hash: str):
        self._secret = TokenManager._derive_secret(device_key, master_hash)

    @staticmethod
    def _derive_secret(device_key: bytes, master_hash: str) -> bytes:
        return hmac.new(
            device_key or b"", master_hash.encode("utf-8"), hashlib.sha256
        ).digest()

    def mint(self, sess_v: int, ttl_s: int, now=None) -> str:
        now = now if now is not None else time.time()
        payload = {
            "sub": self.SUBJECT,
            "iat": int(now),
            "exp": int(now) + int(ttl_s),
            "jti": _b64e(secrets.token_bytes(16)),
            "sess_v": int(sess_v),
        }
        return self._encode(payload)

    def verify(self, token: str, sess_v, now=None) -> dict:
        """Return claims when the token is well-formed, unexpired and bound to
        the current session generation; otherwise None."""
        if not token:
            return None
        try:
            header_b, payload_b, sig_b = token.split(".")
            header = json.loads(_b64d(header_b))
            if header.get("alg") != "HS256":
                return None
            payload = json.loads(_b64d(payload_b))
            signing_input = token[: token.rfind(".")].encode("ascii")
            expected = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
            if not _ct_eq(expected, _b64d(sig_b)):
                return None
            now = now if now is not None else time.time()
            if int(payload.get("exp", 0)) < int(now):
                return None
            if payload.get("sess_v") != int(sess_v):
                return None
            if payload.get("sub") != self.SUBJECT:
                return None
            return payload
        except Exception:
            return None

    # -- internals ----------------------------------------------------------
    def _encode(self, payload: dict) -> str:
        head = _b64e(
            json.dumps(self._HEADER, separators=(",", ":")).encode("utf-8")
        )
        body = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = ("%s.%s" % (head, body)).encode("ascii")
        sig = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        return "%s.%s.%s" % (head, body, _b64e(sig))


# ---------------------------------------------------------------------------
# AESGCMCipher
# ---------------------------------------------------------------------------

class AESGCMCipher:
    """Authenticated sealing envelope: ``aesgcm$v1$<iv_b64>.<ct_b64>``."""

    PREFIX = "aesgcm$v1$"
    IV_LENGTH = 12

    def __init__(self, key: bytes):
        if not _HAS_CRYPTO:
            raise GatekeeperError("cryptography package is required")
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self._key = key

    def seal(self, data: bytes) -> str:
        iv = secrets.token_bytes(self.IV_LENGTH)
        ct = AESGCM(self._key).encrypt(iv, data, None)
        return "%s%s.%s" % (self.PREFIX, _b64e(iv), _b64e(ct))

    def open(self, envelope: str) -> bytes:
        if not envelope.startswith(self.PREFIX):
            raise ValueError("not an aesgcm envelope")
        try:
            iv_b64, ct_b64 = envelope[len(self.PREFIX):].split(".", 1)
            iv = _b64d(iv_b64)
            return AESGCM(self._key).decrypt(iv, _b64d(ct_b64), None)
        except InvalidTag as exc:
            raise ValueError("bad tag / tampered envelope") from exc


# ---------------------------------------------------------------------------
# WebAuthnManager
# ---------------------------------------------------------------------------

class WebAuthnManager:
    """Minimal WebAuthn RP-side logic (challenges + ECDSA P-256 verification).

    Attestation formats supported: "none" (no statement to verify) and "self"
    (verify the credential key's signature over authData || SHA256(clientData)).
    """

    UP_FLAG = 0x01
    UV_FLAG = 0x04
    AT_FLAG = 0x40

    def __init__(self, rp_id=DEFAULT_RP_ID, origin=DEFAULT_ORIGIN, now_fn=time.time):
        if not _HAS_CRYPTO:
            raise GatekeeperError("cryptography package is required")
        self.rp_id = rp_id
        self.origin = origin.rstrip("/")
        self._challenges = _MemoryChallengeStore(now_fn)
        self._now = now_fn

    # -- ceremonies ---------------------------------------------------------
    def begin_register(self) -> dict:
        user_handle = _b64e(secrets.token_bytes(32))
        challenge = self._challenges.issue("register")
        return {
            "challenge": challenge,
            "rp_id": self.rp_id,
            "origin": self.origin,
            "user_handle": user_handle,
        }

    def complete_register(self, client_data_b64: str, attestation_b64: str,
                          user_handle: str = None) -> dict:
        client_data = self._check_client_data(client_data_b64, "webauthn.create")
        try:
            att_obj = cbor2.loads(_b64d(attestation_b64))
        except Exception as exc:
            raise GatekeeperError("invalid attestation object: %s" % exc) from exc
        if not isinstance(att_obj, dict) or 1 not in att_obj or 2 not in att_obj:
            raise GatekeeperError("malformed attestation object")
        fmt = att_obj.get(1)
        auth_data = att_obj.get(2)
        att_stmt = att_obj.get(3) or {}
        auth = self._parse_auth_data(auth_data)
        pub_key = self._parse_cose_key(auth["cose"])
        raw_client = _b64d(client_data_b64)
        signed = auth_data + hashlib.sha256(raw_client).digest()

        if fmt == "self":
            sig = att_stmt.get("sig")
            if not sig:
                raise GatekeeperError("self attestation missing signature")
            self._ecdsa_verify(pub_key, signed, sig)
        elif fmt != "none":
            raise GatekeeperError("unsupported attestation format: %r" % fmt)

        cred_id_b64 = _b64e(auth["cred_id"])
        if self._store_lookup is not None:
            existing = self._store_lookup(cred_id_b64)
            if existing:
                raise GatekeeperError("credential already registered")
        entry = {
            "x": pub_key.public_numbers().x,
            "y": pub_key.public_numbers().y,
            "sign_count": auth["sign_count"],
            "user_handle": user_handle or client_data.get("userHandle"),
            "created": self._now(),
        }
        return {"ok": True, "credential_id": cred_id_b64, "credential": entry,
                "store_and_push": True}

    def begin_assert(self) -> dict:
        challenge = self._challenges.issue("assert")
        return {"challenge": challenge, "rp_id": self.rp_id, "origin": self.origin}

    def complete_assert(self, cred_id_b64: str, client_data_b64: str,
                        auth_data_b64: str, signature_b64: str) -> dict:
        client_data = self._check_client_data(client_data_b64, "webauthn.get")
        auth_data = _b64d(auth_data_b64)
        auth = self._parse_auth_data(auth_data)
        if not (auth["flags"] & self.UP_FLAG):
            raise GatekeeperError("user presence flag not set")
        credential = None
        if self._store_lookup is not None:
            credential = self._store_lookup(cred_id_b64)
        if credential is None:
            raise GatekeeperError("unknown credential")
        pub = ec.EllipticCurvePublicNumbers(
            int(credential["x"]), int(credential["y"]), ec.SECP256R1()
        ).public_key(default_backend())
        signed = auth_data + hashlib.sha256(_b64d(client_data_b64)).digest()
        self._ecdsa_verify(pub, signed, _b64d(signature_b64))
        old_count = int(credential.get("sign_count") or 0)
        new_count = auth["sign_count"] or 0
        if new_count != 0 and old_count != 0 and new_count <= old_count:
            raise GatekeeperError("signature counter regression detected")
        return {"ok": True, "credential_id": cred_id_b64, "new_sign_count": new_count}

    # -- plumbing -----------------------------------------------------------
    # Optional hook so the state machine can look up credentials while
    # completing a ceremony. Set by Gatekeeper after construction.
    _store_lookup = None

    def _check_client_data(self, client_data_b64: str, expected_type: str) -> dict:
        try:
            raw = _b64d(client_data_b64)
            client_data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise GatekeeperError("invalid client data: %s" % exc) from exc
        if not isinstance(client_data, dict):
            raise GatekeeperError("invalid client data")
        if client_data.get("type") != expected_type:
            raise GatekeeperError("unexpected client data type")
        challenge = client_data.get("challenge")
        if not isinstance(challenge, str):
            raise GatekeeperError("challenge missing or invalid")
        purpose = "register" if "create" in expected_type else "assert"
        if self._challenges.consume(challenge, purpose) is not True:
            raise GatekeeperError("challenge invalid or expired")
        origin = (client_data.get("origin") or "").rstrip("/")
        if origin != self.origin:
            raise GatekeeperError(
                "origin mismatch: %r != %r" % (origin, self.origin)
            )
        return client_data

    @staticmethod
    def _parse_auth_data(auth_data: bytes) -> dict:
        if len(auth_data) < 37:
            raise GatekeeperError("authenticator data too short")
        rp_id_hash = auth_data[0:32]
        flags = auth_data[32]
        sign_count = struct.unpack(">I", auth_data[33:37])[0]
        rest = auth_data[37:]
        out = {
            "rp_id_hash": rp_id_hash,
            "flags": flags,
            "sign_count": sign_count,
            "cred_id": None,
            "cose": None,
            "has_attested": bool(flags & WebAuthnManager.AT_FLAG),
        }
        if flags & 0x40:  # AT flag
            aaguid = rest[0:16]
            cred_len = struct.unpack(">H", rest[16:18])[0]
            cred_id = rest[18:18 + cred_len]
            coses = rest[18 + cred_len:]
            out["aaguid"] = aaguid
            out["cred_id"] = cred_id
            out["cose"] = coses
        return out

    @staticmethod
    def _parse_cose_key(cose: bytes) -> "ec.EllipticCurvePublicKey":
        try:
            params = cbor2.loads(cose)
        except Exception as exc:
            raise GatekeeperError("invalid COSE key: %s" % exc) from exc
        try:
            if params.get(1) != 2 or params.get(3) != -7 or params.get(-1) != 1:
                raise GatekeeperError("only EC2 / ES256 / P-256 supported")
            x = params.get(-2)
            y = params.get(-3)
        except Exception as exc:
            raise GatekeeperError("unsupported COSE key: %s" % exc) from exc
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(
            default_backend()
        )

    @staticmethod
    def _ecdsa_verify(pub, message: bytes, raw_sig: bytes) -> None:
        if len(raw_sig) != 64:
            raise GatekeeperError("ECDSA signature must be 64 bytes")
        r = int.from_bytes(raw_sig[0:32], "big")
        s = int.from_bytes(raw_sig[32:64], "big")
        der = asym_utils.encode_dss_signature(r, s)
        try:
            pub.verify(
                der, message, ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature as exc:
            raise GatekeeperError("signature verification failed") from exc

    @staticmethod
    def _pubkey_pem(credential: dict) -> bytes:
        pub = ec.EllipticCurvePublicNumbers(
            int(credential["x"]), int(credential["y"]), ec.SECP256R1()
        ).public_key(default_backend())
        return pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


# ---------------------------------------------------------------------------
# Gatekeeper (state machine facade)
# ---------------------------------------------------------------------------

class Gatekeeper:
    """Thread-safe state machine + entry point for the web layer.

    All mutating calls are guarded by a single ``threading.RLock``.
    ``now_fn`` is injectable so tests can drive auto-lock deterministically.
    """

    def __init__(self, store_path=None, now_fn=time.time,
                 rp_id=DEFAULT_RP_ID, origin=DEFAULT_ORIGIN):
        self._store = GatekeeperStore(store_path, now_fn=now_fn)
        self._hasher = PasswordHasher()
        self._webauthn = WebAuthnManager(rp_id, origin, now_fn=now_fn)
        self._webauthn._store_lookup = self._store.get_credential
        self._lock = threading.RLock()
        self._now = now_fn
        self._last_activity = now_fn()
        self._unlocked = False

    # -- lifecycle ----------------------------------------------------------
    def is_setup(self) -> bool:
        with self._lock:
            return self._store.is_setup()

    def setup(self, password: str, auto_lock_s: int = DEFAULT_AUTO_LOCK_S) -> None:
        with self._lock:
            if len(password) < PASSWORD_MIN_LENGTH:
                raise GatekeeperError(
                    "password must be at least %d characters" % PASSWORD_MIN_LENGTH
                )
            hashed = self._hasher.hash_password(password)
            self._store.ensure_device_key()
            self._store.set_master_hash(hashed)
            self._store.set_auto_lock_seconds(int(auto_lock_s))
            self._store.bump_sess_v()
            self._unlocked = False

    def unlock(self, password: str) -> str:
        with self._lock:
            stored = self._store.master_hash
            if not stored:
                raise GatekeeperError("gatekeeper is not set up")
            if not self._hasher.verify(password, stored):
                raise GatekeeperError("invalid master password")
            self._unlocked = True
            self._last_activity = self._now()
            return self._mint_token()

    def lock(self) -> None:
        with self._lock:
            if self._unlocked:
                # Bump the session generation to revoke outstanding tokens.
                self._store.bump_sess_v()
            self._unlocked = False

    def change_password(self, old_password: str, new_password: str) -> None:
        with self._lock:
            stored = self._store.master_hash
            if not stored:
                raise GatekeeperError("gatekeeper is not set up")
            if not self._hasher.verify(old_password, stored):
                raise GatekeeperError("invalid master password")
            if len(new_password) < PASSWORD_MIN_LENGTH:
                raise GatekeeperError(
                    "password must be at least %d characters" % PASSWORD_MIN_LENGTH
                )
            new_hash = self._hasher.hash_for_verify(new_password, stored)
            self._store.set_master_hash(new_hash)
            self._store.bump_sess_v()  # invalidate all existing tokens
            self._unlocked = False

    def lock_if_expired(self) -> bool:
        """Automatically lock when idle longer than the configured timeout.
        Returns True when the state changed to locked."""
        with self._lock:
            if not self._unlocked:
                return False
            idle = self._now() - self._last_activity
            if idle > self._store.auto_lock_seconds():
                self._store.bump_sess_v()
                self._unlocked = False
                return True
            return False

    def touch(self) -> None:
        with self._lock:
            self._last_activity = self._now()
            if self._unlocked:
                self._unlocked = True

    # -- authorization ------------------------------------------------------
    def authorize(self, token: str):
        """Return the token claims when the gatekeeper is unlocked and the
        token is valid; otherwise None. Refreshes the idle clock on success."""
        with self._lock:
            claims = self._verify_token_locked(token)
            if claims is not None:
                self._last_activity = self._now()
            return claims

    def verify_token(self, token: str) -> dict:
        with self._lock:
            return self._verify_token_locked(token)

    def _verify_token_locked(self, token: str) -> dict:
        if not self._unlocked:
            return None
        if not self._store.is_setup():
            return None
        tm = TokenManager(self._store.device_key, self._store.master_hash)
        return tm.verify(token, self._store.sess_v, now=self._now())

    def _mint_token(self) -> str:
        if not self._store.is_setup():
            raise GatekeeperError("gatekeeper is not set up")
        tm = TokenManager(self._store.device_key, self._store.master_hash)
        ttl = self._store.auto_lock_seconds() + TokenManager.GRACE_SECONDS
        return tm.mint(self._store.sess_v, ttl, now=self._now())

    # -- WebAuthn facade ----------------------------------------------------
    def webauthn_begin_register(self) -> dict:
        with self._lock:
            if not self._store.is_setup():
                raise GatekeeperError("gatekeeper is not set up")
            info = self._webauthn.begin_register()
            info["user_handle"] = _b64e(self._store.device_key)
            return info

    def webauthn_complete_register(self, client_data_b64: str,
                                   attestation_b64: str) -> dict:
        with self._lock:
            res = self._webauthn.complete_register(
                client_data_b64, attestation_b64,
                user_handle=_b64e(self._store.device_key),
            )
            entry = res["credential"]
            self._store.put_credential(res["credential_id"], entry)
            return {"ok": True, "credential_id": res["credential_id"]}

    def webauthn_begin_assert(self) -> dict:
        with self._lock:
            if not self._store.is_setup():
                raise GatekeeperError("gatekeeper is not set up")
            if not self._store.list_credentials():
                raise GatekeeperError("no biometric credentials registered")
            return self._webauthn.begin_assert()

    def webauthn_complete_assert(self, cred_id_b64: str, client_data_b64: str,
                                 auth_data_b64: str, signature_b64: str) -> dict:
        with self._lock:
            res = self._webauthn.complete_assert(
                cred_id_b64, client_data_b64, auth_data_b64, signature_b64
            )
            self._store.update_credential_sign_count(
                cred_id_b64, res["new_sign_count"]
            )
            self._unlocked = True
            self._last_activity = self._now()
            return {"ok": True, "token": self._mint_token()}

    # -- status -------------------------------------------------------------
    def status(self, token: str = None) -> dict:
        with self._lock:
            auto = self._store.auto_lock_seconds()
            remaining = None
            token_valid = False
            if self._unlocked and self._store.is_setup():
                idle = self._now() - self._last_activity
                remaining = max(0, auto - idle)
                if token:
                    token_valid = self._verify_token_locked(token) is not None
            return {
                "setup": self._store.is_setup(),
                "locked": not (
                    self._unlocked and self._store.is_setup()
                ),
                "auto_lock_s": auto,
                "webauthn_registered": bool(self._store.list_credentials()),
                "remaining_s": int(remaining) if remaining is not None else None,
                "token_valid": token_valid,
                "locked_reason": self._locked_reason(),
            }

    def _locked_reason(self) -> str:
        if not self._store.is_setup():
            return "not_setup"
        if not self._unlocked:
            return "locked"
        return "unlocked"