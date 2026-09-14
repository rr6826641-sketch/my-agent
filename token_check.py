# -*- coding: utf-8 -*-
"""Token expiry/health checker for the agent's API keys (.env).

* Offline (default): key presence, format, and JWT 'exp' decoding.
* --probe: additionally hits each provider's live endpoint once (bounded,
  10s timeout) to detect 401/invalid vs healthy.

Usage:  python token_check.py [--probe] [--env .env]
"""
import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error

PAYLOAD_RE = re.compile(r"^[A-Za-z0-9_-]{6,}\.([A-Za-z0-9_-]{6,})\.[A-Za-z0-9_-]{6,}$")

PROBES = {
    "OPENROUTER_API_KEY": ("https://openrouter.ai/api/v1/models", {"Authorization": "Bearer {k}"}),
    "GROQ_API_KEY": ("https://api.groq.com/openai/v1/models", {"Authorization": "Bearer {k}"}),
    "HUGGINGFACE_API_KEY": ("https://huggingface.co/api/whoami-v2", {"Authorization": "Bearer {k}"}),
    "VENICE_API_KEY": ("https://api.venice.ai/api/v1/models", {"Authorization": "Bearer {k}"}),
    "NOTRACK_API_KEY": ("https://notrack-models.ggtyler.dev/v1/models", {"Authorization": "Bearer {k}"}),
}


def _b64d(s):
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s)
    except Exception:
        return None


def jwt_exp(key):
    m = PAYLOAD_RE.match(key.strip())
    if not m:
        return None
    raw = _b64d(m.group(1))
    if not raw:
        return None
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return None
    exp = data.get("exp")
    if isinstance(exp, (int, float)) and exp > 0:
        return exp
    return None


def status_text(exp):
    if exp is None:
        return "n/a (non-JWT or no exp)"
    now = time.time()
    days = (exp - now) / 86400.0
    if days < 0:
        return "EXPIRED (%.1f days ago)" % (-days)
    if days < 7:
        return "EXPIRES SOON (%.1f days)" % days
    return "ok (%.1f days left)" % days


def probe_one(name, key):
    spec = PROBES.get(name)
    if not spec:
        return "skipped (no probe endpoint)"
    url, hdr = spec
    req = urllib.request.Request(url, headers={
        "Authorization": hdr["Authorization"].format(k=key),
        "User-Agent": "hackerai-token-check/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return "HTTP %d OK" % r.status
    except urllib.error.HTTPError as e:
        return "HTTP %d %s" % (e.code, ("AUTH_FAIL" if e.code in (401, 403) else "other"))
    except Exception as e:
        return "ERROR %s" % type(e).__name__


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--env", default=".env")
    args = ap.parse_args()

    env_path = os.path.join(os.getcwd(), args.env)
    keys = {}
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                keys[k.strip()] = v.strip().strip('"').strip("'")
    else:
        print("[FAIL] %s not found" % env_path)
        sys.exit(1)

    print("Token health check  |  env: %s  |  probe: %s" % (env_path, args.probe))
    print("-" * 72)
    failed = 0
    for name, key in keys.items():
        if not key:
            print("[EMPTY] %-24s value missing" % name)
            failed += 1
            continue
        mask = key[:4] + "..." + key[-4:] if len(key) > 12 else "(short)"
        exp = jwt_exp(key)
        print("[JWT ] %-24s %-8s exp-status: %-32s" % (name, mask, status_text(exp)))
        if exp is None:
            # format heuristic
            if len(key) < 20:
                print("      %-24s WARN: suspiciously short key" % "")
                failed += 1
        elif exp < time.time():
            failed += 1
        if args.probe:
            print("      %-24s probe: %s" % ("", probe_one(name, key)))
    print("-" * 72)
    print("RESULT: %s" % ("ALL_KEYS_OK" if failed == 0 else "%d issue(s)" % failed))
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()