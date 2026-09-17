"""
auto_updater.py - MyAgentUltra v16 self-updater
------------------------------------------------
Checks GitHub releases for a newer build and swaps the local EXE / code tree.
- `check_for_update()`  -> latest version tag vs CURRENT_VERSION
- `apply_update()`      -> downloads release asset into dist/ and replaces the
                           running EXE on next launch (rename-via-.old pattern)
- Works with PRIVATE repos too: reads a GitHub token from, in order:
    1) env var GH_TOKEN / GITHUB_TOKEN
    2) config.json  ->  "github_token": "gho_..."
    3) .env         ->  GITHUB_TOKEN=gho_...
  config.json and .env are gitignored, so the token is never committed.
- No telemetry, no external calls except the GitHub releases API.
Works in both dev-tree mode (git pull) and frozen EXE mode.
"""
import os
import sys
import json
import shutil
import urllib.request

CURRENT_VERSION = "v17"
GITHUB_REPO = "rr6826641-sketch/my-agent"
RELEASE_API = "https://api.github.com/repos/%s/releases/latest" % GITHUB_REPO
ASSET_NAME = "MyAgentUltra.exe"


def _here():
    return os.path.dirname(os.path.abspath(__file__))


def is_frozen():
    return bool(getattr(sys, "frozen", False))


def _load_github_token():
    """Return a GitHub token for private-repo access, or None (public repo)."""
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if tok:
        return tok.strip()
    try:
        cfg_path = os.path.join(_here(), "config.json")
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        tok = cfg.get("github_token") or cfg.get("GH_TOKEN")
        if tok:
            return str(tok).strip()
    except Exception:  # noqa: BLE001
        pass
    try:
        env_path = os.path.join(_here(), ".env")
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("GITHUB_TOKEN=") and len(line) > 12:
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:  # noqa: BLE001
        pass
    return None


def _api_headers(token):
    headers = {"User-Agent": "MyAgentUltra/16",
               "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    return headers


def fetch_latest_release(timeout=15):
    """Return (tag, asset_url, size, asset_id) or (None, None, None, None)."""
    try:
        token = _load_github_token()
        req = urllib.request.Request(RELEASE_API, headers=_api_headers(token))
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        tag = data.get("tag_name") or data.get("name") or ""
        assets = data.get("assets") or []
        for a in assets:
            if a.get("name") == ASSET_NAME:
                return (tag, a.get("browser_download_url"),
                        a.get("size"), a.get("id"))
        # fall back to the zipball (dev-tree style update)
        return tag, data.get("zipball_url"), None, None
    except Exception as e:  # noqa: BLE001
        print("[auto-updater] check failed: %s" % e)
        return None, None, None, None


def check_for_update():
    """Returns dict {latest, current, update_available, asset_url}."""
    tag, url, _size, _aid = fetch_latest_release()
    if not tag:
        return {"latest": None, "current": CURRENT_VERSION,
                "update_available": False, "asset_url": None}
    avail = tag.strip().lstrip("v").lower() != CURRENT_VERSION.strip().lstrip("v").lower()
    return {"latest": tag, "current": CURRENT_VERSION,
            "update_available": avail, "asset_url": url}


def _download(url, dst, token, timeout=2400):
    """Stream-download with optional Bearer auth (urllib strips nothing here)."""
    if token:
        # API octet-stream endpoint redirects to a signed CDN URL -> no auth
        # needed on the CDN, and redirects are followed automatically.
        req = urllib.request.Request(url, headers={
            "User-Agent": "MyAgentUltra/16",
            "Authorization": "Bearer %s" % token,
            "Accept": "application/octet-stream",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            with open(dst, "wb") as f:
                shutil.copyfileobj(r, f, length=1024 * 1024)
    else:
        urllib.request.urlretrieve(url, dst)


def apply_update(url, dest_dir=None):
    """Download asset and stage it as <exe>.new for swap-on-next-launch."""
    try:
        here = _here()
        dest_dir = dest_dir or (here if is_frozen() else os.path.join(here, "dist"))
        os.makedirs(dest_dir, exist_ok=True)
        dst = os.path.join(dest_dir, ASSET_NAME)
        new = dst + ".new"
        token = _load_github_token()
        if token:
            # private repo: resolve asset download to the authenticated API URL
            _tag, _burl, _size, aid = fetch_latest_release()
            if aid:
                url = "https://api.github.com/repos/%s/releases/assets/%s" % (
                    GITHUB_REPO, aid)
        print("[auto-updater] downloading %s" % url)
        _download(url, new, token)
        # keep the old exe available as .old (rollback), replace main
        if os.path.exists(dst):
            shutil.move(dst, dst + ".old")
        shutil.move(new, dst)
        print("[auto-updater] applied: %s" % dst)
        return True
    except Exception as e:  # noqa: BLE001
        print("[auto-updater] apply failed: %s" % e)
        return False