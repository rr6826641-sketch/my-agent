"""
auto_updater.py - MyAgentUltra v16 self-updater
------------------------------------------------
Checks GitHub releases for a newer build and swaps the local EXE / code tree.
- `check_for_update()`  -> latest version tag vs CURRENT_VERSION
- `apply_update()`      -> downloads release asset into dist/ and replaces the
                           running EXE on next launch (rename-via-.old pattern)
- No telemetry, no external calls except the GitHub releases API.
Works in both dev-tree mode (git pull) and frozen EXE mode.
"""
import os
import sys
import json
import shutil
import subprocess
import urllib.request

CURRENT_VERSION = "v16"
GITHUB_REPO = "rr6826641-sketch/my-agent"
RELEASE_API = "https://api.github.com/repos/%s/releases/latest" % GITHUB_REPO
ASSET_NAME = "MyAgentUltra.exe"


def _here():
    return os.path.dirname(os.path.abspath(__file__))


def is_frozen():
    return bool(getattr(sys, "frozen", False))


def fetch_latest_release(timeout=15):
    """Return (tag, asset_url, download_url) or (None, None, None)."""
    try:
        req = urllib.request.Request(RELEASE_API, headers={"User-Agent": "MyAgentUltra/16"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        tag = data.get("tag_name") or data.get("name") or ""
        assets = data.get("assets") or []
        for a in assets:
            if a.get("name") == ASSET_NAME:
                return tag, a.get("browser_download_url"), a.get("size")
        # fall back to the zipball (dev-tree style update)
        return tag, data.get("zipball_url"), None
    except Exception as e:  # noqa: BLE001
        print("[auto-updater] check failed: %s" % e)
        return None, None, None


def check_for_update():
    """Returns dict {latest, current, update_available, asset_url}."""
    tag, url, _size = fetch_latest_release()
    if not tag:
        return {"latest": None, "current": CURRENT_VERSION,
                "update_available": False, "asset_url": None}
    avail = tag.strip().lstrip("v").lower() != CURRENT_VERSION.strip().lstrip("v").lower()
    return {"latest": tag, "current": CURRENT_VERSION,
            "update_available": avail, "asset_url": url}


def apply_update(url, dest_dir=None):
    """Download asset and stage it as <exe>.new for swap-on-next-launch."""
    try:
        here = _here()
        dest_dir = dest_dir or (here if is_frozen() else os.path.join(here, "dist"))
        os.makedirs(dest_dir, exist_ok=True)
        dst = os.path.join(dest_dir, ASSET_NAME)
        new = dst + ".new"
        print("[auto-updater] downloading %s" % url)
        urllib.request.urlretrieve(url, new)
        # keep the old exe available as .old (rollback), replace main
        if os.path.exists(dst):
            shutil.move(dst, dst + ".old")
        shutil.move(new, dst)
        print("[auto-updater] applied: %s" % dst)
        return True
    except Exception as e:  # noqa: BLE001
        print("[auto-updater] apply failed: %s" % e)
        return False


def git_pull_update():
    """Dev-tree update path: git fetch + fast-forward (local changes kept)."""
    try:
        here = _here()
        r = subprocess.run(["git", "-C", here, "pull", "--ff-only"],
                           capture_output=True, text=True, timeout=120)
        print("[auto-updater] git pull rc=%d" % r.returncode)
        print(r.stdout[-800:])
        return r.returncode == 0
    except Exception as e:  # noqa: BLE001
        print("[auto-updater] git pull failed: %s" % e)
        return False


if __name__ == "__main__":
    import json as _j
    info = check_for_update()
    print(_j.dumps(info, indent=2))