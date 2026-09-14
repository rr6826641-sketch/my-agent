"""Git Secret Dorker - leaked secret hunter (Tier 2 bundle #9).

Scans a git repository (local path or remote clone) for hardcoded secrets:
  - regex pattern matching against the working tree AND full commit history
  - attribution of each hit to file + commit hash + commit message
  - output is bounded and JSON serialisable

Uses the `git` CLI (subprocess) - no python git libs required.
Every function returns a clean JSON-serialisable dict, never raises, and
respects file-size / count caps so scans stay fast and bounded.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile

# ---------------------------------------------------------------------------
# Secret patterns: name -> (compiled regex, confidence)
# ---------------------------------------------------------------------------
_PATTERNS = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA)[0-9A-Z]{16}\b"), "high"),
    ("aws_secret_key", re.compile(r"(?i)(aws[_-]?secret|secret[_-]?access[_-]?key)\s*[=:]\s*[\"']?([0-9a-zA-Z/+]{40})[\"']?"), "high"),
    ("github_token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,255}\b"), "high"),
    ("github_fine_grained", re.compile(r"github_pat_[0-9A-Za-z_]{22,255}"), "high"),
    ("gitlab_token", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"), "high"),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "high"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), "high"),
    ("stripe_restricted", re.compile(r"\brk_live_[0-9A-Za-z]{24,}\b"), "high"),
    ("twilio_sid", re.compile(r"\bAC[a-f0-9]{32}\b"), "high"),
    ("sendgrid_key", re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"), "high"),
    ("private_key_block", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"), "high"),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "medium"),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*[\"'][0-9A-Za-z_\-./+=]{16,}[\"']"), "medium"),
    ("db_connection_string", re.compile(r"(?i)\b(mongodb(\+srv)?|postgres(ql)?|mysql|mssql|redis|amqp|jdbc:[a-z]+|sqlserver)://[^\s\"']+"), "high"),
    ("azure_storage_key", re.compile(r"(?i)accountkey\s*[=:]\s*[\"']?[A-Za-z0-9+/=]{40,}"), "high"),
    ("firebase_url", re.compile(r"(?i)https://[a-z0-9\-]+\.firebaseio\.com"), "medium"),
    ("heroku_api_key", re.compile(r"\b(?:heroku|hapi)_[0-9a-f-]{36}\b", re.I), "high"),
    ("npm_auth_token", re.compile(r"//registry\.npmjs\.org/:_authToken=[0-9a-f-]{36}"), "high"),
    ("pypi_token", re.compile(r"\bpypi-[A-Za-z0-9_\-]{20,}\b"), "high"),
    ("docker_config_auth", re.compile(r"(?i)\"auth\":\s*\"[A-Za-z0-9+/=]{20,}\""), "medium"),
]

_MAX_FILE_BYTES = 1_000_000   # skip files larger than this
_MAX_FILES = 4000             # cap total files inspected
_MAX_HITS = 500               # cap findings returned
_BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
               ".gz", ".tar", ".woff", ".woff2", ".ttf", ".exe", ".dll",
               ".so", ".dylib", ".bin", ".class", ".pyc", ".pyd", ".jar",
               ".lock", ".min.js", ".min.css", ".map", ".wasm", ".mp4",
               ".mp3", ".webp", ".svgz"}


def _err(msg):
    return {"error": msg}


def _sh(cmd, cwd, timeout=120):
    """Run a git command; return (returncode, stdout)."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout,
                           text=True, errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        raise RuntimeError("git CLI not found on PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError("git command timed out: %s" % " ".join(cmd))


def _is_binary(path):
    return os.path.splitext(path)[1].lower() in _BINARY_EXT


def _scan_text(path, relpath, text, commit="", msg=""):
    """Run all patterns over one text blob. Returns list of hit dicts."""
    hits = []
    if not text:
        return hits
    for name, rx, conf in _PATTERNS:
        for m in rx.finditer(text):
            start = max(0, m.start() - 60)
            end = min(len(text), m.end() + 60)
            snippet = text[start:end].replace("\n", " ").replace("\r", " ")
            hits.append({
                "file": relpath,
                "pattern": name,
                "confidence": conf,
                "commit": commit or "",
                "commit_msg": msg or "",
                "snippet": snippet.strip()[:220],
            })
            if len(hits) >= _MAX_HITS:
                return hits
    return hits


def _scan_worktree(repo_dir, base_rel=""):
    """Walk the checked-out working tree (HEAD)."""
    hits = []
    count = 0
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules",
                                                ".venv", "venv", "__pycache__",
                                                ".tox", "dist", "build")]
        for fname in files:
            if len(hits) >= _MAX_HITS or count >= _MAX_FILES:
                return hits, count
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_dir)
            if _is_binary(rel) or rel.startswith(".git"):
                continue
            try:
                if os.path.getsize(fpath) > _MAX_FILE_BYTES:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            count += 1
            hits.extend(_scan_text(fpath, rel, text))
            if len(hits) >= _MAX_HITS:
                return hits, count
    return hits, count


def _scan_history(repo_dir):
    """Walk full commit history: `git log --all -p` diff blobs."""
    hits = []
    rc, out = _sh(["git", "log", "--all", "--full-history", "-p",
                   "--no-color", "--no-abbrev-commit"], repo_dir, timeout=180)
    if rc != 0:
        return hits, out.strip()[:200]
    current_commit = ""
    current_msg = ""
    blob = []
    for line in out.splitlines():
        if line.startswith("commit "):
            if blob:
                hits.extend(_scan_text("<history>", "<history>",
                                       "\n".join(blob),
                                       current_commit, current_msg))
            current_commit = line.split("commit ", 1)[1][:12]
            current_msg = ""
            blob = []
        elif line.startswith("    ") and not current_msg:
            current_msg = line.strip()[:120]
        elif line.startswith("+") and not line.startswith("+++"):
            blob.append(line[1:])
        if len(hits) >= _MAX_HITS:
            break
    if blob:
        hits.extend(_scan_text("<history>", "<history>",
                               "\n".join(blob),
                               current_commit, current_msg))
    return hits, ""


def tool_git_secret_dork(repo_url="", repo_path="", full_history=True,
                         patterns="all", max_hits=200, keep_clone=False):
    """Git Secret Dorker: scan a repo (remote URL or local path) for leaked
    secrets in the working tree and optionally the full commit history.

    repo_url      - remote git URL; cloned to a temp dir first (anonymous, no auth)
    repo_path     - local repo path (alternative to repo_url)
    full_history  - also scan `git log --all -p` for secrets in history
    patterns      - 'all' (default) or comma list of pattern names (filter)
    max_hits      - cap findings returned (default 200, hard cap 500)
    keep_clone    - keep the cloned temp dir path in the result (for review)
    Returns JSON: {repo, files_scanned, hits: [{file, pattern, confidence,
    commit, commit_msg, snippet}], clone_dir?}
    """
    try:
        max_hits = min(int(max_hits), _MAX_HITS)
    except (TypeError, ValueError):
        max_hits = _MAX_HITS

    temp_dir = None
    try:
        if repo_url:
            temp_dir = tempfile.mkdtemp(prefix="gitdork_")
            rc, out = _sh(["git", "clone", "--quiet", repo_url, temp_dir],
                          os.getcwd(), timeout=240)
            if rc != 0:
                return json.dumps(_err(
                    "clone failed: %s" % out.strip()[:300]), ensure_ascii=False)
            repo_dir = temp_dir
            source = repo_url
        elif repo_path:
            repo_dir = os.path.abspath(repo_path)
            if not os.path.isdir(repo_dir):
                return json.dumps(_err("repo_path not found: %s" % repo_path),
                                  ensure_ascii=False)
            if not os.path.isdir(os.path.join(repo_dir, ".git")):
                return json.dumps(_err(
                    "%s is not a git repository (no .git dir)" % repo_dir),
                    ensure_ascii=False)
            source = repo_dir
        else:
            return json.dumps(_err("provide repo_url or repo_path"),
                              ensure_ascii=False)

        hits, files_scanned = _scan_worktree(repo_dir)
        hist_note = ""
        if full_history:
            hist_hits, hist_note = _scan_history(repo_dir)
            seen = set()
            merged = []
            for h in hits + hist_hits:
                key = (h["pattern"], h["file"], h["snippet"][:80])
                if key in seen:
                    continue
                seen.add(key)
                merged.append(h)
                if len(merged) >= max_hits:
                    break
            hits = merged
        else:
            hits = hits[:max_hits]

        if patterns and patterns.strip().lower() != "all":
            want = {p.strip().lower() for p in patterns.split(",") if p.strip()}
            hits = [h for h in hits if h["pattern"] in want][:max_hits]

        result = {
            "repo": source,
            "files_scanned": files_scanned,
            "history_scanned": bool(full_history),
            "hist_error": hist_note or "",
            "hits_found": len(hits),
            "hits": hits,
        }
        if keep_clone and temp_dir:
            result["clone_dir"] = temp_dir
        return json.dumps(result, ensure_ascii=False, indent=2)
    except RuntimeError as exc:
        return json.dumps(_err(str(exc)), ensure_ascii=False)
    except Exception as exc:
        return json.dumps(_err("git secret dork failed: %r" % exc),
                          ensure_ascii=False)
    finally:
        if temp_dir and not keep_clone:
            shutil.rmtree(temp_dir, ignore_errors=True)
