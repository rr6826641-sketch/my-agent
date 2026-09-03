"""Self-Upgrade tools (F1).

Give the agent the ability to check its own GitHub remote and pull the
latest version of itself:

  * check_update  -> is the local repo behind origin? what changed?
  * apply_update  -> fetch + ff-only pull, then safety gates:
       1. working tree must be clean (or force=True)
       2. compile gate: every .py in the package must compile
       3. optional test gate: pytest quick suite must pass
       On ANY gate failure the repo is rolled back to the previous HEAD
       (git reset --hard) so a bad update can never break the agent.
     A successful update writes .restart_required next to the repo so a
     long-running webui process knows a restart will pick up the new code.

The default repo is the project root (PROJECT_DIR); tests inject their own
temporary repos via repo_dir.
"""

import os
import subprocess
import sys
import time

from ..config import PROJECT_DIR

DEFAULT_REPO = PROJECT_DIR
QUICK_TEST_FILES = [
    "test_verify_arch.py",
    "test_redteam_mode.py",
    "test_pipeline.py",
    "test_webui_export.py",
    "test_webui_master_switch.py",
    "test_webui_quickpicks.py",
]
FULL_TEST_FILES = ["."]
RESTART_MARKER = ".restart_required"


def _run(cmd, cwd, timeout=180):
    """Run a command list and return (rc, combined_output)."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, timeout=timeout,
            text=True, errors="replace")
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "command timed out after %ds: %s" % (timeout, " ".join(cmd))
    except FileNotFoundError as exc:
        return 127, "command not found: %s" % exc


def _git(cwd, *args, timeout=180):
    return _run(["git"] + list(args), cwd, timeout=timeout)


def repo_info(repo_dir=None):
    """Return a dict describing local git state (no network access)."""
    repo = repo_dir or DEFAULT_REPO
    info = {"repo": repo, "exists": os.path.isdir(os.path.join(repo, ".git"))}
    if not info["exists"]:
        return info
    rc, out = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    info["branch"] = out.strip() if rc == 0 else "?"
    rc, out = _git(repo, "rev-parse", "HEAD")
    info["head"] = out.strip() if rc == 0 else ""
    info["head_short"] = (info["head"] or "?")[:10]
    rc, out = _git(repo, "status", "--porcelain")
    # the restart marker is written by apply_update itself, so it must never
    # make the tree look "dirty" on a later run.
    dirty = [ln for ln in (out or "").splitlines()
             if ln.strip() and RESTART_MARKER not in ln]
    info["dirty"] = dirty
    rc, out = _git(repo, "config", "remote.origin.url")
    info["remote"] = out.strip() if rc == 0 else ""
    info["ahead"] = info["behind"] = None
    if info["branch"] and info["branch"] != "?":
        rc, out = _git(repo, "rev-list", "--count", "HEAD..@{upstream}")
        if rc == 0:
            info["behind"] = int(out.strip() or 0)
        rc, out = _git(repo, "rev-list", "--count", "@{upstream}..HEAD")
        if rc == 0:
            info["ahead"] = int(out.strip() or 0)
    return info


def _fmt_change_log(repo, since):
    rc, out = _git(repo, "log", "--oneline", "--no-decorate", "%s..HEAD" % since)
    return out.strip() or "(none)"


def _fetch(repo):
    rc, out = _git(repo, "fetch", "origin", "--prune", timeout=90)
    if rc != 0:
        return "git fetch failed (rc=%d):\n%s" % (rc, out[-800:])
    return ""


def _check_clean(repo, force):
    info = repo_info(repo)
    if info.get("dirty"):
        if force:
            return ""
        return ("Working tree is NOT clean (%d changed file(s)). Commit or "
                "stash local changes first, or retry with force=true (not "
                "recommended - a dirty pull can conflict)." % len(info["dirty"]))
    return ""


def tool_check_update(repo_dir=None):
    """Report local vs origin state (does one fetch to be current)."""
    repo = repo_dir or DEFAULT_REPO
    info = repo_info(repo)
    if not info.get("exists"):
        return "Error: %s is not a git repository." % repo
    fetch_err = _fetch(repo)
    if fetch_err:
        info["behind"] = info["ahead"] = None  # counts unknown without fetch
    else:
        branch = info.get("branch") or ""
        if branch and branch != "?":
            rc, out = _git(repo, "rev-list", "--count", "HEAD..origin/%s" % branch)
            info["behind"] = int(out.strip() or 0) if rc == 0 else None
            rc, out = _git(repo, "rev-list", "--count", "origin/%s..HEAD" % branch)
            info["ahead"] = int(out.strip() or 0) if rc == 0 else None
    lines = ["Local repo : %s" % info.get("repo")]
    lines.append("Branch      : %s @ %s" % (info.get("branch"), info.get("head_short")))
    lines.append("Remote      : %s" % (info.get("remote") or "(no origin set)"))
    if fetch_err:
        lines.append("Fetch       : FAILED - %s" % fetch_err.strip().splitlines()[-1])
    else:
        behind = info.get("behind")
        ahead = info.get("ahead")
        if behind is None:
            lines.append("Sync        : unknown (cannot compare with origin)")
        elif behind == 0 and ahead == 0:
            lines.append("Sync        : up to date with origin")
        elif behind > 0 and ahead == 0:
            lines.append("Sync        : %d commit(s) BEHIND origin -> an update is available" % behind)
        elif ahead > 0 and behind == 0:
            lines.append("Sync        : %d commit(s) AHEAD of origin (local-only work)" % ahead)
        else:
            lines.append("Sync        : %d behind / %d ahead (diverged)" % (behind, ahead))
    if info.get("dirty"):
        lines.append("Local edits : %d uncommitted file(s) - apply_update requires a clean tree" % len(info["dirty"]))
    else:
        lines.append("Local edits : clean")
    return "\n".join(lines)


def tool_apply_update(run_tests="quick", force=False, repo_dir=None):
    """Fetch the latest code, pull it, verify, and roll back on failure."""
    repo = repo_dir or DEFAULT_REPO
    info = repo_info(repo)
    if not info.get("exists"):
        return "Error: %s is not a git repository." % repo
    branch = info.get("branch")
    if not branch or branch == "?":
        return "Error: cannot determine the current git branch."
    dirty_files = info.get("dirty")
    stashed = False
    log = []
    if dirty_files:
        if not force:
            return ("Error: Working tree is NOT clean (%d changed file(s)). "
                    "Commit or stash local changes first, or retry with "
                    "force=true (not recommended - a dirty pull can "
                    "conflict)." % len(dirty_files))
        # force mode: temporarily stash local edits so the pull can apply,
        # then restore them on top of the new code.
        stash_msg = "self-upgrade-force %s" % time.strftime("%Y%m%d-%H%M%S")
        rc, out = _git(repo, "stash", "push", "-u", "-m", stash_msg,
                       timeout=120)
        if rc != 0:
            return ("Error: force update needs a clean tree to pull, but "
                    "stashing local changes FAILED:\n%s" % out[-600:])
        stashed = True
        log.append("Working tree was dirty -> local changes stashed for the "
                   "duration of the update.")
    fetch_err = _fetch(repo)
    if fetch_err:
        return "Error: " + fetch_err.strip()
    rc, out = _git(repo, "rev-list", "--count", "HEAD..origin/%s" % branch)
    if rc != 0:
        return "Error: cannot compare with origin/%s - does the branch exist upstream?" % branch
    behind = int(out.strip() or 0)
    rc, out = _git(repo, "rev-list", "--count", "origin/%s..HEAD" % branch)
    ahead = int(out.strip() or 0) if rc == 0 else 0
    if behind <= 0:
        if stashed:
            _git(repo, "stash", "pop", timeout=120)
        if ahead > 0:
            return ("Already up to date with origin/%s (local is %d commit(s) "
                    "AHEAD). Nothing to pull." % (branch, ahead))
        return "Already up to date with origin/%s." % branch

    prev_head = info.get("head") or ""
    log.append("Update available: %d commit(s) behind origin/%s" % (behind, branch))
    log.append("Pulling origin/%s ..." % branch)
    rc, out = _git(repo, "pull", "--ff-only", "origin", branch, timeout=300)
    if rc != 0:
        _git(repo, "reset", "--hard", prev_head)
        if stashed:
            _git(repo, "stash", "pop", timeout=120)  # restore user work
        return ("Error: git pull --ff-only FAILED and the repo was reset to the "
                "previous HEAD.\n%s" % out[-800:])

    new_info = repo_info(repo)
    new_head = new_info.get("head") or ""
    if not new_head or new_head == prev_head:
        if stashed:
            _git(repo, "stash", "pop", timeout=120)
        return "Error: pull reported success but HEAD did not move (still %s)." % (prev_head or "?")[:10]

    # Safety gate 1: every package module must compile.
    package = os.path.join(repo, "ai_agent")
    if os.path.isdir(package):
        rc, out = _run([sys.executable, "-m", "compileall", "-q", "ai_agent"],
                       repo, timeout=240)
        if rc != 0:
            _git(repo, "reset", "--hard", prev_head)
            if stashed:
                _git(repo, "stash", "pop", timeout=120)
            return ("Error: the pulled code FAILED the compile check -> rolled "
                    "back to %s.\n%s" % (prev_head[:10], out[-600:]))

    # Safety gate 2: optional pytest suite.
    mode = (run_tests or "quick").strip().lower()
    if mode != "none":
        files = FULL_TEST_FILES if mode == "full" else QUICK_TEST_FILES
        if any(os.path.isfile(os.path.join(repo, f)) for f in files if f != "."):
            cmd = [sys.executable, "-m", "pytest", "-q"] + files
            log.append("Running tests: %s" % " ".join(files))
            rc, out = _run(cmd, repo, timeout=420)
            log.append(out[-1200:].strip())
            if rc != 0:
                _git(repo, "reset", "--hard", prev_head)
                if stashed:
                    _git(repo, "stash", "pop", timeout=120)
                return ("Error: the pulled code FAILED the test gate -> rolled "
                        "back to %s.\n%s" % (prev_head[:10], log[-1]))

    changes = _fmt_change_log(repo, prev_head)
    if stashed:
        rc, out = _git(repo, "stash", "pop", timeout=120)
        if rc != 0:
            log.append("WARNING: local changes could not be auto-reapplied on "
                       "top of the update (merge conflict). They are saved in "
                       "the stash - recover with: git stash pop")
        else:
            log.append("Local changes restored on top of the new code.")
    marker = os.path.join(repo, RESTART_MARKER)
    try:
        with open(marker, "w", encoding="utf-8") as f:
            f.write("restart required: %s -> %s at %s\n" % (
                prev_head[:10], new_head[:10],
                time.strftime("%Y-%m-%d %H:%M:%S")))
    except OSError:
        pass
    log.append("OK: updated %s -> %s" % (prev_head[:10], new_head[:10]))
    log.append("New commits:\n%s" % changes)
    log.append("NOTE: if the web UI is running, restart it to load the new "
               "code (marker: %s)." % RESTART_MARKER)
    return "\n".join(log)
