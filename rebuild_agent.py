#!/usr/bin/env python3
"""rebuild_agent.py -- lock-free rebuild + hot-swap + restart for MyAgentUltra.

Why this exists
---------------
``py -m PyInstaller MyAgentUltra.spec`` writes straight into
``dist/MyAgentUltra.exe``.  While the tray app is running, Windows keeps that
image section open, so the write fails with::

    PermissionError: [WinError 5] Access is denied: 'dist\MyAgentUltra.exe'

The usual workaround is to kill the app *before* every build (that is why the
rebuild used to need a manual ``taskkill``).  This script removes the
constraint completely:

  1. BUILD   -- PyInstaller builds into a staging directory, so the file the
                running process has open is never touched.  The app keeps
                serving the whole time.
  2. VERIFY  -- the staged binary must be a valid PE image (MZ magic) and at
                least MIN_EXE_BYTES long, so a broken build can never be
                promoted over a working EXE.
  3. BACKUP  -- the live ``dist/MyAgentUltra.exe`` is *renamed* to
                ``MyAgentUltra.exe.old.<timestamp>``.  Windows permits renaming
                a running executable even though it forbids overwriting or
                deleting it (the same trick Chrome, Discord and this project's
                own auto_updater.py use).
  4. SWAP    -- the verified staged EXE is moved into ``dist/MyAgentUltra.exe``.
  5. RESTART -- the old instance (still running from the renamed backup) is
                stopped and the new EXE is launched detached.
  6. PRUNE   -- old rollback copies beyond ``--keep-old`` are trimmed.

Because steps 3-6 only run after 1 and 2 succeed, a failed build never disturbs
the running app.

Usage
-----
    py rebuild_agent.py                 # build + swap + restart
    py rebuild_agent.py --build-only    # only build into the staging dir
    py rebuild_agent.py --no-restart    # build + swap, leave the app stopped
    py rebuild_agent.py --rollback      # restore newest backup, then restart
    py rebuild_agent.py --status        # show PIDs / backups, change nothing
    py rebuild_agent.py --keep-old 5    # keep 5 rollback copies (default 3)
    py rebuild_agent.py --browser       # open the browser after restart
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

APP = "MyAgentUltra"
EXE_NAME = APP + ".exe"
SPEC_NAME = APP + ".spec"
MIN_EXE_BYTES = 20 * 1024 * 1024  # a real build is ~90 MB
BACKUP_GLOB = EXE_NAME + ".old.*"
LOG_NAME = "rebuild_agent.log"
PORT_FILE_NAME = ".myagent_port"

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
LIVE_EXE = DIST / EXE_NAME
STAGE_DIR = ROOT / "build" / "stage"
WORK_DIR = ROOT / "build" / "pyi-work"
LOG_PATH = ROOT / LOG_NAME
PORT_FILE = DIST / PORT_FILE_NAME

IS_WINDOWS = sys.platform.startswith("win")


# --------------------------------------------------------------------------- #
# tiny logging
# --------------------------------------------------------------------------- #
def _ts() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _log(msg: str) -> None:
    line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8", errors="replace") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def _human(n: int) -> str:
    return format(n, ",")


# --------------------------------------------------------------------------- #
# process control
# --------------------------------------------------------------------------- #
def running_pids() -> list:
    """Return the PIDs of every running MyAgentUltra.exe process."""
    if not IS_WINDOWS:
        cp = subprocess.run(["pgrep", "-f", EXE_NAME],
                            capture_output=True, text=True, errors="replace")
        pids = []
        for tok in cp.stdout.split():
            try:
                pids.append(int(tok))
            except ValueError:
                pass
        return pids

    cp = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq " + EXE_NAME, "/FO", "CSV", "/NH"],
        capture_output=True, text=True, errors="replace")
    pids = []
    for row in csv.reader(io.StringIO(cp.stdout or "")):
        if len(row) >= 2 and row[0].strip().lower() == EXE_NAME.lower():
            try:
                pids.append(int(row[1]))
            except ValueError:
                pass
    return pids


def stop_app(timeout: int = 20) -> bool:
    """Stop every running instance; returns True once none are left."""
    pids = running_pids()
    if not pids:
        _log("no running %s instance" % EXE_NAME)
        return True

    _log("stopping instance(s): %s" % ", ".join(str(p) for p in pids))
    if IS_WINDOWS:
        subprocess.run(["taskkill", "/F", "/T", "/IM", EXE_NAME],
                       capture_output=True, text=True, errors="replace")
    else:
        for pid in pids:
            subprocess.run(["kill", "-9", str(pid)], capture_output=True)

    deadline = time.time() + timeout
    while time.time() < deadline:
        if not running_pids():
            _log("instance stopped")
            return True
        time.sleep(0.3)

    left = running_pids()
    _log("WARNING: instance(s) still alive after %ss: %s"
         % (timeout, ", ".join(str(p) for p in left)))
    return not left


def _port_listening(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def start_app(port=None, browser: bool = False, timeout: int = 60) -> bool:
    """Launch the freshly swapped EXE detached and wait until it serves."""
    if not LIVE_EXE.is_file():
        _log("ERROR: %s is missing; cannot start" % LIVE_EXE)
        return False

    args = [str(LIVE_EXE)]
    if port:
        args += ["--port", str(port)]
    if not browser:
        args.append("--no-browser")

    kwargs = {"cwd": str(DIST), "close_fds": True}
    if IS_WINDOWS:
        kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP

    before_mtime = PORT_FILE.stat().st_mtime if PORT_FILE.exists() else 0.0
    subprocess.Popen(args, **kwargs)
    _log("launched %s (port=%s, browser=%s)"
         % (EXE_NAME, port or "auto", "yes" if browser else "no"))

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if PORT_FILE.exists() and PORT_FILE.stat().st_mtime > before_mtime:
                url = PORT_FILE.read_text(encoding="utf-8", errors="replace").strip()
                if url:
                    _log("app ready at %s" % url)
                    return True
        except OSError:
            pass
        if port and _port_listening(port):
            _log("app listening on 127.0.0.1:%d" % port)
            return True
        time.sleep(0.5)

    if running_pids():
        _log("WARNING: process is up but did not report ready within %ss "
             "(check dist/app.log)" % timeout)
        return True
    _log("ERROR: app failed to start within %ss" % timeout)
    return False


# --------------------------------------------------------------------------- #
# build / verify / swap
# --------------------------------------------------------------------------- #
def build():
    """Build into STAGE_DIR.  Returns the staged EXE, or None on failure."""
    spec = ROOT / SPEC_NAME
    if not spec.is_file():
        _log("ERROR: %s not found in %s" % (SPEC_NAME, ROOT))
        return None

    staged = STAGE_DIR / EXE_NAME
    if staged.exists():
        try:
            staged.unlink()
        except OSError:
            pass  # overwritten by --noconfirm anyway

    cmd = [sys.executable, "-m", "PyI
