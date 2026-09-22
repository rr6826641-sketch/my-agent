#!/usr/bin/env python3
r"""rebuild_agent.py -- lock-free rebuild + hot-swap + restart for MyAgentUltra.

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
                serving real traffic the whole time.
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


def start_app(port: int | None = None, browser: bool = False,
              timeout: int = 60) -> bool:
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
def build() -> Path | None:
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

    cmd = [sys.executable, "-m", "PyInstaller",
           "--clean", "--noconfirm",
           "--distpath", str(STAGE_DIR),
           "--workpath", str(WORK_DIR),
           "--log-level", "INFO",
           SPEC_NAME]
    _log("build: %s" % " ".join(cmd))
    _log("build: staging to %s (the running EXE is NOT touched)"
         % STAGE_DIR.relative_to(ROOT))

    t0 = time.time()
    with open(LOG_PATH, "a", encoding="utf-8", errors="replace") as fh:
        fh.write("\n===== PyInstaller %s =====\n" % _ts())
        cp = subprocess.run(cmd, cwd=str(ROOT), stdout=fh,
                            stderr=subprocess.STDOUT)
    elapsed = time.time() - t0
    _log("PyInstaller exit=%s in %.1fs (full output: %s)"
         % (cp.returncode, elapsed, LOG_NAME))

    if cp.returncode != 0:
        _log("ERROR: build failed - nothing was swapped, running app untouched")
        return None
    return staged


def verify(path: Path) -> bool:
    """A staged EXE is only promoted if it is a plausible, complete PE image."""
    if not path or not path.is_file():
        _log("ERROR: staged binary missing: %s" % path)
        return False
    size = path.stat().st_size
    with open(path, "rb") as fh:
        magic = fh.read(2)
    ok = magic == b"MZ" and size >= MIN_EXE_BYTES
    _log("verify: %s = %s bytes, magic=%r -> %s"
         % (path.name, _human(size), magic.decode("latin-1"), "OK" if ok else "FAIL"))
    if not ok:
        _log("ERROR: staged binary looks invalid (expected MZ + >=%s bytes)"
             % _human(MIN_EXE_BYTES))
    return ok


def swap(staged: Path) -> Path | None:
    """Rename the live EXE aside, then move the staged EXE into place."""
    DIST.mkdir(parents=True, exist_ok=True)
    backup = None

    if LIVE_EXE.exists():
        backup = LIVE_EXE.with_name("%s.old.%s" % (EXE_NAME, _ts()))
        try:
            os.replace(str(LIVE_EXE), str(backup))
            _log("backed up live EXE -> %s (rename works while running)"
                 % backup.name)
        except OSError as exc:
            _log("rename of live EXE failed (%s); stopping app and retrying" % exc)
            stop_app()
            os.replace(str(LIVE_EXE), str(backup))
            _log("backed up live EXE -> %s (after stop)" % backup.name)

    shutil.move(str(staged), str(LIVE_EXE))
    _log("swapped in new EXE: %s (%s bytes)"
         % (LIVE_EXE, _human(LIVE_EXE.stat().st_size)))
    return backup


# --------------------------------------------------------------------------- #
# backup housekeeping
# --------------------------------------------------------------------------- #
def _backups() -> list:
    if not DIST.is_dir():
        return []
    return sorted(DIST.glob(BACKUP_GLOB),
                  key=lambda p: p.stat().st_mtime, reverse=True)


def prune_backups(keep: int = 3) -> None:
    backups = _backups()
    removed = 0
    for old in backups[keep:]:
        try:
            old.unlink()
            removed += 1
        except OSError:
            pass  # still locked by a live process; next run collects it
    if removed:
        _log("pruned %d old backup(s); kept %d"
             % (removed, min(keep, len(backups))))


def rollback() -> bool:
    backups = _backups()
    if not backups:
        _log("ERROR: no rollback backup (%s) found in %s" % (BACKUP_GLOB, DIST))
        return False

    src = backups[0]
    _log("rolling back to %s (%s bytes)" % (src.name, _human(src.stat().st_size)))
    stop_app()
    if LIVE_EXE.exists():
        try:
            LIVE_EXE.unlink()
        except OSError as exc:
            _log("ERROR: cannot remove current EXE: %s" % exc)
            return False
    shutil.move(str(src), str(LIVE_EXE))
    _log("restored %s" % LIVE_EXE)
    return True


def status() -> None:
    pids = running_pids()
    _log("running PIDs: %s" % (", ".join(str(p) for p in pids) or "none"))
    if LIVE_EXE.is_file():
        _log("live EXE   : %s (%s bytes, mtime %s)"
             % (LIVE_EXE, _human(LIVE_EXE.stat().st_size),
                time.strftime("%Y-%m-%d %H:%M:%S",
                              time.localtime(LIVE_EXE.stat().st_mtime))))
    else:
        _log("live EXE   : missing")
    backups = _backups()
    if not backups:
        _log("backups    : none")
    for b in backups:
        _log("backup     : %s (%s bytes)" % (b.name, _human(b.stat().st_size)))


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Lock-free rebuild + hot-swap + restart for %s" % APP,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-only", action="store_true",
                    help="build into the staging dir only (never touch dist/)")
    ap.add_argument("--no-restart", action="store_true",
                    help="swap in the new EXE but do not relaunch it")
    ap.add_argument("--rollback", action="store_true",
                    help="restore the newest backup EXE (then restart)")
    ap.add_argument("--status", action="store_true",
                    help="show running PIDs and backups, change nothing")
    ap.add_argument("--keep-old", type=int, default=3, metavar="N",
                    help="rollback copies to keep (default 3)")
    ap.add_argument("--port", type=int, default=8080,
                    help="port for the relaunched app (default 8080)")
    ap.add_argument("--browser", action="store_true",
                    help="open the browser after restart")
    args = ap.parse_args(argv)

    _log("=== %s rebuild tool @ %s ===" % (APP, _ts()))

    if args.status:
        status()
        return 0

    if args.rollback:
        if not rollback():
            return 1
        if not args.no_restart:
            start_app(args.port, args.browser)
        prune_backups(args.keep_old)
        _log("done (rollback)")
        return 0

    staged = build()
    if staged is None:
        return 1
    if not verify(staged):
        _log("staged binary failed validation; dist/ left untouched")
        return 1

    if args.build_only:
        _log("build-only: staged binary ready at %s" % staged)
        return 0

    swap(staged)

    if args.no_restart:
        stop_app()
        _log("restart skipped (--no-restart)")
    else:
        stop_app()
        start_app(args.port, args.browser)

    prune_backups(args.keep_old)
    _log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
