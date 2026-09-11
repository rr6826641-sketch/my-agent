"""Cross-platform OS desktop notification engine (ai_agent/core/notifier.py).

STEP 3 security layer: raises a native desktop notification whenever a
user successfully authenticates to the agent web UI.

Payload contract (exact)::

    🚨 [HACKERAI SECURITY ALERT] Agent session opened via {method} at {ts}

Backends (zero-dependency, no :mod:`plyer` required)::

  * Windows -> ``powershell.exe`` WScript.Shell popup (system toast style);
               degrades to a console line when no UI session is present.
  * macOS   -> ``osascript`` "display notification" (Notification Center).
  * Linux   -> ``notify-send`` (libnotify).

The API never raises: auth flows must never fail because a toast could not
be shown. While running under pytest (``PYTEST_CURRENT_TEST``) the login
helper short-circuits so test suites do not spam the operator's desktop.
"""

from __future__ import annotations

import datetime as _dt
import os as _os
import platform as _platform
import shutil as _shutil
import subprocess as _subprocess
import sys as _sys
import threading as _threading

__all__ = ["build_payload", "notify", "notify_login", "ALERT_PREFIX"]

ALERT_PREFIX = "🚨 [HACKERAI SECURITY ALERT]"
_TITLE = "HACKERAI Security Alert"

# Normalize common auth-method spellings to the contract labels.
_LABELS = {
    "password": "Password",
    "pin": "Password",
    "fingerprint": "Fingerprint",
    "biometric": "Fingerprint",
    "webauthn": "Fingerprint",
    "touch id": "Fingerprint",
    "windows hello": "Fingerprint",
}


def _label(method):
    key = str(method or "").strip().lower()
    return _LABELS.get(key, str(method).strip()) or "unknown"


def _now():
    return _dt.datetime.now().astimezone()


def build_payload(method, at=None):
    """Build the exact login-notification payload string.

    ``at`` accepts a tz-aware :class:`datetime.datetime` (default: now,
    local time).  Returns the exact string::

        🚨 [HACKERAI SECURITY ALERT] Agent session opened via {method} at {ts}
    """
    label = _label(method)
    ts = (at if at is not None else _now()).isoformat(timespec="seconds")
    return "{0} Agent session opened via {1} at {2}".format(ALERT_PREFIX, label, ts)


def _detect_backend():
    """Pick the best available native backend for this OS (or 'console')."""
    system = _platform.system().lower()
    if system.startswith("win"):
        return "powershell" if _shutil.which("powershell.exe") else "console"
    if system == "darwin":
        return "osascript" if _shutil.which("osascript") else "console"
    return "notify-send" if _shutil.which("notify-send") else "console"


def _run_backend(backend, title, body):
    """Invoke one native backend; returns True on success, never raises."""
    if backend == "notify-send":
        cmd = ["notify-send", "-a", "HACKERAI", "-u", "normal", title, body]
    elif backend == "osascript":
        safe = body.replace('"', "'")
        cmd = ["osascript", "-e",
               'display notification "{0}" with title "{1}"'.format(safe, title)]
    elif backend == "powershell":
        # WScript.Shell popup - native Windows toast-style dialog.
        safe = body.replace('"', '\\"')
        body_arg = '"{0}",8,"{1}",64'.format(safe, title)
        cmd = ["powershell.exe", "-NoProfile", "-Command",
               "$s=New-Object -ComObject WScript.Shell; $s.Popup(" + body_arg + ")"]
    else:
        return False
    try:
        _subprocess.run(cmd, timeout=4,
                        stdout=_subprocess.DEVNULL, stderr=_subprocess.DEVNULL)
    except Exception:
        return False
    return True


def _console_log(payload):
    line = "[HACKERAI notifier] " + payload
    try:
        _sys.stderr.write(line + "\n")
    except UnicodeEncodeError:
        _sys.stderr.write(line.encode("ascii", "replace").decode("ascii") + "\n")


def notify(method, at=None, dry_run=False):
    """Send the login notification for ``method``.

    Returns ``True`` when a backend accepted the payload, ``False`` when
    the environment cannot show desktop notifications (headless/CI/SSH).
    Never raises.  ``dry_run=True`` only builds the payload.
    """
    payload = build_payload(method, at=at)
    if dry_run:
        return True
    backend = _detect_backend()
    if backend == "console":
        _console_log(payload)
        return False
    return _run_backend(backend, _TITLE, payload)


def _in_test():
    return bool(_os.getenv("PYTEST_CURRENT_TEST"))


def notify_login(method, at=None, async_ok=True):
    """Fire-and-forget login notification (auth success-path helper).

    Short-circuits (no-op) under pytest so suites never pop OS dialogs,
    and never blocks the HTTP response: the OS call runs on a daemon
    thread.  Never raises.
    """
    if _in_test():
        return True
    if async_ok:
        _threading.Thread(target=_safe_notify, args=(method, at), daemon=True).start()
        return True
    return notify(method, at=at)


def _safe_notify(method, at):
    try:
        notify(method, at=at)
    except Exception:
        pass