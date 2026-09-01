"""Persistent interactive PTY terminal process manager.

A dedicated PTY session engine on top of terminal.py's real
pseudo-terminal infrastructure (ConPTY on Windows, posix-pty via
pty.openpty elsewhere). Sessions survive across tool calls, so the
agent can drive fully interactive programs (TUIs, REPLs, ssh, top,
python REPLs, listeners) across many turns.

Exposed tools:
  pty_start_session(command)            -> unique session id
  pty_send_input(session_id, input)     -> raw stdin (incl. '\x03' Ctrl+C)
  pty_read_output(session_id, timeout)  -> non-blocking accumulated output
  pty_kill_session(session_id)          -> teardown + handle cleanup
  pty_status()                          -> PTY session ledger dump

State ledger: every PTY session is tracked in a thread-safe ledger
(session id -> pid, command, status, timestamps, output byte counts)
with a capped finished-history, isolated from the plain (non-PTY)
session engine in terminal.py.
"""

import re
import threading
import time

from . import terminal as _term
from .terminal import (
    _InteractiveSession,
    _VIEW_TAIL,
    _start_pty_session,
    tool_kill_session,
    tool_send_input,
)

# ================================================================
# PTY session ledger (thread-safe, isolated from terminal.py's ledger)
# ================================================================

_PTY_LEDGER = {}                     # session_id -> ledger dict
_PTY_LEDGER_LOCK = threading.RLock()
_PTY_HISTORY = []                    # finished/killed records (capped)
_PTY_HISTORY_MAX = 50


def _ledger_entry(sess, status):
    return {
        "session_id": sess.session_id,
        "pid": sess.pid,
        "command": sess.command,
        "cwd": sess.cwd,
        "status": status,
        "created_at": sess.created_at,
        "ended_at": None,
        "exit_code": None,
        "output_bytes": sess.out.raw_size() + sess.err.raw_size(),
    }


def _pty_register(sess):
    with _PTY_LEDGER_LOCK:
        _PTY_LEDGER[sess.session_id] = _ledger_entry(sess, "running")


def _pty_refresh(sess):
    """Sync one session's live state into the ledger; return its status."""
    with _PTY_LEDGER_LOCK:
        entry = _PTY_LEDGER.get(sess.session_id)
        if entry is None:
            entry = _ledger_entry(sess, "running")
            _PTY_LEDGER[sess.session_id] = entry
        if sess.exited:
            entry["status"] = ("exited(%s)" % sess.exit_code
                               if sess.exit_code is not None else "exited")
            entry["ended_at"] = sess.ended_at or time.time()
            entry["exit_code"] = sess.exit_code
        entry["output_bytes"] = sess.out.raw_size() + sess.err.raw_size()
        return entry["status"]


def _pty_remove(sess, status):
    with _PTY_LEDGER_LOCK:
        entry = _PTY_LEDGER.pop(sess.session_id, None) or \
            _ledger_entry(sess, status)
        entry["status"] = status
        entry["ended_at"] = sess.ended_at or time.time()
        entry["exit_code"] = sess.exit_code
        entry["output_bytes"] = sess.out.raw_size() + sess.err.raw_size()
        _PTY_HISTORY.append(entry)
        del _PTY_HISTORY[:-_PTY_HISTORY_MAX]
    return entry


def _get_pty_session(session_id):
    """Fetch a session and verify it was started through the PTY engine."""
    sess = _term._get_session(session_id)
    if not isinstance(sess, _InteractiveSession):
        return sess
    if not getattr(sess, "is_pty", False):
        return ("Error: session %s was not started on a PTY (use "
                "pty_start_session, or send_input/view_session_output for "
                "plain sessions)" % sess.session_id)
    return sess


# ================================================================
# Tools
# ================================================================

def pty_start_session(command, cwd=None, name=None, env=None, shell=True):
    """Start a long-running process on a real PTY (ConPTY/pty)."""
    result = _start_pty_session(command, cwd=cwd or None, name=name or None,
                                env=env or None, shell=bool(shell))
    # The engine returns a descriptive string on error and a
    # "[session <sid> started] ..." block on success.
    if not result or result.startswith("start_session error"):
        return result
    m = re.search(r"\[session\s+(\S+)\s+started\]", str(result))
    if not m:
        return result
    sid = m.group(1)
    sess = _term._SESSIONS.get(sid)
    if sess is not None:
        sess.is_pty = True
        _pty_register(sess)
        return "[pty session %s started (pid %s)] %s" % (sid, sess.pid,
                                                         command)
    return result


def pty_send_input(session_id, input_data, press_enter=False):
    """Send raw text or control bytes (e.g. Ctrl+C) to a PTY session.

    Input is written literally with press_enter=False by default, so
    control characters pass through untouched. Named signals (ctrl_c,
    enter, esc, ...) are also accepted via the syntax '!signal:ctrl_c'.
    """
    sess = _get_pty_session(session_id)
    if not isinstance(sess, _InteractiveSession):
        return sess
    data = "" if input_data is None else str(input_data)
    if data.startswith("!signal:"):
        return tool_send_input(session_id, signal=data[len("!signal:"):],
                               press_enter=bool(press_enter))
    if data == "":
        return "Error: empty input (use '!signal:ctrl_c' for Ctrl+C)"
    return tool_send_input(session_id, input=data,
                           press_enter=bool(press_enter))


def pty_read_output(session_id, timeout=2.0, tail=_VIEW_TAIL, clear=False,
                    include_stderr=True):
    """Stream accumulated stdout/stderr of a PTY without blocking forever.

    Waits up to `timeout` seconds for NEW output to arrive (returns as
    soon as any appears), then returns the buffer tail. The process is
    never terminated by reads.
    """
    sess = _get_pty_session(session_id)
    if not isinstance(sess, _InteractiveSession):
        return sess
    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        timeout = 2.0
    timeout = max(0.0, min(timeout, 100.0))
    try:
        tail = max(200, int(tail or _VIEW_TAIL))
    except (TypeError, ValueError):
        tail = _VIEW_TAIL

    base_out = sess.out.text(tail=None)
    base_err = sess.err.text(tail=None)
    deadline = time.time() + timeout
    while True:
        if (sess.out.raw_size() > len(base_out)
                or sess.err.raw_size() > len(base_err)):
            break
        if sess.exited or time.time() >= deadline:
            break
        time.sleep(0.1)

    status = _pty_refresh(sess)
    out = sess.out.text(tail=tail)
    if include_stderr:
        err = sess.err.text(tail=tail)
        if err.strip():
            out += "\n[stderr]\n" + err
    if clear:
        sess.out.clear()
        sess.err.clear()
    text = (out or "(no new output within %.1fs)" % timeout).strip()
    return "[%s] pty session %s\n%s" % (status, session_id, text)


def pty_kill_session(session_id):
    """Terminate a PTY session's process tree and clean up its handles."""
    sess = _get_pty_session(session_id)
    if not isinstance(sess, _InteractiveSession):
        return sess
    result = tool_kill_session(session_id)
    if result.startswith("Error"):
        return result
    _pty_remove(sess, "killed" if "killed" in result else "exited")
    return result.replace("session", "pty session", 1)


def pty_status(active_only=False):
    """Dump the PTY ledger: id, pid, status, uptime, output sizes."""
    with _PTY_LEDGER_LOCK:
        with _term._SESSIONS_LOCK:
            live = {sid: s for sid, s in _term._SESSIONS.items()
                    if getattr(s, "is_pty", False)}
            for sid, sess in live.items():
                if sid not in _PTY_LEDGER:
                    _PTY_LEDGER[sid] = _ledger_entry(sess, "running")
                _pty_refresh(sess)
        rows = []
        for sid, entry in _PTY_LEDGER.items():
            if active_only and entry["status"] != "running":
                continue
            age = int(time.time() - entry["created_at"])
            rows.append("%s pid=%s %s age=%ss out=%dB  %s"
                        % (sid, entry["pid"], entry["status"], age,
                           entry["output_bytes"], entry["command"]))
        history = list(_PTY_HISTORY)
    rows.sort()
    if not rows and not history:
        return "(no pty sessions recorded)"
    note = ""
    if history:
        last = history[-1]
        note = ("\n[last finished: %s pid=%s %s exit=%s]"
                % (last["session_id"], last["pid"], last["status"],
                   last["exit_code"]))
    return "\n".join(rows) + note
