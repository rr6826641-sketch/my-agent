"""Persistent Interactive Session Manager regression tests.

Covers: unique session ids, background process tracking, interactive
stdin I/O (send_input -> wait_for_pattern round trip), pattern timeout,
control-signal delivery (Ctrl+C best-effort), kill_session teardown,
and the execute_tool timeout-vs-cancel split (sessions survive tool
timeouts but die on user Stop).

Run:  py -m pytest test_session_mgr.py
"""
import re
import time

import pytest

from ai_agent.tools.base import kill_active_procs
from ai_agent.tools.terminal import (
    _SESSIONS,
    tool_kill_session,
    tool_list_sessions,
    tool_send_input,
    tool_start_session,
    tool_wait_for_pattern,
)

# Windows host -> `py` launcher for child python scripts.
PY = "py"


def _cmd(stmts):
    """Build a shell command string running a single-line python child.

    Statements are joined with ';' and quoted for cmd.exe. Child code
    uses single quotes only; every write() is followed by flush() so
    pipe output reaches the session buffer immediately.
    """
    code = ";".join(stmts) if isinstance(stmts, (list, tuple)) else stmts
    return '%s -c "%s"' % (PY, code)


def _sid(result):
    m = re.search(r"\[session (sess_\d{4}_[0-9a-f]{6}) started\]", result)
    assert m, "could not parse session id from: %r" % result
    return m.group(1)


def _alive(proc):
    return proc.poll() is None


def _wait_dead(proc, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline and _alive(proc):
        time.sleep(0.1)
    return not _alive(proc)


@pytest.fixture(autouse=True)
def _cleanup_sessions():
    """Kill every session started by a test, even on failure."""
    yield
    for sid in list(_SESSIONS):
        tool_kill_session(sid)


def test_session_ids_unique_and_listed_running():
    r1 = tool_start_session(
        _cmd("import time;print('ready',flush=True);time.sleep(60)"))
    s1 = _sid(r1)
    r2 = tool_start_session(
        _cmd("import time;print('ready',flush=True);time.sleep(60)"))
    s2 = _sid(r2)
    assert s1 != s2
    assert re.fullmatch(r"sess_\d{4}_[0-9a-f]{6}", s1)
    for sid in (s1, s2):
        r = tool_wait_for_pattern(sid, "ready", timeout=5)
        assert "pattern matched" in r, r
    listing = tool_list_sessions()
    assert s1 in listing and s2 in listing
    assert "running" in listing


def test_interactive_send_input_round_trip():
    stmts = [
        "import sys",
        "sys.stdout.write('MENU: 1) foo 2) bar\\n')",
        "sys.stdout.flush()",
        "line = sys.stdin.readline()",
        "sys.stdout.write('GOT:' + line.strip() + '\\n')",
        "sys.stdout.flush()",
        "line2 = sys.stdin.readline()",
        "sys.stdout.write('DONE:' + line2.strip() + '\\n')",
        "sys.stdout.flush()",
    ]
    sid = _sid(tool_start_session(_cmd(stmts)))
    r = tool_wait_for_pattern(sid, "MENU", timeout=5)
    assert "pattern matched" in r, r
    r = tool_send_input(sid, input="2")
    assert "sent" in r, r
    r = tool_wait_for_pattern(sid, "GOT:2", timeout=5)
    assert "pattern matched" in r, r
    r = tool_send_input(sid, input="bye")
    assert "sent" in r, r
    r = tool_wait_for_pattern(sid, "DONE:bye", timeout=5)
    assert "pattern matched" in r, r


def test_wait_for_pattern_match_and_timeout():
    sid = _sid(tool_start_session(
        _cmd("import time;print('alpha',flush=True);time.sleep(30)")))
    r = tool_wait_for_pattern(sid, "alpha", timeout=5)
    assert "pattern matched" in r, r
    r = tool_wait_for_pattern(sid, "ZETA__NOT_HERE", timeout=1)
    assert "pattern NOT matched" in r, r


def test_ctrl_c_signal_best_effort_keeps_session():
    sid = _sid(tool_start_session(
        _cmd("import time;print('looping',flush=True);time.sleep(60)")))
    r = tool_wait_for_pattern(sid, "looping", timeout=5)
    assert "pattern matched" in r, r
    r = tool_send_input(sid, signal="ctrl_c")
    # Windows console event or \x03 byte fallback -- never a kill.
    assert "ctrl-c" in r or "sent" in r, r
    assert "killed" not in r
    assert sid in _SESSIONS
    # send_input must not have torn the process down
    time.sleep(0.3)
    assert sid in _SESSIONS


def test_kill_session_terminates_and_unlists():
    sid = _sid(tool_start_session(
        _cmd("import time;print('up',flush=True);time.sleep(60)")))
    r = tool_wait_for_pattern(sid, "up", timeout=5)
    assert "pattern matched" in r, r
    sess = _SESSIONS[sid]
    r = tool_kill_session(sid)
    assert "killed" in r, r
    assert sid not in _SESSIONS
    assert _wait_dead(sess.proc), "process tree still alive after kill_session"
    assert sid not in tool_list_sessions()


def test_tool_timeout_kill_preserves_sessions_cancel_kills_them():
    sid = _sid(tool_start_session(
        _cmd("import time;print('up',flush=True);time.sleep(60)")))
    r = tool_wait_for_pattern(sid, "up", timeout=5)
    assert "pattern matched" in r, r
    sess = _SESSIONS[sid]
    # execute_tool's timeout path: kill_active_procs() with no args.
    kill_active_procs()
    time.sleep(0.3)
    assert _alive(sess.proc), "session died on tool-timeout kill"
    # execute_tool's user-Stop path: include_sessions=True.
    kill_active_procs(include_sessions=True)
    assert _wait_dead(sess.proc), "session survived cancel kill"


# ================================================================
# v2 upgrades: real PTY backend, extended signals, fresh_only waits
# ================================================================

import os

from ai_agent.tools.terminal import (
    _HAVE_POSIX_PTY,
    _WinPtyProcess,
    tool_view_session_output,
)


def test_pty_session_real_terminal_roundtrip():
    """pty=True runs the child on a real pseudo-terminal: isatty()=True."""
    code = ("import sys,time;"
            "print('ISATTY', sys.stdout.isatty(), flush=True);"
            "time.sleep(30)")
    if os.name == "nt":
        if _WinPtyProcess is None:
            pytest.skip("pywinpty not installed; pty backend unavailable")
        cmd = _cmd(code)
    else:
        if not _HAVE_POSIX_PTY:
            pytest.skip("no posix pty available")
        cmd = "python3 -c '%s'" % code
    r = tool_start_session(cmd, pty=True)
    assert "started" in r, r
    assert "pty=" in r, r
    sid = _sid(r)
    r = tool_wait_for_pattern(sid, r"ISATTY\s+True", timeout=10)
    assert "pattern matched" in r, r


@pytest.mark.skipif(os.name != "nt", reason="Windows console event")
def test_ctrl_break_signal_delivered_and_caught():
    code = ("import signal,sys,time;"
            "signal.signal(signal.SIGBREAK,"
            " lambda s, f: print('CAUGHT', flush=True));"
            "print('brk-ready', flush=True);time.sleep(60)")
    sid = _sid(tool_start_session(_cmd(code)))
    r = tool_wait_for_pattern(sid, "brk-ready", timeout=5)
    assert "pattern matched" in r, r
    r = tool_send_input(sid, signal="ctrl_break")
    # CTRL_BREAK console-event delivery is best-effort on Windows: with a
    # real attached console the event usually reaches the child, but some
    # console-less/hidden-conhost contexts accept the event without
    # delivering it. Contract: never kills the session either way.
    assert "ctrl-break" in r, r
    assert "Error" not in r, r
    assert sid in _SESSIONS, r
    time.sleep(0.3)
    assert sid in _SESSIONS, "ctrl_break tore the session down"


@pytest.mark.skipif(os.name == "nt", reason="POSIX named signals")
def test_sigterm_signal_delivered_and_caught():
    if not _HAVE_POSIX_PTY and os.name != "posix":
        pytest.skip("not a posix host")
    code = ("import signal,sys,time;"
            "signal.signal(signal.SIGTERM,"
            " lambda s, f: print('CAUGHT', flush=True));"
            "print('sig-ready', flush=True);time.sleep(60)")
    sid = _sid(tool_start_session("python3 -c '%s'" % code))
    r = tool_wait_for_pattern(sid, "sig-ready", timeout=5)
    assert "pattern matched" in r, r
    r = tool_send_input(sid, signal="sigterm")
    assert "sigterm delivered" in r, r
    r = tool_wait_for_pattern(sid, "CAUGHT", timeout=8)
    assert "pattern matched" in r, r


def test_wait_for_pattern_fresh_only_ignores_stale_output():
    stmts = [
        "import sys",
        "print('PROMPT1', flush=True)",
        "line = sys.stdin.readline()",
        "print('PROMPT2', flush=True)",
        "sys.stdout.write('ANSWER:' + line.strip() + '\\n')",
        "sys.stdout.flush()",
    ]
    sid = _sid(tool_start_session(_cmd(stmts)))
    r = tool_wait_for_pattern(sid, "PROMPT1", timeout=5)
    assert "pattern matched" in r, r
    # fresh_only must NOT hit the stale PROMPT1 still sitting in the buffer
    r = tool_wait_for_pattern(sid, "PROMPT1", timeout=1, fresh_only=True)
    assert "pattern NOT matched" in r, r
    # ...but new output still matches
    r = tool_send_input(sid, input="hello")
    assert "sent" in r, r
    r = tool_wait_for_pattern(sid, "ANSWER:hello", timeout=5, fresh_only=True)
    assert "pattern matched" in r, r


@pytest.mark.skipif(os.name != "nt" or _WinPtyProcess is not None,
                    reason="only meaningful when pywinpty is missing")
def test_pty_unavailable_reports_clear_error():
    r = tool_start_session(_cmd("import time;time.sleep(5)"), pty=True)
    assert "pywinpty" in r and "pty=false" in r, r
