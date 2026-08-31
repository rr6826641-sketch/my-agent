"""Terminal & local file tools."""

import itertools
import json
import locale
import os
import re
import secrets
import signal as _signal
import subprocess
import threading
import time

from .base import kill_proc_tree, register_proc, unregister_proc

# Real ConPTY backend (optional): gives children a genuine Windows console
# (isatty()=True, colors, interactive menus, arrow-key apps). Falls back to
# anonymous pipes when pywinpty is not installed.
try:
    from winpty import PtyProcess as _WinPtyProcess
except Exception:
    _WinPtyProcess = None

_HAVE_POSIX_PTY = hasattr(os, "openpty") and hasattr(os, "setsid")


def _oem_codepage():
    """OEM code page (what cmd.exe writes to pipes), e.g. 437/850/936."""
    try:
        import ctypes
        cp = ctypes.windll.kernel32.GetOEMCP()
        if cp and cp != 65001:
            return "cp%d" % cp
    except Exception:
        pass
    return None


def _ansi_codepage():
    """ANSI code page (locale), e.g. 1252."""
    try:
        import ctypes
        cp = ctypes.windll.kernel32.GetACP()
        if cp and cp != 65001:
            return "cp%d" % cp
    except Exception:
        pass
    return None


def _decode_output(data):
    """Decode raw command bytes: UTF-8 first (PowerShell, chcp 65001,
    UTF-8-emitting tools), then the OEM code page (cmd.exe's default),
    then ANSI. subprocess text=True on Windows only knows the locale
    (cp1252) page, which turns UTF-8 '•'/'—'/'→' into 'â€¢'/'â€“'/'â†’'
    mojibake and OEM box-drawing chars into 'ÄÄÄ' garbage."""
    if not data:
        return ""
    candidates = ["utf-8", _oem_codepage(), _ansi_codepage(),
                  locale.getpreferredencoding(False), "cp437", "cp850", "cp1252"]
    seen = set()
    for enc in candidates:
        if not enc or enc in seen:
            continue
        seen.add(enc)
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("cp1252", errors="replace")


def _decode_stream_bytes(data, flush=False):
    """Decode accumulated stream bytes without mangling a multi-byte UTF-8
    character split across read() boundaries. When not flushing, up to 3
    trailing bytes are held back until the next chunk arrives. Falls back
    to the lossy _decode_output for mixed-encoding streams."""
    if not data:
        return "", b""
    try:
        return data.decode("utf-8"), b""
    except UnicodeDecodeError:
        pass
    if not flush:
        for keep in (3, 2, 1):
            if len(data) <= keep:
                continue
            try:
                return data[:-keep].decode("utf-8"), data[-keep:]
            except UnicodeDecodeError:
                continue
    return _decode_output(data), b""


# ================================================================
# Persistent interactive session engine
# ================================================================
#
# start_session spawns a long-running background process with a unique
# string session_id. Reader threads continuously drain stdout/stderr
# into capped byte buffers; a monitor thread records the exit. The
# session lives in the in-memory ledger (and its lifecycle is mirrored
# to a JSON file under ~/.hackerai/session_ledger.json) so the agent can
# drive interactive tools across multiple tool calls: send_input types
# into stdin (including control signals like Ctrl+C via a console event
# on Windows, or the \x03 byte), view_session_output reads the stream,
# wait_for_pattern blocks until a regex matches, and kill_session tears
# the process tree down.

_MAX_SESSION_BUFFER = 512 * 1024    # per stream (stdout / stderr)
_VIEW_TAIL = 4000                   # default chars returned by views
_MAX_WAIT_TIMEOUT = 100             # cap, below execute_tool's 120s ceiling
_LEDGER_MAX_ENTRIES = 50
_LEDGER_DIRNAME = ".hackerai"
_LEDGER_FILENAME = "session_ledger.json"

_SESSIONS = {}                      # session_id -> _InteractiveSession
_SESSIONS_LOCK = threading.RLock()
_SESSION_COUNTER = itertools.count(1)
_LEDGER_HISTORY = []                # finished/killed records (capped)

_CTRL_BYTES = {
    "ctrl_c": b"\x03",
    "ctrl_d": b"\x04",
    "ctrl_z": b"\x1a",
    "esc": b"\x1b",
    "enter": b"\r",
}

# Real OS signals deliverable by name via proc.send_signal() (POSIX only;
# on Windows use ctrl_c / ctrl_break console events instead).
_POSIX_SIGNALS = {}
for _sig_name in ("SIGINT", "SIGTERM", "SIGKILL", "SIGHUP", "SIGQUIT",
                  "SIGUSR1", "SIGUSR2"):
    if hasattr(_signal, _sig_name):
        _POSIX_SIGNALS[_sig_name.lower()] = getattr(_signal, _sig_name)


def _ledger_path():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, _LEDGER_DIRNAME, _LEDGER_FILENAME)


def _load_ledger_history():
    try:
        with open(_ledger_path(), "r", encoding="utf-8") as f:
            recs = json.load(f)
        if not isinstance(recs, list):
            return []
        for rec in recs:
            if rec.get("status") == "running":
                # the agent process restarted; the session may still exist
                # on the OS but we can no longer drive it.
                rec["status"] = "stale"
        return recs[-_LEDGER_MAX_ENTRIES:]
    except Exception:
        return []


def _persist_ledger():
    """Mirror the in-memory ledger (active sessions + history) to disk."""
    try:
        recs = []
        with _SESSIONS_LOCK:
            for sid in sorted(_SESSIONS):
                s = _SESSIONS[sid]
                recs.append({
                    "session_id": sid,
                    "command": s.command,
                    "cwd": s.cwd,
                    "pid": s.proc.pid,
                    "started_at": s.created_at,
                    "ended_at": s.ended_at,
                    "exit_code": s.exit_code,
                    "status": "running" if not s.exited else "exited",
                    "output_bytes": s.out.raw_size() + s.err.raw_size(),
                })
            recs.extend(_LEDGER_HISTORY)
            recs = recs[-_LEDGER_MAX_ENTRIES:]
        path = _ledger_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(recs, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        pass


def _new_session_id():
    return "sess_%04d_%s" % (next(_SESSION_COUNTER), secrets.token_hex(3))


class _ByteBuffer:
    """Thread-safe raw-byte accumulator with lossless tail handling.

    Text extraction holds back up to 3 trailing bytes until the stream
    ends (eof) so a UTF-8 character split across reads decodes cleanly.
    """

    def __init__(self, max_bytes=_MAX_SESSION_BUFFER):
        self._chunks = []
        self._size = 0
        self._max = max_bytes
        self._pend = b""
        self._dropped = False
        self._eof = False
        self._lock = threading.Lock()

    def append(self, data):
        if not data:
            return
        with self._lock:
            self._chunks.append(data)
            self._size += len(data)
            while self._size > self._max and self._chunks:
                if len(self._chunks) > 1:
                    self._size -= len(self._chunks.pop(0))
                else:
                    self._chunks[0] = self._chunks[0][-(self._max // 2):]
                    self._size = len(self._chunks[0])
                self._dropped = True

    def eof(self):
        with self._lock:
            self._eof = True

    def clear(self):
        with self._lock:
            self._chunks = []
            self._size = 0
            self._pend = b""
            self._dropped = False

    def raw_size(self):
        with self._lock:
            return self._size + len(self._pend)

    def text(self, tail=None):
        with self._lock:
            data = self._pend + b"".join(self._chunks)
            self._pend = b""
            dropped = self._dropped
            if tail and len(data) > tail:
                data = data[-tail:]
                dropped = True
            if self._eof:
                text, rest = _decode_stream_bytes(data, flush=True)
                self._pend = b""
            else:
                text, rest = _decode_stream_bytes(data, flush=False)
                self._pend = rest
            if dropped:
                return "[earlier output truncated] " + text
            return text


class _InteractiveSession:
    """One long-running interactive background process + its streams."""

    def __init__(self, session_id, command, cwd, name, proc, shell):
        self.session_id = session_id
        self.command = command
        self.cwd = cwd or os.getcwd()
        self.name = name
        self.shell = shell
        self.proc = proc
        self.created_at = time.time()
        self.exited = False
        self.exit_code = None
        self.ended_at = None
        self.out = _ByteBuffer()
        self.err = _ByteBuffer()
        self._stdin_lock = threading.Lock()

    @property
    def pid(self):
        return self.proc.pid

    def kill(self):
        kill_proc_tree(self.proc)

    def start_threads(self):
        threading.Thread(target=_pump_stream,
                         args=(self.proc.stdout, self.out),
                         daemon=True, name="sess-out-%s" % self.session_id).start()
        threading.Thread(target=_pump_stream,
                         args=(self.proc.stderr, self.err),
                         daemon=True, name="sess-err-%s" % self.session_id).start()
        threading.Thread(target=_monitor_proc, args=(self,),
                         daemon=True, name="sess-mon-%s" % self.session_id).start()

    def write_stdin(self, raw):
        with self._stdin_lock:
            self.proc.stdin.write(raw)
            self.proc.stdin.flush()

    def describe(self):
        status = "running" if not self.exited else "exited(%s)" % self.exit_code
        age = int(time.time() - self.created_at)
        return ("%s pid=%s %s age=%ss out=%dB err=%dB  %s"
                % (self.session_id, self.pid, status, age,
                   self.out.raw_size(), self.err.raw_size(), self.command))


def _pump_stream(stream, buffer):
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            buffer.append(chunk)
    except Exception:
        pass
    buffer.eof()


def _monitor_proc(session):
    try:
        rc = session.proc.wait()
    except Exception:
        rc = None
    session.exited = True
    session.exit_code = rc
    session.ended_at = time.time()
    unregister_proc(session.proc)
    _record_finished(session, "exited")
    _persist_ledger()


def _record_finished(session, status):
    with _SESSIONS_LOCK:
        if getattr(session, "_finished_recorded", False):
            return
        session._finished_recorded = True
        _LEDGER_HISTORY.append({
            "session_id": session.session_id,
            "command": session.command,
            "cwd": session.cwd,
            "pid": session.proc.pid,
            "started_at": session.created_at,
            "ended_at": session.ended_at or time.time(),
            "exit_code": session.exit_code,
            "status": status,
            "output_bytes": session.out.raw_size() + session.err.raw_size(),
        })
        del _LEDGER_HISTORY[:-_LEDGER_MAX_ENTRIES]


def _get_session(session_id):
    sid = str(session_id or "").strip()
    if not sid:
        return "Error: missing session_id"
    sess = _SESSIONS.get(sid)
    if sess is None:
        return "Error: no such session: %s (use list_sessions)" % sid
    return sess


# ---------------------------------------------------------------- pty engine

class _PtyProcShim:
    """subprocess.Popen stand-in for ConPTY sessions (no Popen exists).

    Exposes only what the session engine needs: pid, poll(), wait(),
    kill(), terminate(). All no-ops delegate to the winpty handle.
    """

    def __init__(self, pty_obj):
        self._pty = pty_obj
        self.pid = pty_obj.pid
        self.returncode = None

    def _sync(self):
        if self.returncode is None and not self._pty.isalive():
            try:
                self.returncode = self._pty.exitstatus or 0
            except Exception:
                self.returncode = 0
        return self.returncode

    def poll(self):
        return self._sync()

    def isalive(self):
        return self._sync() is None

    def wait(self):
        while self._sync() is None:
            time.sleep(0.1)
        return self.returncode

    def terminate(self):
        try:
            self._pty.terminate(force=True)
        except Exception:
            pass
        self.returncode = self._sync() or 0

    kill = terminate


class _PtySession(_InteractiveSession):
    """Interactive session on a REAL pseudo-terminal.

    stdout+stderr are merged by the tty into one stream (`out`); `err`
    stays an empty buffer for interface compatibility. Children see a
    genuine terminal (isatty()=True), so REPLs, pagers, colored output,
    and full-screen/menu apps behave exactly like in a real console.
    """

    def __init__(self, session_id, command, cwd, name, proc, pty_obj,
                 master_fd, backend):
        super().__init__(session_id, command, cwd, name, proc,
                         shell=True)
        self.pty_obj = pty_obj
        self.master_fd = master_fd
        self.backend = backend          # "conpty" | "posix-pty"

    def start_threads(self):
        if self.master_fd is not None:
            threading.Thread(target=_pump_pty_fd, args=(self,),
                             daemon=True,
                             name="sess-pty-%s" % self.session_id).start()
        else:
            threading.Thread(target=_pump_winpty, args=(self,),
                             daemon=True,
                             name="sess-pty-%s" % self.session_id).start()
        threading.Thread(target=_monitor_proc, args=(self,),
                         daemon=True,
                         name="sess-mon-%s" % self.session_id).start()

    def write_stdin(self, raw):
        with self._stdin_lock:
            if self.master_fd is not None:
                os.write(self.master_fd, raw)
            else:
                self.pty_obj.write(raw.decode("utf-8", errors="replace"))

    def kill(self):
        if self.master_fd is not None:
            try:
                os.killpg(self.proc.pid, _signal.SIGKILL)
            except Exception:
                kill_proc_tree(self.proc)
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None
        else:
            try:
                self.pty_obj.terminate(force=True)
            except Exception:
                pass
            kill_proc_tree(self.proc)

    def describe(self):
        status = "running" if not self.exited else "exited(%s)" % self.exit_code
        age = int(time.time() - self.created_at)
        return ("%s pid=%s %s age=%ss out=%dB pty=%s  %s"
                % (self.session_id, self.proc.pid, status, age,
                   self.out.raw_size(), self.backend, self.command))


def _pump_pty_fd(session):
    try:
        while session.master_fd is not None:
            try:
                chunk = os.read(session.master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            session.out.append(chunk)
    except Exception:
        pass
    session.out.eof()


def _pump_winpty(session):
    try:
        while True:
            try:
                chunk = session.pty_obj.read()
            except Exception:
                break
            if chunk:
                session.out.append(chunk.encode("utf-8", errors="replace"))
            if not session.pty_obj.isalive():
                break
    except Exception:
        pass
    session.out.eof()


def _conpty_spawn(cmdline, cwd=None, env_dict=None):
    """Spawn on ConPTY passing the command line RAW (no re-quoting).

    pywinpty's PtyProcess.spawn() re-splits its argv with shlex and
    re-joins via list2cmdline, which mangles commands that contain
    quotes (e.g. python -c "print('hi')" becomes unterminated-string
    garbage). The raw PTY backend accepts appname + cmdline exactly
    like CreateProcess, so quoting survives untouched.
    """
    from winpty._winpty import PTY
    from winpty.ptyprocess import PtyProcess
    env = None
    if env_dict:
        env = "\0".join("%s=%s" % (str(k), str(v))
                        for k, v in env_dict.items()) + "\0"
    if cmdline.startswith('"'):
        end = cmdline.find('"', 1)
        if end == -1:
            appname, rest = cmdline, ""
        else:
            appname, rest = cmdline[:end + 1], cmdline[end + 1:]
    else:
        appname, _, rest = cmdline.partition(" ")
    rest = rest.strip()
    pty = PTY(80, 24)
    if rest:
        pty.spawn(appname, cmdline=" " + rest, cwd=cwd, env=env)
    else:
        pty.spawn(appname, cwd=cwd, env=env)
    return PtyProcess(pty)


def _start_pty_session(command, cwd=None, name=None, env=None, shell=True):
    """start_session on a real pseudo-terminal (ConPTY / POSIX pty)."""
    if not command or not command.strip():
        return "Error: empty command"
    if cwd and not os.path.isdir(cwd):
        return "Error: cwd does not exist: %s" % cwd
    full_env = dict(os.environ)
    if env:
        if not isinstance(env, dict):
            return "Error: env must be an object of key/value strings"
        for k, v in env.items():
            full_env[str(k)] = str(v)
    sid = _new_session_id()
    if os.name == "nt":
        if _WinPtyProcess is None:
            return ("Error: pty=True needs pywinpty (pip install pywinpty); "
                    "retry with pty=false for anonymous pipes")
        backend = "conpty"
        # NOTE: with shell=True and a quoted exe path containing spaces
        # (e.g. cmd.exe /c ""C:\path with spaces\py.exe" -c "print(1)""),
        # cmd.exe strips quotes per its documented /c rules and fails with
        # "is not recognized". This is an OS limitation, not a ConPTY bug;
        # use pty=false (pipes) for such commands or shell=False.
        cmdline = ("cmd.exe /c %s" % command) if shell else command
        proc = None
        try:
            try:
                pty_obj = _conpty_spawn(cmdline, cwd or None, full_env)
            except ImportError:
                # very old pywinpty without the raw PTY module exposed:
                # fall back to PtyProcess.spawn (may mangle inner quotes)
                pty_obj = _WinPtyProcess.spawn(cmdline, cwd=cwd or None,
                                               env=full_env or None)
        except Exception as exc:
            return "start_session error (conpty): %s" % exc
        proc = _PtyProcShim(pty_obj)
        session = _PtySession(sid, command, cwd, name, proc, pty_obj,
                              None, backend)
    elif _HAVE_POSIX_PTY:
        backend = "posix-pty"
        master, slave = os.openpty()
        proc = None
        try:
            proc = subprocess.Popen(
                command, shell=bool(shell), cwd=cwd or None, env=full_env,
                stdin=slave, stdout=slave, stderr=slave,
                preexec_fn=os.setsid, bufsize=0,
            )
        except Exception as exc:
            os.close(master)
            os.close(slave)
            return "start_session error (posix-pty): %s" % exc
        os.close(slave)  # child owns the tty now; keep only the master
        session = _PtySession(sid, command, cwd, name, proc, None,
                              master, backend)
    else:
        return ("Error: no pty backend available on this platform; "
                "retry with pty=false")
    try:
        proc._hackerai_session_proc = True
        proc._hackerai_session_id = sid
        with _SESSIONS_LOCK:
            _SESSIONS[sid] = session
        register_proc(proc)
        session.start_threads()
        _persist_ledger()
        return ("[session %s started] pid=%s cwd=%s pty=%s\n"
                "command: %s\n"
                "Drive it with send_input / view_session_output / "
                "wait_for_pattern; stop it with kill_session."
                % (sid, proc.pid, session.cwd, backend, command))
    except Exception as exc:
        try:
            session.kill()
        except Exception:
            pass
        return "start_session error: %s" % exc


# ---------------------------------------------------------------- tools

def tool_start_session(command, cwd=None, name=None, env=None, shell=True,
                       pty=False):
    """Start a long-running interactive background process.

    Returns a unique session_id that is valid for the rest of the
    conversation: the process keeps running between tool calls.

    pty=True runs the child on a real pseudo-terminal (ConPTY on Windows
    via pywinpty, os.openpty elsewhere) instead of anonymous pipes, so
    interactive TUIs, color output, and isatty()-aware programs work.
    """
    if pty:
        return _start_pty_session(command, cwd=cwd, name=name, env=env,
                                  shell=shell)
    if not command or not command.strip():
        return "Error: empty command"
    if cwd and not os.path.isdir(cwd):
        return "Error: cwd does not exist: %s" % cwd
    sid = _new_session_id()
    proc = None
    try:
        full_env = dict(os.environ)
        if env:
            if not isinstance(env, dict):
                return "Error: env must be an object of key/value strings"
            for k, v in env.items():
                full_env[str(k)] = str(v)
        creationflags = 0
        if os.name == "nt":
            # own process group => we can deliver a real Ctrl+C (console
            # event) to the whole tree instead of killing it.
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        proc = subprocess.Popen(
            command, shell=bool(shell), cwd=cwd or None, env=full_env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0,
            creationflags=creationflags,
        )
        proc._hackerai_session_proc = True
        proc._hackerai_session_id = sid
        session = _InteractiveSession(sid, command, cwd, name, proc,
                                      bool(shell))
        with _SESSIONS_LOCK:
            _SESSIONS[sid] = session
        register_proc(proc)
        session.start_threads()
        _persist_ledger()
        return ("[session %s started] pid=%s cwd=%s\n"
                "command: %s\n"
                "Drive it with send_input / view_session_output / "
                "wait_for_pattern; stop it with kill_session."
                % (sid, proc.pid, session.cwd, command))
    except Exception as exc:
        if proc is not None:
            try:
                kill_proc_tree(proc)
            except Exception:
                pass
        return "start_session error: %s" % exc


def tool_send_input(session_id, input="", signal=None, press_enter=True):
    """Send text or a control signal into a running session's stdin."""
    sess = _get_session(session_id)
    if not isinstance(sess, _InteractiveSession):
        return sess
    if sess.exited:
        return "[session %s already exited (code %s)]" % (session_id,
                                                          sess.exit_code)
    try:
        if signal:
            key = str(signal).lower().replace("-", "_")
            if (key == "ctrl_c" and os.name == "nt"
                    and hasattr(_signal, "CTRL_C_EVENT")
                    and hasattr(sess.proc, "send_signal")):
                try:
                    sess.proc.send_signal(_signal.CTRL_C_EVENT)
                    return ("[ctrl-c delivered as console event to session "
                            "%s]" % session_id)
                except Exception:
                    pass  # no console (service mode) -> fall back to \x03
            if (key == "ctrl_break" and os.name == "nt"
                    and hasattr(_signal, "CTRL_BREAK_EVENT")
                    and hasattr(sess.proc, "send_signal")):
                try:
                    import ctypes
                    if ctypes.windll.kernel32.GetConsoleWindow() == 0:
                        return ("[ctrl-break unavailable: no Windows console "
                                "attached to the agent process; session %s "
                                "unaffected]" % session_id)
                    sess.proc.send_signal(_signal.CTRL_BREAK_EVENT)
                    return ("[ctrl-break delivered as console event to "
                            "session %s]" % session_id)
                except Exception:
                    pass
            if (os.name != "nt" and key in _POSIX_SIGNALS
                    and hasattr(sess.proc, "send_signal")):
                try:
                    sess.proc.send_signal(_POSIX_SIGNALS[key])
                    return ("[%s delivered to session %s]"
                            % (key, session_id))
                except Exception:
                    pass
            raw = _CTRL_BYTES.get(key)
            if raw is None:
                known = sorted(set(_CTRL_BYTES) | set(_POSIX_SIGNALS))
                if os.name == "nt":
                    known = sorted(set(list(_CTRL_BYTES) + ["ctrl_break"]))
                return ("Error: unknown signal %r. Known signals: %s"
                        % (signal, ", ".join(known)))
            sess.write_stdin(raw)
            return "[signal %s sent to session %s]" % (signal, session_id)
        text = str(input)
        if press_enter and not text.endswith(("\n", "\r")):
            text += "\n"
        enc = _oem_codepage() or "utf-8"
        raw = text.encode(enc, errors="replace")
        sess.write_stdin(raw)
        return "[sent %d bytes to session %s]" % (len(raw), session_id)
    except Exception as exc:
        return "send_input error: %s" % exc


def tool_view_session_output(session_id, tail=_VIEW_TAIL, clear=False,
                             include_stderr=True):
    """Read a running session's accumulated output (never blocks)."""
    sess = _get_session(session_id)
    if not isinstance(sess, _InteractiveSession):
        return sess
    status = "running" if not sess.exited else "exited(code=%s)" % sess.exit_code
    out = sess.out.text(tail=tail)
    if include_stderr:
        err = sess.err.text(tail=tail)
        if err.strip():
            out += "\n[stderr]\n" + err
    if clear:
        sess.out.clear()
        sess.err.clear()
    text = (out or "(no output yet)").strip()
    return "[%s] session %s\n%s" % (status, session_id, text)


def tool_wait_for_pattern(session_id, pattern, timeout=60, fresh_only=False):
    """Poll a session until a regex appears in its output (or timeout).

    With fresh_only=True only output produced after this call starts is
    searched, so a pattern that already matched earlier does not hit
    stale buffer content again (e.g. two identical prompts in a row).
    """
    sess = _get_session(session_id)
    if not isinstance(sess, _InteractiveSession):
        return sess
    if not pattern:
        return "Error: empty pattern"
    try:
        regex = re.compile(str(pattern))
    except re.error as exc:
        return "wait_for_pattern error: bad regex %r: %s" % (pattern, exc)
    timeout = max(1, min(int(timeout or 60), _MAX_WAIT_TIMEOUT))
    deadline = time.time() + timeout
    last_text = ""
    base_out = base_err = ""
    if fresh_only:
        base_out = sess.out.text(tail=None)
        base_err = sess.err.text(tail=None)
    while True:
        if fresh_only:
            out = sess.out.text(tail=None)[len(base_out):]
            err = sess.err.text(tail=None)[len(base_err):]
        else:
            out = sess.out.text(tail=_VIEW_TAIL * 2)
            err = sess.err.text(tail=_VIEW_TAIL)
        last_text = (out + ("\n[stderr]\n" + err if err.strip() else "")).strip()
        if regex.search(last_text):
            return ("[pattern matched] session %s\n%s"
                    % (session_id, last_text[:_VIEW_TAIL * 3]))
        if sess.exited or time.time() >= deadline:
            break
        time.sleep(0.25)
    return ("[pattern NOT matched within %ss] session %s\n%s"
            % (timeout, session_id, last_text[:_VIEW_TAIL * 3]))


def tool_kill_session(session_id):
    """Terminate a session's process tree and drop it from the ledger."""
    sess = _SESSIONS.get(str(session_id or "").strip())
    if sess is None:
        return "Error: no such session: %s (use list_sessions)" % session_id
    if not sess.exited:
        sess.kill()
        sess.exited = True
        sess.exit_code = getattr(sess.proc, "returncode", None)
        sess.ended_at = time.time()
        unregister_proc(sess.proc)
        status = "killed"
    else:
        status = "exited"
    with _SESSIONS_LOCK:
        _SESSIONS.pop(sess.session_id, None)
    _record_finished(sess, status)
    _persist_ledger()
    return "[session %s %s (pid %s)]" % (session_id, status, sess.pid)


def tool_list_sessions(active_only=False):
    """List the session ledger: id, pid, status, age, output sizes."""
    with _SESSIONS_LOCK:
        rows = [s.describe() for s in _SESSIONS.values()
                if not active_only or not s.exited]
        history = list(_LEDGER_HISTORY)
    rows.sort()
    if not rows:
        note = ""
    else:
        note = ("\n\nFinished entries in persistent ledger (%d kept): "
                % len(history)) if history else ""
    if not rows and not history:
        return "(no sessions recorded)"
    return "\n".join(rows) + note


# ---------------------------------------------------------------- one-shot

def tool_run_terminal(command, timeout=60, max_output=20000):
    if not command or not command.strip():
        return "Error: empty command"
    proc = None
    try:
        proc = subprocess.Popen(
            command, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        register_proc(proc)
        stdout, stderr = proc.communicate(timeout=timeout)
        out = _decode_output(stdout)
        err = _decode_output(stderr)
        parts = [out]
        if err.strip():
            parts.append("[stderr]\n" + err)
        text = "\n".join(parts).strip() or "(no output)"
        return "[exit code %s]\n%s" % (proc.returncode, text[:max_output])
    except subprocess.TimeoutExpired:
        if proc is not None:
            kill_proc_tree(proc)
        return "[command timed out after %ss]" % timeout
    except Exception as exc:
        return "run_terminal error: %s" % exc
    finally:
        if proc is not None:
            unregister_proc(proc)


def tool_read_file(path, max_chars=60000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_chars)
        if len(content) >= max_chars:
            content += "\n...[truncated]"
        return content
    except Exception as exc:
        return "read_file error: %s" % exc


def tool_write_file(path, content):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return "wrote %s (%d chars)" % (path, len(content))
    except Exception as exc:
        return "write_file error: %s" % exc


def tool_list_files(path="."):
    try:
        entries = sorted(os.listdir(path))
        if not entries:
            return "(empty directory)"
        lines = []
        for name in entries:
            full = os.path.join(path, name)
            if os.path.isdir(full):
                lines.append("[dir]  " + name)
            else:
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = 0
                lines.append("[file] %s (%d bytes)" % (name, size))
        return "\n".join(lines)
    except Exception as exc:
        return "list_files error: %s" % exc


# load durable ledger history at import time
_LEDGER_HISTORY.extend(_load_ledger_history())
