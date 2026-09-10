"""Real-time tool-execution event stream (PHASE 1).

Thread-safe hub that fans structured execution events out to live SSE
subscribers (and into a bounded replay history for late joiners).

Every emitted payload is JSON-serialisable and carries:
  run_id, session_id (when known), ts (epoch seconds),
  step_type (terminal | command | git | tool | subagent),
  command, stdout, stderr, status (running|completed|failed|cancelled),
  exit_code, duration_ms, detail.

Emission points (all additive, never fatal):
  - ai_agent/tools/base.py  execute_tool()
  - ai_agent/tools/terminal.py tool_run_terminal() (live per-line stdout)
  - webui.py  /api/chat worker (validation / sub-agent state re-broadcast)
  - webui.py  /api/exec/stream (SSE fan-out endpoint)

The hub never raises into callers: every public method is guarded so an
event-stream failure can never break a tool execution.
"""

import queue
import subprocess
import threading
import time
import uuid

__all__ = ["EventStreamHub", "hub"]

_HISTORY_MAX = 400
_SUBSCRIBER_MAX = 64
_OUTPUT_EVENT_CHUNK = 8000  # max stdout chars carried per output frame


def _now():
    return time.time()


def _step_type_for(name):
    """Map a tool name onto a coarse step_type for the stream contract."""
    name = (name or "").lower()
    if name in ("run_terminal", "terminal", "bash", "shell", "pty_start_session",
                "pty_send_input", "pty_read_output"):
        return "terminal"
    if name.startswith(("git", "repo")) or name in ("run_git", "git_status",
                                                    "git_commit", "git_push"):
        return "git"
    if name.startswith(("sub", "swarm")) or "subagent" in name:
        return "subagent"
    return "tool"


class EventStreamHub:
    """Thread-safe fan-out hub with bounded replay history."""

    def __init__(self, history_max=_HISTORY_MAX):
        self._lock = threading.RLock()
        self._next_sub = 0
        self._subs = {}           # sub_id -> queue.Queue
        self._history = []        # bounded replay ring
        self._history_max = history_max
        self._runs = {}           # run_id -> context dict (lifecycle state)
        self._local = threading.local()

    # ---------------- subscriber management ----------------
    def subscribe(self):
        """Return (sub_id, queue.Queue). Queue receives every event dict."""
        q = queue.Queue(maxsize=_SUBSCRIBER_MAX)
        with self._lock:
            self._next_sub += 1
            sub_id = self._next_sub
            self._subs[sub_id] = q
        return sub_id, q

    def unsubscribe(self, sub_id):
        with self._lock:
            self._subs.pop(sub_id, None)

    def replay(self, limit=None):
        """Committed events, newest last (for late subscribers)."""
        with self._lock:
            hist = list(self._history)
        return hist if limit is None else hist[-limit:]

    # ---------------- run context (thread-local tagging) ----------------
    def attach_context(self, run_id=None, session_id=None, step_type=None,
                       command=None):
        """Tag the calling thread so emitters inherit run/session identity."""
        prev = getattr(self._local, "ctx", None) or {}
        self._local.ctx = {
            "run_id": run_id if run_id is not None else prev.get("run_id"),
            "session_id": (session_id if session_id is not None
                           else prev.get("session_id")),
            "step_type": (step_type if step_type is not None
                          else prev.get("step_type")),
            "command": command if command is not None else prev.get("command"),
        }
        return self._local.ctx

    def detach_context(self):
        try:
            del self._local.ctx
        except AttributeError:
            pass

    def _ctx(self):
        return getattr(self._local, "ctx", None) or {}

    def context(self):
        """Public read-only snapshot of the thread-local run context."""
        return dict(self._ctx())

    def begin_run(self, run_id=None, session_id=None, step_type="tool",
                  command=None):
        """Open a run lifecycle record; returns the run_id."""
        ctx = self._ctx()
        run_id = run_id or ctx.get("run_id") or uuid.uuid4().hex
        session_id = session_id if session_id is not None else ctx.get("session_id")
        with self._lock:
            self._runs[run_id] = {
                "run_id": run_id,
                "session_id": session_id,
                "step_type": step_type or ctx.get("step_type") or "tool",
                "command": command if command is not None else ctx.get("command"),
                "status": "running",
                "started": _now(),
                "ended": None,
                "exit_code": None,
            }
        return run_id

    def end_run(self, run_id, status="completed", exit_code=None):
        with self._lock:
            rec = self._runs.get(run_id)
            if rec is not None:
                rec["status"] = status
                rec["ended"] = _now()
                rec["exit_code"] = exit_code

    def active_runs(self):
        with self._lock:
            return {rid: dict(r) for rid, r in self._runs.items()
                    if r["status"] == "running"}

    # ---------------- core emission ----------------
    def emit(self, payload):
        """Fan out one payload to subscribers + history ring.

        Stamps ts/run_id/session_id/step_type/command from thread-local
        context when unset. Never raises.
        """
        evt = dict(payload)
        evt.setdefault("ts", _now())
        ctx = self._ctx()
        if not evt.get("run_id"):
            evt["run_id"] = ctx.get("run_id")
        if evt.get("session_id") is None:
            evt["session_id"] = ctx.get("session_id")
        if not evt.get("step_type"):
            evt["step_type"] = ctx.get("step_type") or "tool"
        if evt.get("command") is None:
            evt["command"] = ctx.get("command")
        with self._lock:
            self._history.append(evt)
            if len(self._history) > self._history_max:
                del self._history[:len(self._history) - self._history_max]
            dead = []
            for sub_id, q in self._subs.items():
                try:
                    q.put_nowait(evt)
                except Exception:
                    dead.append(sub_id)
            for sub_id in dead:
                self._subs.pop(sub_id, None)
        return evt

    # ---------------- lifecycle helpers ----------------
    def step_start(self, step_type=None, command=None, run_id=None,
                   session_id=None):
        """Emit the 'running' frame immediately before execution begins."""
        ctx = self._ctx()
        run_id = run_id or ctx.get("run_id") or uuid.uuid4().hex
        session_id = session_id if session_id is not None else ctx.get("session_id")
        step_type = step_type or ctx.get("step_type") or "tool"
        command = command if command is not None else ctx.get("command")
        return self.emit({
            "run_id": run_id,
            "session_id": session_id,
            "step_type": step_type,
            "command": command,
            "stream": None,
            "stdout": None,
            "stderr": None,
            "status": "running",
            "exit_code": None,
            "duration_ms": None,
        })

    def step_output(self, stream="stdout", chunk=None, run_id=None,
                    step_type=None, command=None):
        """Emit a live output chunk (call *during* execution)."""
        ctx = self._ctx()
        run_id = run_id or ctx.get("run_id")
        step_type = step_type or ctx.get("step_type") or "tool"
        command = command if command is not None else ctx.get("command")
        chunk = chunk or ""
        for i in range(0, len(chunk), _OUTPUT_EVENT_CHUNK):
            piece = chunk[i:i + _OUTPUT_EVENT_CHUNK]
            self.emit({
                "run_id": run_id,
                "session_id": ctx.get("session_id"),
                "step_type": step_type,
                "command": command,
                "stream": stream,
                "stdout": piece if stream == "stdout" else None,
                "stderr": piece if stream == "stderr" else None,
                "status": "running",
                "exit_code": None,
                "duration_ms": None,
            })

    def step_end(self, run_id=None, status="completed", exit_code=None,
                 stdout=None, stderr=None, duration_ms=None,
                 step_type=None, command=None):
        """Emit the terminal event after execution finishes."""
        ctx = self._ctx()
        run_id = run_id or ctx.get("run_id")
        step_type = step_type or ctx.get("step_type") or "tool"
        command = command if command is not None else ctx.get("command")
        return self.emit({
            "run_id": run_id,
            "session_id": ctx.get("session_id"),
            "step_type": step_type,
            "command": command,
            "stream": None,
            "stdout": stdout if isinstance(stdout, str) else None,
            "stderr": stderr if isinstance(stderr, str) else None,
            "status": status,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
        })

    def subagent_state(self, name, status="running", detail=None,
                       run_id=None, session_id=None):
        """Sub-agent state event (spawn / work / done / error)."""
        return self.emit({
            "run_id": run_id,
            "session_id": session_id,
            "step_type": "subagent",
            "command": name,
            "stream": None,
            "stdout": None,
            "stderr": None,
            "status": status,
            "exit_code": None,
            "duration_ms": None,
            "detail": detail,
        })

    # ---------------- live command runner ----------------
    def run_command(self, args, cwd=None, env=None, timeout=60, shell=False,
                    run_id=None, session_id=None, step_type=None):
        """Run a command while streaming stdout/stderr lines live through
        the hub. Returns (exit_code, stdout, stderr).

        Emits the start event *before* the process spawns and output
        frames *while* it runs, so subscribers observe the stream during
        execution - not only after completion.
        """
        run_id = run_id or self._ctx().get("run_id") or uuid.uuid4().hex
        session_id = session_id if session_id is not None else self._ctx().get("session_id")
        step_type = step_type or self._ctx().get("step_type") or "tool"
        cmd_str = args if isinstance(args, str) else " ".join(str(a) for a in args)
        started = _now()
        with self._lock:
            self._runs.setdefault(run_id, {
                "run_id": run_id,
                "session_id": session_id,
                "step_type": step_type,
                "command": cmd_str,
                "status": "running",
                "started": started,
                "ended": None,
                "exit_code": None,
            })
        # start event lands BEFORE spawn
        self.emit({"run_id": run_id, "session_id": session_id,
                   "step_type": step_type, "command": cmd_str,
                   "stream": None, "stdout": None, "stderr": None,
                   "status": "running", "exit_code": None,
                   "duration_ms": None})
        proc = None
        out_parts, err_parts = [], []

        def _pump(pipe, sink, stream_kind):
            try:
                for raw in iter(pipe.readline, ""):
                    if not raw:
                        break
                    sink.append(raw)
                    self._emit_chunk(run_id, session_id, step_type, cmd_str,
                                     stream_kind, raw)
            except Exception:
                pass

        try:
            proc = subprocess.Popen(
                args, shell=shell, cwd=cwd, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, errors="replace")
        except Exception as exc:
            self.emit({"run_id": run_id, "session_id": session_id,
                       "step_type": step_type, "command": cmd_str,
                       "stream": None, "stdout": None,
                       "stderr": "spawn error: %s" % exc,
                       "status": "failed", "exit_code": -1,
                       "duration_ms": int((_now() - started) * 1000)})
            return -1, "", "spawn error: %s" % exc
        try:
            t_out = threading.Thread(target=_pump, args=(proc.stdout, out_parts, "stdout"),
                                     daemon=True)
            t_err = threading.Thread(target=_pump, args=(proc.stderr, err_parts, "stderr"),
                                     daemon=True)
            t_out.start()
            t_err.start()
            deadline = _now() + max(1, timeout)
            timed_out = False
            while t_out.is_alive() or t_err.is_alive() or proc.poll() is None:
                if _now() >= deadline:
                    timed_out = True
                    break
                time.sleep(0.05)
            if timed_out:
                raise subprocess.TimeoutExpired(proc, timeout)
            t_out.join(1)
            t_err.join(1)
            exit_code = proc.returncode
            stdout, stderr = "".join(out_parts), "".join(err_parts)
            status = "completed" if exit_code == 0 else "failed"
            self.emit({"run_id": run_id, "session_id": session_id,
                       "step_type": step_type, "command": cmd_str,
                       "stream": None, "status": status,
                       "stdout": stdout or None, "stderr": stderr or None,
                       "exit_code": exit_code,
                       "duration_ms": int((_now() - started) * 1000)})
            self.end_run(run_id, status, exit_code)
            return exit_code, stdout, stderr
        except Exception as exc:
            if proc is not None:
                try:
                    if proc.poll() is None:
                        proc.kill()
                except Exception:
                    pass
            self.emit({"run_id": run_id, "session_id": session_id,
                       "step_type": step_type, "command": cmd_str,
                       "stream": None,
                       "stdout": "".join(out_parts) or None,
                       "stderr": "%s: %s" % (type(exc).__name__, exc),
                       "status": "failed", "exit_code": -1,
                       "duration_ms": int((_now() - started) * 1000)})
            self.end_run(run_id, "failed", -1)
            return -1, "".join(out_parts), "%s: %s" % (type(exc).__name__, exc)
        finally:
            if proc is not None:
                try:
                    if proc.poll() is None:
                        proc.kill()
                except Exception:
                    pass

    def _emit_chunk(self, run_id, session_id, step_type, command, stream, chunk):
        if not chunk:
            return
        for i in range(0, len(chunk), _OUTPUT_EVENT_CHUNK):
            piece = chunk[i:i + _OUTPUT_EVENT_CHUNK]
            self.emit({
                "run_id": run_id,
                "session_id": session_id,
                "step_type": step_type,
                "command": command,
                "stream": stream,
                "stdout": piece if stream == "stdout" else None,
                "stderr": piece if stream == "stderr" else None,
                "status": "running",
                "exit_code": None,
                "duration_ms": None,
            })


hub = EventStreamHub()