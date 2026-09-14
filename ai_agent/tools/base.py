"""Tool base class and shared helpers."""

import json
import os
import subprocess
import threading
import time

from ..core.event_stream import hub, _step_type_for


class Tool:
    def __init__(self, name, description, parameters, func, confirm=False):
        self.name = name
        self.description = description
        self.parameters = parameters
        self.func = func
        self.confirm = confirm

    def schema(self):
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


def truncate(text, limit=6000):
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated, %d more chars]" % (len(text) - limit)


TOOL_TIMEOUT = 120  # hard cap per tool call (seconds)

# Bounded auto-retry (tool wrapper): idempotent read-only tools get a single
# retry when the first attempt fails with a transient network/lookup error,
# so flaky links don't burn an agent turn on a one-shot failure. Side-effect
# tools (write/exec/upload/scan) are deliberately excluded.
RETRYABLE_TOOLS = frozenset({
    "fetch_url", "open_url", "web_search", "search_web",
    "dns_lookup", "dns_axfr", "reverse_dns", "geoip", "whois",
    "cve_lookup", "check_headers", "ssl_info", "url_status",
    "redirect_chain", "robots_txt", "ping_host", "tech_detect", "waf_detect",
})

TRANSIENT_MARKERS = (
    "timed out", "timeout", "connectionerror", "connection error",
    "connection refused", "connection reset", "reset by peer",
    "temporary failure", "temporarily unavailable", "getaddrinfo",
    "read timed out", "remote end closed", "chunkedencoding",
    "http 408", "http 429", "http 502", "http 503", "http 504",
    "too many redirects", "socket.timeout",
)

_proc_lock = threading.Lock()
_active_procs = set()


def register_proc(proc):
    with _proc_lock:
        _active_procs.add(proc)


def unregister_proc(proc):
    with _proc_lock:
        _active_procs.discard(proc)


def kill_proc_tree(proc):
    """Force-kill one subprocess (with its whole tree on Windows)."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10)
        else:
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=10)
    except Exception:
        pass


def kill_active_procs(include_sessions=False):
    """Kill every subprocess currently started by tools.

    Long-lived interactive sessions (started via start_session) survive
    plain tool-timeout kills so a slow wait_for_pattern can never destroy
    a running nmap scan / dev server / listener. Pass include_sessions=True
    on user Stop / shutdown so they are torn down too.
    """
    with _proc_lock:
        procs = [p for p in _active_procs
                 if include_sessions or not getattr(p, "_hackerai_session_proc", False)]
    for proc in procs:
        kill_proc_tree(proc)
        unregister_proc(proc)



def _compact_args(args):
    """Short JSON-ish label of the args for the stream command field."""
    try:
        return json.dumps(args, separators=(",", ":"), ensure_ascii=False)[:500]
    except Exception:
        return "{}"


def execute_tool(tool_by_name, tool_call, timeout=TOOL_TIMEOUT,
                 cancel_event=None):
    """Run one tool call; returns the string result.

    The tool runs in a daemon thread so a hung tool can never block the
    agent (and the UI's "working…" state) forever: after `timeout`
    seconds it reports a timeout and the agent loop moves on to the
    next step. The thread keeps running in the background if needed.
    """
    try:
        fn_name = tool_call["function"]["name"]
        raw_args = tool_call["function"].get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
        except json.JSONDecodeError:
            args = {}
        if not isinstance(args, dict):
            args = {}
        cmd_args = args  # keep original dict for the tool call below
    except (KeyError, TypeError) as exc:
        return "Tool call parse error: %s" % exc
    tool = tool_by_name.get(fn_name)
    if tool is None:
        return "Unknown tool: %s" % fn_name

    # PHASE 1 - real-time execution event stream: open a run lifecycle and
    # emit the 'running' frame BEFORE the tool executes. All hub calls are
    # guarded so stream failures can never break tool execution.
    step_type = _step_type_for(fn_name)
    cmd_label = _compact_args(args)
    run_id = None
    t0 = time.time()
    try:
        run_id = hub.begin_run(step_type=step_type, command=cmd_label)
        hub.step_start(step_type=step_type, command=cmd_label, run_id=run_id,
                       session_id=hub.context().get("session_id"))
    except Exception:
        pass

    box = {}

    def _run():
        try:
            if run_id is not None:
                hub.attach_context(run_id=run_id, step_type=step_type,
                                   command=cmd_label)
        except Exception:
            pass
        try:
            box["out"] = truncate(tool.func(**cmd_args))
        except TypeError as exc:
            box["out"] = "Bad arguments for %s: %s" % (fn_name, exc)
        except Exception as exc:
            box["out"] = "%s error: %s" % (fn_name, exc)

    def _emit_end(out, status="completed", exit_code=0):
        try:
            if run_id is not None:
                hub.step_end(
                    run_id=run_id, status=status, exit_code=exit_code,
                    stdout=out if isinstance(out, str) else None,
                    stderr=None,
                    duration_ms=int((time.time() - t0) * 1000))
                hub.end_run(run_id, status, exit_code)
        except Exception:
            pass

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    deadline = t0 + timeout
    while True:
        if cancel_event is not None and cancel_event.is_set():
            kill_active_procs(include_sessions=True)
            _emit_end("[cancelled by user]", "cancelled", -1)
            return "[cancelled by user]"
        worker.join(0.2)
        if not worker.is_alive():
            break
        if time.time() >= deadline:
            kill_active_procs()
            _emit_end("[%s timed out after %ds — killed]" % (fn_name, timeout),
                      "failed", 124)
            return ("[%s timed out after %ds — killed]" % (fn_name, timeout))
    out = box.get("out", "(no output)")
    # Bounded auto-retry: one retry only, read-only tools only, backoff 0.8s.
    if (fn_name in RETRYABLE_TOOLS and isinstance(out, str)
            and any(m in out.lower() for m in TRANSIENT_MARKERS)
            and not (cancel_event is not None and cancel_event.is_set())):
        time.sleep(0.8)
        try:
            out2 = truncate(tool.func(**cmd_args))
        except Exception:
            out2 = None
        if out2:
            out = out2
    _emit_end(out, "completed" if run_id is not None else "completed",
              0 if run_id is not None else None)
    return out
