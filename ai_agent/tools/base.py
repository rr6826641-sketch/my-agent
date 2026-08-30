"""Tool base class and shared helpers."""

import json
import os
import subprocess
import threading
import time


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
    except (KeyError, TypeError) as exc:
        return "Tool call parse error: %s" % exc
    tool = tool_by_name.get(fn_name)
    if tool is None:
        return "Unknown tool: %s" % fn_name

    box = {}

    def _run():
        try:
            box["out"] = truncate(tool.func(**args))
        except TypeError as exc:
            box["out"] = "Bad arguments for %s: %s" % (fn_name, exc)
        except Exception as exc:
            box["out"] = "%s error: %s" % (fn_name, exc)

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    deadline = time.time() + timeout
    while True:
        if cancel_event is not None and cancel_event.is_set():
            kill_active_procs(include_sessions=True)
            return "[cancelled by user]"
        worker.join(0.2)
        if not worker.is_alive():
            break
        if time.time() >= deadline:
            kill_active_procs()
            return ("[%s timed out after %ds — killed]" % (fn_name, timeout))
    return box.get("out", "(no output)")
