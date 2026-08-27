"""Tool base class and shared helpers."""

import json
import threading


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


def execute_tool(tool_by_name, tool_call, timeout=TOOL_TIMEOUT):
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
    worker.join(timeout=timeout)
    if worker.is_alive():
        return ("[%s timed out after %ds — it may still be running "
                "in the background]" % (fn_name, timeout))
    return box.get("out", "(no output)")
