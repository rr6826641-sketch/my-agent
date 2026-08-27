"""Tool base class and shared helpers."""

import json


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


def execute_tool(tool_by_name, tool_call):
    """Run one tool call; returns the string result."""
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
    try:
        return truncate(tool.func(**args))
    except TypeError as exc:
        return "Bad arguments for %s: %s" % (fn_name, exc)
    except Exception as exc:
        return "%s error: %s" % (fn_name, exc)
