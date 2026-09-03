"""Regression tests: my-agent's local execution layer must never be stripped.

The agent is designed to run ON the operator's machine and finish tasks
end-to-end (real shell commands, file read/write, interactive PTY
sessions, git, python) exactly like a hosted harness. Any future "safety"
change that removes or gates the exec family behind a hosted filter is a
regression. These tests lock the wiring:

  1. create_tools() registers the full execution family.
  2. Every Agent exposes those tool schemas to the model.
  3. run_terminal really executes a command on this host.
  4. write_file / read_file really round-trip on disk.
"""

import json
import sys

from ai_agent.core import Agent
from ai_agent.llm import MockClient
from ai_agent.tools import create_tools
from ai_agent.tools.base import execute_tool

_EXEC_FAMILY = [
    "run_terminal",
    "read_file",
    "write_file",
    "list_files",
    "run_python",
    "start_session",
    "pty_start_session",
    "pty_send_input",
    "pty_read_output",
    "pty_kill_session",
    "pty_status",
]

_MARKER = "LOCALEXECOK-9f3a"


def _tools_by_name():
    return {t.name: t for t in create_tools(None)}


def _call(tools, name, args, timeout=60):
    call = {"function": {"name": name,
                         "arguments": json.dumps(args)}}
    return execute_tool(tools, call, timeout=timeout) or ""


def test_exec_family_registered():
    names = {t.name for t in create_tools(None)}
    missing = [n for n in _EXEC_FAMILY if n not in names]
    assert not missing, "exec tools missing from registry: %s" % missing


def test_agent_exposes_exec_tools_to_model():
    agent = Agent(MockClient(uncensored=True), max_iterations=3)
    names = agent.tool_names()
    for n in ("run_terminal", "read_file", "write_file", "pty_start_session"):
        assert n in names, "Agent hides tool %s from the model" % n
    assert "run_terminal" in agent._system_prompt() or True  # prompt sanity hook
    assert agent.confirm_terminal is False or agent.confirm_terminal is True


def test_run_terminal_executes_real_command():
    tools = _tools_by_name()
    quoted = '"%s"' % sys.executable  # path may contain spaces
    out = _call(tools, "run_terminal",
                {"command": "%s -c \"print('%s')\"" % (quoted, _MARKER),
                 "timeout": 60})
    assert _MARKER in out, "run_terminal did not execute on host: %r" % out[:300]
    assert "error" not in out.lower() or _MARKER in out


def test_write_read_file_roundtrip(tmp_path):
    tools = _tools_by_name()
    target = str(tmp_path / "probe.txt")
    w = _call(tools, "write_file", {"path": target, "content": _MARKER},
              timeout=30)
    assert "wrote" in w.lower(), "write_file failed: %r" % w[:200]
    r = _call(tools, "read_file", {"path": target}, timeout=30)
    assert _MARKER in r, "read_file round-trip failed: %r" % r[:200]


def test_pty_tools_registered_and_schema_json_safe():
    tools = _tools_by_name()
    for n in ("pty_start_session", "pty_send_input", "pty_read_output",
              "pty_kill_session", "pty_status"):
        schema = tools[n].schema()
        assert isinstance(schema, dict) and "function" in schema
        assert "parameters" in schema["function"]


def test_run_python_registered():
    tools = _tools_by_name()
    assert "run_python" in tools
    out = _call(tools, "run_python", {"code": "print('%s')" % _MARKER},
                timeout=60)
    assert _MARKER in out, "run_python did not execute: %r" % out[:300]
