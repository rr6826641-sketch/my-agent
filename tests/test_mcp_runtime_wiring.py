"""Integration tests for the Agent-level MCP auto-wiring layer
(ai_agent/core/main.py Agent._load_mcp_servers + Agent._wire_mcp_servers).

The MCP *client engine* is covered separately in test_mcp_client.py; these
tests prove the runtime glue: config/env spec discovery, live tool
registration into the dispatch map + advertised tool list, the [MCP] system
note injected into the conversation, name-deduplication, and per-server
failure isolation.  No network and no real MCP server is needed -- the
McpClient symbol is monkeypatched with an in-process fake.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_agent.core import Agent  # noqa: E402
from ai_agent.core.mcp_client import McpError  # noqa: E402
from ai_agent.tools.base import Tool  # noqa: E402


# ---------------------------------------------------------------------------
# Fake McpClient: records lifecycle, exposes scripted tools per command
# ---------------------------------------------------------------------------

def _make_tool(name):
    return Tool(
        name=name,
        description="desc %s" % name,
        parameters={"type": "object", "properties": {}},
        func=lambda *a, **k: "ok",
    )


class FakeMcpClient:
    """Drop-in replacement for McpClient used by Agent._wire_mcp_servers."""

    instances = []

    def __init__(self, command=None, args=None, env=None, cwd=None):
        self.command = command
        self.connected = False
        self.closed = False
        self._tools_by_command = {
            "python": ["mcp_alpha", "mcp_beta"],
            "node": ["mcp_gamma"],
        }
        FakeMcpClient.instances.append(self)

    def connect(self):
        if self.command == "boom":
            raise McpError("boom: server crashed on startup")
        self.connected = True

    def as_tool_objects(self, prefix="mcp_", confirm=False):
        if not self.connected:
            raise McpError("connect() first")
        return [_make_tool(name) for name in self._tools_by_command.get(self.command, [])]

    def close(self):
        self.closed = True
        self.connected = False


@pytest.fixture
def patched_client(monkeypatch):
    FakeMcpClient.instances = []
    monkeypatch.setattr("ai_agent.core.mcp_client.McpClient", FakeMcpClient)
    return FakeMcpClient


def _bare_agent():
    """Agent with only the attributes _wire_mcp_servers touches."""
    agent = Agent.__new__(Agent)
    agent._tools_by_name = {}
    agent._tool_list = []
    agent.messages = []
    return agent


def _env_specs(monkeypatch, specs):
    monkeypatch.setenv("MCP_SERVERS", json.dumps(specs))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_load_mcp_servers_merges_config_and_env(monkeypatch):
    specs = [
        {"name": "fs", "command": "python", "args": ["-m", "fake_server"]},
        {"name": "boom", "command": "boom", "args": []},
        {"name": "no-cmd", "prefix": "x_"},          # must be filtered out
    ]
    _env_specs(monkeypatch, specs)
    agent = _bare_agent()
    loaded = agent._load_mcp_servers()
    names = [s.get("name") for s in loaded]
    assert "fs" in names and "boom" in names
    assert "no-cmd" not in names          # spec without command is rejected
    assert all(s.get("command") for s in loaded)


def test_wiring_registers_tools_and_injects_note(monkeypatch, patched_client):
    _env_specs(monkeypatch, [{"name": "fs", "command": "python"}])
    agent = _bare_agent()
    agent._wire_mcp_servers()

    assert "mcp_alpha" in agent._tools_by_name
    assert "mcp_beta" in agent._tools_by_name
    assert len(agent._tool_list) == 2
    notes = [m["content"] for m in agent.messages
             if m["role"] == "system" and m["content"].startswith("[MCP]")]
    assert len(notes) == 1
    assert "'fs': 2 new tool(s)" in notes[0]
    client = patched_client.instances[0]
    assert client.connected is False and client.closed is True  # clean close


def test_wiring_skips_duplicate_tool_names(monkeypatch, patched_client):
    _env_specs(monkeypatch, [{"name": "fs", "command": "python"}])
    agent = _bare_agent()
    agent._tools_by_name["mcp_alpha"] = _make_tool("mcp_alpha")
    agent._tool_list.append(_make_tool("mcp_alpha"))
    agent._wire_mcp_servers()

    assert len(agent._tool_list) == 2          # alpha pre-existing, beta added
    assert "mcp_beta" in agent._tools_by_name
    notes = [m["content"] for m in agent.messages
             if m["role"] == "system" and m["content"].startswith("[MCP]")]
    assert "'fs': 1 new tool(s)" in notes[0]


def test_wiring_isolates_failed_server(monkeypatch, patched_client):
    specs = [
        {"name": "ok", "command": "node"},
        {"name": "boom", "command": "boom"},
    ]
    _env_specs(monkeypatch, specs)
    agent = _bare_agent()
    agent._wire_mcp_servers()          # must not raise despite "boom" failing

    assert "mcp_gamma" in agent._tools_by_name          # good server survived
    notes = [m["content"] for m in agent.messages
             if m["role"] == "system" and m["content"].startswith("[MCP]")]
    assert len(notes) == 1
    assert "'ok': 1 new tool(s)" in notes[0]
