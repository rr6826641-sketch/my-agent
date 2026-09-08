"""Unit tests for the MCP client engine (ai_agent/core/mcp_client.py).

Validates the standard MCP client lifecycle against an in-process fake
server: initialize handshake + initialized notification, dynamic tool
discovery with TTL caching, JSON Schema -> catalog schema translation,
remote payload execution (tools/call), isError / JSON-RPC error
handling, ping liveness, and routing of discovered tools into the
dynamic tool catalog / live tool maps used by the Swarm Orchestrator
(hot_reload_tool + register_live_catalog + the execute_tool calling
convention). All tests run synchronously with no external MCP server.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_agent.core.mcp_client import (  # noqa: E402
    EndpointChannel,
    McpClient,
    McpError,
    McpProtocolError,
    McpToolError,
    McpTransportError,
    json_schema_to_parameters,
    mcp_tool_to_catalog_schema,
    safe_tool_identifier,
)
from ai_agent.tools import (  # noqa: E402
    hot_reload_tool,
    remove_synthesized_tool,
    synthesized_tool_catalog,
)
from ai_agent.tools.base import Tool, execute_tool  # noqa: E402


# ---------------------------------------------------------------------------
# Fake in-process MCP server
# ---------------------------------------------------------------------------

FAKE_TOOLS = [
    {"name": "fs_read", "description": "Read a file from the host",
     "inputSchema": {"type": "object",
                     "properties": {"path": {"type": "string",
                                             "description": "file path"}},
                     "required": ["path"]}},
    {"name": "gh-create-issue", "description": "Open a GitHub issue",
     "inputSchema": {"type": "object",
                     "properties": {
                         "title": {"type": "string"},
                         "labels": {"type": "array",
                                    "items": {"type": "string"}}},
                     "required": ["title"]}},
]


class FakeMcpServer:
    """Scripted JSON-RPC 2.0 MCP server (exchange callable)."""

    def __init__(self):
        self.calls = []          # every received request
        self.initialized_seen = False
        self.list_count = 0
        self.tools = [dict(t) for t in FAKE_TOOLS]
        self.fail_initialize = False
        self.fail_ping = False

    def exchange(self, req):
        self.calls.append(req)
        method = req.get("method")
        rid = req.get("id")
        if "id" not in req:  # notification
            if method == "notifications/initialized":
                self.initialized_seen = True
            return {}
        if method == "initialize":
            if self.fail_initialize:
                return {"jsonrpc": "2.0", "id": rid,
                        "error": {"code": -32603,
                                  "message": "initialize exploded"}}
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "fake-mcp", "version": "9.9"}}}
        if method == "ping":
            if self.fail_ping:
                return {"jsonrpc": "2.0", "id": rid,
                        "error": {"code": -32000, "message": "no"}}
            return {"jsonrpc": "2.0", "id": rid, "result": {}}
        if method == "tools/list":
            self.list_count += 1
            return {"jsonrpc": "2.0", "id": rid,
                    "result": {"tools": self.tools}}
        if method == "tools/call":
            params = req.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            if name == "fs_read":
                return {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text",
                                 "text": "FILE:%s" % args.get("path", "")}],
                    "isError": False}}
            if name == "gh-create-issue":
                if args.get("make_error"):
                    return {"jsonrpc": "2.0", "id": rid, "result": {
                        "content": [{"type": "text", "text": "boom"}],
                        "isError": True}}
                return {"jsonrpc": "2.0", "id": rid, "result": {
                    "structuredContent": {"issue": 42, "title": args.get("title")},
                    "isError": False}}
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602, "message": "no such tool %r" % name}}
        return {"jsonrpc": "2.0", "id": rid, "error": {
            "code": -32601, "message": "unknown method %r" % method}}


@pytest.fixture
def fake_server():
    return FakeMcpServer()


@pytest.fixture
def client(fake_server):
    return McpClient(exchange=fake_server.exchange,
                     endpoint_label="fake-mcp")


# ---------------------------------------------------------------------------
# 1. Handshake
# ---------------------------------------------------------------------------

def test_initialize_handshake_and_initialized_notice(client, fake_server):
    client.connect()
    assert client.connected is True
    assert fake_server.initialized_seen is True
    methods = [c.get("method") for c in fake_server.calls]
    assert methods[0] == "initialize"
    assert "notifications/initialized" in methods
    assert client.server_info == {"name": "fake-mcp", "version": "9.9"}
    assert "tools" in client.server_capabilities
    client.close()
    assert client.connected is False


def test_initialize_protocol_version_sent(client, fake_server):
    client.connect()
    init = [c for c in fake_server.calls if c.get("method") == "initialize"][0]
    params = init.get("params") or {}
    assert params.get("protocolVersion") == "2025-03-26"
    assert params.get("clientInfo", {}).get("name") == "ai-agent-mcp-client"
    client.close()


def test_handshake_failure_raises_and_closes(fake_server):
    fake_server.fail_initialize = True
    c = McpClient(exchange=fake_server.exchange)
    with pytest.raises(McpProtocolError):
        c.connect()
    assert c.connected is False


def test_ping_reports_liveness(client, fake_server):
    client.connect()
    assert client.ping() is True
    fake_server.fail_ping = True
    assert client.ping() is False


def test_ping_before_connect_is_false(client):
    assert client.ping() is False


def test_client_requires_a_transport():
    with pytest.raises(McpError):
        McpClient()


# ---------------------------------------------------------------------------
# 2. Dynamic tool discovery
# ---------------------------------------------------------------------------

def test_discover_tools(client):
    client.connect()
    tools = client.discover_tools()
    assert [t["name"] for t in tools] == ["fs_read", "gh-create-issue"]


def test_discovery_ttl_cache(client, fake_server):
    client.connect()
    client.discover_tools()
    first = fake_server.list_count
    client.discover_tools()          # served from cache
    assert fake_server.list_count == first
    client.discover_tools(refresh=True)  # forced refresh
    assert fake_server.list_count == first + 1
    client.close()


def test_refresh_tools_requires_connection(client):
    with pytest.raises(McpError):
        client.refresh_tools()


def test_refresh_tools_missing_array_raises(client, fake_server):
    client.connect()
    fake_server.tools = "oops"
    with pytest.raises(McpProtocolError):
        client.refresh_tools()
    client.close()


# ---------------------------------------------------------------------------
# 3. Schema translation
# ---------------------------------------------------------------------------

def test_schema_translation_matches_tool_schema_shape(client):
    client.connect()
    schemas = client.catalog_schemas()
    assert len(schemas) == 2
    for s in schemas:
        assert s["type"] == "function"
        assert s["function"]["parameters"]["type"] == "object"
    client.close()


def test_mcp_name_is_namespaced_and_sanitized():
    schema = mcp_tool_to_catalog_schema(
        {"name": "gh-create-issue",
         "description": "d",
         "inputSchema": {"type": "object", "properties": {}}},
        prefix="mcp_")
    assert schema["function"]["name"] == "mcp_gh_create_issue"


def test_safe_tool_identifier_edge_cases():
    assert safe_tool_identifier("gh-create-issue") == "gh_create_issue"
    assert safe_tool_identifier("123start") == "_123start"
    assert safe_tool_identifier("already_ok") == "already_ok"


def test_json_schema_required_preserved():
    params = json_schema_to_parameters(FAKE_TOOLS[0]["inputSchema"])
    assert params["required"] == ["path"]
    assert params["properties"]["path"]["type"] == "string"


def test_json_schema_degenerate_shapes():
    assert json_schema_to_parameters(None) == {"type": "object",
                                               "properties": {}}
    bare = json_schema_to_parameters({"type": "string"})
    assert bare["type"] == "object"
    assert bare["properties"]["value"]["type"] == "string"


def test_catalog_schema_uses_tool_description_default():
    schema = mcp_tool_to_catalog_schema({"name": "x", "inputSchema": {}})
    desc = schema["function"]["description"]
    assert "External MCP tool" in desc
    schema2 = mcp_tool_to_catalog_schema(
        {"name": "x", "description": "hello world", "inputSchema": {}})
    assert schema2["function"]["description"] == "hello world"


# ---------------------------------------------------------------------------
# 4. Payload execution (tools/call)
# ---------------------------------------------------------------------------

def test_call_tool_text_result(client):
    client.connect()
    assert client.call_tool("fs_read", {"path": "/tmp/x"}) == "FILE:/tmp/x"
    client.close()


def test_call_tool_structured_result_renders_json(client):
    client.connect()
    out = client.call_tool("gh-create-issue", {"title": "t", "labels": ["bug"]})
    assert "42" in out and "t" in out
    client.close()


def test_call_tool_passes_exact_arguments(client, fake_server):
    client.connect()
    client.call_tool("fs_read", {"path": "/a/b", "mode": "raw"})
    call = [c for c in fake_server.calls if c.get("method") == "tools/call"][0]
    assert call["params"]["name"] == "fs_read"
    assert call["params"]["arguments"] == {"path": "/a/b", "mode": "raw"}
    client.close()


def test_call_tool_is_error_raises(client):
    client.connect()
    with pytest.raises(McpToolError):
        client.call_tool("gh-create-issue", {"make_error": True})
    client.close()


def test_call_tool_jsonrpc_error_raises(client):
    client.connect()
    with pytest.raises(McpProtocolError):
        client.call_tool("nope", {})
    client.close()


def test_call_tool_requires_connection(client):
    with pytest.raises(McpError):
        client.call_tool("fs_read", {})


def test_rpc_protocol_error(client):
    client.connect()
    with pytest.raises(McpProtocolError):
        client.request("tools/nope", {})
    client.close()


# ---------------------------------------------------------------------------
# 5. Routing into the dynamic tool catalog / Swarm live maps
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_synthesized():
    for nm in list(synthesized_tool_catalog()):
        remove_synthesized_tool(nm)
    yield
    for nm in list(synthesized_tool_catalog()):
        remove_synthesized_tool(nm)


def test_as_tool_objects_builds_catalog_tools(client):
    client.connect()
    objs = client.as_tool_objects()
    assert len(objs) == 2
    for t in objs:
        assert isinstance(t, Tool)
        assert t.name.startswith("mcp_")
    client.close()


def test_wrapped_tool_runs_through_execute_tool_convention(client):
    client.connect()
    by_name = {t.name: t for t in client.as_tool_objects()}
    out = execute_tool(by_name, {"function": {
        "name": "mcp_fs_read",
        "arguments": json.dumps({"path": "/a/b"})}})
    assert out == "FILE:/a/b"
    # invalid JSON arguments must not crash the tool gateway
    out2 = execute_tool(by_name, {"function": {
        "name": "mcp_fs_read", "arguments": "not-json"}})
    assert out2 in ("FILE:", "FILE:/a/b") or "Bad arguments" in out2
    client.close()


def test_register_tools_hotloads_process_wide(client, clean_synthesized):
    client.connect()
    names = client.register_tools()
    assert names == ["mcp_fs_read", "mcp_gh_create_issue"]
    cat = synthesized_tool_catalog()
    assert "mcp_fs_read" in cat and "mcp_gh_create_issue" in cat
    # hot-reloaded tool executes end-to-end from the catalog entry
    tool = cat["mcp_fs_read"]
    assert tool.func(path="/x/y") == "FILE:/x/y"
    client.close()


def test_register_tools_adopts_live_tool_map(client, clean_synthesized):
    client.connect()
    tool_map = {}
    client.register_tools(tool_map=tool_map)
    # the adopted live catalog back-fills the hot-loaded MCP tools
    assert client.live_tool_map is not None
    assert "mcp_fs_read" in client.live_tool_map
    assert "mcp_gh_create_issue" in client.live_tool_map
    client.close()


