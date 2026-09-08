"""Model Context Protocol (MCP) client engine.

Dependency-light MCP client that speaks JSON-RPC 2.0 over either:

* a stdio transport (spawns ``command args...`` and exchanges one
  JSON-RPC message per newline-delimited line on stdin/stdout), or
* any JSON-RPC endpoint exposed as a synchronous ``send/recv`` channel
  (in-process adapter, HTTP wrapper, websocket shim, ...).

Implements the standard MCP client lifecycle used by every modern agent:

* ``initialize`` handshake (protocolVersion negotiation, clientInfo /
  capabilities exchange) plus the ``notifications/initialized`` notice,
* server introspection via ``tools/list`` (dynamic tool discovery),
* ``tools/call`` payload execution with typed content extraction,
* ``ping`` keep-alive / liveness probing.

Schema translation converts an MCP tool's ``inputSchema`` (JSON Schema)
into the exact OpenAI-style catalog shape the existing dynamic tool
catalog and ``Tool.schema()`` use, so a discovered MCP tool is
indistinguishable from a native tool to the agent loop.

Routing to the Swarm Orchestrator happens by materialising each remote
tool as a local :class:`Tool` whose ``func(**kwargs)`` performs a remote
``tools/call`` round-trip, then hot-loading it process-wide through the
existing catalog machinery (``hot_reload_tool`` /
``register_live_catalog``). One :class:`McpClient` bound to one MCP
server therefore shows up in every agent / sub-agent live tool map under
a namespaced ``<prefix><name>`` identifier.

The engine is transport-framing agnostic on purpose: the stdio framing
(jsonrpc server libraries use newline-delimited JSON) is implemented
here, while the 2025+ streamable-HTTP transport can be plugged in later
as another Channel subclass without touching any other layer.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("ai_agent.mcp")

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class McpError(Exception):
    """Base class for all MCP client failures."""


class McpTransportError(McpError):
    """Channel-level failure (spawn, EOF, framing, I/O)."""


class McpHandshakeError(McpError):
    """The MCP initialize exchange did not complete successfully."""


class McpProtocolError(McpError):
    """The peer returned a JSON-RPC error or an unexpected shape."""


class McpToolError(McpError):
    """A remote tool call reported isError=true / errored execution."""


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

_JSONRPC = "2.0"


def _extract_text_result(result: Dict[str, Any]) -> str:
    """Render an MCP ``tools/call`` result dict into a string.

    ``content`` entries of type ``text`` are joined verbatim; any
    ``structuredContent`` is appended as JSON for tooling that returns
    structured payloads instead of prose. Result framing from older
    servers that simply return ``{"result": ...}`` is tolerated too.
    """
    if not isinstance(result, dict):
        return str(result)
    if "content" in result and isinstance(result["content"], list):
        parts: List[str] = []
        for block in result["content"]:
            if not isinstance(block, dict):
                parts.append(str(block))
                continue
            kind = block.get("type", "text")
            if kind == "text":
                parts.append(str(block.get("text", "")))
            elif kind == "image":
                data = block.get("data")
                mime = block.get("mimeType", "image/png")
                parts.append("[image %s (%d bytes base64)]" % (
                    mime, len(data) if isinstance(data, str) else 0))
            elif kind == "resource":
                parts.append("[resource %s] %s" % (
                    block.get("resource", {}).get("uri", "?"),
                    block.get("resource", {}).get("text", "")))
            else:
                parts.append("[%s block omitted]" % kind)
        joined = "\n".join(p for p in parts if p)
        if joined:
            return joined
    if "structuredContent" in result:
        return json.dumps(result["structuredContent"], ensure_ascii=False,
                          default=str)
    if "text" in result:
        return str(result["text"])
    return json.dumps(result, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Transports / channels
# ---------------------------------------------------------------------------

class JsonRpcChannel:
    """Bidirectional JSON-RPC message pipe.

    Subclasses implement :meth:`send` / :meth:`recv` for one concrete
    transport and must be safe to call from multiple threads (the client
    serialises requests with a lock, so a per-connection lock is enough).
    """

    def send(self, message: Dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError

    def recv(self, timeout: float) -> Dict[str, Any]:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover
        raise NotImplementedError

    @property
    def label(self) -> str:  # pragma: no cover
        return self.__class__.__name__


class StdioChannel(JsonRpcChannel):
    """MCP stdio transport: one JSON-RPC message per newline-delimited line.

    Mirrors the framing used by the reference MCP TypeScript/Python SDKs
    (LSP-style newline-delimited JSON over the child's stdin/stdout).
    The child's stderr is drained to the module logger so a server
    crash or traceback surfaces as a diagnosable log entry instead of a
    silent pipe deadlock.
    """

    def __init__(self, command: str, args: Optional[List[str]] = None,
                 env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None):
        if not command or not isinstance(command, str):
            raise McpTransportError("stdio transport requires a command")
        self._command = command
        self._args = list(args or [])
        self._env = dict(os.environ)
        if env:
            self._env.update(env)
        self._cwd = cwd
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.RLock()
        self._read_lock = threading.Lock()
        self._eof = False

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> "StdioChannel":
        if self._proc is not None:
            return self
        try:
            self._proc = subprocess.Popen(
                [self._command] + self._args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env,
                cwd=self._cwd,
                bufsize=0,
            )
        except FileNotFoundError as exc:
            raise McpTransportError(
                "mcp server binary not found: %s (%s)" % (
                    self._command, exc)) from exc
        except Exception as exc:
            raise McpTransportError(
                "failed to spawn mcp server %r: %s" % (self._command, exc)
            ) from exc
        if self._proc.stderr is not None:
            threading.Thread(target=self._drain_stderr, daemon=True).start()
        log.debug("mcp stdio channel up: %s %s", self._command, self._args)
        return self

    def _drain_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        for raw in proc.stderr:
            line = raw.decode("utf-8", "replace").rstrip()
            if line:
                log.debug("[mcp-server] %s", line)

    # -- messaging ---------------------------------------------------------

    def send(self, message: Dict[str, Any]) -> None:
        self._require_proc()
        line = json.dumps(message, ensure_ascii=False,
                          separators=(",", ":")) + "\n"
        try:
            with self._lock:
                assert self._proc and self._proc.stdin
                self._proc.stdin.write(line.encode("utf-8"))
                self._proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise McpTransportError("stdio write failed: %s" % exc) from exc

    def recv(self, timeout: float = 30.0) -> Dict[str, Any]:
        self._require_proc()
        deadline = time.monotonic() + float(timeout)
        linebuf = b""
        with self._read_lock:
            while True:
                if self._eof:
                    raise McpTransportError("mcp server closed the stream (EOF)")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise McpTransportError(
                        "timed out waiting for mcp server response "
                        "(%.1fs)" % timeout)
                assert self._proc and self._proc.stdout
                try:
                    chunk = self._proc.stdout.read(1)
                except (OSError, ValueError) as exc:
                    raise McpTransportError("stdio read failed: %s" % exc) from exc
                if not chunk:  # EOF
                    self._eof = True
                    raise McpTransportError("mcp server closed the stream (EOF)")
                linebuf += chunk
                if chunk == b"\n":
                    break
        raw = linebuf.decode("utf-8", "replace").strip()
        if not raw:
            raise McpProtocolError("empty line from mcp server")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise McpProtocolError("invalid JSON from mcp server: %s" % exc) from exc
        if not isinstance(payload, dict):
            raise McpProtocolError("mcp server sent a non-object message")
        return payload

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _require_proc(self) -> None:
        if self._proc is None or self._proc.poll() is not None:
            raise McpTransportError("mcp stdio channel is not running")

    @property
    def label(self) -> str:
        return "%s %s" % (self._command, " ".join(self._args))


class EndpointChannel(JsonRpcChannel):
    """Adapter over an existing synchronous JSON-RPC endpoint.

    ``exchange`` is a callable ``(payload: dict) -> dict`` that performs
    one request/response round-trip against an arbitrary JSON-RPC
    endpoint (HTTP POST via requests/urllib, websocket, unix socket, or
    an in-process fake used by tests). ``send`` stores the payload and
    ``recv`` drives the exchange, so the channel honours the same
    send/recv contract as the stdio transport.
    """

    def __init__(self, exchange: Callable[[Dict[str, Any]], Dict[str, Any]],
                 label: str = "json-rpc-endpoint"):
        if not callable(exchange):
            raise McpTransportError("endpoint channel requires a callable exchange")
        self._exchange = exchange
        self._label = label
        self._lock = threading.RLock()
        self._pending: List[Dict[str, Any]] = []
        self._closed = False

    def send(self, message: Dict[str, Any]) -> None:
        with self._lock:
            self._pending.append(message)

    def recv(self, timeout: float = 30.0) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise McpTransportError("endpoint channel is closed")
            if not self._pending:
                raise McpTransportError("endpoint channel recv with no pending request")
            request = self._pending.pop(0)
            if request.get("method") == "notifications/initialized":
                return {}  # notifications have no response; consume quietly
            return self._exchange(request)

    def close(self) -> None:
        self._closed = True

    @property
    def label(self) -> str:
        return self._label


class _QueueChannel(JsonRpcChannel):
    """Queue-backed channel for tests / in-process fake MCP servers.

    Two connected halves each carry a send queue; :meth:`send` appends
    to the peer's queue and :meth:`recv` blocks on the local one.
    """

    def __init__(self, name: str = "chan") -> None:
        import queue
        self._name = name
        self._out: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._in: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._peer: Optional["_QueueChannel"] = None
        self._lock = threading.RLock()

    def link(self, peer: "_QueueChannel") -> None:
        self._peer = peer
        peer._peer = self

    def send(self, message: Dict[str, Any]) -> None:
        peer = self._peer
        if peer is None:
            raise McpTransportError("queue channel has no peer")
        peer._in.put(message)

    def recv(self, timeout: float = 30.0) -> Dict[str, Any]:
        import queue
        try:
            return self._in.get(timeout=float(timeout))
        except queue.Empty as exc:
            raise McpTransportError("queue channel recv timed out") from exc

    def close(self) -> None:
        pass

    @property
    def label(self) -> str:
        return self._name


# ---------------------------------------------------------------------------
# Schema translation
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_JSONSCHEMA_TO_PARAMS = {
    "string": "string",
    "number": "number",
    "integer": "integer",
    "boolean": "boolean",
    "array": "array",
    "object": "object",
    "null": "null",
}


def safe_tool_identifier(name: str, fallback: str = "mcp_tool") -> str:
    """Normalise an arbitrary MCP tool name into a Python identifier."""
    if not isinstance(name, str):
        name = str(name)
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not cleaned:
        cleaned = fallback
    if cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned


def json_schema_to_parameters(schema: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Translate an MCP tool ``inputSchema`` into catalog ``parameters``.

    MCP servers usually send JSON Schema whose root is already
    ``{"type": "object", "properties": {...}, "required": [...]}`` - the
    exact OpenAI-style shape used by :class:`Tool` / ``Tool.schema()``.
    This normalises degenerate shapes (missing root, no properties,
    non-object root) so translation is deterministic for every server.
    """
    if not isinstance(schema, dict):
        schema = {}
    ptype = schema.get("type")
    if ptype not in ("object", None):
        # Wrap e.g. a bare property-list root into an object container.
        return {
            "type": "object",
            "properties": {
                "value": {"type": _JSONSCHEMA_TO_PARAMS.get(
                    str(ptype), "string"), "description": "input value"},
            },
        }
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        properties = {}
    required = schema.get("required")
    if not isinstance(required, list):
        required = []
    required = [r for r in required if isinstance(r, str)]
    out: Dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        out["required"] = required
    return out


def mcp_tool_to_catalog_schema(mcp_tool: Dict[str, Any],
                               prefix: str = "mcp_") -> Dict[str, Any]:
    """Full OpenAI ``{"type": "function", "function": {...}}`` schema.

    Matches :meth:`Tool.schema` byte-for-byte so MCP tools drop straight
    into the agent's tool catalog without special-casing in the LLM loop.
    """
    name = (mcp_tool or {}).get("name") or "mcp_tool"
    description = (mcp_tool or {}).get("description") or (
        "External MCP tool '%s' (exposed through the MCP client gateway)."
        % name)
    input_schema = (mcp_tool or {}).get("inputSchema")
    return {
        "type": "function",
        "function": {
            "name": prefix + safe_tool_identifier(name),
            "description": description,
            "parameters": json_schema_to_parameters(input_schema),
        },
    }


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------

class McpClient:
    """A single MCP client bound to one remote MCP server.

    Parameters
    ----------
    command : str
        Executable to spawn for the stdio transport. Mutually exclusive
        with ``channel`` / ``exchange``.
    args : list[str]
        Arguments for ``command``.
    env : dict[str, str]
        Extra environment for the spawned server process.
    channel : JsonRpcChannel
        Pre-built transport (overrides stdio spawning).
    exchange : callable
        Shortcut: wraps ``endpoint`` in an :class:`EndpointChannel`.
    endpoint_label : str
        Human label for ``exchange`` channels.
    client_name / client_version
        Identifiers sent in the ``initialize`` handshake.
    protocol_version
        Requested MCP protocol version (server may negotiate down).
    request_timeout
        Per-request JSON-RPC timeout in seconds.
    auto_handshake
        When True (default) connect() performs the initialize exchange.
    """

    def __init__(self,
                 command: Optional[str] = None,
                 args: Optional[List[str]] = None,
                 env: Optional[Dict[str, str]] = None,
                 cwd: Optional[str] = None,
                 channel: Optional[JsonRpcChannel] = None,
                 exchange: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
                 endpoint_label: str = "json-rpc-endpoint",
                 client_name: str = "ai-agent-mcp-client",
                 client_version: str = "1.0.0",
                 protocol_version: str = "2025-03-26",
                 request_timeout: float = 30.0,
                 auto_handshake: bool = True) -> None:
        if channel is not None:
            self._channel = channel
        elif exchange is not None:
            self._channel = EndpointChannel(exchange, label=endpoint_label)
        elif command:
            self._channel = StdioChannel(command, args=args, env=env, cwd=cwd)
        else:
            raise McpError("McpClient requires command=, channel= or exchange=")
        self.client_name = client_name
        self.client_version = client_version
        self.protocol_version = protocol_version
        self.request_timeout = request_timeout
        self.auto_handshake = auto_handshake

        self._seq = 0
        self._io_lock = threading.RLock()
        self._connected = False
        self._server_info: Dict[str, Any] = {}
        self._server_capabilities: Dict[str, Any] = {}
        self._tools_cache: List[Dict[str, Any]] = []
        self._tools_at: float = 0.0
        self._tools_ttl: float = 5.0  # seconds; refresh after expiry

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> "McpClient":
        """Open the transport and perform the MCP initialize handshake."""
        if self._connected:
            return self
        if isinstance(self._channel, StdioChannel):
            self._channel.open()
        try:
            if self.auto_handshake:
                info = self._initialize()
                self._server_info = info.get("serverInfo", {})
                caps = info.get("capabilities")
                if isinstance(caps, dict):
                    self._server_capabilities = caps
            self._connected = True
        except Exception:
            self.close()
            raise
        log.info("mcp connected: %s | server=%s | caps=%s",
                 self._channel.label,
                 self._server_info.get("name", "?"),
                 sorted(self._server_capabilities.keys()))
        return self

    def _initialize(self) -> Dict[str, Any]:
        result = self.request(
            "initialize",
            {
                "protocolVersion": self.protocol_version,
                "capabilities": {},
                "clientInfo": {
                    "name": self.client_name,
                    "version": self.client_version,
                },
            },
        )
        # spec: after a successful initialize the client must send the
        # initialized notification before any other request.
        self._notify("notifications/initialized", {})
        if not isinstance(result, dict):
            raise McpHandshakeError("initialize returned a non-object result")
        if "serverInfo" not in result and "protocolVersion" not in result:
            raise McpHandshakeError(
                "server initialize result missing serverInfo/protocolVersion: %r"
                % result)
        return result

    # ------------------------------------------------------------------
    # JSON-RPC plumbing
    # ------------------------------------------------------------------

    def request(self, method: str, params: Optional[Dict[str, Any]] = None
                ) -> Dict[str, Any]:
        """Send one JSON-RPC request and wait for its matching response."""
        with self._io_lock:
            self._seq += 1
            req_id = self._seq
            message: Dict[str, Any] = {
                "jsonrpc": _JSONRPC,
                "id": req_id,
                "method": method,
            }
            if params is not None:
                message["params"] = params
            # EndpointChannel delivers via the exchange callable, which
            # performs the round-trip synchronously.
            if isinstance(self._channel, EndpointChannel):
                response = self._channel._exchange(message)  # type: ignore
                return self._validate_response(req_id, response)
            self._channel.send(message)
            deadline = time.monotonic() + float(self.request_timeout)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise McpTransportError(
                        "mcp request %r timed out after %.1fs"
                        % (method, self.request_timeout))
                response = self._channel.recv(remaining)
                if not isinstance(response, dict):
                    continue
                if response.get("method") and "id" not in response:
                    # server -> client notification; spec says ignore.
                    continue
                if response.get("id") != req_id:
                    # Response for a request we did not issue (e.g. a late
                    # reply after our timeout) - drop it and keep waiting.
                    log.debug("dropping mismatched mcp response: %r", response)
                    continue
                return self._validate_response(req_id, response)

    def _notify(self, method: str, params: Optional[Dict[str, Any]] = None
                ) -> None:
        message: Dict[str, Any] = {"jsonrpc": _JSONRPC, "method": method}
        if params is not None:
            message["params"] = params
        if isinstance(self._channel, EndpointChannel):
            try:
                self._channel._exchange(message)  # type: ignore
            except Exception as exc:  # notifications are fire-and-forget
                log.debug("notification %s dropped: %s", method, exc)
            return
        try:
            self._channel.send(message)
        except McpTransportError as exc:
            log.debug("notification %s send failed: %s", method, exc)

    def _validate_response(self, req_id: int, response: Dict[str, Any]
                           ) -> Dict[str, Any]:
        if "error" in response and response["error"] is not None:
            err = response["error"]
            code = err.get("code", -32603) if isinstance(err, dict) else -32603
            msg = err.get("message", "json-rpc error") if isinstance(err, dict) else str(err)
            raise McpProtocolError(
                "mcp request id=%d failed (%d): %s" % (req_id, code, msg))
        if "result" not in response:
            raise McpProtocolError(
                "mcp response id=%d missing 'result': %r" % (req_id, response))
        result = response.get("result")
        if isinstance(result, dict):
            return result
        return {"value": result}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def server_info(self) -> Dict[str, Any]:
        return dict(self._server_info)

    @property
    def server_capabilities(self) -> Dict[str, Any]:
        return dict(self._server_capabilities)

    def ping(self, timeout: Optional[float] = None) -> bool:
        """Liveness probe. Returns True when the server answers."""
        if not self._connected:
            return False
        old = self.request_timeout
        try:
            if timeout is not None:
                self.request_timeout = float(timeout)
            result = self.request("ping", {})
            return bool(result.get("value", True))
        except McpError:
            return False
        finally:
            self.request_timeout = old

    def refresh_tools(self) -> List[Dict[str, Any]]:
        """Force a fresh ``tools/list`` round-trip from the server."""
        result = self.request("tools/list", {})
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise McpProtocolError("tools/list returned no tools array")
        self._tools_cache = [t for t in tools if isinstance(t, dict)]
        self._tools_at = time.monotonic()
        return list(self._tools_cache)

    def discover_tools(self, refresh: bool = False) -> List[Dict[str, Any]]:
        """Dynamically discover remote tools (cached, TTL-bounded).

        Identical to :meth:`refresh_tools` but served from a short-lived
        cache so the agent loop never hammers the server mid-turn.
        """
        if refresh or not self._tools_cache \
                or (time.monotonic() - self._tools_at) > self._tools_ttl:
            return self.refresh_tools()
        return list(self._tools_cache)

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None,
                  _raise_on_error: bool = True) -> str:
        """Execute one remote tool. Returns a rendered string result."""
        if not self._connected:
            raise McpError("call_tool requires connect() first")
        if not isinstance(arguments, dict) or arguments is None:
            arguments = {}
        result = self.request("tools/call",
                              {"name": name, "arguments": arguments})
        if result.get("isError"):
            if _raise_on_error:
                raise McpToolError(
                    "remote tool %r reported an error: %s"
                    % (name, _extract_text_result(result)))
            return "Error: %s" % _extract_text_result(result)
        return _extract_text_result(result)

    # ------------------------------------------------------------------
    # Schema translation API
    # ------------------------------------------------------------------

    @staticmethod
    def to_parameters(input_schema: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return json_schema_to_parameters(input_schema)

    def to_catalog_schema(self, mcp_tool: Dict[str, Any],
                          prefix: str = "mcp_") -> Dict[str, Any]:
        return mcp_tool_to_catalog_schema(mcp_tool, prefix=prefix)

    def catalog_schemas(self, prefix: str = "mcp_") -> List[Dict[str, Any]]:
        """Full catalog schemas for every discovered tool.

        Feed this list into the Swarm Orchestrator's tool-schema view so
        sub-agents see remote MCP tools exactly like native tools.
        """
        return [mcp_tool_to_catalog_schema(t, prefix=prefix)
                for t in self.discover_tools()]

    # ------------------------------------------------------------------
    # Routing to the dynamic tool catalog / Swarm Orchestrator
    # ------------------------------------------------------------------

    def make_tool(self, mcp_tool: Dict[str, Any], prefix: str = "mcp_",
                  confirm: bool = False):
        """Wrap one discovered MCP tool into a local catalog Tool.

        The returned object exposes ``schema()`` identical to every
        native tool; calling its ``func(**kwargs)`` (the exact calling
        convention used by ``execute_tool``) performs the remote
        ``tools/call`` round-trip on this client.
        """
        from ai_agent.tools.base import Tool  # lazy: avoid import cycles

        name = (mcp_tool or {}).get("name") or "mcp_tool"
        local_name = prefix + safe_tool_identifier(name)
        description = (mcp_tool or {}).get("description") or (
            "External MCP tool '%s' (MCP client gateway)." % name)
        parameters = json_schema_to_parameters(
            (mcp_tool or {}).get("inputSchema"))
        client = self
        remote_name = name

        def _remote_call(**kwargs: Any) -> str:
            return client.call_tool(remote_name, kwargs or None)

        return Tool(name=local_name, description=description,
                    parameters=parameters, func=_remote_call,
                    confirm=confirm)

    def as_tool_objects(self, prefix: str = "mcp_",
                        confirm: bool = False) -> List[Any]:
        """Materialise every discovered tool as a catalog Tool object."""
        return [self.make_tool(t, prefix=prefix, confirm=confirm)
                for t in self.discover_tools()]

    def register_tools(self, prefix: str = "mcp_", confirm: bool = False,
                       tool_map: Optional[Dict[str, Any]] = None
                       ) -> List[str]:
        """Route discovered tools into the dynamic tool catalog.

        Each remote tool is hot-registered process-wide through the same
        machinery the Self-Evolution Engine uses (``hot_reload_tool``),
        which fans it out to every live agent/sub-agent catalog via
        ``register_live_catalog``. Pass ``tool_map`` to also adopt the
        caller's own {name: Tool} map as a live catalog.

        Returns the list of local tool names registered.
        """
        from ai_agent.tools import hot_reload_tool, register_live_catalog

        names: List[str] = []
        for t in self.discover_tools():
            tool = self.make_tool(t, prefix=prefix, confirm=confirm)
            hot_reload_tool(tool)
            names.append(tool.name)
        if tool_map is not None:
            if not isinstance(tool_map, dict):
                raise TypeError("tool_map must be a dict of {name: Tool}")
            # register_live_catalog() drains tool_map into a _LiveToolMap
            # and back-fills every hot-loaded tool (incl. the MCP tools
            # registered just above), so the caller's own map becomes a
            # live catalog for the Swarm Orchestrator immediately.
            register_live_catalog(tool_map)
        log.info("registered %d mcp tools under prefix %r: %s",
                 len(names), prefix, names)
        return names

    # ------------------------------------------------------------------
    # Context manager & teardown
    # ------------------------------------------------------------------

    def close(self) -> None:
        try:
            self._channel.close()
        except Exception:
            pass
        self._connected = False

    def __enter__(self) -> "McpClient":
        return self.connect()

    def __exit__(self, *exc: Any) -> None:
        self.close()
