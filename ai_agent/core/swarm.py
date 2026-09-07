"""Sub-Agent Swarm Framework & State Isolation.

A dependency-light asyncio orchestrator that spawns specialized
sub-agents (``ReconSubAgent``, ``PayloadSubAgent``, ``ReporterSubAgent``),
moves typed messages between them over an in-process async bus, and keeps
shared-context state isolated per agent in a SQLite-backed store.

Layers
------
* :class:`StateStore`  - SQLite (stdlib) shared-context store. Every value is
  namespaced. A sub-agent only ever holds an :class:`AgentState` view bound to
  its *own* namespace plus read access to the shared namespace; sibling
  namespaces are unreachable from inside an agent. That binding is what
  enforces context isolation. (ChromaDB can be swapped in later behind the
  same ``AgentState`` interface if embedding similarity is required.)
* :class:`MessageBus`  - async message passing. Each agent owns an
  ``asyncio.Queue`` mailbox. ``recipient`` routes to an agent id, a role
  (all agents of that kind), or ``"*"`` (broadcast). Every message is also
  mirrored into SQLite (``msglog``) for audit/replay. Replies resolve pending
  ``ask()`` futures by correlation id, so orchestration is request/reply.
* :class:`BaseSubAgent` - lifecycle loop (created -> running/idle ->
  stopped/error), a convention that ``on_<message type>`` coroutines handle
  messages, and namespace-scoped state helpers. Agents never touch foreign
  namespaces; cross-agent data flows only through routed messages.
* :class:`SwarmOrchestrator` - spawn/kill agents, ``ask()`` RPC with timeout,
  ``broadcast()`` events, direct ``send()``, and a read-only ``context()``
  that lets *orchestration* compose the next task's context out of any
  namespace (agents cannot).

Usage::

    orb = SwarmOrchestrator()              # :memory: sqlite
    recon = await orb.spawn("recon", config={"ports": [80, 443]})
    result = await orb.ask("recon", "task.recon", {"target": "10.0.0.0/24"})
    rep = await orb.spawn("reporter")
    report = await orb.ask("reporter", "task.report",
                           {"context": orb.context()})
    await orb.shutdown()
"""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("my-agent.swarm")


class SwarmError(Exception):
    """Base error for the swarm framework."""


class IsolationError(SwarmError):
    """Raised when orchestration tries to violate store-level isolation."""


# --------------------------------------------------------------------------
# Messages
# --------------------------------------------------------------------------

@dataclass
class Message:
    """One typed message travelling over the :class:`MessageBus`.

    ``recipient`` is an agent id, a role name (e.g. ``"recon"``), or ``"*"``
    for broadcast. A reply reuses the request's ``corr`` and sets
    ``reply_to`` so the caller's pending ``ask()`` future resolves.
    """
    mtype: str
    sender: str
    recipient: str
    payload: Dict[str, Any] = field(default_factory=dict)
    corr: str = field(default_factory=lambda: uuid.uuid4().hex)
    reply_to: Optional[str] = None
    ts: float = field(default_factory=time.time)

    @property
    def is_reply(self) -> bool:
        return self.mtype.endswith(".reply")


# --------------------------------------------------------------------------
# SQLite-backed shared-context store
# --------------------------------------------------------------------------

class StateStore:
    """Thread-safe, namespace-isolated key/value store on SQLite.

    Keys live in namespaces (``state(ns, key, value, updated_at)``). Agents
    reach the store only through :class:`AgentState`, which pins them to one
    namespace, so isolation is structural rather than by convention.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS state ("
                "  ns TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,"
                "  updated_at REAL NOT NULL,"
                "  PRIMARY KEY (ns, key))"
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS msglog ("
                "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  corr TEXT NOT NULL, ts REAL NOT NULL,"
                "  sender TEXT NOT NULL, recipient TEXT NOT NULL,"
                "  mtype TEXT NOT NULL, payload TEXT NOT NULL)"
            )

    # -- state -------------------------------------------------------------

    def set(self, ns: str, key: str, value: Any) -> None:
        raw = json.dumps(value, ensure_ascii=False, default=str)
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO state (ns, key, value, updated_at)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT(ns, key) DO UPDATE SET"
                "  value=excluded.value, updated_at=excluded.updated_at",
                (ns, key, raw, time.time()),
            )

    def get(self, ns: str, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM state WHERE ns=? AND key=?", (ns, key)
            ).fetchone()
        return json.loads(row["value"]) if row else default

    def get_prefix(self, ns: str, prefix: str = "") -> Dict[str, Any]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT key, value FROM state WHERE ns=? AND key LIKE ?",
                (ns, prefix + "%"),
            ).fetchall()
        return {r["key"]: json.loads(r["value"]) for r in rows}

    def snapshot(self, ns: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """Full store view for orchestration (agents have no such access)."""
        with self._lock:
            if ns is None:
                rows = self._conn.execute(
                    "SELECT ns, key, value FROM state"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT ns, key, value FROM state WHERE ns=?", (ns,)
                ).fetchall()
        out: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            out.setdefault(r["ns"], {})[r["key"]] = json.loads(r["value"])
        return out

    def namespaces(self) -> List[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT ns FROM state"
            ).fetchall()
        return [r["ns"] for r in rows]

    # -- message log -------------------------------------------------------

    def log_message(self, msg: Message) -> None:
        raw = json.dumps(msg.payload, ensure_ascii=False, default=str)
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO msglog (corr, ts, sender, recipient, mtype, payload)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (msg.corr, msg.ts, msg.sender, msg.recipient, msg.mtype, raw),
            )

    def history(self, mtype: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        sql = "SELECT corr, ts, sender, recipient, mtype, payload FROM msglog"
        args: tuple = ()
        if mtype:
            sql += " WHERE mtype=?"
            args = (mtype,)
        sql += " ORDER BY id ASC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, args + (limit,)).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            item["payload"] = json.loads(item["payload"])
            out.append(item)
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()

class AgentState:
    """Namespace-scoped view handed to a sub-agent.

    ``set/get/items`` operate only on the agent's own namespace;
    ``shared_get`` reads the orchestrator-seeded shared namespace. There is
    no API to reach a sibling namespace, which is the isolation boundary.
    """

    __slots__ = ("_store", "_ns", "_shared")

    def __init__(self, store: StateStore, namespace: str, shared: str) -> None:
        self._store = store
        self._ns = namespace
        self._shared = shared

    @property
    def namespace(self) -> str:
        return self._ns

    def set(self, key: str, value: Any) -> None:
        self._store.set(self._ns, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        return self._store.get(self._ns, key, default)

    def items(self, prefix: str = "") -> Dict[str, Any]:
        return self._store.get_prefix(self._ns, prefix)

    def shared_get(self, key: str, default: Any = None) -> Any:
        return self._store.get(self._shared, key, default)


# --------------------------------------------------------------------------
# Async message bus
# --------------------------------------------------------------------------

class MessageBus:
    """Async pub/sub bus with per-agent mailboxes + correlation replies.

    Every published message is persisted to the store's ``msglog`` so a
    mission can be audited or replayed. Replies do not need a mailbox for the
    requester: the bus resolves the pending ``ask()`` future by correlation
    id before routing.
    """

    def __init__(self, store: Optional[StateStore] = None,
                 log_messages: bool = True) -> None:
        self._store = store
        self._log = log_messages
        self._mailboxes: Dict[str, Tuple[str, asyncio.Queue]] = {}  # id -> (role, q)
        self._waiters: Dict[str, asyncio.Future] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def register(self, agent_id: str, role: str, mailbox: asyncio.Queue) -> None:
        if agent_id in self._mailboxes:
            raise SwarmError(f"agent {agent_id!r} already registered")
        self._mailboxes[agent_id] = (role, mailbox)

    def unregister(self, agent_id: str) -> None:
        self._mailboxes.pop(agent_id, None)

    def agents(self) -> Dict[str, str]:
        return {aid: role for aid, (role, _q) in self._mailboxes.items()}

    def _targets(self, recipient: str) -> List[str]:
        if recipient == "*":
            return list(self._mailboxes.keys())
        if recipient in self._mailboxes:
            return [recipient]
        role = recipient.lower()
        return [aid for aid, (r, _q) in self._mailboxes.items() if r == role]

    async def publish(self, msg: Message) -> None:
        """Route ``msg`` to its mailbox(es), persisting it to the audit log."""
        if self._log and self._store is not None:
            self._store.log_message(msg)
        if msg.is_reply and msg.corr in self._waiters:
            fut = self._waiters.pop(msg.corr)
            if not fut.done():
                fut.set_result(msg)
        targets = self._targets(msg.recipient)
        if not targets:
            if msg.is_reply and msg.corr not in self._waiters:
                # caller already gone (ask timed out) - reply is dropped
                return
            raise SwarmError(f"no route for recipient {msg.recipient!r}")
        for aid in targets:
            await self._mailboxes[aid][1].put(msg)

    def ask(self, corr: str) -> asyncio.Future:
        """Register a waiter future that the matching ``*.reply`` resolves.

        The future is created on the running loop and stored by correlation
        id; ``publish`` completes it when a reply with the same ``corr``
        arrives (even before routing, so requesters need no mailbox).
        """
        if self._loop is None:
            self._loop = asyncio.get_running_loop()
        fut: asyncio.Future = self._loop.create_future()
        self._waiters[corr] = fut
        return fut


# --------------------------------------------------------------------------
# Sub-agent base + specialized roles
# --------------------------------------------------------------------------

class BaseSubAgent:
    """A single swarm worker with its own mailbox and lifecycle.

    Subclasses set :attr:`role` and implement ``on_<type>`` coroutines for
    each message type they accept. The default loop marks the agent idle when
    the mailbox is empty, running while it processes, stopped on shutdown and
    error on a handler exception (the loop survives so later work can still
    be handled).
    """

    role: str = "base"
    STOP_TYPE = "ctl.stop"

    def __init__(self, agent_id: str, bus: MessageBus, store: StateStore,
                 config: Optional[Dict[str, Any]] = None,
                 shared_ns: str = "shared") -> None:
        self.agent_id = agent_id
        self.bus = bus
        self.store = store
        self.shared_ns = shared_ns
        self.config: Dict[str, Any] = config or {}
        self.namespace = f"{self.role}:{self.agent_id}"
        self.state = AgentState(store, self.namespace, shared_ns)
        self._mailbox: asyncio.Queue = asyncio.Queue(maxsize=4096)
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._lifecycle = "created"  # created|running|idle|stopped|error
        self._handled = 0
        self._last_error: Optional[str] = None
        self._spawned_at = time.time()
        bus.register(agent_id, self.role, self._mailbox)

    # -- lifecycle ---------------------------------------------------------

    @property
    def lifecycle(self) -> str:
        return self._lifecycle

    async def start(self) -> None:
        if self._task is not None:
            raise SwarmError(f"agent {self.agent_id} already started")
        self._lifecycle = "running"
        self._task = asyncio.create_task(
            self._run_loop(), name=f"swarm:{self.role}:{self.agent_id}"
        )

    async def _run_loop(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    msg = await asyncio.wait_for(self._mailbox.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    self._lifecycle = "idle"
                    continue
                except asyncio.CancelledError:
                    break
                self._lifecycle = "running"
                try:
                    out = await self.handle(msg)
                except Exception as exc:  # noqa: BLE001 - keep the loop alive
                    self._lifecycle = "error"
                    self._last_error = f"{type(exc).__name__}: {exc}"
                    log.warning("sub-agent %s failed on %s: %s",
                                self.agent_id, msg.mtype, self._last_error)
                    out = {"ok": False, "error": self._last_error}
                self._handled += 1
                if out is not None and msg.reply_to:
                    await self.reply(msg, out)
                if msg.mtype == self.STOP_TYPE:
                    self._stop.set()
        finally:
            self._lifecycle = "stopped"
            self.bus.unregister(self.agent_id)

    async def handle(self, msg: Message) -> Optional[Dict[str, Any]]:
        """Dispatch ``msg`` to ``on_<mtype with dots replaced>`` or reply error."""
        if msg.mtype == self.STOP_TYPE:
            return None
        handler: Optional[Callable[[Message], Awaitable[Any]]] = getattr(
            self, "on_" + msg.mtype.replace(".", "_"), None
        )
        if handler is None:
            return {"ok": False, "error": f"unhandled message type {msg.mtype!r}"}
        return await handler(msg)

    async def reply(self, req: Message, result: Dict[str, Any]) -> None:
        await self.bus.publish(Message(
            mtype=req.mtype + ".reply",
            sender=self.agent_id,
            recipient=req.reply_to or req.sender,
            payload=result,
            corr=req.corr,
            reply_to=self.agent_id,
        ))

    async def send_to(self, recipient: str, mtype: str,
                      payload: Optional[Dict[str, Any]] = None) -> None:
        """Agent-to-agent message (fire and forget)."""
        await self.bus.publish(Message(
            mtype=mtype, sender=self.agent_id, recipient=recipient,
            payload=payload or {},
        ))

    async def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        try:
            await self._mailbox.put(Message(
                mtype=self.STOP_TYPE, sender="orchestrator",
                recipient=self.agent_id,
            ))
        except Exception:  # noqa: BLE001 - already stopping
            pass
        if self._task is None:
            return
        try:
            await asyncio.wait_for(asyncio.shield(self._task), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    # -- status ------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "lifecycle": self._lifecycle,
            "handled": self._handled,
            "namespace": self.namespace,
            "last_error": self._last_error,
            "uptime": round(time.time() - self._spawned_at, 3),
        }


class ReconSubAgent(BaseSubAgent):
    """Discovers observations about a target and records them in its namespace.

    The shipped ``_discover`` returns a deterministic structured profile so
    the framework runs anywhere (no scanner binary required). Point
    ``config["scanner"]`` at an async callable for real tooling:
    ``scanner(target, options) -> dict``.
    """

    role = "recon"

    async def on_task_recon(self, msg: Message) -> Dict[str, Any]:
        target = msg.payload.get("target")
        if not target:
            return {"ok": False, "error": "payload requires 'target'"}
        options = msg.payload.get("options") or {}
        profile = await self._discover(target, options)
        self.state.set("recon.findings", profile)
        return {
            "ok": True,
            "agent": self.agent_id,
            "target": target,
            "findings": profile,
            "ref": f"{self.namespace}:recon.findings",
        }

    async def _discover(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        scanner = self.config.get("scanner")
        if scanner is not None:
            found = await scanner(target, options)
            return {"host": target, "source": "custom-scanner",
                    "data": found, "ts": time.time()}
        ports = options.get("ports") or self.config.get("ports") or [80, 443, 8080]
        services = [f"tcp/{p}" for p in ports]
        return {
            "host": target,
            "source": "framework-profile",
            "ports": list(ports),
            "services": services,
            "open_count": len(services),
            "tags": ["in-scope", "simulated"],
            "ts": time.time(),
        }


class PayloadSubAgent(BaseSubAgent):
    """Assembles a payload descriptor for a requested attack kind.

    Pure framework: returns a validated metadata descriptor. The descriptor
    is handed to the orchestrator / external executor, never executed by the
    framework itself. Records every build in its private namespace.
    """

    role = "payload"

    KNOWN_KINDS = frozenset({
        "sqli", "xss", "command-injection", "ssrf", "xxe",
        "path-traversal", "open-redirect",
    })

    async def on_ctl_validate(self, msg: Message) -> Dict[str, Any]:
        """Framework probe - return availability so workers never answer on
        the control channel even if a role accidentally matches it."""
        kind = str((msg.payload or {}).get("kind") or "").lower()
        return {"ok": True, "supported": kind in self.KNOWN_KINDS}

    async def on_task_payload(self, msg: Message) -> Dict[str, Any]:
        kind = str(msg.payload.get("kind") or "generic").lower()
        target = msg.payload.get("target")
        transport = msg.payload.get("transport", "https")
        if kind not in self.KNOWN_KINDS:
            return {"ok": False, "error": f"unknown payload kind {kind!r}",
                    "supported": sorted(self.KNOWN_KINDS)}
        descriptor = {
            "kind": kind,
            "target": target,
            "transport": transport,
            "generator": self.agent_id,
            "payload": self._render(kind, target, transport),
            "ts": time.time(),
        }
        self.state.set(f"payloads.{kind}", descriptor)
        return {"ok": True, "agent": self.agent_id, "descriptor": descriptor}

    def _render(self, kind: str, target: Any, transport: str) -> Dict[str, Any]:
        base = {"transport": transport}
        if kind == "sqli":
            return {**base, "vector": "' OR 1=1 --", "technique": "error-based"}
        if kind == "xss":
            return {**base, "vector": "<script>alert(1)</script>",
                    "context": "reflected"}
        if kind == "command-injection":
            return {**base, "vector": "; id", "shell": "sh"}
        if kind == "ssrf":
            return {**base, "vector": "http://169.254.169.254/latest/meta-data/"}
        if kind == "xxe":
            return {**base, "vector": "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>",
                    "entity": "x"}
        if kind == "path-traversal":
            return {**base, "vector": "../../../../etc/passwd"}
        if kind == "open-redirect":
            return {**base, "vector": "//evil.example.com"}
        return {**base, "vector": "generic"}


class ReporterSubAgent(BaseSubAgent):
    """Aggregates an assessment snapshot from the messages it receives.

    ``on_task_report`` only consumes the payload it is handed by the
    orchestrator (the orchestrated cross-namespace read flow) and stores the
    consolidated record in its own namespace. It never reaches into another
    agent's namespace itself, which keeps state isolation intact while still
    supporting end-to-end pipelines.
    """

    role = "reporter"

    async def on_task_report(self, msg: Message) -> Dict[str, Any]:
        items = msg.payload.get("findings") or []
        report = {
            "report_id": uuid.uuid4().hex[:12],
            "target": msg.payload.get("target"),
            "finding_count": len(items),
            "findings": items,
            "status": "draft",
            "ts": time.time(),
        }
        self.state.set("reports.latest", report)
        seq = int(self.state.get("reports.seq") or 0) + 1
        self.state.set("reports.seq", seq)
        self.state.set(f"reports.{seq}", report)
        return {"ok": True, "agent": self.agent_id, "report": report}


class SwarmOrchestrator:
    """Owns the bus + isolated state store and supervises a sub-agent swarm.

    Responsibilities:
    * spawn / stop workers (registry extensible via :meth:`register_kind`),
    * fire-and-forget ``send``, one-shot ``ask`` (role or agent id) and
      ``broadcast`` messaging,
    * lifecycle + status visibility and clean ``shutdown``,
    * a shared, read-only-for-agents context namespace the orchestrator
      writes into (workers see it via ``AgentState.shared_get``).

    Each worker keeps its own private namespace inside the SQLite-backed
    store, giving per-sub-agent state isolation on top of a single process.
    """

    def __init__(self, store: Optional[StateStore] = None,
                 bus: Optional[MessageBus] = None,
                 shared_ns: str = "shared") -> None:
        self.shared_ns = shared_ns
        self.store = store if store is not None else StateStore()
        self.bus = bus if bus is not None else MessageBus(self.store)
        self._kinds: Dict[str, type] = {}
        self._agents: Dict[str, BaseSubAgent] = {}
        self._counters: Dict[str, int] = {}
        self._closed = False
        # built-in roles ship with the framework
        self.register_kind("recon", ReconSubAgent)
        self.register_kind("payload", PayloadSubAgent)
        self.register_kind("reporter", ReporterSubAgent)

    # -- registry ----------------------------------------------------------

    def register_kind(self, kind: str, cls: type) -> None:
        if not (isinstance(cls, type) and issubclass(cls, BaseSubAgent)):
            raise TypeError(f"{kind!r} must be a BaseSubAgent subclass")
        self._kinds[kind] = cls

    @property
    def kinds(self) -> List[str]:
        return sorted(self._kinds)

    @property
    def running(self) -> List[str]:
        return sorted(self._agents)

    def get(self, agent_id: str) -> BaseSubAgent:
        """Return the live agent handle or raise SwarmError."""
        agent = self._agents.get(agent_id)
        if agent is None:
            raise SwarmError(f"no such agent {agent_id!r}")
        return agent

    # -- lifecycle ---------------------------------------------------------

    async def spawn(self, kind: str, agent_id: Optional[str] = None,
                    config: Optional[Dict[str, Any]] = None) -> BaseSubAgent:
        if self._closed:
            raise SwarmError("orchestrator is shut down")
        if kind not in self._kinds:
            raise SwarmError(
                f"unknown agent kind {kind!r}; known kinds: {self.kinds}")
        if agent_id is None:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            agent_id = f"{kind}-{self._counters[kind]}"
        if agent_id in self._agents:
            raise SwarmError(f"agent {agent_id!r} already running")
        agent = self._kinds[kind](
            agent_id, self.bus, self.store,
            config=config, shared_ns=self.shared_ns)
        self._agents[agent_id] = agent
        await agent.start()
        return agent

    async def shutdown(self, timeout: float = 5.0) -> None:
        agents, self._agents = list(self._agents.values()), {}
        if agents:
            await asyncio.gather(
                *(a.stop(timeout=timeout) for a in agents),
                return_exceptions=True)
        if not self._closed:
            self._closed = True
            self.store.close()

    # -- messaging ---------------------------------------------------------

    async def send(self, recipient: str, mtype: str,
                   payload: Optional[Dict[str, Any]] = None,
                   sender: str = "orchestrator") -> None:
        """Fire-and-forget message to one agent, a role, or ``*``."""
        await self.bus.publish(Message(
            mtype=mtype, sender=sender, recipient=recipient,
            payload=payload or {},
        ))

    async def ask(self, recipient: str, mtype: str,
                  payload: Optional[Dict[str, Any]] = None,
                  timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        """Send a correlated request and await the worker's reply payload.

        Returns the reply payload dict, or ``None`` when no reply arrives
        within ``timeout`` (the pending waiter is cancelled).
        """
        corr = uuid.uuid4().hex
        fut = self.bus.ask(corr)
        try:
            await self.bus.publish(Message(
                mtype=mtype, sender="orchestrator", recipient=recipient,
                payload=payload or {}, corr=corr, reply_to="orchestrator"))
            reply = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            self.bus._waiters.pop(corr, None)
            if not fut.done():
                fut.cancel()
        return dict(reply.payload or {})

    async def broadcast(self, mtype: str,
                        payload: Optional[Dict[str, Any]] = None) -> int:
        """Fan out to every live worker; returns the number of routes used."""
        await self.bus.publish(Message(
            mtype=mtype, sender="orchestrator", recipient="*",
            payload=payload or {}))
        return len(self.bus.agents())

    # -- shared context ----------------------------------------------------

    def shared_set(self, key: str, value: Any) -> None:
        """Write into the shared context namespace (workers only read)."""
        self.store.set(self.shared_ns, key, value)

    def context(self) -> Dict[str, Any]:
        """Snapshot: workers, shared context and the recent message log."""
        return {
            "agents": [a.status() for a in self._agents.values()],
            "shared": self.store.get_prefix(self.shared_ns, ""),
            "recent_messages": self.store.history(limit=20),
        }
