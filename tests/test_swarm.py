"""Unit tests for the sub-agent swarm framework (ai_agent/core/swarm.py).

Validates sub-agent lifecycle management and the async communication bus:
auto-id spawning, spawn/stop transitions, ask/reply roundtrips, role
multicast and broadcast routing, agent-to-agent messaging, per-namespace
state isolation, the recon -> payload -> reporter pipeline,
extensibility (register_kind), error containment, ask timeouts and
routing errors.

pytest-asyncio is not installed, so every async scenario is driven
through asyncio.run() from a plain sync test function.
"""

import asyncio
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_agent.core.swarm import (  # noqa: E402
    BaseSubAgent,
    Message,
    MessageBus,
    PayloadSubAgent,
    ReconSubAgent,
    ReporterSubAgent,
    StateStore,
    SwarmError,
    SwarmOrchestrator,
)


async def wait_until(predicate, timeout=3.0, interval=0.02):
    """Async-poll ``predicate`` (yields to the loop) or raise on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    raise AssertionError(f"condition not met within {timeout}s")


class EchoAgent(BaseSubAgent):
    """Extensibility probe: answers task.echo and records a private key."""

    role = "echo"

    async def on_task_echo(self, msg):
        text = msg.payload.get("text", "")
        self.state.set("echo.last", text)
        return {"ok": True, "text": text.upper(), "echoed_by": self.agent_id}


class BrokenAgent(BaseSubAgent):
    """Handler raises - exercises the loop's error-containment path."""

    role = "broken"

    async def on_task_boom(self, msg):
        raise RuntimeError("boom")


class MuteAgent(BaseSubAgent):
    """Never replies - drives ask() timeout behaviour."""

    role = "mute"

    async def on_task_mute(self, msg):
        return None


# ---------------------------------------------------------------------------
# lifecycle management
# ---------------------------------------------------------------------------

def test_spawn_auto_ids_and_lifecycle_roundtrip():
    """Spawn auto-numbers per kind and transitions running->idle->stopped."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            a1 = await orch.spawn("recon")
            a2 = await orch.spawn("recon")
            assert a1.agent_id == "recon-1"
            assert a2.agent_id == "recon-2"
            assert orch.running == ["recon-1", "recon-2"]
            # loop goes idle once the mailbox poll times out
            await wait_until(lambda: a1.lifecycle == "idle")
            await wait_until(lambda: a2.lifecycle == "idle")

            await orch.ask("recon-1", "task.recon",
                           {"target": "t.example"}, timeout=3.0)
            assert a1.lifecycle == "running"

            await a1.stop()
            await a2.stop()
            assert a1.lifecycle == "stopped"
            assert a2.lifecycle == "stopped"
            # workers unregister their own mailboxes on shutdown
            assert a1.agent_id not in orch.bus.agents()
            assert a2.agent_id not in orch.bus.agents()
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_duplicate_and_unknown_spawn_rejected():
    """Duplicate live ids and unknown kinds raise SwarmError."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            await orch.spawn("recon", agent_id="dup")
            with pytest.raises(SwarmError):
                await orch.spawn("recon", agent_id="dup")
            with pytest.raises(SwarmError):
                await orch.spawn("not-a-kind")
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# communication bus: ask / reply roundtrip
# ---------------------------------------------------------------------------

def test_ask_reply_roundtrip():
    """A correlated task.ask returns the worker's reply payload."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            await orch.spawn("recon", config={"ports": [22, 443]})
            out = await orch.ask("recon-1", "task.recon",
                                 {"target": "scanme.example"}, timeout=3.0)
            assert out["ok"] is True
            assert out["agent"] == "recon-1"
            assert out["findings"]["host"] == "scanme.example"
            assert out["findings"]["ports"] == [22, 443]
            # result persisted into the worker's private namespace
            assert "recon:recon-1" in orch.store.snapshot()
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_agent_to_agent_messaging():
    """One worker can publish directly to another worker on the bus."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            orch.register_kind("echo", EchoAgent)
            e1 = await orch.spawn("echo")
            e2 = await orch.spawn("echo")
            await e1.send_to("echo-2", "task.echo", {"text": "yo"})
            await wait_until(lambda: e2.state.get("echo.last") == "yo")
            assert e2.status()["handled"] == 1
            # the sender's own namespace stayed untouched
            assert e1.state.items() == {}
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_role_multicast_fans_out_to_kind():
    """Recipient 'recon' reaches every live recon worker."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            r1 = await orch.spawn("recon", agent_id="r1")
            r2 = await orch.spawn("recon", agent_id="r2")
            out = await orch.ask("recon", "task.recon",
                                 {"target": "10.0.0.9"}, timeout=3.0)
            assert out["ok"] is True
            await wait_until(lambda: r1.status()["handled"] == 1)
            await wait_until(lambda: r2.status()["handled"] == 1)
            snap = orch.store.snapshot()
            assert snap["recon:r1"]["recon.findings"]["host"] == "10.0.0.9"
            assert snap["recon:r2"]["recon.findings"]["host"] == "10.0.0.9"
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_broadcast_reaches_all_workers():
    """Recipient '*' fans out to every live mailbox."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            orch.register_kind("echo", EchoAgent)
            await orch.spawn("echo")
            await orch.spawn("echo")
            n = await orch.broadcast("task.echo", {"text": "all"})
            assert n == 2
            for aid in ("echo-1", "echo-2"):
                ag = orch.get(aid)
                await wait_until(lambda a=ag: a.state.get("echo.last") == "all")
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# state isolation between workers
# ---------------------------------------------------------------------------

def test_state_isolation_across_agents():
    """Workers see only their own namespace plus the read-only shared one."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            r1 = await orch.spawn("recon", agent_id="r1")
            r2 = await orch.spawn("recon", agent_id="r2")
            orch.shared_set("scope.target", "10.0.0.1")

            await orch.ask("r1", "task.recon", {"target": "10.0.0.1"}, timeout=3.0)
            await orch.ask("r2", "task.recon", {"target": "10.0.0.2"}, timeout=3.0)

            # private findings are per-worker
            assert r1.state.get("recon.findings")["host"] == "10.0.0.1"
            assert r2.state.get("recon.findings")["host"] == "10.0.0.2"
            # AgentState exposes no foreign-namespace read path: a shared_get
            # for a private key can never see it
            assert r1.state.shared_get("recon.findings") is None
            # ...while the shared context is readable from both
            assert r1.state.shared_get("scope.target") == "10.0.0.1"
            assert r2.state.shared_get("scope.target") == "10.0.0.1"
            # the store keeps the two namespaces physically apart
            namespaces = set(orch.store.namespaces())
            assert {"recon:r1", "recon:r2", "shared"} <= namespaces
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_recon_payload_reporter_pipeline():
    """Orchestrator gathers isolated findings and the reporter consolidates."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            await orch.spawn("recon", config={"ports": [80, 443]})
            await orch.spawn("payload")
            await orch.spawn("reporter")

            recon = await orch.ask("recon-1", "task.recon",
                                   {"target": "10.0.0.5"}, timeout=3.0)
            assert recon["ok"] is True
            pl = await orch.ask("payload-1", "task.payload",
                                {"kind": "xss", "target": "10.0.0.5"},
                                timeout=3.0)
            assert pl["ok"] is True
            assert pl["descriptor"]["payload"]["vector"] == "<script>alert(1)</script>"

            # only the orchestrator composes cross-namespace context
            snap = orch.store.snapshot()
            findings = snap["recon:recon-1"]["recon.findings"]
            artifact = snap["payload:payload-1"]["payloads.xss"]
            rep = await orch.ask("reporter-1", "task.report", {
                "target": "10.0.0.5",
                "findings": [
                    {"title": "Open 443", "severity": "medium"},
                    {"title": "Staged xss", "severity": "high"},
                ],
            }, timeout=3.0)
            assert rep["ok"] is True
            report = rep["report"]
            assert report["finding_count"] == 2
            assert report["status"] == "draft"
            assert findings["services"] == ["tcp/80", "tcp/443"]
            assert artifact["kind"] == "xss"
            # reporter stored the consolidated report in its own namespace
            assert orch.get("reporter-1").state.get("reports.latest")["finding_count"] == 2
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_extensibility_register_kind_and_ask():
    """Custom BaseSubAgent kinds can be registered and driven by the bus."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            orch.register_kind("echo", EchoAgent)
            await orch.spawn("echo")
            out = await orch.ask("echo-1", "task.echo",
                                 {"text": "hi"}, timeout=3.0)
            assert out == {"ok": True, "text": "HI", "echoed_by": "echo-1"}
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_error_containment_keeps_agent_alive():
    """A raising handler replies an error and does not kill the worker."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            orch.register_kind("broken", BrokenAgent)
            ag = await orch.spawn("broken")
            out = await orch.ask("broken-1", "task.boom", {}, timeout=3.0)
            assert out["ok"] is False
            assert "boom" in out["error"]
            assert ag.status()["last_error"].startswith("RuntimeError: boom")
            # still registered; lifecycle shows the contained error
            assert "broken-1" in orch.bus.agents()
            assert ag.lifecycle == "error"
            # and the worker is still usable for a follow-up message
            await orch.send("broken-1", "task.boom", {})
            await wait_until(lambda: ag.status()["handled"] == 2)
            assert "broken-1" in orch.bus.agents()
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_unhandled_type_returns_error_reply():
    """Messages with no handler come back as a clean error reply."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            await orch.spawn("recon")
            out = await orch.ask("recon-1", "task.nope", {}, timeout=3.0)
            assert out["ok"] is False
            assert "unhandled message type" in out["error"]
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_ask_timeout_returns_none():
    """ask() gives up cleanly when the worker never replies."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            orch.register_kind("mute", MuteAgent)
            await orch.spawn("mute")
            t0 = time.monotonic()
            out = await orch.ask("mute-1", "task.mute", {}, timeout=0.3)
            elapsed = time.monotonic() - t0
            assert out is None
            assert elapsed < 2.0
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_routing_errors_raise_swarm_error():
    """Asking/sending to an unknown recipient raises instead of hanging."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            orch.register_kind("echo", EchoAgent)
            await orch.spawn("echo")
            with pytest.raises(SwarmError):
                await orch.ask("ghost", "task.echo", {}, timeout=1.0)
            with pytest.raises(SwarmError):
                await orch.send("ghost", "task.echo", {"text": "x"})
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_shared_context_and_message_audit_log():
    """Shared context is visible in context() and every msg hits msglog."""

    async def scenario():
        orch = SwarmOrchestrator()
        try:
            await orch.spawn("recon")
            orch.shared_set("mission.title", "alpha")
            out = await orch.ask("recon-1", "task.recon",
                                 {"target": "t.example"}, timeout=3.0)
            assert out["ok"] is True
            ctx = orch.context()
            assert ctx["shared"]["mission.title"] == "alpha"
            # task.recon request + its reply were both persisted
            types = [m["mtype"] for m in ctx["recent_messages"]]
            assert "task.recon" in types
            assert "task.recon.reply" in types
            assert ctx["agents"][0]["agent_id"] == "recon-1"
        finally:
            await orch.shutdown()

    asyncio.run(scenario())


def test_state_store_json_roundtrip_and_namespaces():
    """StateStore persists JSON values, namespaces and an audit log."""

    store = StateStore()
    try:
        store.set("ns:a", "count", 3)
        store.set("ns:a", "nested", {"ports": [80, 443]})
        store.set("ns:b", "count", 9)
        assert store.get("ns:a", "count") == 3
        assert store.get("ns:a", "nested") == {"ports": [80, 443]}
        assert store.get("ns:a", "missing", "dflt") == "dflt"
        assert store.get_prefix("ns:a") == {
            "count": 3, "nested": {"ports": [80, 443]}}
        assert set(store.namespaces()) == {"ns:a", "ns:b"}
        snap = store.snapshot()
        assert snap["ns:a"]["count"] == 3
        assert snap["ns:b"]["count"] == 9
        # overwrite keeps a single row per (ns, key)
        store.set("ns:a", "count", 7)
        assert store.get("ns:a", "count") == 7
        assert len(store.snapshot("ns:a")) == 1
        assert len(store.snapshot("ns:a")["ns:a"]) == 2
        # audit log roundtrip
        msg = Message(mtype="task.recon", sender="orch", recipient="recon-1",
                      payload={"target": "x"})
        store.log_message(msg)
        hist = store.history()
        assert len(hist) == 1
        assert hist[0]["payload"] == {"target": "x"}
    finally:
        store.close()
