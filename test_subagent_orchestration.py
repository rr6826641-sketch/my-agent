"""Tests for the Managed Asynchronous Sub-Agent Orchestration Protocol.

Run: py -m pytest test_subagent_orchestration.py

Covers the bounded OrchestrationManager protocol: sibling/child caps
(max 2 siblings running / 4 children tracked), the async agent_id
spawn flow, success-criteria validation, transcript fetching,
continue_agent / cancel_agent lifecycle management, depth limits and
the agent-level wiring (spawn_agent / spawn_agents plus the four
management tools).
"""

import json
import threading
import time

from ai_agent.core import Agent
from ai_agent.llm import MockClient
from ai_agent.orchestration import (
    DEFAULT_MAX_CHILDREN,
    DEFAULT_MAX_SIBLINGS,
    OrchestrationManager,
    STATUS_CANCELLED,
    STATUS_DONE,
    STATUS_QUEUED,
    STATUS_RUNNING,
)


class _FakeChild:
    """Deterministic stand-in for a real sub-agent Agent.

    - gate: a threading.Event the run_stream blocks on until released,
      so tests can hold children in RUNNING state deterministically.
    - produce: callable(task) -> final answer text.
    - stop_event: when set (cancel request), yields an explicit
      "(cancelled)" final instead of the produced answer.
    """

    def __init__(self, produce=None, gate=None, name="fake-child"):
        self.name = name
        self._tool_list = []                      # claims no capabilities
        self._produce = produce or (lambda task: "done: %s" % task)
        self._gate = gate

    def run_stream(self, task, stop_event=None):
        if self._gate is not None:
            self._gate.wait()
        if stop_event is not None and stop_event.is_set():
            yield {"type": "final", "content": "(cancelled)"}
            return
        text = self._produce(task)
        for word in str(text).split():
            yield {"type": "delta", "content": word + " "}
        yield {"type": "final", "content": text}


def _manager(produce=None, gate=None, **kw):
    child = _FakeChild(produce=produce, gate=gate)
    return OrchestrationManager(
        parent_name="test-parent",
        make_child=lambda task, depth: (child, task),
        **kw)


def _wait_done(om, agent_id, timeout=10):
    deadline = time.time() + timeout
    detail = om.check_status(agent_id)
    while "status:   done" not in detail and time.time() < deadline:
        time.sleep(0.05)
        detail = om.check_status(agent_id)
    return detail


# ------------------------------------------------------------ async flow

def test_async_spawn_returns_agent_id_json():
    om = _manager()
    out = om.spawn("inspect the target")
    data = json.loads(out)
    assert data["agent_id"].startswith("sa-")
    # fast children may already be done by the time the JSON is read
    assert data["status"] in (STATUS_QUEUED, STATUS_RUNNING, STATUS_DONE)
    assert data["depth"] == 0
    assert "UNVERIFIED" in data["note"]
    assert "check_agent_status(validate=true)" in data["note"]
    # wait=True restores the legacy synchronous behaviour
    sync = om.spawn("hello", wait=True)
    assert "done: hello" in sync
    # empty task is rejected
    assert "Error: spawn needs a task." in om.spawn("   ")
    # unknown agent id handling
    assert "Error: unknown sub-agent bogus" in om.sync_result("bogus")


def test_spawn_many_async_contract():
    om = _manager(produce=lambda task: "result for %s" % task)
    data = json.loads(om.spawn_many(["a", "b", "c"]))
    assert data["spawned"] == 3
    assert data["rejected"] == 0
    assert "max 2 siblings at once, 4 tracked" in data["note"]
    ids = [s["agent_id"] for s in data["queued_or_running"]]
    assert len(ids) == 3
    # sync batch results follow task order with legacy markers
    out = om.sync_results(ids)
    assert "--- Sub-agent 1: a ---" in out
    assert "--- Sub-agent 3: c ---" in out
    assert "result for b" in out
    # empty / invalid inputs
    assert "Error: spawn_agents needs at least one task." in \
        om.spawn_many("")
    assert "Error: tasks JSON is invalid." in om.spawn_many("[not json")


def test_spawn_many_rejects_over_cap():
    gate = threading.Event()
    om = _manager(gate=gate)
    data = json.loads(om.spawn_many(["t%d" % i for i in range(6)]))
    assert data["spawned"] == 4
    assert data["rejected"] == 2
    errors = [s for s in data["queued_or_running"] if "error" in s]
    assert len(errors) == 2
    assert "rejected: child cap (4) reached" in errors[0]["error"]
    # clean up so no worker threads leak into later tests
    om.cancel_agent()
    gate.set()


# ------------------------------------------------------------ caps

def test_caps_two_siblings_four_children():
    gate = threading.Event()          # closed: children block in RUNNING
    om = _manager(gate=gate)
    ids = []
    for i in range(4):
        ids.append(json.loads(om.spawn("task %d" % i))["agent_id"])
    assert om._running_count() == DEFAULT_MAX_SIBLINGS == 2
    assert om._active_count() == DEFAULT_MAX_CHILDREN == 4
    # a 5th tracked child is rejected
    rejected = om.spawn("overflow")
    assert "Error: sub-agent cap reached" in rejected
    assert "4 children tracked" in rejected
    # cancel-all: queued children are cancelled immediately, running
    # children get a stop request and unwind as DONE
    msg = om.cancel_agent()
    assert "Cancel requested for 4 active sub-agent(s)" in msg
    for aid in ids[2:]:
        assert "status:   cancelled" in om.check_status(aid)
    gate.set()
    deadline = time.time() + 10
    while om._running_count() > 0 and time.time() < deadline:
        time.sleep(0.05)
    for aid in ids[:2]:
        detail = om.check_status(aid)
        assert "status:   done" in detail
        assert "(cancelled)" in detail
    # no active children remain to cancel
    assert "No active sub-agents to cancel" in om.cancel_agent()


def test_registry_summary():
    gate = threading.Event()
    om = _manager(gate=gate)
    om.spawn("a")
    om.spawn("b")
    s = om.registry_summary()
    assert s["parent"] == "test-parent"
    assert s["tracked"] == 2
    assert s["running"] == 2
    assert s["active"] == 2
    assert s["max_siblings"] == DEFAULT_MAX_SIBLINGS
    assert s["max_children"] == DEFAULT_MAX_CHILDREN
    om.cancel_agent()
    gate.set()


# ------------------------------------------------------------ validation

def test_success_criteria_validation():
    om = _manager(produce=lambda task: "answer: secret-token delivered")
    aid = json.loads(om.spawn("task",
                              success_criteria=["secret-token"]))["agent_id"]
    result = om.sync_result(aid)
    assert "secret-token" in result
    detail = om.check_status(aid, validate=True)
    assert "verified: True" in detail
    assert "all 1 success criteria met" in detail
    # the verified mark persists on later plain status checks
    assert "verified: True" in om.check_status(aid)
    assert "VERIFIED against success criteria" in om.check_status(aid)


def test_success_criteria_failure():
    om = _manager(produce=lambda task: "answer without the marker")
    aid = json.loads(om.spawn("task",
                              success_criteria=["needle-token"]))["agent_id"]
    om.sync_result(aid)
    detail = om.check_status(aid, validate=True)
    assert "verified: False" in detail
    assert "criteria NOT met" in detail
    assert "needle-token" in detail


def test_no_criteria_treated_satisfied():
    om = _manager()
    aid = json.loads(om.spawn("task"))["agent_id"]
    om.sync_result(aid)
    detail = om.check_status(aid, validate=True)
    assert "verified: True" in detail
    assert "no success criteria declared; treated as satisfied" in detail


def test_capability_report():
    om = _manager()
    aid = json.loads(om.spawn("task",
                              capabilities=["spawn", "terminal",
                                            "bogus-tag"]))["agent_id"]
    om.sync_result(aid)
    detail = om.check_status(aid)
    # fake child claims no tools, so declared capabilities are reported
    assert '"spawn": "missing: spawn_agent"' in detail
    assert '"terminal": "missing: run_terminal"' in detail
    assert '"bogus-tag": "unknown-tag"' in detail


# ------------------------------------------------------------ lifecycle

def test_transcript_entries():
    om = _manager(produce=lambda task: "completed work on %s" % task)
    aid = json.loads(om.spawn("the objective"))["agent_id"]
    om.sync_result(aid)
    t = om.fetch_transcript(aid)
    assert t.startswith("=== Transcript: %s" % aid)
    assert "entries)" in t
    assert "note: child agent ready" in t
    assert "final: completed work on the objective" in t
    assert "Error: unknown sub-agent bogus" in om.fetch_transcript("bogus")
    # summary table lists every tracked child
    table = om.fetch_transcript()
    assert "transcripts available for test-parent" in table
    assert aid in table


def test_status_table():
    om = _manager()
    aid = json.loads(om.spawn("one"))["agent_id"]
    om.spawn("two", wait=True)
    table = om.check_status()
    assert "Sub-agents of test-parent (2 tracked, cap 4 children / 2 siblings)" \
        in table
    assert aid in table
    assert "check_agent_status(<agent_id>, validate=true)" in table


def test_continue_agent_resumes():
    om = _manager(produce=lambda task: "first answer for %s" % task)
    aid = json.loads(om.spawn("objective"))["agent_id"]
    first = om.sync_result(aid)
    assert "first answer" in first
    cont = json.loads(om.continue_agent(aid, "go deeper"))
    assert cont["agent_id"] == aid
    # resumed child is immediately redispatched; a fast child may
    # already be done by the time the status JSON is read
    assert cont["status"] in (STATUS_QUEUED, STATUS_RUNNING, STATUS_DONE)
    assert "UNVERIFIED" in cont["note"]
    # resumed run appends a marker and keeps the same conversation
    second = om.sync_result(aid)
    assert "[continued run 2]" in second
    assert "first answer" in second
    # output re-marked unverified on resume
    assert "verified: False" in om.check_status(aid)
    # empty follow-up and unknown ids are rejected
    assert "Error: continue_agent needs a follow-up prompt." in \
        om.continue_agent(aid, "   ")
    assert "Error: unknown sub-agent bogus" in om.continue_agent("bogus", "x")


def test_continue_while_running_rejected():
    gate = threading.Event()
    om = _manager(gate=gate)
    aid = json.loads(om.spawn("long task"))["agent_id"]
    err = om.continue_agent(aid, "more")
    assert "still" in err
    assert "running" in err
    gate.set()
    detail = _wait_done(om, aid)
    assert "status:   done" in detail


def test_cancel_flows():
    gate = threading.Event()
    om = _manager(gate=gate)
    # running child: cancel request, then it unwinds as DONE
    running = json.loads(om.spawn("long task"))["agent_id"]
    msg = om.cancel_agent(running)
    assert "cancel requested" in msg.lower()
    assert "unwinding" in msg
    gate.set()
    detail = _wait_done(om, running)
    assert "status:   done" in detail
    assert "(cancelled)" in detail
    # terminal children cannot be cancelled again
    msg2 = om.cancel_agent(running)
    assert "already" in msg2
    assert "done" in msg2
    # unknown ids are rejected
    assert "Error: unknown sub-agent bogus" in om.cancel_agent("bogus")
    assert "No active sub-agents to cancel" in om.cancel_agent()


def test_sync_timeout_marks_timed_out():
    gate = threading.Event()
    om = _manager(gate=gate)
    aid = json.loads(om.spawn("slow", timeout=1))["agent_id"]
    result = om.sync_result(aid, timeout=1)
    assert "timed out" in result
    assert "status:   timed_out" in om.check_status(aid)
    gate.set()                      # let the daemon worker unwind


def test_depth_limit():
    om = _manager(max_depth=3)      # max_depth is the deepest allowed depth
    assert "Error: sub-agent depth limit reached" in om.spawn("deep", depth=4)
    data = json.loads(om.spawn("ok", depth=2))
    assert data["agent_id"].startswith("sa-")
    om.sync_result(data["agent_id"])


# ------------------------------------------------------------ agent wiring

def test_agent_level_management_tools():
    agent = Agent(llm=MockClient(), name="manager")
    names = {t.name for t in agent._tool_list}
    assert {"spawn_agent", "spawn_agents", "check_agent_status",
            "fetch_agent_transcript", "continue_agent",
            "cancel_agent"} <= names
    # async spawn -> agent_id, then poll to done
    aid = json.loads(agent.spawn_agent("say hello"))["agent_id"]
    detail = _wait_done(agent._orchestrator, aid)
    assert "Mock LLM reply" in detail
    # transcript and continue round-trip on the same agent_id
    assert agent.fetch_agent_transcript(aid).startswith("=== Transcript:")
    cont = json.loads(agent.continue_agent(aid, "elaborate"))
    assert cont["agent_id"] == aid
    assert "UNVERIFIED" in cont["note"]
    final = agent._orchestrator.sync_result(aid)
    assert "[continued run 2]" in final
    # management tools reject unknown ids
    assert "Error: unknown sub-agent bogus" in agent.cancel_agent("bogus")
    assert "Error: unknown sub-agent bogus" in \
        agent.check_agent_status("bogus")


def test_agent_depth_limit():
    agent = Agent(llm=MockClient(), name="deep",
                  spawn_depth=2, max_spawn_depth=3)
    err = agent.spawn_agent("say hi")
    assert "Error: sub-agent depth limit reached" in err
    # legacy sync wrapper enforces the same limit when asked for a
    # deeper child than the cap allows
    assert "Error: sub-agent depth limit reached" in \
        agent._spawn_impl("say hi", depth=3)


def test_agent_spawn_disabled():
    agent = Agent(llm=MockClient(), name="no-spawn", allow_subagents=False)
    assert "Error: sub-agents are disabled." in agent.spawn_agent("say hi")
    assert "Error: sub-agents are disabled." in \
        agent.spawn_agents(["say hi"])


def test_mock_stream_uses_async_spawn_tool():
    agent = Agent(llm=MockClient(), name="streamer")
    events = list(agent.run_stream("spawns [\"one\", \"two\"]"))
    finals = [e.get("content", "") for e in events if e.get("type") == "final"]
    assert finals
    assert "spawned" in finals[-1]
