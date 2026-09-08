"""Unit tests for the Context Auto-Compaction Engine.

Validates the three Phase-1 contracts:
1. Threshold trigger  - sliding token window fires at/above the 70% watermark
2. Summary synthesis  - historic turns distill into structured key-finding nodes
3. History pruning    - old raw messages are purged, note injected at head
Plus persistence (per-target rolling digest store).
"""

import pytest

from ai_agent.memory.compactor import (
    CompactionStore,
    Compactor,
    DEFAULT_COMPACTION_THRESHOLD,
    build_keyfinding_nodes,
    render_nodes,
    summarize_history,
)


def make_msgs(n, fill=400):
    """n alternating user/assistant turns of ~fill chars, high-signal text."""
    msgs = []
    for i in range(n):
        if i % 2 == 0:
            core = "target http://10.0.0.%d port scan continue mission" % (i % 250)
            role = "user"
        else:
            core = ("FOUND open port 8080 password token session key=abc "
                    "conclusion: next step decided continue")
            role = "assistant"
        body = (core * (fill // len(core) + 1))[:fill]
        msgs.append({"role": role, "content": body})
    msgs.append({"role": "tool", "name": "nmap", "content": "scan done"})
    return msgs


# --------------------------------------------------------------------------
# 1. Threshold trigger
# --------------------------------------------------------------------------
def test_threshold_triggers_at_70_percent():
    comp = Compactor(max_tokens=1000, threshold=0.70)
    below = make_msgs(6)            # ~660 tokens -> 66%
    over = make_msgs(7)             # ~770 tokens -> 77%
    assert comp.usage_ratio(below) < 0.70
    assert not comp.should_compact(below)
    assert comp.usage_ratio(over) >= 0.70
    assert comp.should_compact(over)


def test_default_threshold_is_70_percent():
    assert DEFAULT_COMPACTION_THRESHOLD == 0.70


def test_usage_ratio_is_bounded_and_monotonic():
    comp = Compactor(max_tokens=500)
    small = comp.usage_ratio(make_msgs(2))
    big = comp.usage_ratio(make_msgs(9))
    assert 0.0 <= small <= big <= 1.0


# --------------------------------------------------------------------------
# 2. Summary synthesis (structured key-finding nodes)
# --------------------------------------------------------------------------
def test_summary_synthesis_structured_nodes():
    nodes, note = summarize_history(make_msgs(10), budget=2000)
    kinds = {nd["kind"] for nd in nodes}
    for nd in nodes:
        assert nd["kind"] in {"finding", "decision", "action", "context"}
        assert str(nd["text"]).strip()
    assert kinds & {"finding", "decision"}          # high-signal substance kept
    assert note.startswith("[AUTO-COMPACTED")
    assert "finding" in note or "decision" in note


def test_node_render_respects_budget():
    nodes = build_keyfinding_nodes(make_msgs(12))
    note = render_nodes(nodes, budget=300)
    assert len(note) <= 1500                       # rendered within a sane cap
    assert note.count("\n") >= 1


def test_llm_summarizer_failure_falls_back_deterministic():
    def broken(messages):
        raise RuntimeError("provider offline")
    nodes, note = summarize_history(make_msgs(8), llm_summarizer=broken)
    assert note.startswith("[AUTO-COMPACTED")       # deterministic fallback
    assert nodes


# --------------------------------------------------------------------------
# 3. History pruning + prompt-head injection
# --------------------------------------------------------------------------
def test_compaction_purges_old_and_injects_note():
    msgs = make_msgs(20)
    comp = Compactor(max_tokens=1000, threshold=0.70)
    out = comp.compact(msgs)
    assert out["compacted"] is True
    assert out["purged"] > 0
    pruned = out["messages"]
    assert pruned[0]["role"] == "system"            # note injected at head
    assert "[AUTO-COMPACTED" in pruned[0]["content"]
    assert len(pruned) < len(msgs)                  # raw history pruned
    assert pruned[-1] == msgs[-1]                   # recent tail preserved
    assert pruned[-2] == msgs[-2]
    assert out["usage_after"] < out["usage_before"]
    assert all("system" != m.get("role") for m in pruned[1:])


def test_no_compaction_below_threshold():
    comp = Compactor(max_tokens=1000, threshold=0.70)
    out = comp.compact(make_msgs(3))                # far below watermark
    assert out["compacted"] is False
    assert out["system_note"] == ""
    assert len(out["messages"]) == 4                # 3 turns + tool msg


def test_force_compaction_always_compacts():
    comp = Compactor(max_tokens=1000, threshold=0.70)
    out = comp.compact(make_msgs(6), force=True)
    assert out["compacted"] is True
    assert out["purged"] >= 1


def test_llm_summary_injected_when_available():
    def fake_summarizer(messages):
        return "LLM-SUMMARY: recon finished, next target 10.0.0.9"
    comp = Compactor(max_tokens=1000, llm_summarizer=fake_summarizer)
    out = comp.compact(make_msgs(9), force=True)
    assert "LLM-SUMMARY" in out["system_note"]
    assert out["system_note"] in out["messages"][0]["content"]


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------
def test_store_record_consult_roundtrip(tmp):
    store = CompactionStore(base_dir=tmp)
    store.record("target-a", "digest-one")
    store.record("target-a", "digest-two")
    store.record("target-b", "digest-b")
    assert store.count("target-a") == 2
    assert store.count() == 3
    assert store.consult("target-a") == "digest-two"


def test_store_ring_cap_and_reload(tmp):
    store = CompactionStore(base_dir=tmp)
    for i in range(8):                                # exceed the ring cap
        store.record("target-a", "digest-%d" % i)
    assert store.count("target-a") <= 4               # ring-capped
    assert store.consult("target-a") == "digest-7"    # latest survives

    reloaded = CompactionStore(base_dir=tmp)          # survives restart
    assert reloaded.consult("target-a") == "digest-7"


# --------------------------------------------------------------------------
# 4. Agent-loop integration (runtime hook)
# --------------------------------------------------------------------------
def _mk_agent(tmp, tokens=4000):
    from ai_agent.core import Agent
    from ai_agent.llm import MockClient
    store = CompactionStore(base_dir=tmp)
    agent = Agent(
        llm=MockClient(),
        name="test-agent",
        max_context_chars=tokens * 4,      # ~token window for the compactor
        compaction_store=store,
        learner=None,
    )
    return agent, store


def test_agent_loop_compacts_at_watermark(tmp):
    agent, store = _mk_agent(tmp)
    agent.messages = make_msgs(200, fill=120)   # ~ (120+10)tok*200 = 26k tok
    agent._maybe_compact()
    assert agent.messages[0]["role"] == "system"        # digest at prompt head
    assert "[AUTO-COMPACTED" in agent.messages[0]["content"]
    assert len(agent.messages) < 200                    # raw history pruned
    assert store.count("test-agent") >= 1               # digest persisted
    # loop-safe: repeated calls never raise, window stays bounded
    agent._maybe_compact()
    agent._maybe_compact()


def test_agent_loop_skips_below_watermark(tmp):
    agent, _ = _mk_agent(tmp)
    agent.messages = make_msgs(3, fill=120)   # tiny history, no compaction
    agent._maybe_compact()
    assert len(agent.messages) == 4           # untouched (3 turns + tool msg)
    assert agent.messages[0]["role"] != "system"
