"""Tests for the 4-Stage Autonomous Multi-Agent Pipeline.

Run: py -m pytest test_pipeline.py

Covers: strict sequential execution of the four PIPELINE_STAGES,
explicit state passing (Stage N output -> bounded context of Stage N+1),
context bounding, failure gates (error / empty output abort the pipeline
and remaining stages never run), cancellation, and the pipeline events
(pipeline_start / stage_start / stage_complete / pipeline_done).
"""

import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

import ai_agent.core as core
from ai_agent.core import (PIPELINE_STAGES, PipelineState, Agent,
                           _pipeline_bounded, _pipeline_stage_prompt)


class MockLLM:
    def __init__(self):
        self.model = "mock"

    def complete(self, *a, **k):
        return "mock"

    def chat_stream(self, prompt, tools=None, cancel_event=None, model=None):
        yield {"type": "message",
               "message": {"content": "mock", "tool_calls": []}}


def _agent():
    return Agent(llm=MockLLM(), memory=None, name="pipeline-test")


class _FakeRun:
    """Scripted stand-in for Agent.run_stream: records every prompt and
    yields one 'final' event per stage from `outputs` (dict num -> text
    or Exception)."""

    def __init__(self, outputs=None):
        self.prompts = []
        self.outputs = outputs or {}

    def __call__(self, agent):
        outer = self

        def run_stream(user_input, stop_event=None, model=None):
            outer.prompts.append(user_input)
            num = len(outer.prompts)
            out = outer.outputs.get(num, "STAGE %d REPORT: ok" % num)
            if isinstance(out, Exception):
                raise out
            yield {"type": "final", "content": out}
        return run_stream


def _collect(agent, target="example.com", stop_event=None):
    events = []
    for ev in agent.run_autonomous_pipeline(target, stop_event=stop_event):
        events.append(ev)
    return events


# ------------------------------------------------ stage definitions

def test_pipeline_stages_defined():
    assert len(PIPELINE_STAGES) == 4
    titles = [s["title"] for s in PIPELINE_STAGES]
    assert titles[0] == "Reconnaissance & Surface Mapping"
    assert titles[1] == "Hypothesis Generation & Vulnerability Modeling"
    assert titles[2] == "Deep Technical Analysis & Targeted Testing"
    assert titles[3] == "Proof-of-Concept Execution & Validated Reporting"
    assert [s["num"] for s in PIPELINE_STAGES] == [1, 2, 3, 4]


# ------------------------------------------------ happy path

def test_pipeline_runs_all_four_stages_in_order():
    agent = _agent()
    fake = _FakeRun()
    agent.run_stream = fake(agent)
    events = _collect(agent)

    types = [e["type"] for e in events]
    assert types[0] == "pipeline_start"
    assert types.count("stage_start") == 4
    assert types.count("stage_complete") == 4
    assert types[-1] == "pipeline_done"

    starts = [e["num"] for e in events if e["type"] == "stage_start"]
    completes = [e["num"] for e in events if e["type"] == "stage_complete"]
    assert starts == [1, 2, 3, 4]
    assert completes == [1, 2, 3, 4]
    # strictly sequential: each stage_start comes after previous complete
    order = [(e["type"], e.get("num")) for e in events
             if e["type"] in ("stage_start", "stage_complete")]
    assert order == [("stage_start", 1), ("stage_complete", 1),
                     ("stage_start", 2), ("stage_complete", 2),
                     ("stage_start", 3), ("stage_complete", 3),
                     ("stage_start", 4), ("stage_complete", 4)]


def test_pipeline_final_report_and_state():
    agent = _agent()
    fake = _FakeRun()
    agent.run_stream = fake(agent)
    events = _collect(agent)

    done = events[-1]
    assert done["type"] == "pipeline_done"
    st = done["state"]
    assert st["completed_stages"] == [1, 2, 3, 4]
    assert st["failed_stage"] is None
    assert st["target"] == "example.com"
    report = done["report"]
    assert report.startswith("# Autonomous Pipeline Report: example.com")
    for s in PIPELINE_STAGES:
        assert "## Stage %d: %s" % (s["num"], s["title"]) in report
    assert "aborted" not in report


# ------------------------------------------------ state passing

def test_stage_n_output_becomes_bounded_context_of_stage_n_plus_1():
    agent = _agent()
    out1 = "ATTACK SURFACE MAP: host web01, ports 80/443, nginx 1.24"
    out2 = "HYPOTHESES: H1 nginx TLS misconfig, H2 SQLi on /login"
    fake = _FakeRun(outputs={1: out1, 2: out2})
    agent.run_stream = fake(agent)
    _collect(agent)

    assert len(fake.prompts) == 4
    # Stage 1 starts from zero: no prior-stage context marker.
    assert "BOUNDED CONTEXT" not in fake.prompts[0]
    assert "TARGET: example.com" in fake.prompts[0]
    # Stage 2 sees only Stage 1 output.
    assert "BOUNDED CONTEXT" in fake.prompts[1]
    assert out1 in fake.prompts[1]
    assert out2 not in fake.prompts[1]
    # Stage 3 sees Stage 1 + Stage 2 outputs (in order).
    assert out1 in fake.prompts[2]
    assert out2 in fake.prompts[2]
    i1 = fake.prompts[2].index(out1)
    i2 = fake.prompts[2].index(out2)
    assert i1 < i2
    # Stage 4 sees all three prior outputs.
    assert out1 in fake.prompts[3]
    assert out2 in fake.prompts[3]
    # each prompt is addressed to the right stage
    assert "[PIPELINE STAGE 1/4]" in fake.prompts[0]
    assert "[PIPELINE STAGE 4/4]" in fake.prompts[3]


def test_bounded_context_is_capped():
    big = "X" * (core._PIPELINE_STAGE_CONTEXT_LIMIT * 5)
    text = _pipeline_bounded(big)
    assert len(text) <= core._PIPELINE_STAGE_CONTEXT_LIMIT + 40
    assert "context truncated" in text
    # short text passes through untouched
    assert _pipeline_bounded("short") == "short"


# ------------------------------------------------ failure gates

def test_stage_failure_aborts_remaining_stages():
    agent = _agent()
    fake = _FakeRun(outputs={2: RuntimeError("llm exploded")})
    agent.run_stream = fake(agent)
    events = _collect(agent)

    assert len(fake.prompts) == 2          # stages 3/4 never prompted
    errs = [e for e in events if e["type"] == "error"]
    assert len(errs) == 1
    assert errs[0]["stage"] == 2
    assert "RuntimeError" in errs[0]["content"]
    assert events[-1]["type"] == "pipeline_done"
    st = events[-1]["state"]
    assert st["completed_stages"] == [1]
    assert st["failed_stage"] == 2
    assert "aborted at Stage 2" in events[-1]["report"]


def test_empty_stage_output_is_a_failure():
    agent = _agent()
    fake = _FakeRun(outputs={3: "   "})
    agent.run_stream = fake(agent)
    events = _collect(agent)

    assert len(fake.prompts) == 3
    assert events[-1]["state"]["failed_stage"] == 3
    assert events[-1]["state"]["completed_stages"] == [1, 2]
    assert "no usable output" in events[-1]["state"]["error"]


def test_llm_error_marker_output_is_a_failure():
    agent = _agent()
    fake = _FakeRun(outputs={1: "[LLM error] upstream unavailable"})
    agent.run_stream = fake(agent)
    events = _collect(agent)

    assert len(fake.prompts) == 1          # abort before stage 2
    assert events[-1]["state"]["failed_stage"] == 1


# ------------------------------------------------ cancellation

def test_stop_event_cancels_before_next_stage():
    agent = _agent()
    fake = _FakeRun()
    stop = threading.Event()

    def run_stream(user_input, stop_event=None, model=None):
        fake.prompts.append(user_input)
        if len(fake.prompts) >= 2:
            stop.set()                     # cancel just before stage 3
        yield {"type": "final", "content": "ok"}

    agent.run_stream = run_stream
    events = _collect(agent, stop_event=stop)

    assert len(fake.prompts) == 2
    assert events[-1]["state"]["completed_stages"] == [1, 2]
    assert events[-1]["state"]["failed_stage"] == 3
    assert events[-1]["type"] == "pipeline_done"


# ------------------------------------------------ empty target

def test_empty_target_yields_error_only():
    agent = _agent()
    events = _collect(agent, target="   ")
    assert len(events) == 1
    assert events[0]["type"] == "error"


# ------------------------------------------------ PipelineState units

def test_pipeline_state_record_and_bounded_context():
    st = PipelineState("t.local")
    assert st.completed_stages == [] and st.failed_stage is None
    st.record(1, "recon output", True)
    st.record(2, "hyp output", True)
    assert st.completed_stages == [1, 2]
    ctx = st.bounded_context()
    assert "[STAGE 1 OUTPUT - Reconnaissance & Surface Mapping]" in ctx
    assert "[STAGE 2 OUTPUT - Hypothesis Generation" in ctx
    assert "recon output" in ctx and "hyp output" in ctx
    d = st.to_dict()
    assert d["target"] == "t.local" and d["stage"] == 2


def test_pipeline_state_final_report_includes_abort_section():
    st = PipelineState("t.local")
    st.record(1, "ok", True)
    st.record(2, "", False, "boom")
    rep = st.final_report()
    assert "## Pipeline aborted at Stage 2" in rep
    assert "boom" in rep
    assert "Stages completed: 1/4" in rep
