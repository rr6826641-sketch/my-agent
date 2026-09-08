"""Tests for agent.run() wall-clock deadline watchdog.

Run: py -m pytest tests/test_run_deadline.py

Covers: a blocking LLM round-trip is aborted cleanly by the deadline
timer (RunCancelled instead of a zombie thread), the abort happens fast
after the deadline, and the normal no-deadline path is unchanged.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from ai_agent.core import Agent, IntentReformulator
from ai_agent.llm import MockClient, RunCancelled


class BlockingClient(MockClient):
    """MockClient whose chat_stream blocks until cancel_event is set,
    then aborts the same way a real LLM client would (RunCancelled)."""

    def chat_stream(self, messages, tools=None, temperature=0.2,
                    cancel_event=None, model=None):
        while cancel_event is None or not cancel_event.is_set():
            time.sleep(0.02)
        raise RunCancelled("generation cancelled by user")


def _make_agent(llm):
    return Agent(llm, intent_reformulator=IntentReformulator())


class TestDeadlineWatchdog:
    def test_blocking_llm_aborts_after_deadline(self):
        agent = _make_agent(BlockingClient())
        t0 = time.time()
        with pytest.raises(RunCancelled):
            agent.run("scan 10.0.0.5 full chain", deadline=1.5)
        elapsed = time.time() - t0
        # aborts shortly after the 1.5s deadline - never hangs
        assert elapsed < 10.0, "watchdog did not stop the run: %.1fs" % elapsed

    def test_no_deadline_path_unchanged(self):
        agent = _make_agent(MockClient())
        out = agent.run("quick hello")
        assert out and "empty" not in out.lower()
