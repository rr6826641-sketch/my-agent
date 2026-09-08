"""Tests for the empty-final retry nudge in run_stream().

A heavy tool chain can end with an LLM turn that returns an empty
message (no content, no tool calls) - Groq nondeterminism observed in
live probes. run_stream() now nudges the model once (bounded) instead
of surfacing "(empty reply)" the moment a tool chain has done real work.

Run: py -m pytest tests/test_empty_final_retry.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_agent.core import Agent, IntentReformulator
from ai_agent.llm import MockClient


class EmptyFirstClient(MockClient):
    """Returns an empty content-less message on the first chat call,
    then a normal final answer on subsequent calls."""

    def __init__(self):
        super().__init__()
        self.calls = 0

    def chat_stream(self, messages, tools=None, temperature=0.2,
                    cancel_event=None, model=None):
        self.calls += 1
        if self.calls == 1:
            yield {"type": "message",
                   "message": {"role": "assistant",
                               "content": "", "tool_calls": []}}
            return
        yield {"type": "message",
               "message": {"role": "assistant",
                           "content": "Done: hardened everything.",
                           "tool_calls": []}}


class AlwaysEmptyClient(MockClient):
    """Always returns empty content-less messages - retries must be
    bounded so the loop cannot spin forever."""

    def __init__(self):
        super().__init__()
        self.calls = 0

    def chat_stream(self, messages, tools=None, temperature=0.2,
                    cancel_event=None, model=None):
        self.calls += 1
        yield {"type": "message",
               "message": {"role": "assistant",
                           "content": "", "tool_calls": []}}


def _make_agent(llm):
    return Agent(llm, intent_reformulator=IntentReformulator())


class TestEmptyFinalRetry:
    def test_empty_final_is_nudged_and_recovers(self):
        llm = EmptyFirstClient()
        out = _make_agent(llm).run("run the full chain")
        assert out == "Done: hardened everything.", repr(out)
        assert llm.calls >= 2

    def test_always_empty_is_bounded(self):
        llm = AlwaysEmptyClient()
        out = _make_agent(llm).run("run the full chain")
        assert out == "(empty reply)", repr(out)
        assert llm.calls <= 4, "retry loop not bounded: %d calls" % llm.calls
