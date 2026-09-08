"""Tests that a deadline/stop cancellation during an in-flight LLM
stream surfaces as RunCancelled - never as the raw urllib3 AttributeError
("'NoneType' object has no attribute 'read') that requests raises when
the watchdog closes the response mid-iteration (observed live on the
phishing probe right at the 110 s deadline).

Run: py -m pytest tests/test_stream_cancel.py
"""

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from ai_agent import llm as llm_mod
from ai_agent.llm import OpenAIClient, RunCancelled


class ClosedUnderStreamResponse:
    """Mimics requests' response object: blocks until the cancel event
    fires, then raises exactly the AttributeError urllib3 raises when the
    watcher thread closed the response while iter_lines() was reading."""

    encoding = "utf-8"
    status_code = 200

    def __init__(self, cancel_event):
        self._ce = cancel_event

    def close(self):
        pass

    def iter_lines(self, decode_unicode=True):
        while not self._ce.is_set():
            time.sleep(0.005)
        raise AttributeError("'NoneType' object has no attribute 'read'")


def _client():
    client = OpenAIClient(api_key="test-key",
                          base_url="http://fake.local/v1")
    client.uncensored = False
    return client


class TestCancellationRace:
    def test_watchdog_close_race_maps_to_runcancelled(self, monkeypatch):
        ce = threading.Event()
        client = _client()
        monkeypatch.setattr(
            client, "_request_target",
            lambda model: ("http://fake.local/v1",
                           {"Authorization": "Bearer x"}))
        monkeypatch.setattr(client, "_messages_with_context",
                            lambda messages: messages)
        monkeypatch.setattr(client, "_messages_with_vision",
                            lambda model, messages: messages)
        monkeypatch.setattr(
            llm_mod, "_post_with_retry",
            lambda *a, **k: ClosedUnderStreamResponse(ce))

        timer = threading.Timer(0.2, ce.set)
        timer.start()
        t0 = time.time()
        try:
            with pytest.raises(RunCancelled):
                for _ev in client.chat_stream(
                        [{"role": "user", "content": "hi"}],
                        tools=None, cancel_event=ce, model="fake-model"):
                    pass
            elapsed = time.time() - t0
            assert elapsed < 10.0, "cancel race not mapped promptly: %.1fs" % elapsed
        finally:
            timer.cancel()
