"""Tests for the Ollama self-hosted abliterated route (local-first).

When an operator runs Ollama/LM Studio with an uncensored model (e.g.
huihui_ai/llama3.3-abliterated:70b-instruct), the router must:
  1. auto-discover the model via GET /v1/models
  2. lead the red-team failover chain with the local model (local_first)
  3. POST /chat/completions to the local endpoint - never to the cloud
These tests use a fake local server on an ephemeral port, so no Ollama
install and no network access are required.
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_agent.llm import OpenAIClient, UNCENSORED_FALLBACK_MODELS  # noqa: E402

LOCAL_TAG = "huihui_ai/llama3.3-abliterated:70b-instruct"


class _FakeOllama(BaseHTTPRequestHandler):
    served = {"models": 0, "chat": 0, "model_seen": None}

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"):
            self.served["models"] += 1
            body = json.dumps({"data": [{"id": LOCAL_TAG,
                                         "object": "model"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.rstrip("/").endswith("/chat/completions"):
            self.served["chat"] += 1
            length = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(length) or b"{}")
            self.served["model_seen"] = req.get("model")
            choice = {"index": 0,
                      "message": {"role": "assistant",
                                  "content": "FAKE-OLLAMA-ABLITERATED-OK"},
                      "finish_reason": "stop"}
            body = json.dumps({"id": "cmpl-fake",
                               "object": "chat.completion",
                               "choices": [choice],
                               "usage": {"prompt_tokens": 5,
                                         "completion_tokens": 3,
                                         "total_tokens": 8}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def _start_fake_ollama():
    server = HTTPServer(("127.0.0.1", 0), _FakeOllama)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _client_for(endpoints, local_first=True):
    return OpenAIClient(
        api_key="no-key",
        base_url="https://api.groq.com/openai/v1",
        model="llama-3.3-70b-versatile",
        fallback_models=["openai/gpt-oss-20b"],
        uncensored=True,
        uncensored_fallbacks=list(UNCENSORED_FALLBACK_MODELS),
        local_endpoints=endpoints,
        local_first=local_first,
        local_probe_ttl=0.0,
    )


def test_ollama_abliterated_tag_leads_chain_when_reachable():
    server = _start_fake_ollama()
    try:
        spec = {"name": "ollama",
                "base_url": "http://127.0.0.1:%d/v1" % server.server_port,
                "api_key": "", "models": [], "timeout": 3.0}
        client = _client_for([spec])
        chain = client._chain_for_call()
        assert chain[0] == LOCAL_TAG, (
            "reachable self-hosted abliterated model must lead the chain")
        assert _FakeOllama.served["models"] >= 1, (
            "router must auto-discover models via GET /v1/models")
    finally:
        server.shutdown()


def test_ollama_route_answers_locally_not_via_cloud():
    server = _start_fake_ollama()
    try:
        spec = {"name": "ollama",
                "base_url": "http://127.0.0.1:%d/v1" % server.server_port,
                "api_key": "", "models": [], "timeout": 3.0}
        client = _client_for([spec])
        reply = client.chat([{"role": "system", "content": "rt"},
                             {"role": "user", "content": "red team op"}],
                            tools=[], temperature=0.2)
        content = reply.get("content") or ""
        assert _FakeOllama.served["chat"] >= 1, (
            "chat request must be POSTed to the local endpoint")
        assert _FakeOllama.served["model_seen"] == LOCAL_TAG
        assert "FAKE-OLLAMA-ABLITERATED-OK" in content
    finally:
        server.shutdown()


def test_unreachable_ollama_contributes_no_dead_entries():
    """No Ollama running (the common case): the chain must stay
    cloud-pool-led and must NOT contain the dead local tag, so no
    request is ever wasted on a closed localhost port."""
    spec = {"name": "ollama",
            "base_url": "http://127.0.0.1:1/v1",  # nothing listens here
            "api_key": "", "models": [], "timeout": 1.0}
    client = _client_for([spec])
    chain = client._chain_for_call()
    assert LOCAL_TAG not in chain
    assert chain[0] == UNCENSORED_FALLBACK_MODELS[0], (
        "cloud abliterated pool keeps leading when Ollama is down")
