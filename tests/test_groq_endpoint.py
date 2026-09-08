"""Tests for the Groq-style remote endpoint plug-in (own API key).

Covers the api_key_env resolution, authenticated /models probing,
non-chat/audio model filtering, and routing of discovered model ids back
to the endpoint's own base_url + key (same mechanism as the Ollama/LM
Studio plug-in, generalised to any OpenAI-compatible remote host).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ai_agent.llm as llm
from ai_agent.llm import OpenAIClient

GROQ = {"name": "groq", "base_url": "https://api.groq.com/openai/v1",
        "api_key_env": "GROQ_API_KEY", "timeout": 5.0}


def test_normalize_reads_api_key_from_env(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test123")
    specs = llm._normalize_local_endpoints([dict(GROQ)])
    assert specs and specs[0]["api_key"] == "gsk_test123"


def test_normalize_tolerates_missing_env_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    specs = llm._normalize_local_endpoints([dict(GROQ)])
    assert specs and specs[0]["api_key"] == ""


def test_probe_sends_auth_and_filters_audio(monkeypatch):
    captured = {}

    class R:
        status_code = 200

        @staticmethod
        def json(**kw):
            return {"data": [{"id": "llama-3.3-70b-versatile"},
                             {"id": "whisper-large-v3"},
                             {"id": "openai/gpt-oss-120b"}]}

    def fake_get(url, timeout=None, headers=None):
        captured["url"] = url
        captured["headers"] = headers
        return R()

    monkeypatch.setattr(llm.requests, "get", fake_get)
    ids = llm._probe_local_endpoint(
        {"base_url": GROQ["base_url"], "api_key": "gsk_x", "timeout": 5.0})
    assert captured["url"].endswith("/models")
    assert captured["headers"].get("Authorization") == "Bearer gsk_x"
    assert "whisper-large-v3" not in ids
    assert "llama-3.3-70b-versatile" in ids
    assert "openai/gpt-oss-120b" in ids


def test_discovered_groq_models_route_to_groq_key(monkeypatch):
    monkeypatch.setattr(
        llm, "_probe_local_endpoint",
        lambda spec: ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"])
    c = OpenAIClient(
        api_key="sk-main", base_url="https://openrouter.ai/api/v1",
        model="m", uncensored=True,
        local_endpoints=[dict(GROQ, api_key="gsk_x")],
        local_probe_ttl=0.0)
    c._refresh_local_models()
    assert "llama-3.3-70b-versatile" in c._local_route
    base, key = c._local_route["llama-3.3-70b-versatile"]
    assert base == GROQ["base_url"]
    assert key == "gsk_x"
    b2, h2 = c._request_target("llama-3.3-70b-versatile")
    assert b2 == base
    assert h2["Authorization"] == "Bearer gsk_x"


def test_chain_includes_endpoint_models_after_uncensored_pool(monkeypatch):
    monkeypatch.setattr(llm, "_probe_local_endpoint",
                        lambda spec: ["llama-3.3-70b-versatile"])
    c = OpenAIClient(
        api_key="sk-main", base_url="https://openrouter.ai/api/v1",
        model="m", uncensored=True,
        uncensored_fallbacks=["u-one", "u-two"],
        local_endpoints=[dict(GROQ, api_key="gsk_x")],
        local_probe_ttl=0.0)
    chain = c._effective_fallbacks()
    assert chain.index("u-one") < chain.index("llama-3.3-70b-versatile")
    assert "llama-3.3-70b-versatile" in chain
