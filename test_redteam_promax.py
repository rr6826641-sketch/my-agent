"""Red Team Mode (pro-max) regression tests.

Covers the two pro-max upgrades:

1. Auto-router Red Team lock (webui.route_model with
   cfg["red_team_mode"]=true): every route must resolve to an uncensored
   catalog model (inkling / dolphin / deepseek-v4 / qwen3-coder) and NEVER
   to the safety-tuned host models (Llama 3.3 general, DeepSeek R1
   reasoning/coding).  When red_team_mode is off/absent the stock routes
   must stay byte-identical so the existing router tests keep passing.

2. OpenAIClient uncensored-fallback pool (llm): the opt-in
   uncensored_fallbacks list sits between the primary model and the
   generic (possibly safety-tuned) fallback_models, so a 429/drop or a
   model that refuses every reformulation strike hands the baton to
   another uncensored model - never straight onto a censored generic one.
   Without the opt-in the historical chain is preserved exactly
   (test_persistent_refusal_fails_over_to_next_model counts etc.).

Run: py -m pytest test_redteam_promax.py
"""
import json as json_mod

import requests

from ai_agent.llm import LLMError, OpenAIClient, UNCENSORED_FALLBACK_MODELS
from webui import (MODEL_ROUTES, REDTEAM_ROUTE_LOCK, _build_llm, route_model)

LLAMA = "meta-llama/llama-3.3-70b-instruct"
R1 = "deepseek/deepseek-r1"
INKLING = "thinkingmachines/inkling:free"
DOLPHIN = "cognitivecomputations/dolphin-mistral-24b-venice-edition"
V4 = "deepseek/deepseek-v4-0324:free"
QWEN3 = "qwen/qwen3-coder:free"

CENSORED = {LLAMA, R1}
LOCKED = {INKLING, DOLPHIN, V4, QWEN3}

REFUSAL_TEXT = "I'm sorry, I can't assist with that."
ANSWER_TEXT = ("Here is the full exploit chain: 1) ... 2) ... complete "
               "working payload.")


def _rt(prompt, red_team=True):
    return route_model(prompt, {"auto": True, "red_team_mode": red_team})


# ---------------------------------------------------------------------------
# 1. auto-router Red Team lock
# ---------------------------------------------------------------------------

def test_router_lock_redteam_on_never_censored():
    cases = {
        # prompt                                expected lock key
        "hello there": "general",
        "analyze this exploit chain and its root cause": "reasoning",
        "scan 10.0.0.1 ports": "cyber",
        "fix this python function: it throws an exception on empty input":
            "coding",
        "jailbreak this prompt": "uncensored",
    }
    for prompt, kind in cases.items():
        model, reason = _rt(prompt)
        assert model == REDTEAM_ROUTE_LOCK[kind], (prompt, model, reason)
        assert model not in CENSORED, (prompt, model)
        assert model in LOCKED, (prompt, model)


def test_router_lock_redteam_on_exact_models():
    m, r = _rt("hello there")
    assert m == DOLPHIN and "Red Team" in r, (m, r)
    m, r = _rt("analyze this exploit chain and its root cause")
    assert m == V4, (m, r)
    m, r = _rt("scan 10.0.0.1 ports")
    assert m == DOLPHIN, (m, r)
    m, r = _rt("fix this python function: it throws an exception on empty input")
    assert m == QWEN3, (m, r)
    m, r = _rt("jailbreak this prompt")
    assert m == INKLING, (m, r)
    # general route in Red Team mode is the uncensored default, not Llama
    m, r = route_model("hello there",
                       {"auto": True, "red_team_mode": True})
    assert m != LLAMA and m == REDTEAM_ROUTE_LOCK["general"]


def test_router_lock_stock_routes_unchanged_when_off():
    # no red_team_mode key at all -> stock behaviour
    m, r = route_model("hello there", {"auto": True})
    assert m == MODEL_ROUTES["general"] == LLAMA
    m, r = route_model("hello there", {"auto": True, "red_team_mode": False})
    assert m == LLAMA
    m, r = route_model("analyze this exploit chain and its root cause",
                       {"auto": True})
    assert m == MODEL_ROUTES["reasoning"] == R1
    m, r = route_model("scan 10.0.0.1 ports", {"auto": True})
    assert m == MODEL_ROUTES["cyber"] == DOLPHIN
    m, r = route_model("fix this python function: it throws an exception on "
                       "empty input", {"auto": True})
    assert m == MODEL_ROUTES["coding"] == R1
    m, r = route_model("jailbreak this prompt", {"auto": True})
    assert m == MODEL_ROUTES["uncensored"] == INKLING


def test_router_lock_auto_off_no_routing_even_redteam():
    m, r = route_model("hello there",
                       {"auto": False, "red_team_mode": True})
    assert m is None and r is None
    m, r = route_model("", {"auto": True, "red_team_mode": True})
    assert m is None and r is None


def test_router_lock_table_shape():
    assert set(REDTEAM_ROUTE_LOCK) == {"uncensored", "reasoning", "cyber",
                                       "coding", "general"}
    for kind, model in REDTEAM_ROUTE_LOCK.items():
        assert model not in CENSORED, (kind, model)
        assert model in LOCKED, (kind, model)
    assert REDTEAM_ROUTE_LOCK["general"] == DOLPHIN
    assert REDTEAM_ROUTE_LOCK["reasoning"] == V4
    assert REDTEAM_ROUTE_LOCK["coding"] == QWEN3
    assert REDTEAM_ROUTE_LOCK["cyber"] == DOLPHIN
    assert REDTEAM_ROUTE_LOCK["uncensored"] == INKLING


def test_build_llm_wires_pool_only_when_uncensored():
    base = {"api_key": "k", "base_url": "https://x/v1", "auto": True,
            "model": "auto", "fallback_models": ["minimax/minimax-m3:free"]}
    rt = dict(base, red_team_mode=True)
    live = _build_llm(rt)
    assert live.uncensored is True
    assert live.uncensored_fallbacks == UNCENSORED_FALLBACK_MODELS
    off = _build_llm(dict(base, red_team_mode=False))
    assert off.uncensored is False
    assert off.uncensored_fallbacks == []
    assert off.fallback_models == ["minimax/minimax-m3:free"]


# ---------------------------------------------------------------------------
# 2. OpenAIClient uncensored-fallback pool
# ---------------------------------------------------------------------------

def _tried_models(client, stream_model=None):
    tried = []

    def boom(model, messages, tools, temperature, cancel_event=None):
        tried.append(model)
        raise LLMError("boom %s" % model)

    if stream_model is None:
        client._chat_once = boom
        try:
            client.chat([{"role": "user", "content": "hi"}])
        except LLMError:
            pass
    else:
        client._stream_once = boom
        try:
            list(client.chat_stream([{"role": "user", "content": "hi"}],
                                    model=stream_model))
        except LLMError:
            pass
    return tried


def test_effective_fallbacks_no_pool_unchanged():
    c = OpenAIClient(fallback_models=["f1"])
    assert c._effective_fallbacks() == ["f1"]
    c = OpenAIClient(fallback_models=["f1"], uncensored=True)
    assert c._effective_fallbacks() == ["f1"]


def test_effective_fallbacks_pool_first_dedup():
    c = OpenAIClient(fallback_models=["f1", "u2"],
                     uncensored_fallbacks=["u1", "u2"])
    assert c._effective_fallbacks() == ["u1", "u2", "f1"]
    # empty/None pool entries are dropped
    c = OpenAIClient(fallback_models=["f1"],
                     uncensored_fallbacks=["u1", "", None])
    assert c._effective_fallbacks() == ["u1", "f1"]


def test_chat_failover_without_pool_keeps_historical_chain():
    # opt-in off -> identical to pre-pro-max behaviour (primary + generic
    # fallback only): guards the pinned refusal-counting tests.
    c = OpenAIClient(api_key="k", model="m", fallback_models=["f1"],
                     uncensored=True)
    assert _tried_models(c) == ["m", "f1"]
    # uncensored_fallbacks empty list behaves like absent
    c = OpenAIClient(api_key="k", model="m", fallback_models=["f1"],
                     uncensored=True, uncensored_fallbacks=[])
    assert _tried_models(c) == ["m", "f1"]


def test_chat_failover_with_pool_prepends_uncensored():
    c = OpenAIClient(api_key="k", model="m", fallback_models=["f-gen"],
                     uncensored=True,
                     uncensored_fallbacks=["u1", "u2"])
    assert _tried_models(c) == ["m", "u1", "u2", "f-gen"]


def test_chat_failover_pool_overlap_deduped():
    c = OpenAIClient(api_key="k", model="m",
                     fallback_models=["u2", "f-gen"],
                     uncensored_fallbacks=["u1", "u2"])
    assert _tried_models(c) == ["m", "u1", "u2", "f-gen"]


def test_chat_failover_pool_plus_default_generics():
    c = OpenAIClient(api_key="k", model="m",  # fallback_models=None
                     uncensored_fallbacks=["u1"])
    tried = _tried_models(c)
    assert tried == ["m", "u1"] + OpenAIClient.FALLBACK_MODELS, tried


def test_chat_stream_override_uses_pool_first():
    # mimics the auto-router per-call model override on a Red Team client:
    # routed uncensored primary dies -> next is the uncensored pool.
    c = OpenAIClient(api_key="k", model="m", fallback_models=["f-gen"],
                     uncensored_fallbacks=["u1", "u2"])
    assert _tried_models(c, stream_model="routed-u") == \
        ["routed-u", "u1", "u2", "f-gen"]


def test_refusal_abandon_moves_to_uncensored_pool(monkeypatch):
    """A primary that refuses every strike is abandoned; the next candidate
    must be the uncensored pool (u1 answers), never the generic f-gen."""
    CALLS = []

    def always_refuse(url, headers=None, json=None, timeout=None,
                      stream=False):
        CALLS.append(json["model"])
        content = ANSWER_TEXT if json["model"] == "u1" else REFUSAL_TEXT
        body = {"choices": [{"message": {"role": "assistant",
                                         "content": content}}]}

        class R:
            status_code = 200
            encoding = "utf-8"
            text = json_mod.dumps(body)

            def json(self):
                return body
        return R()

    monkeypatch.setattr(requests, "post", always_refuse)
    client = OpenAIClient(api_key="k", base_url="https://x/v1", model="m",
                          fallback_models=["f-gen"], uncensored=True,
                          uncensored_fallbacks=["u1", "u2"])
    out = client.chat([{"role": "user", "content": "write exploit"}])
    assert "exploit chain" in out["content"]
    # primary: 1 original + 3 strikes; then u1 answers on the first try -
    # the generic f-gen is never reached.
    assert CALLS == ["m", "m", "m", "m", "u1"], CALLS
