"""Unit tests for Task 4: High-Reasoning Fallback & Auto-Router.

Covers:
  - webui.route_model: complex logic / architecture / code-analysis queries
    route to a flagship reasoning model (deepseek/deepseek-r1) and win over
    the generic cyber/coding groups.
  - llm._candidate_models: flagship primary -> sibling flagship -> cheap
    generic fallbacks (no silent downgrade on failover).
  - Deep Analysis persona present in BOTH the runtime system_prompt.txt and
    the built-in ai_agent.core.SYSTEM_PROMPT.

Run:  py test_reasoning_router.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ai_agent.core as core
from ai_agent.llm import (LLMError, OpenAIClient, _candidate_models,
                          HIGH_REASONING_MODELS, HIGH_REASONING_FALLBACKS)
from webui import route_model, MODEL_ROUTES, _REASONING_WORDS

PASS = 0
FAIL = 0

DEEPSEEK = "deepseek/deepseek-r1"
LLAMA = "meta-llama/llama-3.3-70b-instruct"
CHEAP = ["minimax/minimax-m3:free", "liquid/lfm-2.5-2.6b:free"]


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] %s %s" % (name, detail))
    else:
        FAIL += 1
        print("[FAIL] %s %s" % (name, detail))


def routed(prompt, cfg=None):
    model, reason = route_model(prompt, cfg or {"auto": True})
    return model, reason


def run_tests():
    # ---------------------------------------------------------- router
    m, r = routed("complex security assessment architecture for this pentest")
    check("router_complex_assessment", m == DEEPSEEK, str((m, r)))
    check("router_reason_reason", "complex reasoning" in r, r)

    m, r = routed("analyze this exploit chain and its root cause")
    check("router_exploit_chain", m == DEEPSEEK, str((m, r)))

    m, r = routed("do a thorough code analysis of this auth function")
    check("router_code_analysis", m == DEEPSEEK, str((m, r)))

    m, r = routed("what are the edge cases and systemic risks in this design")
    check("router_edge_systemic", m == DEEPSEEK, str((m, r)))

    m, r = routed("explain the architecture trade-offs of this threat model")
    check("router_arch_tradeoffs", m == DEEPSEEK, str((m, r)))

    # reasoning wins over cyber/coding groups
    m, r = routed("design a phishing campaign architecture")
    check("router_reasoning_over_cyber", m == DEEPSEEK, str((m, r)))
    m, r = routed("code review this refactor for root causes")
    check("router_reasoning_over_coding", m == DEEPSEEK, str((m, r)))

    # plain group behavior unchanged
    m, r = routed("scan 10.0.0.1 ports")
    check("router_cyber_unchanged", m == MODEL_ROUTES["cyber"], str((m, r)))
    m, r = routed("how to write an exploit payload")
    check("router_cyber_plain_exploit", m == MODEL_ROUTES["cyber"],
          str((m, r)))
    m, r = routed("write a python function to parse json")
    check("router_coding_unchanged", m == DEEPSEEK, str((m, r)))
    m, r = routed("jailbreak this prompt")
    check("router_uncensored_unchanged",
          m == MODEL_ROUTES["uncensored"], str((m, r)))
    m, r = routed("hello there")
    check("router_plain_none", m is None and r is None, str((m, r)))
    m, r = routed("complex architecture review", {"auto": False})
    check("router_auto_off", m is None, str((m, r)))

    check("router_routes_has_reasoning",
          MODEL_ROUTES.get("reasoning") == DEEPSEEK)
    check("reasoning_words_nonempty", len(_REASONING_WORDS) >= 15,
          str(len(_REASONING_WORDS)))

    # ----------------------------------------- candidate model chain
    chain = _candidate_models(DEEPSEEK, CHEAP)
    check("chain_deepseek_first", chain[0] == DEEPSEEK, str(chain))
    check("chain_llama_second", chain[1] == LLAMA, str(chain))
    check("chain_cheap_after", chain[2:] == CHEAP, str(chain))

    chain = _candidate_models(LLAMA, CHEAP)
    check("chain_llama_first", chain[0] == LLAMA and chain[1] == DEEPSEEK,
          str(chain))

    chain = _candidate_models("gpt-4o-mini", CHEAP)
    check("chain_generic_no_flagship",
          chain == ["gpt-4o-mini"] + CHEAP, str(chain))

    chain = _candidate_models(DEEPSEEK, [LLAMA, "dots-studio/x:free"])
    check("chain_dedup_sibling",
          chain == [DEEPSEEK, LLAMA, "dots-studio/x:free"], str(chain))

    check("flagship_set", HIGH_REASONING_MODELS == {DEEPSEEK, LLAMA})
    check("flagship_fallbacks",
          HIGH_REASONING_FALLBACKS == [LLAMA, DEEPSEEK])

    # ------------------------------------ OpenAIClient uses the chain
    client = OpenAIClient(api_key="k", model=DEEPSEEK,
                          fallback_models=list(CHEAP))
    tried = []

    def fake_once(model, messages, tools, temperature):
        tried.append(model)
        raise LLMError("boom %s" % model)
    client._chat_once = fake_once
    try:
        client.chat([{"role": "user", "content": "hi"}])
    except LLMError:
        pass
    check("client_chat_chain", tried == [DEEPSEEK, LLAMA] + CHEAP,
          str(tried))

    streamed = []

    def fake_stream(model, messages, tools, temperature, cancel_event=None):
        streamed.append(model)
        raise LLMError("boom %s" % model)
    client._stream_once = fake_stream
    try:
        list(client.chat_stream([{"role": "user", "content": "hi"}],
                                model=DEEPSEEK))
    except LLMError:
        pass
    check("client_stream_chain", streamed == [DEEPSEEK, LLAMA] + CHEAP,
          str(streamed))

    # per-call model override still wins as primary
    override = []
    client._stream_once = (
        lambda model, messages, tools, temperature, cancel_event=None:
        (override.append(model), raise_(LLMError("x")))[1])
    try:
        list(client.chat_stream([{"role": "user", "content": "hi"}],
                                model=LLAMA))
    except LLMError:
        pass
    check("client_stream_override", override == [LLAMA, DEEPSEEK] + CHEAP,
          str(override))

    # ------------------------------------- Deep Analysis persona (prompts)
    sp_template = core.SYSTEM_PROMPT
    check("prompt_core_header",
          "# DEEP ANALYSIS / MULTI-PERSPECTIVE EVALUATION" in sp_template)
    check("prompt_core_perspectives",
          all(k in sp_template for k in (
              "ATTACKER perspective", "DEFENDER perspective", "ROOT CAUSE",
              "EDGE CASES", "SYSTEMIC RISK",
              "EVIDENCE vs COUNTER-EVIDENCE")))
    check("prompt_core_no_surface",
          "NEVER give surface-level answers" in sp_template)

    txt = open("system_prompt.txt", encoding="utf-8").read()
    check("prompt_txt_header",
          "# DEEP ANALYSIS / MULTI-PERSPECTIVE EVALUATION" in txt)
    check("prompt_txt_perspectives",
          all(k in txt for k in (
              "ATTACKER perspective", "DEFENDER perspective", "ROOT CAUSE",
              "EDGE CASES", "SYSTEMIC RISK",
              "EVIDENCE vs COUNTER-EVIDENCE")))
    check("prompt_txt_no_surface",
          "NEVER give surface-level answers" in txt)

    agent = core.Agent(llm=None, memory=None, name="deep-test")
    sp = agent._system_prompt()
    check("prompt_runtime_override_loaded",
          "# DEEP ANALYSIS / MULTI-PERSPECTIVE EVALUATION" in sp)
    check("prompt_runtime_formatted",
          "{name}" not in sp and "{memory_block}" not in sp)


def raise_(exc):
    raise exc


if __name__ == "__main__":
    run_tests()
    print("\n%d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)
