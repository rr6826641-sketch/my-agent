"""E2E integration test: live agent loop with web research discipline.

Verifies that:
  1. A research prompt makes the agent call search_web (and/or research).
  2. fetch_url is used to extract details from at least one source.
  3. The final rendered answer contains cited source URLs.

pytest-compatible: no module-level sys.exit. The heavy live-network flow
only runs when RUN_E2E=1 is set; otherwise the test skips.
"""
import os
import time

import pytest

from ai_agent.config import load_config
from ai_agent.llm import OpenAIClient

PROMPT = ("What is CVE-2024-3094? Use current web research to get accurate "
          "details. You MUST end your final answer with a 'Sources:' list "
          "of every URL you actually fetched, each as a Markdown link.")

SEARCH_ALIASES = {"search_web", "web_search", "research", "search",
                  "websearch"}
FETCH_ALIASES = {"fetch_url", "open_url", "browse_page", "http_request"}
TOOL_HITS = {"search": [], "fetch": []}


def _record(name, args):
    if name in SEARCH_ALIASES:
        TOOL_HITS["search"].append((name, args))
    elif name in FETCH_ALIASES:
        TOOL_HITS["fetch"].append((name, args))


def _make_agent():
    from ai_agent.core import Agent
    import ai_agent.core as _core_mod
    import ai_agent.tools as _tools_mod
    orig = _tools_mod.execute_tool

    def _spy(tools, call, *a, **kw):
        name = getattr(call, "name", None) or (
            call.get("name") if isinstance(call, dict) else None)
        args = getattr(call, "arguments", None)
        if args is None and isinstance(call, dict):
            args = call.get("arguments")
        _record(name, args)
        return orig(tools, call, *a, **kw)

    _tools_mod.execute_tool = _spy
    _core_mod.execute_tool = _spy

    cfg = load_config()
    llm = OpenAIClient(
        api_key=cfg.get("api_key"),
        base_url=cfg.get("base_url"),
        model=cfg.get("model"),
        fallback_models=cfg.get("fallback_models") or [],
    )
    return Agent(llm=llm, name="e2e-test", max_iterations=12,
                 allow_subagents=False)


def test_e2e_web_research():
    if not os.environ.get("RUN_E2E"):
        pytest.skip("live-network e2e; set RUN_E2E=1 to run")
    agent = _make_agent()
    final_text = ""
    t0 = time.time()
    for evt in agent.run_stream(PROMPT):
        if not isinstance(evt, dict):
            continue
        et = evt.get("type")
        if et == "tool_call":
            _record(evt.get("name"), evt.get("arguments"))
        elif et == "final":
            final_text = evt.get("content") or ""
    elapsed = time.time() - t0
    search_ok = bool(TOOL_HITS["search"])
    fetch_ok = bool(TOOL_HITS["fetch"])
    cite_ok = ("http" in final_text
               and ("Source" in final_text or "](http" in final_text))
    print("elapsed: %.1fs | tool hits: %s" % (elapsed, TOOL_HITS))
    assert search_ok, "agent never called a search tool"
    assert cite_ok, "final answer has no rendered source citations"
    assert fetch_ok, "fetch_url never fired (not blocking, but expected)"


if __name__ == "__main__":
    agent = _make_agent()
    final_text = ""
    t0 = time.time()
    for evt in agent.run_stream(PROMPT):
        if isinstance(evt, dict) and evt.get("type") == "final":
            final_text = evt.get("content") or ""
    search_ok = bool(TOOL_HITS["search"])
    cite_ok = ("http" in final_text
               and ("Source" in final_text or "](http" in final_text))
    print("E2E RESULT:", "PASS" if (search_ok and cite_ok) else
          ("PARTIAL" if search_ok else "FAIL"))
    raise SystemExit(0 if (search_ok and cite_ok) else 1)
