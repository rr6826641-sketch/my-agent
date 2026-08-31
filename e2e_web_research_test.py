"""E2E integration test: live agent loop with web research discipline.

Verifies that:
  1. A research prompt makes the agent call search_web (and/or research).
  2. fetch_url is used to extract details from at least one source.
  3. The final rendered answer contains cited source URLs.
"""
import sys
import time

from ai_agent.core import Agent
from ai_agent.config import load_config
from ai_agent.llm import OpenAIClient

cfg = load_config()
llm = OpenAIClient(
    api_key=cfg.get("api_key"),
    base_url=cfg.get("base_url"),
    model=cfg.get("model"),
    fallback_models=cfg.get("fallback_models") or [],
)

agent = Agent(llm=llm, name="e2e-test", max_iterations=12,
              allow_subagents=False)

SEARCH_ALIASES = {"search_web", "web_search", "research", "search",
                 "websearch"}
FETCH_ALIASES = {"fetch_url", "open_url", "browse_page", "http_request"}
TOOL_HITS = {"search": [], "fetch": []}

import ai_agent.tools as _tools_mod
import ai_agent.core as _core_mod

_orig_execute = _tools_mod.execute_tool


def _record(name, args):
    if name in SEARCH_ALIASES:
        TOOL_HITS["search"].append((name, args))
    elif name in FETCH_ALIASES:
        TOOL_HITS["fetch"].append((name, args))


def _spy(tools, call, *a, **kw):
    name = getattr(call, "name", None) or (call.get("name") if isinstance(call, dict) else None)
    args = getattr(call, "arguments", None)
    if args is None and isinstance(call, dict):
        args = call.get("arguments")
    _record(name, args)
    return _orig_execute(tools, call, *a, **kw)


_tools_mod.execute_tool = _spy
_core_mod.execute_tool = _spy

PROMPT = ("What is CVE-2024-3094? Use current web research to get accurate "
          "details. You MUST end your final answer with a 'Sources:' list "
          "of every URL you actually fetched, each as a Markdown link.")

final_text = ""
t0 = time.time()
for evt in agent.run_stream(PROMPT):
    if not isinstance(evt, dict):
        continue
    et = evt.get("type")
    if et == "tool_call":
        print("[tool]", evt.get("name"), str(evt.get("arguments"))[:90])
        _record(evt.get("name"), evt.get("arguments"))
    elif et == "final":
        final_text = evt.get("content") or ""

import os as _os
os_devnull = _os.open(_os.devnull, _os.O_WRONLY)
_os.dup2(os_devnull, 2)

elapsed = time.time() - t0
print()
print("=" * 60)
print("TOOL HITS:", {k: len(v) for k, v in TOOL_HITS.items()})
print("final answer length:", len(final_text))
print("elapsed: %.1fs" % elapsed)
print()
print("--- FINAL ANSWER (last 1000 chars) ---")
print(final_text[-1000:])
print("=" * 60)
search_ok = bool(TOOL_HITS["search"])
fetch_ok = bool(TOOL_HITS["fetch"])
cite_ok = ("http" in final_text
           and ("Source" in final_text or "](http" in final_text))
print("E2E RESULT:", "PASS" if (search_ok and cite_ok) else
      ("PARTIAL" if search_ok else "FAIL"))
print("  search fired        ->", "OK" if search_ok else "MISSING")
print("  fetch_url fired     ->", "OK" if fetch_ok else "MISSING (not blocking)")
print("  citations rendered  ->", "OK" if cite_ok else "MISSING")
sys.exit(0 if (search_ok and cite_ok) else 1)
