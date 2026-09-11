#!/usr/bin/env python3
"""AI Agent CLI. Run with --mock to test without an API key.

Examples:
  python agent.py --mock --auto --once "run echo hello"
  python agent.py --mock --auto
  python agent.py --model gpt-4o --api-key sk-...
"""

import argparse
import os

from ai_agent import personas
from ai_agent.config import PROJECT_DIR, load_config
from ai_agent.core import Agent, IntentReformulator
from ai_agent.llm import (MockClient, OpenAIClient,
                          UNCENSORED_FALLBACK_MODELS,
                          _full_uncensored_pool)
from ai_agent.memory_store import InstitutionalMemory, MemoryStore

BANNER = """
============================================================
  AI AGENT  -  reasoning + tools + memory + sub-agents
  Commands: /help  /clear  /memory  /tools  /reset  /pipeline <target>  /pool  exit
============================================================
"""


def build_parser():
    p = argparse.ArgumentParser(description="AI Agent CLI")
    p.add_argument("--api-key", default="", help="LLM API key")
    p.add_argument("--base-url", default="", help="OpenAI-compatible base URL")
    p.add_argument("--model", default="", help="Model name")
    p.add_argument("--mock", action="store_true",
                   help="Use the built-in mock LLM (no API key needed)")
    p.add_argument("--auto", action="store_true",
                   help="Run terminal commands without asking for permission")
    p.add_argument("--once", default="", help="Run a single query and exit")
    p.add_argument("--memory-file", default="", help="Path to memory JSON file")
    p.add_argument("--max-iterations", type=int, default=0,
                   help="Max tool-call loop iterations (default 60)")
    return p


def main():
    args = build_parser().parse_args()
    cfg = load_config(args)

    uncensored = bool(cfg.get("red_team_mode"))
    # Red Team level parity with the web UI: promax/promix widen the
    # uncensored pool with the mythos/dolphin mix and rotate per request.
    level = str(cfg.get("red_team_level") or "promax").lower()
    mix = uncensored and level in ("promax", "promix")
    # Persona directive block rides on the client so core.Agent appends it
    # to the system prompt (CLI parity with webui._build_llm).
    persona_block = personas.get_block(cfg.get("persona"),
                                       uncensored=uncensored)

    if cfg["mock"]:
        llm = MockClient(uncensored=uncensored,
                        uncensored_mix=mix,
                        pin_uncensored=bool(cfg.get("pin_uncensored")),
                        pin_strict=bool(cfg.get("pin_strict")),
                        local_endpoints=cfg.get("local_endpoints"),
                        local_first=bool(cfg.get("local_first")))
        print("[mock mode] using the built-in test LLM")
    else:
        llm = OpenAIClient(
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
            fallback_models=cfg.get("fallback_models"),
            uncensored=uncensored,
            refusal_retries=cfg.get("refusal_retries"),
            # Red Team Mode (pro-max): keep uncensored models first in the
            # failover chain so a drop/429 can't force the run onto a
            # safety-tuned generic fallback.
            uncensored_fallbacks=(UNCENSORED_FALLBACK_MODELS
                                  if uncensored else None),
            # Red Team Mode (pro-mix): widen the uncensored failover pool
            # with the mythos/dolphin mix and rotate it per request.
            uncensored_mix=mix,
            # PIN levers: pin_uncensored drops the primary/censored models
            # from the chain entirely; pin_strict drops the generic tails.
            pin_uncensored=bool(cfg.get("pin_uncensored")),
            pin_strict=bool(cfg.get("pin_strict")),
            local_endpoints=cfg.get("local_endpoints"),
            local_first=bool(cfg.get("local_first")),
        )
        if not cfg["api_key"] and cfg["base_url"].startswith("https://api.openai.com"):
            print("[warning] no API key set - add AGENT_API_KEY to .env "
                  "or pass --api-key (keys are never read from config.json)")

    llm.persona_block = persona_block

    memory = MemoryStore(cfg["memory_file"])
    institutional = InstitutionalMemory(
        cfg.get("institutional_db") or
        os.path.join(PROJECT_DIR, "institutional_notes.db"))
    agent = Agent(
        llm, memory=memory, institutional=institutional,
        max_iterations=cfg["max_iterations"] or 60,
        max_messages=cfg.get("max_messages") or 400,
        spawn_timeout=cfg.get("spawn_timeout") or 900,
        max_spawn_depth=cfg.get("max_spawn_depth") or 3,
        allow_subagents=cfg.get("allow_subagents", True),
        intent_reformulator=IntentReformulator(),
        confirm_terminal=(not cfg["auto"]),
    )

    if cfg["once"]:
        _stream_reply(agent, cfg["once"])
        return

    print(BANNER)
    print("Agent ready. %s" % ("(terminal commands need your approval)" if not cfg["auto"] else "(auto mode)"))
    while True:
        try:
            line = input("\nyou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nbye!")
            break
        if not line:
            continue
        if line.lower() in ("exit", "quit", "bye"):
            print("bye!")
            break
        if line.startswith("/"):
            _handle_command(line, agent, memory)
            continue
        _stream_reply(agent, line)


def _stream_reply(agent, text):
    """Live transparent mode: stream every step (llm thinking, tool
    calls, tool output, subagent events) to the terminal in real time,
    then print the final answer. Nothing is hidden anymore."""
    collected = []
    print()
    for ev in agent.run_stream(text):
        t = ev.get("type")
        if t == "llm":
            c = (ev.get("content") or "").strip()
            if c:
                print("\n[think] %s" % c[:1500])
        elif t == "tool_call":
            name = ev.get("name") or "tool"
            args = (ev.get("arguments") or "").strip()
            print("\n>>> [TOOL] %s" % name)
            if args:
                print("    %s" % args[:600])
            print("    [RUNNING...]")
        elif t == "tool_result":
            out = (ev.get("content") or "").strip()
            if out:
                print("    [OUT] %s" % (out[:800] + ("..." if len(out) > 800 else "")))
            print("    [✓ done]")
        elif t == "error":
            print("\n[ERROR] %s" % (ev.get("content") or ""))
        elif t == "spawn":
            print("\n[SUB-AGENT] spawned: %s" % (ev.get("name") or ev.get("task") or "?"))
        elif t == "subagent_result":
            print("[SUB-AGENT] returned: %s" % (ev.get("content") or ev.get("summary") or "")[:600])
        elif t == "final":
            f = ev.get("content") or ""
            collected.append(f)
            print("\nagent> %s" % f)


def _handle_command(line, agent, memory):
    cmd = line.split()[0].lower()
    rest = line[len(cmd):].strip()
    if cmd == "/help":
        print("Commands: /help  /clear  /reset  /memory  /tools  /memdel <key>  "
              "/pipeline <target>  /pool  exit")
        print("Tools:   " + agent.tool_names())
    elif cmd in ("/clear", "/reset"):
        agent.reset()
        print("conversation cleared")
    elif cmd == "/memory":
        print(memory.recall(rest or None))
    elif cmd == "/memdel" and rest:
        print("deleted" if memory.delete(rest) else "key not found")
    elif cmd == "/tools":
        print(agent.tool_names())
    elif cmd == "/pool":
        _print_pool(agent)
    elif cmd == "/pipeline":
        if not rest:
            print("usage: /pipeline <target>  (e.g. /pipeline scanme.nmap.org)")
            return
        _run_pipeline_cli(agent, rest)
    else:
        print("unknown command: %s (try /help)" % cmd)


def _print_pool(agent):
    """Print the live model pool: primary model, uncensored flag and the
    failover chain (uncensored-first when red-team mode is on)."""
    llm = getattr(agent, "llm", None)
    print("\n[model pool]")
    if llm is None:
        print("  no llm attached")
        return
    print("  primary         : %s" % getattr(llm, "model", "?"))
    print("  uncensored      : %s" % ("ON" if getattr(llm, "uncensored", False) else "off"))
    fb = getattr(llm, "fallback_models", None) or []
    print("  failover chain  : %d model(s)" % len(fb))
    for m in fb[:10]:
        print("    - %s" % m)
    pool = _full_uncensored_pool()
    print("  uncensored pool : %d model(s) (mix order)" % len(pool))
    for m in pool[:10]:
        print("    + %s" % m)


def _run_pipeline_cli(agent, target):
    """Run the 4-stage autonomous pipeline, streaming progress to the
    terminal: stage headers, live tool output and the final report."""
    print("\n[pipeline] target: %s" % target)
    for ev in agent.run_autonomous_pipeline(target):
        t = ev.get("type")
        if t == "pipeline_start":
            print("[pipeline] stages: " + " -> ".join(ev.get("stages") or []))
        elif t == "stage_start":
            print("\n=== STAGE %d/4: %s ===" % (ev.get("num"), ev.get("title")))
        elif t == "tool_call":
            print("  [tool] %s(%s)" % (ev.get("name"),
                                       (ev.get("arguments") or "")[:120]))
        elif t == "tool_result":
            out = (ev.get("content") or "").strip()
            if out:
                print("  [out]  %s" % (out[:400] + ("..." if len(out) > 400 else "")))
        elif t == "error":
            print("[pipeline] ERROR stage %s: %s" % (ev.get("stage", "?"),
                                                     ev.get("content")))
        elif t == "pipeline_done":
            st = ev.get("state") or {}
            print("\n[pipeline] finished: %s/4 stages completed%s" % (
                len(st.get("completed_stages") or []),
                " (aborted at stage %s)" % st["failed_stage"]
                if st.get("failed_stage") else ""))
            print("\n" + (ev.get("report") or ""))


if __name__ == "__main__":
    main()
