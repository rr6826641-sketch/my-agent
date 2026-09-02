#!/usr/bin/env python3
"""AI Agent CLI. Run with --mock to test without an API key.

Examples:
  python agent.py --mock --auto --once "run echo hello"
  python agent.py --mock --auto
  python agent.py --model gpt-4o --api-key sk-...
"""

import argparse
import os
import sys

from ai_agent.config import PROJECT_DIR, load_config
from ai_agent.core import Agent
from ai_agent.llm import MockClient, OpenAIClient
from ai_agent.memory_store import InstitutionalMemory, MemoryStore

BANNER = """
============================================================
  AI AGENT  -  reasoning + tools + memory + sub-agents
  Commands: /help  /clear  /memory  /tools  /reset  /pipeline <target>  exit
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

    if cfg["mock"]:
        llm = MockClient(uncensored=cfg.get("red_team_mode"))
        print("[mock mode] using the built-in test LLM")
    else:
        llm = OpenAIClient(
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
            fallback_models=cfg.get("fallback_models"),
            uncensored=cfg.get("red_team_mode"),
        )
        if not cfg["api_key"] and cfg["base_url"].startswith("https://api.openai.com"):
            print("[warning] no API key set - add AGENT_API_KEY to .env "
                  "or pass --api-key (keys are never read from config.json)")

    memory = MemoryStore(cfg["memory_file"])
    institutional = InstitutionalMemory(
        cfg.get("institutional_db") or
        os.path.join(PROJECT_DIR, "institutional_notes.db"))
    interactive = sys.stdin.isatty() and not cfg["once"]
    agent = Agent(
        llm, memory=memory, institutional=institutional,
        max_iterations=cfg["max_iterations"] or 60,
        max_messages=cfg.get("max_messages") or 400,
        spawn_timeout=cfg.get("spawn_timeout") or 900,
        max_spawn_depth=cfg.get("max_spawn_depth") or 3,
        allow_subagents=cfg.get("allow_subagents", True),
        confirm_terminal=(not cfg["auto"]),
    )

    if cfg["once"]:
        print(agent.run(cfg["once"]))
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
        print("\nagent> %s" % agent.run(line))


def _handle_command(line, agent, memory):
    cmd = line.split()[0].lower()
    rest = line[len(cmd):].strip()
    if cmd == "/help":
        print("Commands: /help  /clear  /reset  /memory  /tools  /memdel <key>  "
              "/pipeline <target>  exit")
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
    elif cmd == "/pipeline":
        if not rest:
            print("usage: /pipeline <target>  (e.g. /pipeline scanme.nmap.org)")
            return
        _run_pipeline_cli(agent, rest)
    else:
        print("unknown command: %s (try /help)" % cmd)


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
