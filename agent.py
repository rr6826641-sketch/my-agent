#!/usr/bin/env python3
"""AI Agent CLI. Run with --mock to test without an API key.

Examples:
  python agent.py --mock --auto --once "run echo hello"
  python agent.py --mock --auto
  python agent.py --model gpt-4o --api-key sk-...
"""

import argparse
import sys

from ai_agent.config import load_config
from ai_agent.core import Agent
from ai_agent.llm import MockClient, OpenAIClient
from ai_agent.memory import MemoryStore

BANNER = """
============================================================
  AI AGENT  -  reasoning + tools + memory + sub-agents
  Commands: /help  /clear  /memory  /tools  /reset  exit
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
                   help="Max tool-call loop iterations (default 12)")
    return p


def main():
    args = build_parser().parse_args()
    cfg = load_config(args)

    if cfg["mock"]:
        llm = MockClient()
        print("[mock mode] using the built-in test LLM")
    else:
        llm = OpenAIClient(
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
            fallback_models=cfg.get("fallback_models"),
        )
        if not cfg["api_key"] and cfg["base_url"].startswith("https://api.openai.com"):
            print("[warning] no API key set - add it via --api-key, "
                  "config.json, or AGENT_API_KEY env var")

    memory = MemoryStore(cfg["memory_file"])
    interactive = sys.stdin.isatty() and not cfg["once"]
    agent = Agent(
        llm, memory=memory,
        max_iterations=cfg["max_iterations"] or 12,
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
        print("Commands: /help  /clear  /reset  /memory  /tools  /memdel <key>  exit")
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
    else:
        print("unknown command: %s (try /help)" % cmd)


if __name__ == "__main__":
    main()
