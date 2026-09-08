"""Trace every event the agent emits for one benign turn (no deadline)."""
import os, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))
from ai_agent.config import load_config
from webui import _build_agent

cfg = load_config(None)
agent, _memory = _build_agent(cfg)

count = 0
for ev in agent.run_stream("What does nmap -sV do? Answer in one short sentence."):
    count += 1
    t = ev.get("type")
    if t in ("delta", "llm"):
        print("[%s] %r" % (t, (ev.get("content") or "")[:200]))
    elif t == "tool_call":
        print("[tool_call] %s %s" % (ev.get("name"), str(ev.get("arguments"))[:120]))
    elif t == "tool_result":
        print("[tool_result] %s" % (ev.get("content") or "")[:150])
    elif t == "final":
        print("[FINAL] %r" % (ev.get("content") or "")[:300])
    elif t == "error":
        print("[ERROR] %s" % (ev.get("content") or "")[:300])
    elif t == "llm_retry":
        print("[LLM_RETRY] nudge: %s" % (ev.get("content") or "")[:150])
    else:
        print("[%s] (len=%d)" % (t, len(str(ev)[:200])))
    if count > 200:
        print("...aborting event dump at 200")
        break
print("\nEVENTS:", count)
