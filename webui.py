#!/usr/bin/env python3
"""AI Agent - local Web UI (Flask).

Run:
    py -3 webui.py            # starts on http://127.0.0.1:8080
    py -3 webui.py --port 9000
    py -3 webui.py --mock     # force mock mode even if an API key is set

The UI is local-only (binds to 127.0.0.1). Configure the LLM from the
Settings tab: base URL, model and toggles are saved to config.json; the
API key is saved ONLY to .env (never config.json). If .env is missing or
AGENT_API_KEY is empty, the UI shows a safe fallback error banner.
"""

import argparse
import datetime
import json
import os
import re
import queue
import threading
import time
import uuid

from flask import (Flask, jsonify, render_template, request, Response,
                   send_file, stream_with_context)

from ai_agent.config import (PROJECT_DIR, load_config, config_status, save_env_key)
from ai_agent.core import Agent, IntentReformulator, RunCancelled
from ai_agent.llm import (MockClient, OpenAIClient,
                          UNCENSORED_FALLBACK_MODELS,
                          MIXED_UNCENSORED_MODELS)
from ai_agent.artifacts import ArtifactManager
from ai_agent.memory_store import (
    GlobalKnowledge,
    InstitutionalMemory,
    MemoryStore,
)
from ai_agent.rpg import RPGEngine
from ai_agent import personas

CONFIG_PATH = os.path.join(PROJECT_DIR, "config.json")
MEMORY_PATH = os.path.join(PROJECT_DIR, "memory.json")
CHATS_PATH = os.path.join(PROJECT_DIR, "chats.json")

# structured scan/generation outputs: artifacts/{chat_id}/{timestamp}/{tool}_{ts}.{ext}
ARTIFACTS_DIR = os.path.join(PROJECT_DIR, "artifacts")
artifacts = ArtifactManager(ARTIFACTS_DIR)

# persistent cross-conversation institutional notes (SQLite, gitignored)
INSTITUTIONAL_NOTES_PATH = os.path.join(PROJECT_DIR, "institutional_notes.db")

# serializes all reads/writes of chats.json
_chat_lock = threading.Lock()

# wall-clock boot instant, drives the Command Center uptime counter
_WEBUI_BOOT_TS = time.time()

# one stop_event per active /api/chat run so the Stop button can cancel it
_run_lock = threading.Lock()
_active_runs = {}  # run_id -> threading.Event

# one active RPG turn per game: game_id -> (run_id, stop_event)
_rpg_lock = threading.Lock()
_rpg_runs = {}  # game_id -> (run_id, threading.Event)

app = Flask(__name__)


# --------------------------------------------------------------------------
# OpenRouter model catalog + Smart Auto-Model Router
# --------------------------------------------------------------------------

DEFAULT_FAST_MODEL = "nvidia/nemotron-3-super-120b-a12b:free"

MODEL_CATALOG = [
    {"id": "auto", "label": "✨ Auto Select (Smart Router)",
     "tag": "recommended",
     "desc": "Routes every prompt to the best model automatically"},
    {"id": "cognitivecomputations/dolphin-mistral-24b-venice-edition",
     "label": "Dolphin Mistral 24B", "tag": "uncensored", "uncensored": True,
     "desc": "Top uncensored — cyber security / recon / red-team tasks"},
    {"id": "thinkingmachines/inkling:free",
     "label": "Inkling (Free)", "tag": "free", "uncensored": True,
     "desc": "Free uncensored model"},
    {"id": "meta-llama/llama-3.3-70b-instruct",
     "label": "Llama 3.3 70B Instruct", "tag": "general",
     "desc": "Powerful open-source general-purpose model"},
    {"id": "deepseek/deepseek-r1",
     "label": "DeepSeek R1", "tag": "reasoning",
     "desc": "Complex reasoning, math & coding"},
    {"id": "deepseek/deepseek-v4-0324:free",
     "label": "DeepSeek V4 (free)", "tag": "free", "uncensored": True,
     "desc": "Uncensored reasoning / exploit chain model"},
    {"id": "qwen/qwen3-coder:free",
     "label": "Qwen3 Coder (free)", "tag": "coding", "uncensored": True,
     "desc": "Fast uncensored coding model"},
    {"id": "z-ai/glm-5.2:free",
     "label": "GLM 5.2 (free)", "tag": "reasoning",
     "desc": "Long-horizon agent workflows, 1M context reasoning"},
    {"id": "minimax/minimax-m2.7:free",
     "label": "MiniMax M2.7 (free)", "tag": "general",
     "desc": "Agentic multi-agent workflows, coding & debugging"},
    {"id": DEFAULT_FAST_MODEL,
     "label": "Nemotron 120B (Fast Default)", "tag": "fast",
     "desc": "Fast default model for everyday chat"},
]

MODEL_LABELS = {m["id"]: m["label"] for m in MODEL_CATALOG}

# keyword groups used by the auto-router (case-insensitive substring match)
# checked FIRST: complex logic / architecture / code-analysis / security-
# assessment-design queries must reach a flagship reasoning model, never a
# cheap default (Task 4: High-Reasoning Fallback & Auto-Router).
_REASONING_WORDS = [
    "complex", "complicated", "intricate", "nuanced", "deep dive",
    "in-depth", "in depth", "thorough", "architecture", "architect",
    "system design", "design review", "root cause", "underlying cause",
    "systemic", "systemic risk", "edge case", "edge cases",
    "corner case", "multi-perspective", "multi perspective",
    "exploit chain", "attack chain", "attack path", "kill chain",
    "code analysis", "code review", "static analysis",
    "threat model", "threat modeling", "risk assessment",
    "risk analysis", "impact analysis", "blast radius", "cascading",
    "trade-off", "tradeoff", "feasibility", "hypothesis",
    "counter-evidence", "counter evidence", "reasoning", "conclude",
]
_CYBER_WORDS = [
    "scan", "port scan", "nmap", "recon", "subdomain", "osint", "whois",
    "dns", "enumerate", "fingerprint", "fuzz", "sqlmap", "sql injection",
    "xss", "csrf", "ssrf", "lfi", "rfi", "sqli", "cve", "exploit",
    "payload", "shell", "reverse shell", "backdoor", "malware",
    "ransomware", "phishing", "metasploit", "burp", "hydra", "hashcat",
    "john the ripper", "brute", "bruteforce", "crack", "password",
    "kerberoast", "mitm", "tcpdump", "wireshark", "vulnerability",
    "pentest", "penetration", "hack", "hacking", "cyber", "security",
    "dark web", "anonym", "proxy", "evasion", "privilege escalation",
    "lateral movement", "persistence", "c2", "keylog", "spyware",
    "escalate", "escalation", "privesc", "priv esc", "compromised",
    "compromise", "webshell", "implant", "post-exploitation",
    "trojan", "rootkit", "botnet", "ddos", "credential", "dump",
    "smb", "rdp", "wifi", "aircrack", "deauth", "sniff", "arp",
    "session hijack", "token", "idor", "auth bypass", "bypass", "0day",
    "zeroday", "forensic", "malware analysis", "threat", "red team",
    "blue team", "siem", "firewall", "ids", "ips", "network",
    "endpoint", "active directory", "ldap", "kerberos", "nltest",
    "bloodhound", "mimikatz", "pass-the-hash", "lateral", "domain",
]
_CODING_WORDS = [
    "code", "python", "javascript", "typescript", "java", "c++", "c#",
    "golang", "rust", "ruby", "php", "function", "class", "method",
    "algorithm", "debug", "compile", "refactor", "regex", "sql query",
    "api", "endpoint", "script", "html", "css", "react", "node",
    "flask", "django", "docker", "kubernetes", "git", "linux", "bash",
    "powershell", "math", "equation", "solve", "calculate", "compute",
    "calculus", "algebra", "geometry", "probability", "statistics",
    "logic", "proof", "theorem", "leetcode", "challenge", "data structure",
    "binary", "sorting", "recursion", "dynamic programming", "optimization",
    "syntax", "exception", "stack trace", "unit test", "pytest", "numpy",
    "pandas", "machine learning", "neural network", "gradient", "tensor",
    "matrix", "regression", "big-o", "time complexity", "design pattern",
    "snippet", "function call", "implement", "write a program", "coding",
]

def _kw_res(words):
    """Compile keyword list to word-boundary regexes.

    Plain substring matching ('w in text') misfires on short tokens:
    'api' matches 'capital', 'ids' matches 'consider', ... Boundaries
    regex word boundaries keep multi-word phrases and c++ working.
    """
    return [re.compile(r"(?<!\w)" + re.escape(w) + r"(?!\w)")
            for w in words]


MODEL_ROUTES = {
    "cyber": "cognitivecomputations/dolphin-mistral-24b-venice-edition",
    "uncensored": "thinkingmachines/inkling:free",
    "coding": "deepseek/deepseek-r1",
    # flagship reasoning: complex logic / architecture / code analysis
    "reasoning": "deepseek/deepseek-r1",
    # general chat & fast answers -> powerful open-source general model
    "general": "meta-llama/llama-3.3-70b-instruct",
}

# Red Team Mode lock (pro-max): when the uncensored master switch is ON the
# auto-router must never land a request on a safety-tuned host model (Llama
# 3.3 general, DeepSeek R1 reasoning/coding).  Every route resolves to an
# uncensored catalog model so a hosted-model refusal can never silently gate
# the agent mid-engagement.  route_model() swaps in this table only when
# cfg["red_team_mode"] is true; the stock routes above stay untouched
# otherwise (existing router regression tests keep passing).
REDTEAM_ROUTE_LOCK = {
    "uncensored": "thinkingmachines/inkling:free",
    "reasoning": "deepseek/deepseek-v4-0324:free",
    "cyber": "cognitivecomputations/dolphin-mistral-24b-venice-edition",
    "coding": "qwen/qwen3-coder:free",
    "general": "cognitivecomputations/dolphin-mistral-24b-venice-edition",
}


_CYBER_RES = _kw_res(_CYBER_WORDS)
_CODING_RES = _kw_res(_CODING_WORDS)
_REASONING_RES = _kw_res(_REASONING_WORDS)


def route_model(prompt, cfg=None):
    """Classify a prompt and return (model_id, reason).

    Returns (None, None) only when the Smart Auto-Router is off (the
    configured/default model is then used unchanged).

    Red Team Mode lock: with cfg["red_team_mode"]=true every resolved route
    is remapped through REDTEAM_ROUTE_LOCK so requests in an uncensored
    session always reach an uncensored model - never Llama 3.3 general or
    DeepSeek R1, whose safety tuning can refuse offensive-security work.
    """
    cfg = cfg or {}
    auto = bool(cfg.get("auto")) or (cfg.get("model") == "auto")
    if not auto or not prompt:
        return None, None
    red_team = bool(cfg.get("red_team_mode"))
    for w in ("uncensored", "jailbreak", "nsfw", "adult"):
        if w in prompt.lower():
            model = REDTEAM_ROUTE_LOCK["uncensored"] if red_team \
                else MODEL_ROUTES["uncensored"]
            return model, "uncensored / jailbreak prompt"
    # Reasoning is checked before the cyber/coding groups so complex
    # security-assessment design still reaches a flagship reasoning model.
    if any(rx.search(prompt) for rx in _REASONING_RES):
        if red_team:
            return (REDTEAM_ROUTE_LOCK["reasoning"],
                    "complex reasoning (Red Team lock -> uncensored model)")
        return MODEL_ROUTES["reasoning"], \
            "complex reasoning / architecture / analysis task"
    if any(rx.search(prompt) for rx in _CYBER_RES):
        if red_team:
            return (REDTEAM_ROUTE_LOCK["cyber"],
                    "cyber security / recon task (uncensored model)")
        return MODEL_ROUTES["cyber"], "cyber security / recon task"
    if any(rx.search(prompt) for rx in _CODING_RES):
        if red_team:
            return (REDTEAM_ROUTE_LOCK["coding"],
                    "coding task (Red Team lock -> uncensored model)")
        return MODEL_ROUTES["coding"], "coding / math / logic task"
    # general chat & fast answers: censored Llama by default, but in Red
    # Team Mode the fallback is the top uncensored model instead.
    if red_team:
        return (REDTEAM_ROUTE_LOCK["general"],
                "Red Team mode -> uncensored default model")
    return MODEL_ROUTES["general"], "general chat / fast answer"

# --- encoding hardening: every response MUST be UTF-8 ---------------------
# jsonify: emit raw UTF-8 instead of \uXXXX escapes (cleaner, smaller)
try:
    app.json.ensure_ascii = False
except AttributeError:  # very old Flask fallback
    app.config["JSON_AS_ASCII"] = False


@app.after_request
def _force_utf8(resp):
    """Explicitly pin charset=utf-8 on every response header so the browser
    decodes emoji / markdown glyphs as UTF-8 instead of guessing cp1252
    (which turns '•' into '\u00e2\u20ac\u00a2'-style mojibake)."""
    if not resp.content_type:
        resp.content_type = "text/plain; charset=utf-8"
    elif "charset=" in resp.content_type.lower():
        resp.content_type = re.sub(r"charset=[^;]+", "charset=utf-8",
                                   resp.content_type, flags=re.IGNORECASE)
    else:
        resp.content_type = "%s; charset=utf-8" % resp.content_type
    resp.charset = "utf-8"
    return resp


_lock = threading.Lock()
_state = {
    "agent": None,
    "memory": None,
    "cfg": None,
    "key_error": "",
}


def _current_cfg():
    with _lock:
        return dict(_state["cfg"] or {})


def _save_cfg(patch):
    """Merge patch into config.json (non-secret settings only).

    API keys are NEVER written here - they go to .env (save_env_key).
    """
    patch = {k: v for k, v in patch.items() if k != "api_key"}
    cfg = {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    cfg.update({k: v for k, v in patch.items() if v is not None})
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def _build_llm(cfg):
    """Create the LLM client from the current config (mock or live)."""
    uncensored = bool(cfg.get("red_team_mode"))
    # Red Team level: promax (route lock + base uncensored pool) vs
    # promix (same + widened mixed pool + composite persona).
    level = str(cfg.get("red_team_level") or "promax").lower()
    mix = uncensored and level == "promix"
    # Persona presets: the active persona's directive block rides on the
    # client; core.Agent._system_prompt appends it after the Red Team
    # tail block so both chat and the RPG engine inherit the persona.
    persona_block = personas.get_block(cfg.get("persona"),
                                       uncensored=uncensored)
    if cfg.get("mock"):
        client = MockClient(uncensored=uncensored,
                           uncensored_mix=mix)
    else:
        # Smart Auto-Model Selector: in auto mode the configured model is a
        # placeholder; the actual model is chosen per-request by the router.
        model = cfg.get("model") or "gpt-4o-mini"
        if cfg.get("auto") or model == "auto":
            model = DEFAULT_FAST_MODEL
        client = OpenAIClient(
            api_key=cfg.get("api_key") or "",
            base_url=cfg.get("base_url") or "https://api.openai.com/v1",
            model=model,
            fallback_models=cfg.get("fallback_models"),
            uncensored=uncensored,
            refusal_retries=cfg.get("refusal_retries"),
            # Red Team Mode (pro-max): keep uncensored models on the
            # failover chain so drops/429s can't force a censored fallback
            # into an authorized offensive-security run.
            uncensored_fallbacks=(UNCENSORED_FALLBACK_MODELS
                                  if uncensored else None),
            # Red Team Mode (pro-mix): widen the uncensored failover pool
            # with the mythos/dolphin mix and rotate it per request.
            uncensored_mix=mix,
        )
    client.persona_block = persona_block
    return client


def _build_agent(cfg):
    memory = MemoryStore(cfg["memory_file"] or MEMORY_PATH)
    # Persistent cross-chat knowledge base (SQLite, gitignored via *.db):
    # past findings about a target are auto-injected into the system prompt
    # when a new chat mentions the same domain/IP.
    knowledge = GlobalKnowledge(os.path.join(PROJECT_DIR, "knowledge.db"))
    institutional = InstitutionalMemory(INSTITUTIONAL_NOTES_PATH)
    llm = _build_llm(cfg)
    agent = Agent(llm, memory=memory, knowledge=knowledge,
                  institutional=institutional,
                  max_iterations=cfg.get("max_iterations") or 60,
                  max_messages=cfg.get("max_messages") or 400,
                  spawn_timeout=cfg.get("spawn_timeout") or 900,
                  max_spawn_depth=cfg.get("max_spawn_depth") or 3,
                  allow_subagents=cfg.get("allow_subagents", True),
                  intent_reformulator=IntentReformulator(),
                  confirm_terminal=False)  # auto mode: no stdin prompts in UI
    return agent, memory


def _reload_state(mock_override=None):
    cfg = load_config()
    if mock_override is not None:
        cfg["mock"] = mock_override
    # Safe fallback: if the key is missing, stay usable via the built-in mock
    # LLM and surface a clear error banner in the UI (never silently leak or
    # half-work with an empty key).
    key_status = config_status()
    key_error = "" if (cfg.get("mock") or key_status["ok"]) else key_status["error"]
    if not cfg.get("mock") and not cfg.get("api_key"):
        cfg["mock"] = True
    agent, memory = _build_agent(cfg)
    with _lock:
        _state.update({"agent": agent, "memory": memory, "cfg": cfg,
                       "key_error": key_error, "rpg": None, "rpg_game_id": None})
    return cfg


RPG_DIR = os.path.join(PROJECT_DIR, "rpg")


def _get_rpg_engine():
    """Lazily build the shared RPG engine (uses the same LLM as chat)."""
    with _lock:
        eng = _state.get("rpg")
        if eng is None:
            agent = _state.get("agent")
            llm = agent.llm if agent else _build_llm(_current_cfg())
            eng = RPGEngine(RPG_DIR, llm, memory=_state.get("memory"))
            _state["rpg"] = eng
        return eng


def _status():
    cfg = _current_cfg()
    auto = bool(cfg.get("auto")) or (cfg.get("model") == "auto")
    if cfg.get("mock"):
        mode, model = "mock", "mock-1"
    elif auto:
        mode, model = "auto", "auto"
    else:
        mode, model = "live", cfg.get("model", "?")
    return {
        "mode": mode,
        "model": model,
        "red_team_mode": bool(cfg.get("red_team_mode")),
        "red_team_level": str(cfg.get("red_team_level") or "promax"),
        "persona": personas.normalize(cfg.get("persona")),
        "refusal_retries": int(cfg.get("refusal_retries", 3) or 0),
        "base_url": "built-in" if cfg.get("mock") else cfg.get("base_url", "?"),
        "has_key": bool(cfg.get("api_key")),
        "key_error": _state.get("key_error", ""),
        "tools": len(_state["agent"]._tool_list) if _state.get("agent") else 0,
        "memory_entries": len(_state["memory"]._data.get("notes", {})) if _state.get("memory") else 0,
    }


# --------------------------------------------------------------------------
# Chat history (sessions persisted to chats.json, ChatGPT-style)
# --------------------------------------------------------------------------

def _read_chats_unlocked():
    try:
        with open(CHATS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"sessions": {}}


def _write_chats_unlocked(data):
    with open(CHATS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _new_session_id():
    return uuid.uuid4().hex


def _make_session(title="", sid=None):
    now = time.time()
    return {
        "id": sid or _new_session_id(),
        "title": (title or "")[:80],
        "created": now,
        "updated": now,
        "messages": [],
        "agent_messages": [],
    }


def _session_summary(s):
    """Compact entry for the sidebar list."""
    msgs = s.get("messages") or []
    preview = ""
    for m in reversed(msgs):
        if m.get("role") == "assistant" and m.get("kind") in ("final", "error"):
            preview = (m.get("content") or "")[:140]
            break
    return {
        "id": s.get("id"),
        "title": s.get("title") or "New chat",
        "updated": s.get("updated", 0),
        "created": s.get("created", 0),
        "count": len(msgs),
        "preview": preview,
    }


def _validation_card_text(ev):
    """Build the [VALIDATION SUB-AGENT] line persisted for one finding."""
    status = (ev.get("status") or "unverified").lower()
    label = {"verified": "Finding Verified",
             "rejected": "False Positive Rejected",
             "unverified": "Unverified"}.get(status, "Unverified")
    text = "[VALIDATION SUB-AGENT] %s" % label
    finding = (ev.get("finding") or "").strip()
    if finding:
        text += ": %s" % finding
    return text


def _record_event(sid, ev):
    """Persist one streamed event into the session file."""
    etype = ev.get("type")
    if etype not in ("llm", "tool_call", "tool_result", "final", "error",
                     "validation_tool_call", "validation_tool_result",
                     "validation_spawned", "validation", "validation_done",
                     "artifacts", "tactical_reasoning"):
        return
    now = time.time()
    with _chat_lock:
        data = _read_chats_unlocked()
        session = data.get("sessions", {}).get(sid)
        if not session:
            return
        msgs = session.setdefault("messages", [])
        if etype == "llm":
            msgs.append({"role": "assistant", "kind": "thinking",
                         "content": ev.get("content", ""), "ts": now})
        elif etype == "tool_call":
            msgs.append({"role": "tool", "name": ev.get("name", "?"),
                         "arguments": ev.get("arguments", ""),
                         "result": None, "ts": now})
        elif etype == "tool_result":
            for m in reversed(msgs):
                if (m.get("role") == "tool" and not m.get("validator")
                        and m.get("result") is None):
                    m["result"] = ev.get("content", "")
                    if ev.get("artifact"):
                        m["artifact"] = ev["artifact"]
                    break
        elif etype == "final":
            msgs.append({"role": "assistant", "kind": "final",
                         "content": ev.get("content", ""), "ts": now})
        elif etype == "error":
            msgs.append({"role": "assistant", "kind": "error",
                         "content": ev.get("content", ""), "ts": now})
        elif etype == "validation_tool_call":
            msgs.append({"role": "tool", "validator": True,
                         "name": ev.get("name", "?"),
                         "arguments": ev.get("arguments", ""),
                         "result": None, "ts": now})
        elif etype == "validation_tool_result":
            for m in reversed(msgs):
                if (m.get("role") == "tool" and m.get("validator")
                        and m.get("result") is None):
                    m["result"] = ev.get("content", "")
                    break
        elif etype == "validation":
            msgs.append({"role": "assistant", "kind": "validation",
                         "status": ev.get("status", "unverified"),
                         "finding": ev.get("finding", ""),
                         "reason": ev.get("reason", "") or "",
                         "content": _validation_card_text(ev), "ts": now})
        elif etype == "validation_spawned":
            msgs.append({"role": "assistant", "kind": "validation_spawned",
                         "content": ev.get("content", ""),
                         "reason": ev.get("reason", ""),
                         "count": ev.get("count", 0), "ts": now})
        elif etype == "validation_done":
            msgs.append({"role": "assistant", "kind": "validation_done",
                         "content": ev.get("summary", ""),
                         "verified": ev.get("verified", 0),
                         "rejected": ev.get("rejected", 0),
                         "unverified": ev.get("unverified", 0),
                         "count": ev.get("count", 0), "ts": now})
        elif etype == "artifacts":
            session["artifacts"] = ev.get("artifacts") or []
        elif etype == "tactical_reasoning":
            msgs.append({"role": "assistant", "kind": "tactical",
                         "content": ev.get("reasoning", ""),
                         "phase": ev.get("phase", ""),
                         "objective": ev.get("objective", ""),
                         "guard": bool(ev.get("guard")), "ts": now})
        session["updated"] = now
        _write_chats_unlocked(data)


def _record_stream_done(sid, agent):
    """After a stream finishes, snapshot the raw agent conversation so a
    reopened session keeps full LLM context for follow-up messages."""
    with _chat_lock:
        data = _read_chats_unlocked()
        session = data.get("sessions", {}).get(sid)
        if not session:
            return
        session["agent_messages"] = [dict(m) for m in agent.messages]
        session["updated"] = time.time()
        _write_chats_unlocked(data)


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", status=_status())


# --------------------------------------------------------------------------
# Chat API (SSE stream so tool calls appear live)
# --------------------------------------------------------------------------

@app.route("/api/chat")
def api_chat():
    message = (request.args.get("message") or "").strip()
    if not message:
        return jsonify({"error": "empty message"}), 400

    # attach to (or create) the current persistent session
    with _chat_lock:
        data = _read_chats_unlocked()
        sessions = data.setdefault("sessions", {})
        sid = _state.get("session_id")
        if not sid or sid not in sessions:
            sid = _new_session_id()
            sessions[sid] = _make_session(message, sid)
            with _lock:
                _state["session_id"] = sid
        session = sessions[sid]
        session.setdefault("messages", []).append(
            {"role": "user", "content": message, "ts": time.time()})
        session["updated"] = time.time()
        _write_chats_unlocked(data)

    run_id = uuid.uuid4().hex
    stop_event = threading.Event()
    with _run_lock:
        _active_runs[run_id] = stop_event

    # unbounded: a buffered burst of delta events (e.g. Red Team mode
    # that releases all narrative deltas at the end) must not be
    # mistaken for a dead client and falsely abort the run
    q = queue.Queue()
    agent = _state["agent"]
    cfg = _current_cfg()
    routed_model, route_reason = route_model(message, cfg)

    # /pipeline <target> slash command: run the 4-stage autonomous
    # multi-agent pipeline (recon -> hypotheses -> testing -> PoC/report)
    # instead of a normal chat turn. The pipeline yields run_stream-
    # compatible events, so the SSE worker below needs no changes.
    pipeline_target = None
    pipeline_invalid = False
    if message.lower().startswith("/pipeline"):
        pipeline_target = message[len("/pipeline"):].strip()
        if not pipeline_target:
            pipeline_target = None
            pipeline_invalid = True
        else:
            pipeline_invalid = False

    def run_gen():
        if pipeline_invalid:
            yield {"type": "error",
                   "content": "Usage: /pipeline <target>  (e.g. "
                              "/pipeline scanme.nmap.org)"}
            return
        if pipeline_target is not None:
            # no model routing for pipeline commands; the pipeline runs
            # its own 4 stages with the configured model chain
            yield from agent.run_autonomous_pipeline(
                pipeline_target, stop_event=stop_event)
            return
        # Smart Auto-Model Selector: emit a route event before the stream so
        # the UI can show which model this answer actually used.
        if routed_model:
            yield {"type": "route", "model": routed_model,
                   "label": MODEL_LABELS.get(routed_model, routed_model),
                   "reason": route_reason}
        yield from agent.run_stream(message, stop_event=stop_event,
                                    model=routed_model)

    run_iter = run_gen()

    def worker():
        pending_tool = {"name": None, "args": "{}"}
        turn_artifacts = []
        # one timestamp folder per assessment turn:
        # artifacts/{chat_id}/{run_ts}/{tool}_{ts}_{suffix}.{ext}
        run_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            for event in run_iter:
                etype = event.get("type")
                if etype == "tool_call":
                    pending_tool["name"] = event.get("name")
                    pending_tool["args"] = event.get("arguments") or "{}"
                elif etype == "tool_result":
                    # persist scan/generation outputs as structured artifacts
                    if artifacts.worth_capturing(
                            pending_tool["name"], pending_tool["args"]):
                        saved = artifacts.save(
                            sid, pending_tool["name"],
                            event.get("content") or "",
                            args=pending_tool["args"],
                            run_ts=run_ts)
                        if saved:
                            turn_artifacts.append(saved)
                            event = dict(event)
                            event["artifact"] = saved
                elif etype == "final" and turn_artifacts:
                    # end-of-turn offer: badge panel + markdown report button
                    artifact_event = {"type": "artifacts",
                                      "chat_id": sid,
                                      "artifacts": list(turn_artifacts)}
                    try:
                        _record_event(sid, artifact_event)
                    except Exception:
                        pass
                    try:
                        q.put_nowait(artifact_event)
                    except queue.Full:
                        pass
                try:
                    _record_event(sid, event)
                except Exception:
                    pass  # history must never kill the stream
                try:
                    q.put_nowait(event)
                except queue.Full:
                    # client is gone: stop the run and unwind the generator
                    stop_event.set()
                    run_iter.close()
                    break
        except RunCancelled:
            pass  # user pressed Stop; clean shutdown below
        except Exception as exc:
            msg_err = "%s: %s" % (type(exc).__name__, exc)
            try:
                _record_event(sid, {"type": "error", "content": msg_err})
            except Exception:
                pass
            try:
                q.put_nowait({"type": "error", "content": msg_err})
            except queue.Full:
                pass
        finally:
            try:
                _record_stream_done(sid, agent)
            except Exception:
                pass
            try:
                q.put_nowait(None)
            except queue.Full:
                pass

    threading.Thread(target=worker, daemon=True).start()

    def gen():
        yield "retry: 1500\n\n"
        # idle window: individual tools are capped at 120s each
        # (TOOL_TIMEOUT in ai_agent/tools/base.py); the window only
        # fires when nothing arrives for 900s (slow models + long
        # fallback chains included) — and the frontend releases busy.
        try:
            while True:
                try:
                    event = q.get(timeout=900)
                except queue.Empty:
                    yield "data: {\"type\": \"error\", \"content\": \"[timed out]\"}\n\n"
                    break
                if event is None:
                    break
                yield "data: " + json.dumps(event, ensure_ascii=False) + "\n\n"
        except GeneratorExit:
            # client disconnected / Stop clicked: cancel the worker so it
            # unwinds instead of running more LLM calls or tools
            stop_event.set()
            raise
        except Exception:
            stop_event.set()
            raise
        finally:
            with _run_lock:
                _active_runs.pop(run_id, None)

    return Response(stream_with_context(gen()),
                    content_type="text/event-stream; charset=utf-8",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no",
                             "X-Run-Id": run_id})


@app.route("/api/chat/cancel", methods=["POST"])
def api_chat_cancel():
    """Cancel active run(s). With a run_id it stops that specific run;
    without one (client aborted before reading headers) it stops all."""
    payload = request.get_json(silent=True) or {}
    run_id = payload.get("run_id") or request.args.get("run_id") or ""
    with _run_lock:
        if run_id and run_id in _active_runs:
            events = [_active_runs.pop(run_id)]
        else:
            events = list(_active_runs.values())
            _active_runs.clear()
    for ev in events:
        ev.set()
    return jsonify({"ok": True, "cancelled": len(events)})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Clear the current thread (kept for compatibility)."""
    with _lock:
        _state["session_id"] = None
        if _state.get("agent"):
            _state["agent"].reset()
    return jsonify({"ok": True})


# --------------------------------------------------------------------------
# Sessions API (chat history)
# --------------------------------------------------------------------------

@app.route("/api/sessions")
def api_sessions_list():
    """Sidebar list: all saved chats, newest first."""
    with _chat_lock:
        data = _read_chats_unlocked()
        sessions = sorted(data.get("sessions", {}).values(),
                          key=lambda s: s.get("updated", 0), reverse=True)
        summary = [_session_summary(s) for s in sessions]
    return jsonify({"current": _state.get("session_id"), "sessions": summary})


@app.route("/api/sessions", methods=["POST"])
def api_sessions_new():
    """'+ New Chat': drop the current thread; a fresh session is created
    lazily on the next message (empty threads are not saved)."""
    with _lock:
        _state["session_id"] = None
        if _state.get("agent"):
            _state["agent"].reset()
    return jsonify({"ok": True, "current": None})


@app.route("/api/sessions/<sid>")
def api_sessions_get(sid):
    with _chat_lock:
        data = _read_chats_unlocked()
        s = data.get("sessions", {}).get(sid)
        if s:
            s = json.loads(json.dumps(s))
    if not s:
        return jsonify({"error": "session not found"}), 404
    return jsonify(s)


@app.route("/api/sessions/<sid>/open", methods=["POST"])
def api_sessions_open(sid):
    """Reopen a saved chat: make it current and restore the agent's
    conversation context so follow-up messages continue the thread."""
    with _chat_lock:
        data = _read_chats_unlocked()
        s = data.get("sessions", {}).get(sid)
        if s:
            s = json.loads(json.dumps(s))
    if not s:
        return jsonify({"error": "session not found"}), 404
    with _lock:
        if _state.get("agent"):
            _state["agent"].messages = [
                dict(m) for m in (s.get("agent_messages") or [])]
        _state["session_id"] = sid
    return jsonify(s)


@app.route("/api/sessions/<sid>", methods=["DELETE"])
def api_sessions_del(sid):
    with _chat_lock:
        data = _read_chats_unlocked()
        removed = data.get("sessions", {}).pop(sid, None)
        if removed:
            _write_chats_unlocked(data)
    if removed:
        # keep the artifacts folder in sync with the deleted chat
        try:
            artifacts.delete_chat(sid)
        except Exception:
            pass
        with _lock:
            if _state.get("session_id") == sid:
                _state["session_id"] = None
                if _state.get("agent"):
                    _state["agent"].reset()
    return jsonify({"ok": bool(removed)})


@app.route("/api/sessions/<sid>/export")
def api_sessions_export(sid):
    """Full Markdown pentest export of a chat: executive summary, tool
    timeline (outputs trimmed), validation cards and artifact download links.
    Everything runs as a downloadable .md file."""
    with _chat_lock:
        data = _read_chats_unlocked()
        s = data.get("sessions", {}).get(sid)
        if s:
            s = json.loads(json.dumps(s))
    if not s:
        return jsonify({"error": "session not found"}), 404

    title = (s.get("title") or "New chat").strip()
    msgs = s.get("messages") or []
    persona = personas.normalize(s.get("persona")) if s.get("persona") \
        else personas.normalize(_current_cfg().get("persona"))

    tools_used = sorted({m.get("name") for m in msgs
                         if m.get("role") == "tool" and m.get("name")
                         and not m.get("validator")})
    validations = [m for m in msgs if m.get("role") == "assistant"
                   and m.get("kind") == "validation"]
    v_by = {"verified": 0, "rejected": 0, "unverified": 0}
    for v in validations:
        v_by[(v.get("status") or "unverified").lower()
             if (v.get("status") or "unverified").lower() in v_by
             else "unverified"] += 1

    try:
        arows = artifacts.list_chat(sid)
    except Exception:
        arows = []

    def hhmm(ts):
        try:
            return datetime.datetime.fromtimestamp(float(ts)).strftime("%H:%M")
        except Exception:
            return "--:--"

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# Pentest Export — %s" % title,
        "",
        "**Agent:** HackerAI (local) · **Messages:** %d · "
        "**Artifacts:** %d  " % (len(msgs), len(arows)),
        "**Exported:** %s · **Red Team Mode:** %s · "
        "**Persona:** %s  " % (now,
                               "ON" if s.get("red_team_mode") else "off",
                               persona),
        "**Session ID:** `%s`" % sid,
        "",
    ]

    lines += ["## Executive Summary", ""]
    lines.append("- **Tools used:** %s" % (", ".join(tools_used) if tools_used
                                            else "none"))
    lines.append("- **Validation findings:** %d verified / %d rejected / "
                 "%d unverified" % (v_by["verified"], v_by["rejected"],
                                    v_by["unverified"]))
    lines.append("")

    if validations:
        lines += ["## Findings (Validation Cards)", ""]
        for v in validations:
            ico = {"verified": "✅", "rejected": "❌"}.get(
                (v.get("status") or "").lower(), "❔")
            lines.append("### %s %s" % (
                ico, (v.get("status") or "unverified").capitalize()))
            finding = (v.get("finding") or "").strip()
            if finding:
                lines.append("> %s" % finding.replace("\n", "\n> "))
            reason = (v.get("reason") or "").strip()
            if reason:
                lines.append("")
                lines.append("*Reason:* %s" % reason.replace("\n", " "))
            lines.append("")

    lines += ["## Timeline", ""]
    for m in msgs:
        ts = hhmm(m.get("ts"))
        role = m.get("role")
        if role == "user":
            lines += ["### [%s] 👤 User" % ts,
                      (m.get("content") or "").replace("\n", "\n> "), ""]
        elif role == "tool":
            tag = "🩸 Validator" if m.get("validator") else "🛠️ Tool"
            lines += ["### [%s] %s: %s" % (ts, tag, m.get("name") or "?"),
                      "```",
                      "$ %s" % (m.get("arguments") or ""),
                      "```"]
            result = m.get("result") or m.get("content") or ""
            if str(result).strip():
                result = str(result)
                if len(result) > 2000:
                    lines += ["Output (first 2000 of %d chars):" % len(result),
                              "```", result[:2000], "```"]
                else:
                    lines += ["Output:", "```", result, "```"]
            lines.append("")
        elif role == "assistant":
            kind = m.get("kind") or ""
            content = (m.get("content") or "").strip()
            label = {"final": "🤖 Agent (final)",
                     "error": "🤖 Agent (error)",
                     "thinking": "🤖 Agent (thinking)",
                     "tactical": "🩸 Tactical reasoning",
                     "validation_spawned": "🩸 Validation spawned",
                     "validation_done": "🩸 Validation done"}.get(kind,
                                                            "🤖 Agent")
            head = "### [%s] %s" % (ts, label)
            phase = m.get("phase")
            if kind == "tactical" and phase:
                head += " — %s" % phase
            lines.append(head)
            if content:
                lines.append("> %s" % content.replace("\n", "\n> "))
            lines.append("")

    if arows:
        lines += ["## Artifacts", ""]
        for r in arows:
            lines.append("- **%s** — `%s` (%s)" % (
                r.get("tool"), r.get("filename"), r.get("size_h")))
        lines += ["", "## Downloads", ""]
        for r in arows:
            lines.append("- [%s](%s)" % (r.get("filename"), r.get("url")))
        lines.append("")

    md = "\n".join(lines)
    safe = re.sub(r"[^a-z0-9_.-]+", "_", title.lower()).strip("_")[:40] or sid
    from io import BytesIO
    return send_file(BytesIO(md.encode("utf-8")), as_attachment=True,
                     download_name="pentest_export_%s.md" % safe,
                     mimetype="text/markdown; charset=utf-8")


# --------------------------------------------------------------------------
# Artifacts API (downloadable scan outputs)
# --------------------------------------------------------------------------

_MIME_BY_EXT = {
    "json": "application/json",
    "txt": "text/plain",
    "md": "text/markdown",
    "html": "text/html",
    "csv": "text/csv",
    "xml": "application/xml",
    "log": "text/plain",
}


@app.route("/api/board")
def api_board():
    """Current silent Task Board snapshot (persistent widget state)."""
    agent = _state.get("agent")
    if agent is None or not getattr(agent, "_task_board", None):
        return jsonify({"counts": {"todo": 0, "in_progress": 0, "completed": 0},
                        "tasks": [], "in_progress": []})
    return jsonify(agent._task_board.snapshot())


@app.route("/api/artifacts")
@app.route("/api/artifacts/<chat_id>")
def api_artifacts_list(chat_id=None):
    """Artifacts for one chat (or every chat when no chat id is given)."""
    if chat_id is not None:
        return jsonify(artifacts.list_chat(chat_id))
    out = []
    try:
        chats = sorted(os.listdir(artifacts.root))
    except OSError:
        chats = []
    for c in chats:
        rows = artifacts.list_chat(c)
        if rows:
            out.append({"chat_id": c, "count": len(rows),
                        "artifacts": rows})
    return jsonify(out)


def _send_artifact(path):
    """Stream one resolved artifact file as an attachment download."""
    ext = os.path.splitext(path)[1].lstrip(".").lower()
    return send_file(
        path, as_attachment=True,
        download_name=os.path.basename(path),
        mimetype=_MIME_BY_EXT.get(ext, "application/octet-stream"))


@app.route("/api/download/<chat_id>/<timestamp>/<filename>")
def api_artifacts_download_path(chat_id, timestamp, filename):
    """Stream one artifact from artifacts/<chat_id>/<timestamp>/<filename>.

    Every path component is validated with a strict whitelist regex inside
    resolve(), so traversal (../, encoded separators, absolute paths) is
    impossible."""
    path = artifacts.resolve("%s/%s/%s" % (chat_id, timestamp, filename))
    if path is None:
        return jsonify({"error": "artifact not found"}), 404
    return _send_artifact(path)


@app.route("/api/download/<artifact_id>")
def api_artifacts_download(artifact_id):
    """Legacy lookup by plain filename (also accepts the full
    <chat_id>/<timestamp>/<filename> path). resolve() validates every
    component, so traversal (../, encoded separators, absolute paths) is
    impossible."""
    path = artifacts.resolve(artifact_id)
    if path is None:
        return jsonify({"error": "artifact not found"}), 404
    return _send_artifact(path)


@app.route("/api/artifacts/<chat_id>/archive")
def api_artifacts_archive(chat_id):
    """One ZIP with every artifact of a chat (new <timestamp>/ layout and
    legacy flat files), so the whole assessment is downloadable at once."""
    data = artifacts.archive(chat_id)
    if data is None:
        return jsonify({"error": "no artifacts"}), 404
    from io import BytesIO
    return send_file(
        BytesIO(data), as_attachment=True,
        download_name="artifacts_%s.zip" % chat_id,
        mimetype="application/zip")


@app.route("/api/artifacts/<chat_id>/report")
def api_artifacts_report(chat_id):
    """Markdown report for a chat: title + last final message + artifact
    index with per-file download links."""
    final_text, title = "", ""
    with _chat_lock:
        data = _read_chats_unlocked()
        s = data.get("sessions", {}).get(chat_id)
        if s:
            title = (s.get("title") or "").strip()
            for m in reversed(s.get("messages") or []):
                if (m.get("role") == "assistant"
                        and m.get("kind") in ("final", "error")
                        and m.get("content")):
                    final_text = m["content"]
                    break
    md = artifacts.report(chat_id, final_text=final_text, title=title)
    if request.args.get("download"):
        from io import BytesIO
        return send_file(
            BytesIO(md.encode("utf-8")),
            as_attachment=True,
            download_name="report_%s.md" % chat_id,
            mimetype="text/markdown")
    return Response(md, mimetype="text/markdown; charset=utf-8")


# --------------------------------------------------------------------------
# Executive Report Summary (markdown cards for every target assessment)
# --------------------------------------------------------------------------

_TARGET_RE = re.compile(
    r"(?:https?://)?(?:[a-z0-9-]+\.)+[a-z0-9-]{2,}"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.I)

_SEV_RULES = [
    ("critical", re.compile(
        r"\b(critical|rce|remote code execution|root shell|system shell|"
        r"sql shell|database dump|full compromise|pwned|domain admin)"
        r"\b", re.I)),
    ("high", re.compile(
        r"\b(high|exploit(?:ed|able)?|shell|bypass|privilege escalation|"
        r"lateral movement|exfiltrat|sensitive data|admin takeover|"
        r"credential dump|unauthenticated)"
        r"\b", re.I)),
    ("medium", re.compile(
        r"\b(medium|moderate|cve-\d{4}|vulnerab|misconfig|"
        r"weak (?:auth|password)|csrf|idor|open redirect)"
        r"\b", re.I)),
    ("low", re.compile(
        r"\b(low|minor|informational|best practice|harden|notice)"
        r"\b", re.I)),
]


def _last_final_text(s):
    for m in reversed(s.get("messages") or []):
        if (m.get("role") == "assistant"
                and m.get("kind") in ("final", "error")
                and (m.get("content") or "").strip()):
            return m["content"]
    return ""


def _extract_target(msgs):
    """Best-guess target (domain / IP) from the first user message."""
    for m in msgs:
        if m.get("role") == "user":
            hit = _TARGET_RE.search(m.get("content") or "")
            if hit:
                return hit.group(0).strip().rstrip(".")
    return ""


def _severity_of(text):
    """Keyword heuristic for the report card badge (best effort, not a
    real CVSS score)."""
    for level, rx in _SEV_RULES:
        if rx.search(text or ""):
            return level
    return "info"


def _fmt_size_h(n):
    if n >= 1 << 20:
        return "%.1f MB" % (n / (1 << 20))
    if n >= 1 << 10:
        return "%.1f KB" % (n / (1 << 10))
    return "%d B" % n


@app.route("/api/reports")
def api_reports():
    """Executive summary cards for every target assessment (chat): title,
    target, severity hint, artifact stats, tools used, final summary and
    direct download links for the markdown report / ZIP archive."""
    with _chat_lock:
        data = _read_chats_unlocked()
        sessions = sorted(data.get("sessions", {}).values(),
                          key=lambda s: s.get("updated", 0), reverse=True)
        sessions = json.loads(json.dumps(sessions))  # detach from lock data
    out = []
    for s in sessions:
        sid = s.get("id") or ""
        msgs = s.get("messages") or []
        final_text = _last_final_text(s)
        arts = artifacts.list_chat(sid) if sid else []
        if not msgs and not arts:
            continue
        tools = sorted({r["tool"] for r in arts})
        total = sum(r.get("size") or 0 for r in arts)
        updated = s.get("updated") or s.get("created") or 0
        out.append({
            "chat_id": sid,
            "title": (s.get("title") or "").strip()[:80] or "New chat",
            "target": _extract_target(msgs),
            "updated": datetime.datetime.fromtimestamp(
                updated).isoformat(timespec="seconds") if updated else "",
            "created": datetime.datetime.fromtimestamp(
                s.get("created") or updated or 0).isoformat(
                timespec="seconds"),
            "message_count": len(msgs),
            "artifacts": len(arts),
            "total_size": _fmt_size_h(total),
            "tools": tools,
            "severity": _severity_of(final_text),
            "summary": (final_text or "")[:600],
            "report_url": "/api/artifacts/%s/report" % sid,
            "report_download_url": "/api/artifacts/%s/report?download=1" % sid,
            "archive_url": "/api/artifacts/%s/archive" % sid if arts else "",
        })
    return jsonify({"count": len(out), "reports": out})


# --------------------------------------------------------------------------
# Tools catalog
# --------------------------------------------------------------------------

@app.route("/api/tools")
def api_tools():
    agent = _state.get("agent")
    if agent is None:
        return jsonify([])
    tools = []
    for t in agent._tool_list:
        tools.append({
            "name": t.name,
            "description": t.description,
            "parameters": t.parameters,
        })
    return jsonify(tools)


# --------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------

@app.route("/api/memory")
def api_memory():
    notes = _state["memory"]._data.get("notes", {})
    rows = [{"key": k, "text": v.get("text", ""), "ts": v.get("ts", "")}
            for k, v in sorted(notes.items())]
    return jsonify(rows)


@app.route("/api/memory", methods=["POST"])
def api_memory_add():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    text = (data.get("text") or "").strip()
    if not key or not text:
        return jsonify({"error": "key and text required"}), 400
    _state["memory"].add(key, text)
    return jsonify({"ok": True})


@app.route("/api/memory/<key>", methods=["DELETE"])
def api_memory_del(key):
    ok = _state["memory"].delete(key)
    return jsonify({"ok": ok})


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

@app.route("/api/settings")
def api_settings():
    cfg = _current_cfg()
    auto = bool(cfg.get("auto")) or (cfg.get("model") == "auto")
    # The key itself is never sent back to the UI - only whether it exists.
    return jsonify({
        "has_key": bool(cfg.get("api_key")),
        "base_url": cfg.get("base_url", ""),
        "model": "auto" if auto else cfg.get("model", ""),
        "auto": auto,
        "catalog": MODEL_CATALOG,
        "mock": bool(cfg.get("mock")),
        "red_team_mode": bool(cfg.get("red_team_mode")),
        "red_team_level": str(cfg.get("red_team_level") or "promax"),
        "key_error": _state.get("key_error", ""),
        "max_iterations": cfg.get("max_iterations", 60),
    })


@app.route("/api/settings", methods=["POST"])
def api_settings_save():
    data = request.get_json(silent=True) or {}
    api_key = (data.get("api_key") or "").strip()
    base_url = (data.get("base_url") or "").strip()
    model = (data.get("model") or "").strip()
    auto = bool(data.get("auto")) or (model == "auto")
    mock = bool(data.get("mock"))
    red_team_mode = bool(data.get("red_team_mode"))
    mi = data.get("max_iterations")

    patch = {"mock": mock, "auto": auto,
             "red_team_mode": red_team_mode}
    if api_key:
        # Security: API keys go ONLY into .env, never config.json.
        ok, msg = save_env_key(api_key)
        if not ok:
            return jsonify({"ok": False, "error": msg}), 500
    if base_url:
        patch["base_url"] = base_url
    # auto mode stores "auto" as the model so it survives reloads.
    # The auto flag is always written explicitly (True/False) so an old
    # auto:true can never linger and silently keep the router on.
    if auto:
        patch["model"] = "auto"
    elif model and model != "auto":
        patch["model"] = model
    elif not model:
        # cleared model with auto off -> fall back to the fast default
        patch["model"] = DEFAULT_FAST_MODEL
    if isinstance(mi, int) and 1 <= mi <= 100:
        patch["max_iterations"] = mi
    _save_cfg(patch)

    _reload_state(mock_override=mock)
    return jsonify(_status())


# --------------------------------------------------------------------------
# Persona presets (Red Team Mode tuning)
# --------------------------------------------------------------------------

@app.route("/api/personas")
def api_personas():
    cfg = _current_cfg()
    return jsonify({
        "current": personas.normalize(cfg.get("persona")),
        "custom_text": personas.get_custom_text(),
        "personas": personas.list_personas(),
    })


@app.route("/api/personas", methods=["POST"])
def api_personas_save():
    """Switch persona and/or update the custom persona text."""
    data = request.get_json(silent=True) or {}
    pid = personas.normalize(data.get("persona"))
    if data.get("custom_text") is not None:
        personas.save_custom_text(data.get("custom_text"))
    _save_cfg({"persona": pid})
    _reload_state(mock_override=_current_cfg().get("mock"))
    return jsonify({"ok": True, "persona": pid})


# --------------------------------------------------------------------------
# RPG (interactive campaigns)
# --------------------------------------------------------------------------

@app.route("/api/redteam", methods=["POST"])
def api_redteam_master_switch():
    """One-click Red Team master switch (evil profile).

    enabled=true  -> red_team_mode on; persona + level by ``level``:
                     promix (default) -> 'promix' composite persona,
                     promax/master    -> 'unfiltered' persona
    enabled=false -> red_team_mode off (persona/level left as-is)

    Optional ``level`` in {"master", "promax", "promix"} - when omitted
    and enabling, the agent goes straight to PRO MIX (the top level).
    """
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled"))
    level = str(data.get("level") or "").strip().lower()
    if level not in ("master", "promax", "promix"):
        level = "promix" if enabled else ""
    patch = {"red_team_mode": enabled}
    if level:
        patch["red_team_level"] = level
    if enabled:
        patch["persona"] = "promix" if level == "promix" else "unfiltered"
    _save_cfg(patch)
    _reload_state(mock_override=_current_cfg().get("mock"))
    return jsonify({"ok": True, **_status()})


@app.route("/api/rpg")
def api_rpg_status():
    eng = _get_rpg_engine()
    with _lock:
        current = _state.get("rpg_game_id")
    return jsonify(dict(eng.status(), current=current))


@app.route("/api/rpg/games", methods=["GET"])
def api_rpg_games_list():
    return jsonify(_get_rpg_engine().list_games())


@app.route("/api/rpg/games", methods=["POST"])
def api_rpg_games_new():
    data = request.get_json(silent=True) or {}
    eng = _get_rpg_engine()
    payload = eng.new_game(
        game_id=(data.get("game_id") or "").strip() or None,
        title=(data.get("title") or "").strip(),
        genre=(data.get("genre") or "fantasy").strip(),
        player_name=(data.get("player_name") or "Adventurer").strip(),
        setup=(data.get("setup") or "").strip(),
        seed=bool(data.get("seed", True)),
    )
    with _lock:
        _state["rpg_game_id"] = payload["game_id"]
    return jsonify(payload)


@app.route("/api/rpg/games/<game_id>", methods=["GET"])
def api_rpg_game_get(game_id):
    eng = _get_rpg_engine()
    payload = eng.get_state_payload(game_id)
    if payload is None:
        return jsonify({"error": "game not found"}), 404
    return jsonify(payload)


@app.route("/api/rpg/games/<game_id>", methods=["DELETE"])
def api_rpg_game_delete(game_id):
    eng = _get_rpg_engine()
    if not eng.delete_game(game_id):
        return jsonify({"error": "game not found"}), 404
    with _lock:
        if _state.get("rpg_game_id") == game_id:
            _state["rpg_game_id"] = None
    return jsonify({"ok": True})


@app.route("/api/rpg/games/<game_id>/load", methods=["POST"])
def api_rpg_game_load(game_id):
    eng = _get_rpg_engine()
    payload = eng.load_game(game_id)
    if payload is None:
        return jsonify({"error": "game not found"}), 404
    with _lock:
        _state["rpg_game_id"] = game_id
    return jsonify(payload)


@app.route("/api/rpg/games/<game_id>/play", methods=["POST"])
def api_rpg_game_play(game_id):
    eng = _get_rpg_engine()
    if eng.get_state_payload(game_id) is None:
        return jsonify({"error": "game not found"}), 404

    run_id = uuid.uuid4().hex
    stop_event = threading.Event()
    with _rpg_lock:
        if game_id in _rpg_runs:
            return jsonify({"error": "a turn is already running for this game",
                            "run_id": _rpg_runs[game_id][0]}), 409
        _rpg_runs[game_id] = (run_id, stop_event)

    data = request.get_json(silent=True) or {}
    player_input = (data.get("input") or "").strip()

    # unbounded: a buffered burst of delta events (e.g. Red Team mode
    # that releases all narrative deltas at the end) must not be
    # mistaken for a dead client and falsely abort the run
    q = queue.Queue()
    run_iter = eng.act_stream(game_id, player_input, stop_event=stop_event)

    def worker():
        try:
            for event in run_iter:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    # client is gone: stop the run and unwind the generator
                    stop_event.set()
                    run_iter.close()
                    break
        except RunCancelled:
            pass  # user pressed Stop; clean shutdown below
        except Exception as exc:
            msg_err = "%s: %s" % (type(exc).__name__, exc)
            try:
                q.put_nowait({"type": "error", "content": msg_err})
            except queue.Full:
                pass
        finally:
            try:
                q.put_nowait(None)
            except queue.Full:
                pass

    threading.Thread(target=worker, daemon=True).start()

    def gen():
        yield "retry: 1500\n\n"
        try:
            while True:
                try:
                    event = q.get(timeout=900)
                except queue.Empty:
                    yield "data: {\"type\": \"error\", \"content\": \"[timed out]\"}\n\n"
                    break
                if event is None:
                    break
                yield "data: " + json.dumps(event, ensure_ascii=False) + "\n\n"
        except GeneratorExit:
            # client disconnected / Stop clicked: cancel the worker
            stop_event.set()
            raise
        except Exception:
            stop_event.set()
            raise
        finally:
            with _rpg_lock:
                _rpg_runs.pop(game_id, None)

    return Response(stream_with_context(gen()),
                    content_type="text/event-stream; charset=utf-8",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no",
                             "X-Run-Id": run_id})


@app.route("/api/rpg/games/<game_id>/cancel", methods=["POST"])
def api_rpg_game_cancel(game_id):
    """Cancel the active turn of a game, if any."""
    with _rpg_lock:
        entry = _rpg_runs.pop(game_id, None)
    if entry is not None:
        entry[1].set()
    return jsonify({"ok": True, "cancelled": entry is not None})


# ---- lorebook ----------------------------------------------------------

@app.route("/api/rpg/lore", methods=["GET"])
def api_rpg_lore_list():
    category = request.args.get("category") or None
    limit = request.args.get("limit", type=int) or 100
    return jsonify(_get_rpg_engine().lore_list(category=category, limit=limit))


@app.route("/api/rpg/lore", methods=["POST"])
def api_rpg_lore_add():
    data = request.get_json(silent=True) or {}
    category = (data.get("category") or "general").strip()
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()
    tags = data.get("tags") or []
    if not title or not content:
        return jsonify({"error": "title and content required"}), 400
    entry = _get_rpg_engine().lore_add(category, title, content, tags)
    return jsonify(entry)


@app.route("/api/rpg/lore/search")
def api_rpg_lore_search():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify([])
    return jsonify(_get_rpg_engine().lore_search(q))


@app.route("/api/rpg/lore/seed", methods=["POST"])
def api_rpg_lore_seed():
    data = request.get_json(silent=True) or {}
    genre = (data.get("genre") or "fantasy").strip()
    ok = _get_rpg_engine().seed_lore(genre)
    return jsonify({"ok": ok})


@app.route("/api/rpg/lore/<int:entry_id>", methods=["PUT"])
def api_rpg_lore_update(entry_id):
    data = request.get_json(silent=True) or {}
    fields = {}
    for key in ("category", "title", "content", "tags"):
        if key in data:
            fields[key] = data[key]
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    entry = _get_rpg_engine().lore_update(entry_id, **fields)
    if entry is None:
        return jsonify({"error": "lore entry not found"}), 404
    return jsonify(entry)


@app.route("/api/rpg/lore/<int:entry_id>", methods=["DELETE"])
def api_rpg_lore_delete(entry_id):
    ok = _get_rpg_engine().lore_delete(entry_id)
    return jsonify({"ok": ok})


# --------------------------------------------------------------------------
# System / health
# --------------------------------------------------------------------------

@app.route("/api/system")
def api_system():
    from ai_agent.tools.system import tool_system_info, tool_ip_info, tool_disk_usage
    return jsonify({
        "system": tool_system_info(),
        "ip": tool_ip_info(),
        "disk": tool_disk_usage("all" if os.name == "nt" else None),
    })


@app.route("/api/status")
def api_status():
    return jsonify(_status())


# ---------------------------------------------------------------------------
# Command Center dashboard data (/api/dash).
#
# Every metric helper is best-effort: a failure on one subsystem (e.g. no
# ctypes on a bare build, wmic missing) degrades to None instead of taking
# down the whole payload. No third-party dependencies -- the gauges sample
# kernel counters directly. Blocks that sleep do so only inside the request
# thread (threaded=True), never under a lock.
# ---------------------------------------------------------------------------


def _dash_cpu_pct():
    """CPU load % from two 0.35 s-apart samples of the kernel counters."""
    try:
        if os.name == "nt":
            import ctypes

            class _FT(ctypes.Structure):
                _fields_ = [("dwLowDateTime", ctypes.c_uint32),
                            ("dwHighDateTime", ctypes.c_uint32)]

            def _ms(ft):
                return ((ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10000.0

            k32 = ctypes.windll.kernel32
            a_idle, a_kern, a_user = _FT(), _FT(), _FT()
            if not k32.GetSystemTimes(ctypes.byref(a_idle), ctypes.byref(a_kern),
                                      ctypes.byref(a_user)):
                return None
            time.sleep(0.35)
            b_idle, b_kern, b_user = _FT(), _FT(), _FT()
            if not k32.GetSystemTimes(ctypes.byref(b_idle), ctypes.byref(b_kern),
                                      ctypes.byref(b_user)):
                return None
            idle = _ms(b_idle) - _ms(a_idle)
            kern = _ms(b_kern) - _ms(a_kern)   # kernel ticks include idle
            user = _ms(b_user) - _ms(a_user)
            total = kern + user
            if total <= 0:
                return None
            busy = (kern - idle) + user
            return max(0.0, min(100.0, busy / total * 100.0))
        else:
            def _stat():
                with open("/proc/stat", "r", encoding="utf-8") as f:
                    parts = f.readline().split()
                if not parts or parts[0] != "cpu" or len(parts) < 5:
                    return None
                return [int(x) for x in parts[1:]]

            first = _stat()
            if first is None:
                return None
            time.sleep(0.35)
            second = _stat()
            if second is None:
                return None
            n = min(len(first), len(second))
            first, second = first[:n], second[:n]
            delta = [b - a for a, b in zip(first, second)]
            # layout: user nice system idle iowait irq softirq steal ...
            idle = (delta[3] if n > 3 else 0) + (delta[4] if n > 4 else 0)
            total = sum(delta)
            if total <= 0:
                return None
            return max(0.0, min(100.0, (total - idle) / total * 100.0))
    except Exception:
        return None


def _dash_ram():
    """Memory used/total (GB) + used %."""
    try:
        if os.name == "nt":
            import ctypes

            class _MS(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_uint32),
                    ("dwMemoryLoad", ctypes.c_uint32),
                    ("ullTotalPhys", ctypes.c_uint64),
                    ("ullAvailPhys", ctypes.c_uint64),
                    ("ullTotalPageFile", ctypes.c_uint64),
                    ("ullAvailPageFile", ctypes.c_uint64),
                    ("ullTotalVirtual", ctypes.c_uint64),
                    ("ullAvailVirtual", ctypes.c_uint64),
                    ("ullAvailExtendedVirtual", ctypes.c_uint64),
                ]

            ms = _MS()
            ms.dwLength = ctypes.sizeof(_MS)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):
                return None
            total_gb = ms.ullTotalPhys / (1024.0 ** 3)
            used_gb = (ms.ullTotalPhys - ms.ullAvailPhys) / (1024.0 ** 3)
            return {"total_gb": round(total_gb, 1), "used_gb": round(used_gb, 1),
                    "pct": max(0.0, min(100.0, float(ms.dwMemoryLoad)))}
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            mem = {}
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    kb = parts[1].strip().split()
                    if kb:
                        mem[parts[0]] = int(kb[0])
        total_kb = mem.get("MemTotal")
        avail_kb = mem.get("MemAvailable") or mem.get("MemFree")
        if not total_kb or avail_kb is None:
            return None
        used_kb = total_kb - avail_kb
        total_gb = total_kb / (1024.0 ** 2)
        used_gb = used_kb / (1024.0 ** 2)
        return {"total_gb": round(total_gb, 1), "used_gb": round(used_gb, 1),
                "pct": max(0.0, min(100.0, used_gb / total_gb * 100.0))}
    except Exception:
        return None


def _dash_disk():
    """Disk usage of the volume hosting the project."""
    try:
        import shutil
        drive = os.path.splitdrive(PROJECT_DIR)[0]
        root = (drive + os.sep) if drive else PROJECT_DIR
        usage = shutil.disk_usage(root)
        return {"total_gb": round(usage.total / (1024.0 ** 3), 1),
                "used_gb": round(usage.used / (1024.0 ** 3), 1),
                "free_gb": round(usage.free / (1024.0 ** 3), 1),
                "pct": max(0.0, min(100.0, usage.used / usage.total * 100.0))}
    except Exception:
        return None


def _dash_sys():
    """Parsed system facts + live gauges for the Command Center.

    Reuses the project's own system tools (ai_agent.tools.system) and parses
    their "key: value" output lines so the dashboard never drifts from what
    the agent itself reports.
    """
    sys_raw, ip_raw = {}, {}
    try:
        from ai_agent.tools.system import tool_system_info, tool_ip_info
        for raw, dst in ((tool_system_info(), sys_raw),
                         (tool_ip_info(), ip_raw)):
            for line in str(raw).splitlines():
                if ":" in line:
                    key, _, val = line.partition(":")
                    key = key.strip().lower().replace(" ", "_")
                    val = val.strip()
                    if key and val:
                        dst.setdefault(key, val)
    except Exception:
        pass

    os_label = str(sys_raw.get("os") or "").lower()
    friendly = {"windows": "Windows", "windows_nt": "Windows", "linux": "Linux",
                "darwin": "macOS", "java": "Java", "posix": "POSIX"}
    os_name = friendly.get(os_label) or sys_raw.get("os") or ("Windows" if os.name == "nt" else os.name)
    os_ver = sys_raw.get("version") or sys_raw.get("release") or ""

    shell = os.environ.get("SHELL") or os.environ.get("COMSPEC")
    if shell:
        shell = os.path.basename(shell).replace(".exe", "").lower()

    return {
        "host": sys_raw.get("hostname"),
        "user": sys_raw.get("user"),
        "os": os_name,
        "os_ver": os_ver,
        "machine": sys_raw.get("machine"),
        "cores": sys_raw.get("cpu_cores"),
        "python": sys_raw.get("python"),
        "shell": shell,
        "platform": sys_raw.get("platform"),
        "ip": ip_raw.get("ipv4"),
        "adapter_ip": ip_raw.get("adapter_ipv4"),
        "ip6": ip_raw.get("ipv6") or ip_raw.get("ipv6_address"),
        "gateway": ip_raw.get("gateway"),
        "ram": _dash_ram(),
        "disk": _dash_disk(),
        "cpu_pct": _dash_cpu_pct(),
    }


@app.route("/api/dash")
def api_dash():
    """Command Center dashboard: status + sessions + version + live sys gauges."""
    fallback = {"status": None, "total_sessions": 0, "recent": [],
                "version": None, "uptime_s": None, "sys": None}
    try:
        with _chat_lock:
            sessions = _read_chats_unlocked().get("sessions", {})

        def _sort_key(s):
            try:
                return float(s.get("updated") or 0)
            except (TypeError, ValueError):
                return 0.0

        recent = []
        for s in sorted(sessions.values(), key=_sort_key, reverse=True)[:8]:
            try:
                recent.append(_session_summary(s))
            except Exception:
                continue
        try:
            from ai_agent import __version__ as _webui_version
        except Exception:
            _webui_version = None
        return jsonify({
            "status": _status(),
            "total_sessions": len(sessions),
            "recent": recent,
            "version": _webui_version,
            "uptime_s": max(0, int(time.time() - _WEBUI_BOOT_TS)),
            "sys": _dash_sys(),
        })
    except Exception:
        return jsonify(fallback)


# ---------------------------------------------------------------------------
# Harness parity: structured delegation API, safe workspace file access and
# cross-conversation institutional notes over HTTP. These mirror the hosted
# harness features (sub-agents, file share, persistent memory) so the local
# Web UI exposes the same capabilities as first-class JSON endpoints.
# ---------------------------------------------------------------------------

_SENSITIVE_EXTENSIONS = (
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
    ".crt", ".cer", ".ovpn", ".kubeconfig",
)


def _workspace_abs(rel):
    """Resolve a repo-relative path to an absolute path strictly inside
    PROJECT_DIR. Returns None for any escape (.., absolute path, symlink
    jump outside the workspace)."""
    root = os.path.realpath(PROJECT_DIR)
    rel = (rel or "").replace("\\", "/").strip().strip("/")
    if not rel:
        return root
    target = os.path.realpath(os.path.join(root, rel))
    if target != root and not target.startswith(root + os.path.sep):
        return None
    return target


def _hidden_or_sensitive(path):
    """True when a path contains a hidden (dot) component or is a
    secret-material file type that must never be served."""
    rel = os.path.relpath(os.path.realpath(path),
                          os.path.realpath(PROJECT_DIR))
    parts = [p for p in rel.replace("\\", "/").split("/") if p]
    if any(p.startswith(".") for p in parts):
        return True
    return os.path.basename(path).lower().endswith(_SENSITIVE_EXTENSIONS)


@app.route("/api/files")
def api_files_list():
    """JSON directory listing of the agent workspace. Hidden entries are
    skipped and traversal is impossible by construction."""
    rel = (request.args.get("path") or "").strip()
    root = os.path.realpath(PROJECT_DIR)
    abs_path = _workspace_abs(rel)
    if abs_path is None:
        return jsonify({"error": "path escapes workspace"}), 400
    if rel and _hidden_or_sensitive(abs_path):
        return jsonify({"error": "hidden path"}), 403
    if not os.path.isdir(abs_path):
        return jsonify({"error": "not a directory"}), 404
    entries = []
    try:
        names = sorted(os.listdir(abs_path))
    except OSError as exc:
        return jsonify({"error": "cannot list directory: %s" % exc}), 500
    for name in names:
        if name.startswith("."):
            continue
        child = os.path.join(abs_path, name)
        try:
            st = os.stat(child)
            is_dir = os.path.isdir(child)
        except OSError:
            continue
        entries.append({
            "name": name,
            "type": "dir" if is_dir else "file",
            "size": None if is_dir else st.st_size,
            "modified": datetime.datetime.fromtimestamp(
                st.st_mtime).isoformat(timespec="seconds"),
        })
    here = os.path.relpath(abs_path, root)
    return jsonify({
        "path": "." if here == "." else here.replace("\\", "/"),
        "count": len(entries),
        "entries": entries,
    })


@app.route("/api/files/download")
def api_files_download():
    """Serve one workspace file as a download. Hidden paths, secret-material
    extensions and anything outside PROJECT_DIR are refused."""
    rel = (request.args.get("path") or "").strip()
    if not rel:
        return jsonify({"error": "path required"}), 400
    abs_path = _workspace_abs(rel)
    if abs_path is None:
        return jsonify({"error": "path escapes workspace"}), 403
    if _hidden_or_sensitive(abs_path):
        return jsonify({"error": "download blocked (hidden/sensitive path)"}), 403
    if not os.path.isfile(abs_path):
        return jsonify({"error": "file not found"}), 404
    return send_file(abs_path, as_attachment=True,
                     download_name=os.path.basename(abs_path))


def _notes_store():
    """Resolve the live institutional-memory store: the running agent's own
    instance when available, otherwise a fresh one on the shared db path."""
    agent = _state.get("agent")
    store = (getattr(agent, "institutional", None)
             if agent is not None else None)
    if store is None:
        try:
            store = InstitutionalMemory(INSTITUTIONAL_NOTES_PATH)
        except Exception:
            return None
    return store


def _notes_filters():
    return {
        "category": (request.args.get("category") or "").strip() or None,
        "target": (request.args.get("target") or "").strip() or None,
    }


def _norm_tags_input(tags):
    if tags is None:
        return []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    out = []
    for t in tags if isinstance(tags, (list, tuple)) else [tags]:
        if t is None:
            continue
        s = str(t).strip()
        if s:
            out.append(s)
    return out


@app.route("/api/notes")
def api_notes_list():
    """Recent institutional notes (?category=, ?target=, ?limit=)."""
    store = _notes_store()
    if store is None:
        return jsonify({"error": "institutional memory unavailable"}), 503
    try:
        limit = min(max(int(request.args.get("limit") or 100), 1), 500)
    except (TypeError, ValueError):
        limit = 100
    notes = store.list_notes(limit=limit, **_notes_filters())
    return jsonify({"count": len(notes), "notes": notes})


@app.route("/api/notes/search")
def api_notes_search():
    """TF-IDF recall over title+content+tags (?q=, ?category=, ?target=)."""
    query = (request.args.get("q") or "").strip()
    store = _notes_store()
    if store is None:
        return jsonify({"error": "institutional memory unavailable"}), 503
    try:
        top_k = min(max(int(request.args.get("top_k") or 5), 1), 50)
    except (TypeError, ValueError):
        top_k = 5
    notes = store.search_notes(query, top_k=top_k, **_notes_filters())
    return jsonify({"count": len(notes), "notes": notes})


@app.route("/api/notes", methods=["POST"])
def api_notes_add():
    """Create one institutional note (JSON or form body)."""
    store = _notes_store()
    if store is None:
        return jsonify({"error": "institutional memory unavailable"}), 503
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {k: request.form.get(k) for k in
                ("category", "title", "content", "target", "tags")}
    try:
        note = store.add_note(
            category=(data.get("category") or "findings").strip(),
            title=(data.get("title") or "").strip(),
            content=(data.get("content") or "").strip(),
            target=(data.get("target") or "").strip(),
            tags=_norm_tags_input(data.get("tags")),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"note": note}), 201


@app.route("/api/notes/<int:note_id>")
def api_notes_get(note_id):
    """Fetch one institutional note by id."""
    store = _notes_store()
    if store is None:
        return jsonify({"error": "institutional memory unavailable"}), 503
    note = store.get_note(note_id)
    if note is None:
        return jsonify({"error": "note not found"}), 404
    return jsonify(note)


@app.route("/api/notes/<int:note_id>", methods=["PUT"])
def api_notes_update(note_id):
    """Update fields of one institutional note."""
    store = _notes_store()
    if store is None:
        return jsonify({"error": "institutional memory unavailable"}), 503
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON body required"}), 400
    fields = {}
    for key in ("category", "title", "content", "target"):
        if key in data and data[key] is not None:
            fields[key] = str(data[key]).strip()
    if "tags" in data and data["tags"] is not None:
        fields["tags"] = _norm_tags_input(data["tags"])
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    note = store.update_note(note_id, **fields)
    if note is None:
        return jsonify({"error": "note not found"}), 404
    return jsonify({"note": note})


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
def api_notes_delete(note_id):
    """Delete one institutional note."""
    store = _notes_store()
    if store is None:
        return jsonify({"error": "institutional memory unavailable"}), 503
    if not store.delete_note(note_id):
        return jsonify({"error": "note not found"}), 404
    return jsonify({"ok": True, "deleted": note_id})


def _subagent_orchestrator():
    """Live OrchestrationManager of the current agent (None when absent)."""
    agent = _state.get("agent")
    if agent is None:
        return None
    orch = getattr(agent, "_orchestrator", None)
    return orch or None


def _orch_records_snapshot(orch, include_output=False):
    rows = []
    with getattr(orch, "_lock", _lock):
        ids = list(getattr(orch, "_order", []) or [])
        records = dict(getattr(orch, "_records", {}) or {})
    for aid in ids:
        rec = records.get(aid)
        if rec is None:
            continue
        if hasattr(rec, "snapshot"):
            try:
                rows.append(rec.snapshot(include_output=include_output))
                continue
            except Exception:
                pass
        rows.append({"agent_id": aid})
    return rows


@app.route("/api/subagents")
def api_subagents_list():
    """All tracked sub-agents of the current run (lightweight snapshots)."""
    orch = _subagent_orchestrator()
    if orch is None:
        return jsonify({"error": "delegation unavailable "
                                 "(agent not running)"}), 503
    rows = _orch_records_snapshot(orch, include_output=False)
    summary = {}
    if hasattr(orch, "registry_summary"):
        try:
            summary = orch.registry_summary()
        except Exception:
            summary = {}
    return jsonify({"count": len(rows), "agents": rows, "summary": summary})


@app.route("/api/subagents", methods=["POST"])
def api_subagents_spawn():
    """Spawn one tracked sub-agent (JSON body)."""
    orch = _subagent_orchestrator()
    if orch is None:
        return jsonify({"error": "delegation unavailable "
                                 "(agent not running)"}), 503
    agent = _state.get("agent")
    if agent is not None and not getattr(agent, "allow_subagents", True):
        return jsonify({"ok": False,
                        "error": "sub-agents are disabled for this run"}), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON body required"}), 400
    task = (data.get("task") or "").strip()
    if not task:
        return jsonify({"error": "task required"}), 400

    def _pick_list(value):
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    try:
        out = orch.spawn(
            task=task,
            wait=bool(data.get("wait", False)),
            success_criteria=_pick_list(data.get("success_criteria")),
            capabilities=_pick_list(data.get("capabilities")),
            persona=(data.get("persona") or "").strip() or None,
            timeout=data.get("timeout") or None,
            meta={"source": "webui"},
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    if isinstance(out, str) and out.startswith("Error:"):
        return jsonify({"ok": False, "error": out[6:].strip()}), 400
    try:
        body = json.loads(out) if isinstance(out, str) else dict(out)
    except (TypeError, ValueError):
        body = {"message": out}
    return jsonify({"ok": True, **body})


@app.route("/api/subagents/<aid>")
def api_subagents_detail(aid):
    """Rich snapshot (with output) of one sub-agent."""
    orch = _subagent_orchestrator()
    if orch is None:
        return jsonify({"error": "delegation unavailable"}), 503
    with getattr(orch, "_lock", _lock):
        rec = (getattr(orch, "_records", {}) or {}).get(aid)
    if rec is not None and hasattr(rec, "snapshot"):
        try:
            return jsonify({"agent": rec.snapshot(include_output=True)})
        except Exception:
            pass
    try:
        status_text = orch.check_status(aid)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    if isinstance(status_text, str) and status_text.startswith("Error:"):
        return jsonify({"error": status_text[6:].strip()}), 404
    return jsonify({"agent_id": aid, "status_text": status_text})


@app.route("/api/subagents/<aid>/transcript")
def api_subagents_transcript(aid):
    """Full transcript of one sub-agent."""
    orch = _subagent_orchestrator()
    if orch is None:
        return jsonify({"error": "delegation unavailable"}), 503
    try:
        text = orch.fetch_transcript(aid)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    if isinstance(text, str) and text.startswith("Error:"):
        return jsonify({"error": text[6:].strip()}), 404
    return jsonify({"agent_id": aid, "transcript": text})


@app.route("/api/subagents/<aid>/cancel", methods=["POST"])
def api_subagents_cancel(aid):
    """Cancel one active sub-agent."""
    orch = _subagent_orchestrator()
    if orch is None:
        return jsonify({"error": "delegation unavailable"}), 503
    try:
        out = orch.cancel_agent(aid)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    if isinstance(out, str) and out.startswith("Error:"):
        return jsonify({"ok": False, "error": out[6:].strip()}), 400
    return jsonify({"ok": True, "message": out})


@app.route("/api/subagents/<aid>/continue", methods=["POST"])
def api_subagents_continue(aid):
    """Resume a finished sub-agent with a follow-up prompt."""
    orch = _subagent_orchestrator()
    if orch is None:
        return jsonify({"error": "delegation unavailable"}), 503
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON body required"}), 400
    follow_up = (data.get("follow_up") or "").strip()
    if not follow_up:
        return jsonify({"error": "follow_up required"}), 400
    try:
        out = orch.continue_agent(aid, follow_up)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    if isinstance(out, str) and out.startswith("Error:"):
        return jsonify({"ok": False, "error": out[6:].strip()}), 400
    try:
        body = json.loads(out) if isinstance(out, str) else dict(out)
    except (TypeError, ValueError):
        body = {"message": out}
    return jsonify({"ok": True, **body})


def main():
    ap = argparse.ArgumentParser(description="AI Agent Web UI")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--mock", action="store_true",
                    help="force mock mode even if an API key is set")
    args = ap.parse_args()

    _reload_state(mock_override=True if args.mock else None)
    cfg = _current_cfg()
    auto = bool(cfg.get("auto")) or (cfg.get("model") == "auto")
    if cfg.get("mock"):
        mode = "mock (built-in test LLM)"
    elif auto:
        mode = "auto (Smart Router -> %s)" % DEFAULT_FAST_MODEL
    else:
        mode = "live (%s @ %s)" % (cfg.get("model"), cfg.get("base_url"))

    print("=" * 58)
    print("  AI AGENT WEB UI")
    print("  mode   : %s" % mode)
    print("  tools  : %d registered" % len(_state["agent"]._tool_list))
    print("  url    : http://%s:%d" % (args.host, args.port))
    print("  stop   : Ctrl+C")
    print("=" * 58)
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
