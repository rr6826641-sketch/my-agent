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
import sys
import threading
import time
import uuid

from flask import (Flask, jsonify, render_template, request, Response,
                   send_file, stream_with_context)

from ai_agent.config import (PROJECT_DIR, load_config, config_status, save_env_key)
from ai_agent.core import Agent, RunCancelled
from ai_agent.llm import MockClient, OpenAIClient
from ai_agent.artifacts import ArtifactManager
from ai_agent.memory import GlobalKnowledge, MemoryStore
from ai_agent.rpg import RPGEngine
from ai_agent.tools import create_tools

CONFIG_PATH = os.path.join(PROJECT_DIR, "config.json")
MEMORY_PATH = os.path.join(PROJECT_DIR, "memory.json")
CHATS_PATH = os.path.join(PROJECT_DIR, "chats.json")

# structured scan/generation outputs: artifacts/{chat_id}/{timestamp}/{tool}_{ts}.{ext}
ARTIFACTS_DIR = os.path.join(PROJECT_DIR, "artifacts")
artifacts = ArtifactManager(ARTIFACTS_DIR)

# serializes all reads/writes of chats.json
_chat_lock = threading.Lock()

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
     "label": "Dolphin Mistral 24B", "tag": "uncensored",
     "desc": "Top uncensored — cyber security / recon / red-team tasks"},
    {"id": "thinkingmachines/inkling:free",
     "label": "Inkling (Free)", "tag": "free",
     "desc": "Free uncensored model"},
    {"id": "meta-llama/llama-3.3-70b-instruct",
     "label": "Llama 3.3 70B Instruct", "tag": "general",
     "desc": "Powerful open-source general-purpose model"},
    {"id": "deepseek/deepseek-r1",
     "label": "DeepSeek R1", "tag": "reasoning",
     "desc": "Complex reasoning, math & coding"},
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
    "trojan", "rootkit", "botnet", "ddos", "credential", "dump",
    "smb", "rdp", "wifi", "aircrack", "deauth", "sniff", "arp",
    "session hijack", "token", "idor", "auth bypass", "bypass", "0day",
    "zeroday", "forensic", "malware analysis", "threat", "red team",
    "blue team", "siem", "firewall", "ids", "ips", "network",
    "endpoint", "active directory", "ad", "ldap", "kerberos", "nltest",
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

MODEL_ROUTES = {
    "cyber": "cognitivecomputations/dolphin-mistral-24b-venice-edition",
    "uncensored": "thinkingmachines/inkling:free",
    "coding": "deepseek/deepseek-r1",
    # flagship reasoning: complex logic / architecture / code analysis
    "reasoning": "deepseek/deepseek-r1",
}


def route_model(prompt, cfg=None):
    """Classify a prompt and return (model_id, reason).

    Returns (None, None) when the Smart Auto-Router is off or no special
    class matches (the default fast model is then used).
    """
    cfg = cfg or {}
    auto = bool(cfg.get("auto")) or (cfg.get("model") == "auto")
    if not auto or not prompt:
        return None, None
    text = (" " + prompt.lower() + " ")

    for w in ("uncensored", "jailbreak", "nsfw", "adult"):
        if w in text:
            return MODEL_ROUTES["uncensored"], "uncensored / jailbreak prompt"
    for w in _REASONING_WORDS:
        if w in text:
            return MODEL_ROUTES["reasoning"], "complex reasoning / architecture / analysis task"
    for w in _CYBER_WORDS:
        if w in text:
            return MODEL_ROUTES["cyber"], "cyber security / recon task"
    for w in _CODING_WORDS:
        if w in text:
            return MODEL_ROUTES["coding"], "coding / math / logic task"
    return None, None

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
    if cfg.get("mock"):
        return MockClient(uncensored=cfg.get("red_team_mode"))
    # Smart Auto-Model Selector: in auto mode the configured model is a
    # placeholder; the actual model is chosen per-request by the router.
    model = cfg.get("model") or "gpt-4o-mini"
    if cfg.get("auto") or model == "auto":
        model = DEFAULT_FAST_MODEL
    return OpenAIClient(
        api_key=cfg.get("api_key") or "",
        base_url=cfg.get("base_url") or "https://api.openai.com/v1",
        model=model,
        fallback_models=cfg.get("fallback_models"),
        uncensored=cfg.get("red_team_mode"),
    )


def _build_agent(cfg):
    memory = MemoryStore(cfg["memory_file"] or MEMORY_PATH)
    # Persistent cross-chat knowledge base (SQLite, gitignored via *.db):
    # past findings about a target are auto-injected into the system prompt
    # when a new chat mentions the same domain/IP.
    knowledge = GlobalKnowledge(os.path.join(PROJECT_DIR, "knowledge.db"))
    llm = _build_llm(cfg)
    agent = Agent(llm, memory=memory, knowledge=knowledge,
                  max_iterations=cfg.get("max_iterations") or 60,
                  max_messages=cfg.get("max_messages") or 400,
                  spawn_timeout=cfg.get("spawn_timeout") or 900,
                  max_spawn_depth=cfg.get("max_spawn_depth") or 3,
                  allow_subagents=cfg.get("allow_subagents", True),
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

    q = queue.Queue(maxsize=64)
    agent = _state["agent"]
    cfg = _current_cfg()
    routed_model, route_reason = route_model(message, cfg)

    def run_gen():
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
        # overall stream cap; individual tools are capped at 120s each
        # (TOOL_TIMEOUT in ai_agent/tools/base.py) so this only fires
        # when something is truly stuck — and the frontend releases busy.
        try:
            while True:
                try:
                    event = q.get(timeout=360)
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
# RPG (interactive campaigns)
# --------------------------------------------------------------------------

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

    q = queue.Queue(maxsize=64)
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
                    event = q.get(timeout=360)
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
