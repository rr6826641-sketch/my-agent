#!/usr/bin/env python3
"""AI Agent - local Web UI (Flask).

Run:
    py -3 webui.py            # starts on http://127.0.0.1:8080
    py -3 webui.py --port 9000
    py -3 webui.py --mock     # force mock mode even if an API key is set

The UI is local-only (binds to 127.0.0.1). Configure the LLM from the
Settings tab: API key, base URL and model are saved to config.json.
"""

import argparse
import json
import os
import queue
import sys
import threading
import time

from flask import Flask, jsonify, render_template, request, Response, stream_with_context

from ai_agent.config import PROJECT_DIR, load_config
from ai_agent.core import Agent
from ai_agent.llm import MockClient, OpenAIClient
from ai_agent.memory import MemoryStore
from ai_agent.tools import create_tools

CONFIG_PATH = os.path.join(PROJECT_DIR, "config.json")
MEMORY_PATH = os.path.join(PROJECT_DIR, "memory.json")

app = Flask(__name__)

_lock = threading.Lock()
_state = {
    "agent": None,
    "memory": None,
    "cfg": None,
}


def _current_cfg():
    with _lock:
        return dict(_state["cfg"] or {})


def _save_cfg(patch):
    """Merge patch into config.json (load_config reads this file first)."""
    cfg = {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    cfg.update({k: v for k, v in patch.items() if v is not None})
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def _build_agent(cfg):
    memory = MemoryStore(cfg["memory_file"] or MEMORY_PATH)
    if cfg.get("mock"):
        llm = MockClient()
    else:
        llm = OpenAIClient(
            api_key=cfg.get("api_key") or "",
            base_url=cfg.get("base_url") or "https://api.openai.com/v1",
            model=cfg.get("model") or "gpt-4o-mini",
        )
    agent = Agent(llm, memory=memory,
                  max_iterations=cfg.get("max_iterations") or 12,
                  confirm_terminal=False)  # auto mode: no stdin prompts in UI
    return agent, memory


def _reload_state(mock_override=None):
    cfg = load_config()
    if mock_override is not None:
        cfg["mock"] = mock_override
    if not cfg.get("mock") and not cfg.get("api_key"):
        cfg["mock"] = True  # no key configured -> fall back to mock
    agent, memory = _build_agent(cfg)
    with _lock:
        _state.update({"agent": agent, "memory": memory, "cfg": cfg})
    return cfg


def _status():
    cfg = _current_cfg()
    return {
        "mode": "mock" if cfg.get("mock") else "live",
        "model": "mock-1" if cfg.get("mock") else cfg.get("model", "?"),
        "base_url": "built-in" if cfg.get("mock") else cfg.get("base_url", "?"),
        "has_key": bool(cfg.get("api_key")),
        "tools": len(_state["agent"]._tool_list) if _state.get("agent") else 0,
        "memory_entries": len(_state["memory"]._data.get("notes", {})) if _state.get("memory") else 0,
    }


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

    q = queue.Queue(maxsize=64)
    agent = _state["agent"]

    def worker():
        try:
            for event in agent.run_stream(message):
                q.put(event)
        except Exception as exc:
            q.put({"type": "error", "content": "%s: %s" % (type(exc).__name__, exc)})
        finally:
            q.put(None)

    threading.Thread(target=worker, daemon=True).start()

    def gen():
        yield "retry: 1500\n\n"
        while True:
            try:
                event = q.get(timeout=300)
            except queue.Empty:
                yield "data: {\"type\": \"error\", \"content\": \"[timed out]\"}\n\n"
                break
            if event is None:
                break
            yield "data: " + json.dumps(event, ensure_ascii=False) + "\n\n"

    return Response(stream_with_context(gen()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    with _lock:
        if _state.get("agent"):
            _state["agent"].reset()
    return jsonify({"ok": True})


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
    return jsonify({
        "api_key": cfg.get("api_key", ""),
        "base_url": cfg.get("base_url", ""),
        "model": cfg.get("model", ""),
        "mock": bool(cfg.get("mock")),
        "max_iterations": cfg.get("max_iterations", 12),
    })


@app.route("/api/settings", methods=["POST"])
def api_settings_save():
    data = request.get_json(silent=True) or {}
    api_key = (data.get("api_key") or "").strip()
    base_url = (data.get("base_url") or "").strip()
    model = (data.get("model") or "").strip()
    mock = bool(data.get("mock"))
    mi = data.get("max_iterations")

    patch = {"mock": mock}
    if api_key:
        patch["api_key"] = api_key
    if base_url:
        patch["base_url"] = base_url
    if model:
        patch["model"] = model
    if isinstance(mi, int) and 1 <= mi <= 100:
        patch["max_iterations"] = mi
    _save_cfg(patch)

    _reload_state(mock_override=mock)
    return jsonify(_status())


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
    mode = "mock (built-in test LLM)" if cfg.get("mock") else \
        "live (%s @ %s)" % (cfg.get("model"), cfg.get("base_url"))

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
