"""Configuration loading: CLI args > environment > config.json > defaults."""

import json
import os

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULTS = {
    "api_key": "",
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-4o-mini",
    "mock": False,
    "auto": False,
    "once": "",
    "memory_file": os.path.join(PROJECT_DIR, "memory.json"),
    "max_iterations": 12,
}

ENV_MAP = {
    "api_key": "AGENT_API_KEY",
    "base_url": "AGENT_BASE_URL",
    "model": "AGENT_MODEL",
    "memory_file": "AGENT_MEMORY_FILE",
}


def _parse_env_file(path):
    out = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return out


def load_config(args=None):
    cfg = dict(DEFAULTS)

    # 1. config.json (lowest priority file)
    cfg_path = os.path.join(PROJECT_DIR, "config.json")
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    except Exception:
        pass

    # 2. .env file
    env = _parse_env_file(os.path.join(PROJECT_DIR, ".env"))
    for key, var in ENV_MAP.items():
        if os.environ.get(var):
            cfg[key] = os.environ[var]
        elif env.get(var):
            cfg[key] = env[var]

    # 3. CLI arguments (highest priority)
    if args:
        if args.api_key:
            cfg["api_key"] = args.api_key
        if args.base_url:
            cfg["base_url"] = args.base_url
        if args.model:
            cfg["model"] = args.model
        if args.mock:
            cfg["mock"] = True
        if args.auto:
            cfg["auto"] = True
        if args.once:
            cfg["once"] = args.once
        if args.memory_file:
            cfg["memory_file"] = args.memory_file
        if args.max_iterations:
            cfg["max_iterations"] = args.max_iterations

    return cfg
