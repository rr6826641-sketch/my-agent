"""Configuration loading.

Security policy (v2 - API key isolation):
- API keys are loaded STRICTLY from the environment / .env file.
- config.json may NEVER provide API keys: any api_key field present in
  config.json is stripped on load and ignored. config.json only holds
  non-secret runtime settings (base_url, model, toggles, limits).
- CLI arguments may override at runtime (never persisted to disk).
- If .env is missing or AGENT_API_KEY is not set, config_status() returns a
  clear message so the UI can show a safe fallback error.
"""

import json
import os

try:
    from dotenv import load_dotenv  # python-dotenv (optional, preferred)
except ImportError:
    load_dotenv = None

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(PROJECT_DIR, ".env")
CONFIG_PATH = os.path.join(PROJECT_DIR, "config.json")

DEFAULTS = {
    "api_key": "",
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-4o-mini",
    "mock": False,
    "auto": False,
    "red_team_mode": True,  # uncensored by default (filter removed)
    "once": "",
    "memory_file": os.path.join(PROJECT_DIR, "memory.json"),
    "max_iterations": 60,
}

# The ONLY env vars allowed to carry secrets / provider overrides.
ENV_MAP = {
    "api_key": "AGENT_API_KEY",
    "base_url": "AGENT_BASE_URL",
    "model": "AGENT_MODEL",
    "memory_file": "AGENT_MEMORY_FILE",
}

_PLACEHOLDER_KEYS = {"", "sk-your-key-here", "your-key-here", "REPLACE_WITH_YOUR_KEY"}


def _parse_env_file(path):
    """Minimal .env parser (fallback when python-dotenv is not installed)."""
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


def _load_env():
    """Load .env into os.environ (python-dotenv first, manual parser fallback)."""
    if load_dotenv:
        try:
            load_dotenv(ENV_PATH, override=False)
        except Exception:
            pass
    else:
        for k, v in _parse_env_file(ENV_PATH).items():
            os.environ.setdefault(k, v)


def _read_non_secret_json():
    """Read config.json but NEVER return API keys from it."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    # Security: config.json must not supply secrets, even if present.
    data.pop("api_key", None)
    data.pop("AGENT_API_KEY", None)
    return data


def _effective_api_key():
    env = _parse_env_file(ENV_PATH)
    return (os.environ.get("AGENT_API_KEY") or env.get("AGENT_API_KEY") or "").strip()


def config_status():
    """Return a dict describing key availability for a safe UI fallback.

    ok=False means the UI must surface an error and (optionally) keep the
    agent in mock mode so nothing silently half-works.
    """
    env_exists = os.path.isfile(ENV_PATH)
    key = _effective_api_key()
    if key and key not in _PLACEHOLDER_KEYS:
        return {"ok": True, "env_exists": env_exists, "has_api_key": True, "error": ""}
    if not env_exists:
        msg = ("No .env file found. Copy .env.example to .env and set "
               "AGENT_API_KEY=<your key>, or paste the key in the Settings tab.")
    else:
        msg = ("AGENT_API_KEY is missing in .env. Open the Settings tab and paste "
               "your key - it is saved to .env, never to config.json.")
    return {"ok": False, "env_exists": env_exists, "has_api_key": False, "error": msg}


def save_env_key(api_key, base_url=None, model=None):
    """Persist provider settings to .env (never config.json).

    Returns (ok: bool, message: str).
    """
    api_key = (api_key or "").strip()
    if not api_key:
        return False, "API key is empty"
    env = _parse_env_file(ENV_PATH)
    env["AGENT_API_KEY"] = api_key
    if base_url and base_url.strip():
        env["AGENT_BASE_URL"] = base_url.strip()
    if model and model.strip():
        env["AGENT_MODEL"] = model.strip()
    lines = [f"{k}={v}" for k, v in env.items()]
    try:
        with open(ENV_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        try:
            os.chmod(ENV_PATH, 0o600)  # best-effort on POSIX; ignored on Windows
        except Exception:
            pass
        return True, "saved to .env"
    except OSError as e:
        return False, "could not write .env: %s" % e


def load_config(args=None):
    _load_env()
    cfg = dict(DEFAULTS)

    # 1. config.json - non-secret runtime settings only (keys stripped)
    cfg.update(_read_non_secret_json())

    # 2. Environment / .env - the ONLY source for API keys
    env = _parse_env_file(ENV_PATH)
    for key, var in ENV_MAP.items():
        val = os.environ.get(var) or env.get(var)
        if val:
            cfg[key] = val

    # 3. CLI arguments (highest priority, never persisted)
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
        if getattr(args, "red_team_mode", False):
            cfg["red_team_mode"] = True
        if args.once:
            cfg["once"] = args.once
        if args.memory_file:
            cfg["memory_file"] = args.memory_file
        if args.max_iterations:
            cfg["max_iterations"] = args.max_iterations

    return cfg
