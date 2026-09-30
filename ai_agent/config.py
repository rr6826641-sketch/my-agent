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
import sys

try:
    from dotenv import load_dotenv  # python-dotenv (optional, preferred)
except ImportError:
    load_dotenv = None


# Desktop App (frozen) support:
# - writable project data (env, chats, memory, artifacts) lives NEXT TO the EXE
# - bundled read-only assets (personas_custom.txt, data/) are seeded on first run
if getattr(sys, "frozen", False):  # PyInstaller onefile/onedir
    PROJECT_DIR = os.path.dirname(os.path.abspath(sys.executable))
    CODE_DIR = getattr(sys, "_MEIPASS", PROJECT_DIR)
else:
    CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    PROJECT_DIR = CODE_DIR

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


# ---------------------------------------------------------------------------
# Dynamic provider routing (v2 fix: API key / base URL mismatch)
# ---------------------------------------------------------------------------
# A key prefix must always match its own endpoint. A Groq key (gsk_…) left on
# https://api.openai.com/v1 returns "API 401: Incorrect API key provided" on
# every call and the run gets trapped retrying a broken route. This table
# keeps the key and its endpoint in sync on every config load and save.
PROVIDER_BASE_URLS = {
    "groq": "https://api.groq.com/openai/v1",
    "openai": "https://api.openai.com/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "ollama": "http://localhost:11434/v1",
}


def detect_provider(api_key):
    """Return the provider implied by an API key's prefix ('' if unknown)."""
    key = (api_key or "").strip()
    if key.startswith("gsk_"):
        return "groq"
    if key.startswith("sk-or-"):
        return "openrouter"
    if key.startswith("sk-"):
        return "openai"
    return ""


def detect_url_provider(base_url):
    """Return the provider a base_url belongs to ('' if custom/unknown)."""
    u = (base_url or "").strip().lower()
    if "groq.com" in u:
        return "groq"
    if "openai.com" in u:
        return "openai"
    if "openrouter.ai" in u:
        return "openrouter"
    if "localhost:11434" in u or "127.0.0.1:11434" in u:
        return "ollama"
    return ""


def apply_provider_routing(cfg):
    """Keep the API key and base_url in sync (config.json loader safety net).

    Routing rules:
    - key starts with 'gsk_'  -> https://api.groq.com/openai/v1
    - key starts with 'sk-'   -> https://api.openai.com/v1
      (sk-or-… is an OpenRouter key and stays on openrouter.ai)
    - Ollama / local LLM URL  -> http://localhost:11434/v1

    A URL that belongs to a different known provider than the key (the
    reported 401 case) is auto-corrected to the key's own endpoint. Custom
    proxy URLs are only replaced when they are empty. Returns cfg.

    Priority: an explicit 'provider' selection saved from the Settings UI
    (e.g. Ollama / local LLM) wins; otherwise the key prefix routes.
    """
    explicit = (cfg.get("provider") or "").strip().lower()
    if explicit == "ollama":
        # Ollama / local LLM needs no key - explicit selection wins even
        # when an old cloud key is still present in .env.
        cfg["base_url"] = PROVIDER_BASE_URLS["ollama"]
        return cfg
    if explicit in ("openai", "groq", "openrouter"):
        # Explicit cloud selection is honoured, EXCEPT when the effective
        # key clearly belongs to another cloud provider: the credential
        # must be able to authenticate against the endpoint, otherwise
        # every call 401s. gsk_… always lands on Groq.
        det = detect_provider(cfg.get("api_key"))
        cfg["base_url"] = PROVIDER_BASE_URLS[det or explicit]
        return cfg
    provider = detect_provider(cfg.get("api_key"))
    url = (cfg.get("base_url") or "").strip()
    if provider:
        routed = PROVIDER_BASE_URLS[provider]
        url_prov = detect_url_provider(url)
        if not url or (url_prov and url_prov != provider):
            # Empty URL, or definite mismatch (e.g. Groq key on api.openai.com)
            # -> route to the endpoint the key actually belongs to.
            cfg["base_url"] = routed
        return cfg
    # No recognised key prefix: keep Ollama/local selection canonical.
    if detect_url_provider(url) == "ollama" and url != PROVIDER_BASE_URLS["ollama"]:
        cfg["base_url"] = PROVIDER_BASE_URLS["ollama"]
    return cfg


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

    # 2.5 Dynamic provider routing: the key prefix must match the endpoint
    # (gsk_ -> Groq, sk- -> OpenAI, ollama -> localhost:11434). Fixes the
    # "API 401: Incorrect API key provided" mismatch on every load.
    cfg = apply_provider_routing(cfg)

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
        if getattr(args, "selftest", False):
            cfg["selftest"] = True
        if args.once:
            cfg["once"] = args.once
        if args.memory_file:
            cfg["memory_file"] = args.memory_file
        if args.max_iterations:
            cfg["max_iterations"] = args.max_iterations

    return cfg
