"""Security regression tests: secrets isolation policy (v2).

Guards the API-key isolation invariants:
  1. config.json never carries an API key (live repo file + loader strips it)
  2. AGENT_API_KEY is loaded STRICTLY from .env / environment
  3. placeholder keys are rejected
  4. save_env_key writes ONLY to .env (never config.json)
  5. .gitignore ignores .env, config.json, runtime DBs and artifacts
  6. git tracks neither .env nor config.json
  7. no hardcoded key literals in the python sources

Run:  py -m pytest test_security_audit.py -q
"""
import json
import os
import re
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_agent import config as config_mod

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture()
def isolated_paths(tmp_path, monkeypatch):
    """Point config.py at temp config.json / .env and clear env secrets."""
    cfg_path = tmp_path / "config.json"
    env_path = tmp_path / ".env"
    monkeypatch.setattr(config_mod, "CONFIG_PATH", str(cfg_path))
    monkeypatch.setattr(config_mod, "ENV_PATH", str(env_path))
    monkeypatch.delenv("AGENT_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_BASE_URL", raising=False)
    monkeypatch.delenv("AGENT_MODEL", raising=False)
    return {"config": str(cfg_path), "env": str(env_path)}


def test_live_config_json_has_no_api_key():
    """The developer's live config.json must stay key-free."""
    path = os.path.join(PROJECT_DIR, "config.json")
    if not os.path.isfile(path):
        pytest.skip("no live config.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "api_key" not in data, "config.json contains an api_key field"
    assert "AGENT_API_KEY" not in data, "config.json contains AGENT_API_KEY"


def test_loader_strips_api_key_from_config_json(isolated_paths):
    """Even a poisoned config.json can never supply the API key."""
    with open(isolated_paths["config"], "w", encoding="utf-8") as f:
        json.dump({"api_key": "sk-poisoned-never-load",
                   "model": "test-model"}, f)
    data = config_mod._read_non_secret_json()
    assert "api_key" not in data
    assert data.get("model") == "test-model"


def test_env_is_the_only_key_source(isolated_paths):
    """Key comes from .env; without it cfg['api_key'] stays empty."""
    with open(isolated_paths["env"], "w", encoding="utf-8") as f:
        f.write("AGENT_API_KEY=env-side-key-12345\n")
    cfg = config_mod.load_config()
    assert cfg["api_key"] == "env-side-key-12345"


def test_missing_key_is_reported_not_silent(isolated_paths):
    """No .env key -> config_status() flags ok=False with guidance."""
    status = config_mod.config_status()
    assert status["ok"] is False
    assert status["has_api_key"] is False
    assert ".env" in status["error"]


def test_placeholder_key_rejected(isolated_paths, monkeypatch):
    """Known placeholder keys must not count as configured."""
    monkeypatch.setenv("AGENT_API_KEY", "sk-your-key-here")
    status = config_mod.config_status()
    assert status["ok"] is False


def test_save_env_key_writes_env_not_config(isolated_paths):
    """save_env_key persists to .env only; config.json is untouched."""
    ok, msg = config_mod.save_env_key("sk-fresh-key-98765")
    assert ok, msg
    assert os.path.isfile(isolated_paths["env"])
    assert not os.path.isfile(isolated_paths["config"])
    with open(isolated_paths["env"], "r", encoding="utf-8") as f:
        content = f.read()
    assert "AGENT_API_KEY=sk-fresh-key-98765" in content


def test_gitignore_covers_secrets_and_runtime():
    """.gitignore must ignore env files, config.json, DBs and artifacts."""
    with open(os.path.join(PROJECT_DIR, ".gitignore"), "r",
              encoding="utf-8") as f:
        gi = f.read()
    for pattern in (".env", "config.json", "*.db", "*.sqlite",
                    "artifacts/", "*.env.local"):
        assert pattern in gi, "missing .gitignore pattern: %s" % pattern


def test_git_tracks_no_secret_files():
    """git ls-files must never list .env or config.json."""
    try:
        out = subprocess.run(
            ["git", "ls-files"], cwd=PROJECT_DIR, capture_output=True,
            text=True, timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip("git unavailable or not a repo: %s" % exc)
    tracked = [ln.strip() for ln in out.splitlines() if ln.strip()]
    for path in tracked:
        assert os.path.basename(path) != ".env", "tracked secret: %s" % path
        assert path != "config.json", "tracked secret: config.json"
        assert path.endswith(".env.example") or not \
            path.endswith(".env"), "unexpected env file tracked: %s" % path


_KEY_LITERALS = (
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"(?i)(?:api_key|apikey|secret|password|token)\s*=\s*"
               r"[\"'][A-Za-z0-9+/_\-]{24,}[\"']"),
)


def test_no_hardcoded_key_literals_in_sources():
    """Python sources must not embed real-looking key literals."""
    offenders = []
    for root, dirs, files in os.walk(PROJECT_DIR):
        dirs[:] = [d for d in dirs if d not in (
            ".git", "__pycache__", "artifacts", "node_modules", ".pytest_cache",
            "data", "memory", "reports", "rpg", "static", "templates")]
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    src = f.read()
            except OSError:
                continue
            for rx in _KEY_LITERALS:
                m = rx.search(src)
                if m:
                    offenders.append("%s: %s" % (name, m.group(0)[:40]))
    assert not offenders, "hardcoded key literal(s): %s" % offenders


def test_config_example_is_secret_free():
    """config.example.json must not ship an api_key field either."""
    path = os.path.join(PROJECT_DIR, "config.example.json")
    if not os.path.isfile(path):
        pytest.skip("no config.example.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "api_key" not in data
    assert "AGENT_API_KEY" not in data
