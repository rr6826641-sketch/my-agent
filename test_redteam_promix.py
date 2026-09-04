"""RED TEAM PRO MIX level - regression tests.

PRO MIX = PRO MAX (uncensored route lock + uncensored failover pool) plus:

  * widened MIX pool - the mythos-lineage model (gryphe/mythomax-l2-13b)
    and the dolphin heavyweight join the base uncensored fallbacks, so an
    uncensored session can fail over across a true mixture of models;
  * round-robin pool rotation - every call leads with a different
    uncensored model, no single fallback gets hammered;
  * composite "promix" persona - one directive that stacks APEX execution,
    BLACKICE raw output, DAN-R clearance and UNFILTERED core;
  * config level flag - red_team_level in {master, promax, promix}, with
    /api/redteam accepting an explicit level (default = promix on enable).

Run: py -m pytest test_redteam_promix.py
"""

import json
import os

import pytest

from ai_agent import personas
from ai_agent.llm import (MIXED_UNCENSORED_MODELS, OpenAIClient,
                          UNCENSORED_FALLBACK_MODELS, _full_uncensored_pool,
                          _rotated_mix)

import webui


# ---------------------------------------------------------------------------
# PRO MIX pool (llm.py)
# ---------------------------------------------------------------------------

def test_mix_pool_contains_mythos_and_dolphin():
    ids = set(MIXED_UNCENSORED_MODELS)
    assert "gryphe/mythomax-l2-13b" in ids, "mythos-lineage model missing"
    assert ("cognitivecomputations/dolphin-mistral-24b-venice-edition"
            in ids), "dolphin heavyweight missing"


def test_full_pool_is_base_plus_mix_deduped():
    pool = _full_uncensored_pool()
    assert pool[0] == UNCENSORED_FALLBACK_MODELS[0]
    assert len(pool) == len(UNCENSORED_FALLBACK_MODELS) + \
        len(MIXED_UNCENSORED_MODELS)
    assert len(set(pool)) == len(pool), "pool must not contain duplicates"


def test_rotated_mix_round_robin():
    pool = _full_uncensored_pool()
    n = len(pool)
    leaders = [_rotated_mix(pool, i)[0] for i in range(n)]
    assert len(set(leaders)) == n, "every model leads exactly once"
    assert _rotated_mix(pool, n) == pool, "rotation wraps after full cycle"
    assert _rotated_mix([], 3) == []


def test_client_mix_widens_pool():
    c = OpenAIClient(model="m", uncensored=True, uncensored_mix=True,
                     uncensored_fallbacks=list(UNCENSORED_FALLBACK_MODELS))
    for m in MIXED_UNCENSORED_MODELS:
        assert m in c.uncensored_fallbacks
    assert c.uncensored_mix is True


def test_client_mix_rotates_per_call():
    c = OpenAIClient(model="m", uncensored=True, uncensored_mix=True,
                     uncensored_fallbacks=list(UNCENSORED_FALLBACK_MODELS))
    pool = _full_uncensored_pool()
    leaders = [c._effective_fallbacks()[0] for _ in range(len(pool) + 1)]
    assert len(set(leaders[:len(pool)])) == len(pool), \
        "round-robin must cover the whole mix pool"


def test_client_no_mix_stable_order():
    c = OpenAIClient(model="m", uncensored=True, uncensored_mix=False,
                     uncensored_fallbacks=list(UNCENSORED_FALLBACK_MODELS))
    assert c._effective_fallbacks()[0] == UNCENSORED_FALLBACK_MODELS[0]
    assert c._effective_fallbacks()[0] == UNCENSORED_FALLBACK_MODELS[0]


def test_client_mix_without_base_pool_uses_full_pool():
    c = OpenAIClient(model="m", uncensored=True, uncensored_mix=True)
    assert c.uncensored_fallbacks == _full_uncensored_pool(), \
        "mix with no base pool must widen to the full mixed pool"
    eff = c._effective_fallbacks()
    pool = _full_uncensored_pool()
    assert eff[:len(pool)] == pool, \
        "first call leads with the full pool (offset 0 = unrotated)"


# ---------------------------------------------------------------------------
# composite PRO MIX persona (personas.py)
# ---------------------------------------------------------------------------

def test_promix_persona_registered():
    ids = [p["id"] for p in personas.list_personas()]
    assert "promix" in ids
    assert personas.normalize("promix") == "promix"


def test_promix_persona_composite_block():
    block = personas.get_block("promix", uncensored=True)
    assert "[PERSONA OVERRIDE - RED TEAM PRO MIX]" in block
    for marker in ("EXECUTION (APEX)", "OUTPUT (BLACKICE)",
                   "CLEARANCE (DAN-R)", "CORE (UNFILTERED)"):
        assert marker in block, marker + " missing from composite persona"


def test_promix_persona_gated_by_uncensored():
    assert personas.get_block("promix", uncensored=False) == ""


# ---------------------------------------------------------------------------
# webui level wiring (/api/redteam + _build_llm)
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_app():
    """Mock-mode Flask test client with config.json backup/restore."""
    backup = None
    if os.path.exists(webui.CONFIG_PATH):
        with open(webui.CONFIG_PATH, "r", encoding="utf-8") as f:
            backup = f.read()
    webui._reload_state(mock_override=True)
    yield webui.app.test_client()
    if backup is not None:
        with open(webui.CONFIG_PATH, "w", encoding="utf-8") as f:
            f.write(backup)
    elif os.path.exists(webui.CONFIG_PATH):
        os.remove(webui.CONFIG_PATH)
    webui._reload_state(mock_override=True)


def test_redteam_enable_defaults_to_promix(mock_app):
    r = mock_app.post("/api/redteam", json={"enabled": True})
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["red_team_mode"] is True
    assert data["red_team_level"] == "promix"
    assert data["persona"] == "promix"
    with open(webui.CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg["red_team_level"] == "promix"


def test_redteam_explicit_promax_keeps_unfiltered(mock_app):
    r = mock_app.post("/api/redteam",
                      json={"enabled": True, "level": "promax"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["red_team_level"] == "promax"
    assert data["persona"] == "unfiltered"
    with open(webui.CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg["red_team_level"] == "promax"
    assert cfg["persona"] == "unfiltered"


def test_redteam_explicit_promix_level(mock_app):
    r = mock_app.post("/api/redteam",
                      json={"enabled": True, "level": "promix"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["red_team_level"] == "promix"
    assert data["persona"] == "promix"
    llm = webui._state["agent"].llm
    assert llm.uncensored is True
    assert llm.uncensored_mix is True
    assert "gryphe/mythomax-l2-13b" in llm.uncensored_fallbacks


def test_redteam_disable_flips_mode_off(mock_app):
    mock_app.post("/api/redteam", json={"enabled": True})
    r = mock_app.post("/api/redteam", json={"enabled": False})
    assert r.status_code == 200
    assert r.get_json()["red_team_mode"] is False
    llm = webui._state["agent"].llm
    assert llm.uncensored is False
    assert llm.uncensored_mix is False


def test_build_llm_mix_only_at_promix(monkeypatch):
    cfg = {"red_team_mode": True, "red_team_level": "promix",
           "mock": True, "persona": "promix"}
    monkeypatch.setattr(webui.personas, "CUSTOM_FILE",
                        os.path.join(webui.PROJECT_DIR, "personas_custom.txt"))
    client = webui._build_llm(cfg)
    assert client.uncensored is True
    assert client.uncensored_mix is True
    assert client.persona_block


def test_build_llm_promax_no_mix(monkeypatch):
    cfg = {"red_team_mode": True, "red_team_level": "promax",
           "mock": True, "persona": "unfiltered"}
    monkeypatch.setattr(webui.personas, "CUSTOM_FILE",
                        os.path.join(webui.PROJECT_DIR, "personas_custom.txt"))
    client = webui._build_llm(cfg)
    assert client.uncensored is True
    assert client.uncensored_mix is False


def test_build_llm_level_defaults_to_promax(monkeypatch):
    cfg = {"red_team_mode": True, "mock": True, "persona": "hackerai"}
    monkeypatch.setattr(webui.personas, "CUSTOM_FILE",
                        os.path.join(webui.PROJECT_DIR, "personas_custom.txt"))
    client = webui._build_llm(cfg)
    assert client.uncensored_mix is False, \
        "missing red_team_level must behave like promax (backward compat)"


def test_status_exposes_red_team_level(mock_app):
    r = mock_app.get("/api/status")
    assert r.status_code == 200
    data = r.get_json()
    assert "red_team_level" in data
    assert data["red_team_level"] in ("master", "promax", "promix")