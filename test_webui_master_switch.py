"""Feature: Red Team master switch (/api/redteam) + status persona exposure.

One-click evil profile: enabled=true -> red_team_mode on + top tier
PRO MAX level ('promax' composite persona by default; explicit
level=promix -> 'promix', level=master -> 'unfiltered'); enabled=false ->
red_team_mode off. The LLM client must be
rebuilt so the uncensored tail + persona block actually ride on the active
client.

Runs the real Flask app in mock mode; config.json is backed up and restored
so the developer's live settings are never modified by the test run.
"""

import json
import os

import pytest

import webui


@pytest.fixture()
def mock_app():
    """Mock-mode Flask test client with config.json backup/restore."""
    backup = None
    if os.path.exists(webui.CONFIG_PATH):
        with open(webui.CONFIG_PATH, "r", encoding="utf-8") as f:
            backup = f.read()
    webui._reload_state(mock_override=True)
    yield webui.app.test_client()
    # restore the developer's original config.json no matter what happened
    if backup is not None:
        with open(webui.CONFIG_PATH, "w", encoding="utf-8") as f:
            f.write(backup)
    elif os.path.exists(webui.CONFIG_PATH):
        os.remove(webui.CONFIG_PATH)
    webui._reload_state(mock_override=True)


def test_status_exposes_persona_and_retries(mock_app):
    r = mock_app.get("/api/status")
    assert r.status_code == 200
    data = r.get_json()
    assert "persona" in data
    assert "refusal_retries" in data
    assert isinstance(data["refusal_retries"], int)


def test_master_switch_enable_evil_profile(mock_app):
    r = mock_app.post("/api/redteam", json={"enabled": True})
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["red_team_mode"] is True
    assert data["red_team_level"] == "promax"
    assert data["persona"] == "promax"
    # config.json actually persisted the evil profile
    with open(webui.CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg["red_team_mode"] is True
    assert cfg["red_team_level"] == "promax"
    assert cfg["persona"] == "promax"
    # the rebuilt LLM client carries uncensored + the unfiltered persona block
    llm = webui._state["agent"].llm
    assert llm.uncensored is True
    assert getattr(llm, "persona_block", "")


def test_master_switch_disable(mock_app):
    r = mock_app.post("/api/redteam", json={"enabled": False})
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["red_team_mode"] is False
    # persona is left as-is when disabling (only red_team_mode flips)
    with open(webui.CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg["red_team_mode"] is False
    llm = webui._state["agent"].llm
    assert llm.uncensored is False


def test_master_switch_round_trip(mock_app):
    client = mock_app
    on = client.post("/api/redteam", json={"enabled": True}).get_json()
    assert on["red_team_mode"] is True and on["persona"] == "promax"
    assert on["red_team_level"] == "promax"
    off = client.post("/api/redteam", json={"enabled": False}).get_json()
    assert off["red_team_mode"] is False
    # the status endpoint agrees with the switch state
    status = client.get("/api/status").get_json()
    assert status["red_team_mode"] is False
