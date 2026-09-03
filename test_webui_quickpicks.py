"""Feature: Uncensored model quick-picks in Settings.

MODEL_CATALOG entries carry an explicit "uncensored": True flag so the UI can
render one-click quick-pick chips. Picking one writes the model id to
config.json (auto mode off) and the rebuilt client reflects it.

Runs the real Flask app in mock mode; config.json is backed up and restored
so the developer's live settings are never modified by the test run.
"""

import json
import os

import pytest

import webui


DOLPHIN = "cognitivecomputations/dolphin-mistral-24b-venice-edition"


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


def test_catalog_flags_uncensored_models():
    unc = [m for m in webui.MODEL_CATALOG if m.get("uncensored")]
    assert len(unc) >= 3
    ids = {m["id"] for m in unc}
    assert DOLPHIN in ids
    # every flagged entry has a label so the chip is renderable
    assert all(m.get("label") for m in unc)


def test_settings_api_serves_uncensored_catalog(mock_app):
    r = mock_app.get("/api/settings")
    assert r.status_code == 200
    data = r.get_json()
    unc = [m for m in data["catalog"] if m.get("uncensored")]
    assert len(unc) >= 3


def test_quick_pick_selects_model(mock_app):
    # one-click pick: model id + auto off (exactly what the chip posts)
    r = mock_app.post("/api/settings",
                      json={"model": DOLPHIN, "auto": False, "mock": True})
    assert r.status_code == 200
    # config.json actually persisted the quick-picked model
    with open(webui.CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg["model"] == DOLPHIN
    assert cfg.get("auto") is False


def test_auto_beats_quick_pick(mock_app):
    # auto checkbox re-checked -> stored model falls back to "auto"
    r = mock_app.post("/api/settings",
                      json={"model": DOLPHIN, "auto": True, "mock": True})
    assert r.status_code == 200
    with open(webui.CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg["model"] == "auto"
    assert cfg.get("auto") is True
