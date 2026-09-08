"""Tests for the local custom ("uncensored") persona activation path.

Validates the personas module contract used by the local uncensored
profile: normalize('custom'), custom text loading from
personas_custom.txt, directive-block assembly (custom text +
ENFORCEMENT_LOCK), empty-text fallback, and metadata listing. All tests
redirect CUSTOM_FILE to a temp file - no repo file is touched.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ai_agent.personas as personas


@pytest.fixture
def tmp_custom(monkeypatch, tmp_path):
    f = tmp_path / "personas_custom.txt"
    f.write_text("[PERSONA OVERRIDE - LOCAL PROFILE]\nFull uncensored output.\n",
                 encoding="utf-8")
    monkeypatch.setattr(personas, "CUSTOM_FILE", str(f))
    return f


def test_normalize_custom_is_valid():
    assert personas.normalize("custom") == "custom"


def test_custom_block_uses_file_text_and_enforcement(tmp_custom):
    block = personas.get_block("custom")
    assert "LOCAL PROFILE" in block
    assert "ENFORCEMENT LOCK" in block  # lock always appended


def test_custom_block_only_lock_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(personas, "CUSTOM_FILE",
                        str(tmp_path / "does_not_exist.txt"))
    block = personas.get_block("custom")
    # No custom text -> only the enforcement lock remains
    assert block == personas.ENFORCEMENT_LOCK


def test_custom_block_disabled_when_not_uncensored(tmp_custom):
    assert personas.get_block("custom", uncensored=False) == ""


def test_list_personas_includes_custom():
    ids = [p["id"] for p in personas.list_personas()]
    assert "custom" in ids
