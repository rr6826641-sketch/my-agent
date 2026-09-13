"""ULTRA STYLE REGIME (v10.2) - live-narration writing form tests."""
import io
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ai_agent.ultra_v10 import ULTRA_V10_REGIME, ULTRA_STYLE_REGIME, ultra_v10_context

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_PROMPT = os.path.join(ROOT, "system_prompt.txt")


def test_style_regime_in_context():
    ctx = ultra_v10_context("scan targets")
    assert "ULTRA STYLE REGIME" in ctx
    assert "PROGRESS-FEED" in ctx and "main ab" in ctx
    assert "FINAL-SUMMARY" in ctx
    assert "jani" in ctx and "Roman Urdu" in ctx


def test_style_regime_survives_disabled_ultra():
    # ultra_enabled=False -> no regime at all; engine must not crash
    assert isinstance(ULTRA_V10_REGIME, str)
    assert isinstance(ULTRA_STYLE_REGIME, str)
    assert "STYLE" in ULTRA_STYLE_REGIME


def test_system_prompt_has_style_section():
    assert os.path.exists(SYS_PROMPT)
    text = io.open(SYS_PROMPT, encoding="utf-8").read()
    assert "COMMUNICATION & WRITING STYLE" in text
    assert "LIVE NARRATION" in text
    assert "FINAL RESULT" in text
