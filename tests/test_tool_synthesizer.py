"""Phase 3 - Dynamic Tool Synthesizer with auto-patching.

Simulates the full "missing tool -> synthesis -> sandbox rejection ->
auto-patch feedback loop -> hot reload" lifecycle using a stub code
model that ships broken code first and a stub validator that replays
sandbox verdicts, so no subprocess is spawned and the real store at
memory/synthesized_tools.db is never touched.
"""

import copy

from ai_agent.core.self_evolution import (
    CapabilityGap,
    SelfEvolutionEngine,
    ToolSynthesizer,
)

GAP_MISSING_TOOL = "missing_tool"


class _StubValidator:
    """Validator that rejects any source containing 'BROKEN' (replays a
    syntax error verdict), otherwise accepts and exposes a runnable func."""

    sandbox = None

    def __init__(self):
        self.runs = 0

    def validate(self, spec, run_probes=True):
        self.runs += 1
        source = (spec or {}).get("source", "") or ""
        if "BROKEN" in source:
            return {
                "ok": False,
                "errors": ["syntax error: bad indentation"],
                "probe_failures": [],
                "func": None,
            }
        return {
            "ok": True,
            "errors": [],
            "probe_failures": [],
            "func": (lambda **kw: "ok-%s" % (kw.get("data", ""))),
        }


def _make_synthesizer(calls):
    """code model returns a BROKEN module on the first call and a fixed
    module on every later call; the gap detail (with AUTO-PATCH feedback)
    is recorded in ``calls``."""
    def code_model(gap):
        calls.append(copy.copy(gap.detail or ""))
        if len(calls) == 1:
            return {
                "name": gap.tool_name,
                "description": "test tool",
                "parameters": {"type": "object",
                               "properties": {},
                               "required": []},
                "source": "BROKEN def run(**kw):\n    return kw",
                "probe": [{"args": {}, "expect": {}}],
            }
        return {
            "name": gap.tool_name,
            "description": "test tool",
            "parameters": {"type": "object",
                           "properties": {},
                           "required": []},
            "source": "def run(**kw):\n    return 'ok'",
            "probe": [{"args": {}, "expect": "ok"}],
        }
    return ToolSynthesizer(code_model=code_model)


def _detector_for(name):
    class _D:
        def parse(self, result=None, planner_state=None):
            return [CapabilityGap(GAP_MISSING_TOOL, name)]
    return _D()


def test_missing_tool_request_auto_patches_and_registers(tmp_path):
    calls = []
    registered = []
    engine = SelfEvolutionEngine(
        store_path=str(tmp_path / "synth.db"),
        hot_reload=lambda spec: (registered.append(spec["name"])
                                 or spec["name"]),
        detector=_detector_for("hex_diff_tool"),
        synthesizer=_make_synthesizer(calls),
        validator=_StubValidator(),
        max_patches=3,
    )
    out = engine.observe(result="Unknown tool: hex_diff_tool")
    assert out is not None
    assert out["status"] == "synthesized"
    assert out["registered"] is True
    assert out["name"] == "hex_diff_tool"
    # code model was re-prompted exactly once with the syntax feedback
    assert len(calls) == 2
    assert "[AUTO-PATCH #1]" in calls[1]
    assert "syntax error" in calls[1]
    assert engine.stats["patched"] == 1
    assert engine.stats["rejected"] == 0
    assert registered == ["hex_diff_tool"]
    engine.close()


def test_patch_budget_exhausted_rejects(tmp_path):
    calls = []

    def always_broken(gap):
        calls.append(gap.detail or "")
        return {"source": "BROKEN def run(**kw):\n    return kw",
                "probe": [{"args": {}, "expect": {}}]}

    engine = SelfEvolutionEngine(
        store_path=str(tmp_path / "synth2.db"),
        hot_reload=lambda spec: spec["name"],
        detector=_detector_for("fancy_tool_zz"),
        synthesizer=ToolSynthesizer(code_model=always_broken),
        validator=_StubValidator(),
        max_patches=2,
    )
    out = engine.observe(result="Unknown tool: fancy_tool_zz")
    assert out is not None
    assert out["status"] == "rejected"
    assert out["registered"] is False
    # 1 original + 2 patch attempts = 3 code-model calls
    assert len(calls) == 3
    assert engine.stats["patched"] == 0  # only successful patches count
    assert engine.stats["rejected"] == 1
    engine.close()


def test_no_rule_no_code_model_is_no_match(tmp_path):
    engine = SelfEvolutionEngine(
        store_path=str(tmp_path / "synth3.db"),
        hot_reload=lambda spec: spec["name"],
        detector=_detector_for("b64_encode"),  # rule-generator tool
        synthesizer=ToolSynthesizer(),          # no code model at all
        validator=_StubValidator(),
    )
    # rule tools still synthesize without any code model (16 rule gens)
    out = engine.observe(result="Unknown tool: b64_encode")
    assert out is not None
    assert out["status"] == "synthesized"
    assert engine.stats["patched"] == 0
    engine.close()
