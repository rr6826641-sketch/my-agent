"""Phase 3 - Dynamic Tool Synthesizer with auto-patching.

Simulates the full "missing tool -> synthesis -> sandbox rejection ->
auto-patch feedback loop -> hot reload" lifecycle using a stub code
model that ships broken code first and a stub validator that replays
sandbox verdicts, so no subprocess is spawned and the real store at
memory/synthesized_tools.db is never touched.

The payload-handler tier (_PAYLOAD_RULES) is covered end-to-end with the
REAL SynthesizedToolValidator (in-process probes, sandbox=None) so the
catalog itself is regression-tested: every rule source must compile, its
probes must pass, and the full engine pipeline must synthesize and
hot-reload each payload key.
"""

import copy

import pytest

from ai_agent.core.self_evolution import (
    CapabilityGap,
    SelfEvolutionEngine,
    SynthesizedToolValidator,
    ToolSynthesizer,
    _PAYLOAD_RULES,
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


# ---------------------------------------------------------------------------
# Payload-handler tier (_PAYLOAD_RULES)
# ---------------------------------------------------------------------------

PAYLOAD_KEYS = tuple(rule["key"] for rule in _PAYLOAD_RULES
                     if isinstance(rule, dict) and rule.get("key"))


@pytest.mark.parametrize("key", PAYLOAD_KEYS)
def test_payload_rule_compiles_and_passes_probes_with_real_validator(key):
    """Every payload rule must survive the REAL validator: source compiles
    under the AST allowlist and its micro unit tests (probes) pass against
    the built func.  Guards against tokenizer/quoting bugs silently eating
    backslashes inside rule source (the html_entity_encode regression)."""
    spec = ToolSynthesizer().synthesize(name=key)
    assert spec is not None, "rule %r not synthesizable" % key
    assert spec.get("source")
    verdict = SynthesizedToolValidator().validate(spec, run_probes=True)
    assert verdict["ok"] is True, (
        "%s: errors=%r probe_failures=%r"
        % (key, verdict["errors"], verdict["probe_failures"]))
    func = verdict["func"]
    for probe in spec["probe"]:
        args = dict(probe.get("args") or {})
        assert func(**args) == probe["expect"]


@pytest.mark.parametrize("key", PAYLOAD_KEYS)
def test_payload_rule_registers_through_engine(key, tmp_path):
    """Full missing-tool lifecycle for each payload key with the real
    validator: detector -> rule synthesis -> validation -> hot reload ->
    persistence.  No code model is required (declarative rule tier)."""
    registered = []
    engine = SelfEvolutionEngine(
        store_path=str(tmp_path / ("%s.db" % key)),
        hot_reload=lambda spec: (registered.append(spec["name"])
                                 or spec["name"]),
        detector=_detector_for(key),
        synthesizer=ToolSynthesizer(),
        validator=SynthesizedToolValidator(),
        max_patches=2,
    )
    try:
        out = engine.observe(result="Unknown tool: %s" % key)
        assert out is not None
        assert out["status"] == "synthesized", \
            "%s: status=%s detail=%s" % (key, out["status"], out["detail"])
        assert out["registered"] is True
        assert out["name"] == key
        assert engine.stats["patched"] == 0
        assert engine.stats["rejected"] == 0
        assert registered == [key]
    finally:
        engine.close()


def test_payload_rules_flagged_in_catalog():
    """rules() must expose the payload tier: exactly the _PAYLOAD_RULES
    entries flagged payload=True and no rule left without a flag."""
    synth = ToolSynthesizer()
    catalog = synth.rules()
    payload = [r for r in catalog if r.get("payload")]
    assert len(payload) == len(PAYLOAD_KEYS) == len(_PAYLOAD_RULES)
    assert {r["key"] for r in payload} == set(PAYLOAD_KEYS)
    # every catalog entry carries an explicit boolean payload marker
    assert all("payload" in r for r in catalog)
    assert any(not r["payload"] for r in catalog), \
        "generic tier must remain non-payload"
    # probe self-tests are shipped with every payload generator
    assert all(r.get("probe_count", 0) >= 1 for r in payload)
