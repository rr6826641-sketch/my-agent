"""Autonomous Self-Evolution & Dynamic Tool Synthesis Engine tests.

Covers the PHASE-1 Dynamic Capability Gap Detector surface:

* CapabilityGap record shape / alias sync / JSON-safe export
* is_valid_tool_name guard rails
* CapabilityGapDetector: unknown-tool results, bad-argument schema
  inference (declared schema wins, deep-copied), timeout bottlenecks,
  planner-failure + planner-prose gaps, parse_execution de-dup/ordering
* SynthesizedToolStore SQLite CRUD + hit accounting (tmp DB)
* ToolSynthesizer alias matching + safe-spec shape
* SynthesizedToolValidator static + probe gating
* SelfEvolutionEngine note_gap log / callback / bounded history, and the
  full observe() -> synthesize -> validate -> persist -> hot-register
  -> reload pipeline (tmp DB, injected register callback)
* Agent._evolution_watch glue: absorbs a hot-loaded tool into its live
  catalog and emits the self_evolution event (real catalog fan-out)

Every store-backed test points at tmp_path, so the repo's
memory/synthesized_tools.db is never touched.

Run: py -m pytest tests/test_self_evolution.py
"""

from ai_agent.core.self_evolution import (
    GAP_EXECUTION_FAILURE,
    GAP_MISSING_TOOL,
    GAP_PLANNER_BLOCK,
    CapabilityGap,
    CapabilityGapDetector,
    SelfEvolutionEngine,
    IsolatedExecutionSandbox,
    SandboxResult,
    SynthesizedToolStore,
    SynthesizedToolValidator,
    ToolSynthesizer,
    build_micro_test_script,
    is_valid_tool_name,
)
from ai_agent.core import main as core_main
from ai_agent.planner import GOAPPlanner
from ai_agent.tools import (
    hot_reload_tool,
    register_live_catalog,
    remove_synthesized_tool,
    synthesized_tool_catalog,
)

DETECTOR = CapabilityGapDetector()
UNKNOWN_TOOL_RESULT = "Unknown tool: b64_encode"


# --------------------------------------------------------------------------
# CapabilityGap record
# --------------------------------------------------------------------------

def test_capability_gap_syncs_canonical_name_and_to_dict():
    gap = CapabilityGap(kind=GAP_MISSING_TOOL, tool_name="b64_encode",
                        detail="executor: ...Unknown tool: b64_encode...",
                        source="executor",
                        required_capability_name="encode_as_base64",
                        input_schema={"type": "object"},
                        expected_output_type="text",
                        functional_description="Base64-encode a string.")
    # canonical name wins; legacy alias stays in sync
    assert gap.required_capability_name == "encode_as_base64"
    assert gap.tool_name == "encode_as_base64"
    assert gap.created_at  # auto-stamped

    d = gap.to_dict()
    assert d["kind"] == GAP_MISSING_TOOL
    assert d["tool_name"] == "encode_as_base64"
    assert d["required_capability_name"] == "encode_as_base64"
    assert d["input_schema"] == {"type": "object"}
    assert d["expected_output_type"] == "text"
    assert d["functional_description"].startswith("Base64-encode")
    assert d["detail"].startswith("executor:")
    assert d["source"] == "executor"
    assert d["created_at"] == gap.created_at
    import json as json_mod
    json_mod.dumps(d)  # must be JSON-safe


def test_capability_gap_legacy_positional_and_defaults():
    gap = CapabilityGap(GAP_EXECUTION_FAILURE, "dns_bruteforce")
    assert gap.kind == GAP_EXECUTION_FAILURE
    assert gap.required_capability_name == "dns_bruteforce"
    assert gap.tool_name == "dns_bruteforce"
    assert gap.input_schema == {}
    assert gap.expected_output_type == "any"
    assert gap.source == "executor"
    assert gap.functional_description == ""
    assert gap.detail == ""


def test_is_valid_tool_name_guards():
    assert is_valid_tool_name("b64_encode")
    assert is_valid_tool_name("hex2dec")
    assert not is_valid_tool_name("not valid")
    assert not is_valid_tool_name("1abc")
    assert not is_valid_tool_name("_private")
    assert not is_valid_tool_name("__dunder__")
    assert not is_valid_tool_name("execute_tool")   # reserved
    assert not is_valid_tool_name("create_tools")   # reserved
    assert not is_valid_tool_name("")               # empty
    assert not is_valid_tool_name(None)             # non-str


# --------------------------------------------------------------------------
# CapabilityGapDetector: executor signals
# --------------------------------------------------------------------------

def test_parse_tool_result_unknown_tool():
    gap = DETECTOR.parse_tool_result(UNKNOWN_TOOL_RESULT)
    assert gap is not None
    assert gap.kind == GAP_MISSING_TOOL
    assert gap.required_capability_name == "b64_encode"
    assert gap.tool_name == "b64_encode"
    assert gap.source == "executor"
    assert "Unknown tool: b64_encode" in gap.detail
    # non-signals
    assert DETECTOR.parse_tool_result("everything worked fine") is None
    assert DETECTOR.parse_tool_result("") is None
    assert DETECTOR.parse_tool_result(None) is None
    assert DETECTOR.parse_tool_result("Unknown tool: execute_tool") is None


def test_detect_missing_tool_helper():
    assert DETECTOR.detect_missing_tool(
        "error: Unknown tool: hex_encode reported") == "hex_encode"
    assert DETECTOR.detect_missing_tool("no tool talk here") is None
    assert DETECTOR.detect_missing_tool(None) is None
    assert DETECTOR.detect_missing_tool(12345) is None


def test_bad_arguments_gap_infers_schema_from_error():
    text = ("Bad arguments for b64_encode: b64_encode() missing 2 required "
            "positional arguments: 'data' and 'salt'")
    gaps = DETECTOR.parse_execution(result=text, args='{"data": "x"}')
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.kind == GAP_EXECUTION_FAILURE
    assert gap.required_capability_name == "b64_encode"
    assert set(gap.input_schema["required"]) == {"data", "salt"}
    assert set(gap.input_schema["properties"]) == {"data", "salt"}
    assert gap.input_schema["properties"]["data"]["type"] == "string"
    assert "missing data, salt" in gap.functional_description


def test_bad_arguments_declared_schema_wins_and_is_copied():
    declared = {"type": "object",
                "properties": {"data": {"type": "string",
                                        "description": "raw input"}},
                "required": ["data"]}
    text = ("Bad arguments for t1: t1() missing 1 required positional "
            "argument: 'salt'")
    gaps = DETECTOR.parse_execution(result=text, args="{}",
                                    parameters=declared)
    assert len(gaps) == 1
    schema = gaps[0].input_schema
    assert schema is not declared
    assert schema["properties"]["data"]["type"] == "string"
    assert schema["properties"]["salt"]["type"] == "string"
    assert schema["required"] == ["data", "salt"]
    # original untouched
    assert declared["required"] == ["data"]
    assert "salt" not in declared["properties"]


def test_timeout_functional_bottleneck():
    text = "[dns_bruteforce timed out after 120s \u2014 killed]"
    gaps = DETECTOR.parse_execution(result=text)
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.kind == GAP_EXECUTION_FAILURE
    assert gap.required_capability_name == "dns_bruteforce"
    assert "120" in gap.functional_description
    assert "timed out" in gap.functional_description
    # the timeout regex is fully anchored: surrounding text or a wrong
    # dash prevents the near-miss from firing
    assert DETECTOR.parse_functional_bottleneck(
        "prefix [we timed out after 120s \u2014 killed]") is None
    assert DETECTOR.parse_functional_bottleneck(
        "[dns_bruteforce timed out after 120s - killed]") is None


def test_infer_input_schema_types_and_safety():
    schema = DETECTOR.infer_input_schema('{"host": "x", "port": 80, '
                                         '"retries": true, "tags": [1]}')
    assert schema["properties"]["host"]["type"] == "string"
    assert schema["properties"]["port"]["type"] == "number"
    assert schema["properties"]["retries"]["type"] == "boolean"
    assert schema["properties"]["tags"]["type"] == "array"
    assert "required" not in schema
    assert DETECTOR.infer_input_schema("") is None
    assert DETECTOR.infer_input_schema("not json") is None
    # python dict inputs work too
    s2 = DETECTOR.infer_input_schema({"a": 1})
    assert s2["properties"]["a"]["type"] == "number"
    # declared schema deep-copied even without extras
    declared = {"type": "object",
                "properties": {"a": {"type": "string"}}, "required": ["a"]}
    s3 = DETECTOR.infer_input_schema('{}', declared)
    assert s3 is not declared and declared["required"] == ["a"]


def test_infer_output_type_classification():
    cases = {"plain text here": "text",
             "": "any",
             None: "any",
             "   ": "any",
             '{"a": 1}': "dict",
             "[1, 2]": "list",
             "42": "number",
             "true": "boolean",
             '"quoted"': "json"}
    for raw, want in cases.items():
        assert DETECTOR.infer_output_type(raw) == want, (raw, want)


# --------------------------------------------------------------------------
# CapabilityGapDetector: planner signals
# --------------------------------------------------------------------------

def test_on_plan_failure_planner_block_gap():
    planner = GOAPPlanner()
    planner.target = "example.com"
    gap = DETECTOR.on_plan_failure(planner=planner,
                                   objective="Enumerate subdomains of example com",
                                   error="no plan")
    assert gap is not None
    assert gap.kind == GAP_PLANNER_BLOCK
    assert gap.source == "planner"
    assert gap.expected_output_type == "plan"
    assert set(gap.input_schema["properties"]) == {"objective", "target"}
    assert gap.input_schema["required"] == ["objective"]
    assert gap.input_schema["properties"]["objective"]["default"] == \
        "Enumerate subdomains of example com"
    assert gap.required_capability_name.startswith("enumerate_")
    assert "no plan" in gap.detail
    # empty objective cannot produce a usable capability name
    g2 = DETECTOR.on_plan_failure(objective="")
    assert g2 is not None and g2.required_capability_name is None


def test_parse_planner_text_prose_gaps():
    text = ("GOAP: to finish this objective we need b64_decode, and then "
            "we will need hex_encode for the next step.")
    gaps = DETECTOR.parse_planner_text(text)
    names = [g.required_capability_name for g in gaps]
    assert "b64_decode" in names and "hex_encode" in names
    for gap in gaps:
        assert gap.kind == GAP_PLANNER_BLOCK
        assert gap.source == "planner"
    # prose that only mentions needing "something" (no snake_case tool
    # adjacent to a trigger verb) produces no gaps
    assert DETECTOR.parse_planner_text(
        "nothing extra is required for this step") == []
    assert DETECTOR.parse_planner_text("") == []
    assert DETECTOR.parse_planner_text(None) == []


def test_parse_execution_combines_signals_and_dedups():
    # same capability signalled twice -> one gap, executor kind first
    planner_text = "GOAP plan: we need b64_encode as step 2"
    gaps = DETECTOR.parse_execution(result=UNKNOWN_TOOL_RESULT,
                                    planner_state=planner_text)
    assert len(gaps) == 1
    assert gaps[0].kind == GAP_MISSING_TOOL
    # distinct capabilities both surface, executor signal ordered first
    gaps = DETECTOR.parse_execution(result=UNKNOWN_TOOL_RESULT,
                                    planner_state="we need rot13 here")
    assert [g.required_capability_name for g in gaps] == \
        ["b64_encode", "rot13"]
    # empty inputs -> no gaps
    assert DETECTOR.parse_execution() == []
    assert DETECTOR.parse_execution(result="clean result") == []


def test_parse_alias_backwards_compatible():
    assert DETECTOR.parse(result=UNKNOWN_TOOL_RESULT)[0].tool_name == \
        "b64_encode"
    gaps = DETECTOR.parse(planner_state="we need reverse_text now")
    assert gaps and gaps[0].required_capability_name == "reverse_text"


# --------------------------------------------------------------------------
# SynthesizedToolStore
# --------------------------------------------------------------------------

def test_store_crud_and_stats(tmp_path):
    db = str(tmp_path / "synth.db")
    spec = {"name": "b64_encode", "rule": "b64_encode",
            "description": "enc", "parameters": {"type": "object"},
            "source": "import base64\n\ndef run(**kw):\n    return 'x'\n",
            "probe": [{"args": {}, "expect": "x"}]}
    with SynthesizedToolStore(db) as store:
        assert store.save(spec) is True
        row = store.get("b64_encode")
        assert row is not None
        assert row["name"] == "b64_encode"
        assert row["rule"] == "b64_encode"
        assert "func" not in row          # never persisted
        assert row["probe"][0]["expect"] == "x"
        assert store.get("nope") is None

        store.increment_hit("b64_encode")
        store.increment_hit("b64_encode")
        stats = store.stats()
        assert stats["count"] == 1
        assert stats["total_hits"] == 2

        assert store.save(spec) is True   # upsert by name
        assert len(store.all()) == 1
        assert store.remove("b64_encode") is True
        assert store.remove("b64_encode") is False
        assert store.get("b64_encode") is None
        assert store.stats()["count"] == 0


# --------------------------------------------------------------------------
# ToolSynthesizer
# --------------------------------------------------------------------------

def test_synthesizer_alias_matching_and_spec_shape():
    synth = ToolSynthesizer()
    assert synth.match_rule("b64_encode")["key"] == "b64_encode"
    # aliases and messy spellings all resolve to the canonical rule
    for alias in ("base64_encode", "b64encode", "B64_ENCODE", "b64 encode"):
        assert synth.match_rule(alias)["key"] == "b64_encode", alias

    spec = synth.synthesize("b64_encode")
    assert set(spec) == {"name", "rule", "description", "parameters",
                         "source", "probe"}
    assert spec["name"] == "b64_encode"
    assert spec["rule"] == "b64_encode"
    assert spec["parameters"]["required"] == ["data"]
    assert spec["probe"][0]["expect"] == "aGVsbG8="
    assert "def run(**kw)" in spec["source"]

    assert synth.synthesize("b64_encode") is not spec  # fresh copy each time
    assert synth.match_rule("no_such_tool_zzz") is None
    assert synth.synthesize("no_such_tool_zzz") is None
    assert synth.synthesize("execute_tool") is None    # reserved
    assert synth.synthesize(None) is None
    assert synth.rules()  # non-empty catalog of dicts


# --------------------------------------------------------------------------
# SynthesizedToolValidator
# --------------------------------------------------------------------------

def test_validator_accepts_rule_source_and_passes_probes():
    synth = ToolSynthesizer()
    spec = synth.synthesize("b64_encode")
    verdict = SynthesizedToolValidator().validate(spec, run_probes=True)
    assert verdict["ok"] is True, verdict["errors"]
    assert verdict["errors"] == []
    assert verdict["probe_failures"] == []
    func = verdict["func"]
    assert callable(func)
    assert func(data="hello") == "aGVsbG8="
    assert func(data="") == ""


def test_validator_rejects_dangerous_and_broken_specs():
    validator = SynthesizedToolValidator()
    synth = ToolSynthesizer()
    good = synth.synthesize("b64_encode")

    # disallowed import
    bad_import = dict(good)
    bad_import["source"] = good["source"].replace(
        "import base64", "import os")
    verdict = validator.validate(bad_import, run_probes=False)
    assert verdict["ok"] is False
    assert any("import" in e for e in verdict["errors"])
    assert verdict["func"] is None

    # call to a forbidden builtin
    bad_call = dict(good)
    bad_call["source"] = "def run(**kw):\n    return eval('1+1')\n"
    verdict = validator.validate(bad_call, run_probes=False)
    assert verdict["ok"] is False
    assert any("eval" in e for e in verdict["errors"])

    # syntax error
    bad_syntax = dict(good)
    bad_syntax["source"] = "def run(**kw):\n  return (1\n"
    verdict = validator.validate(bad_syntax, run_probes=False)
    assert verdict["ok"] is False
    assert any("syntax" in e for e in verdict["errors"])

    # probe expectation mismatch fails only at runtime
    bad_probe = dict(good)
    bad_probe["probe"] = [{"args": {"data": "hello"}, "expect": "WRONG"}]
    verdict = validator.validate(bad_probe, run_probes=True)
    assert verdict["ok"] is False
    assert verdict["probe_failures"]
    assert verdict["probe_failures"][0]["expected"] == "WRONG"

    # empty spec
    verdict = validator.validate({}, run_probes=False)
    assert verdict["ok"] is False
    assert verdict["errors"]


# --------------------------------------------------------------------------
# SelfEvolutionEngine: record-only tier (no store I/O)
# --------------------------------------------------------------------------

def test_engine_note_gap_records_callback_and_history(tmp_path):
    seen = []
    engine = SelfEvolutionEngine(
        store_path=str(tmp_path / "never_opened.db"),
        on_gap=lambda g: seen.append(g.required_capability_name))
    assert engine.store_path == str(tmp_path / "never_opened.db")
    assert engine.stats["gaps_recorded"] == 0

    gap = CapabilityGap(GAP_MISSING_TOOL, "b64_encode")
    assert engine.note_gap(gap) is gap
    assert engine.last_gap is gap
    assert seen == ["b64_encode"]
    assert engine.stats["gaps_recorded"] == 1

    engine.note_gap(CapabilityGap(GAP_PLANNER_BLOCK, "plan_tool"))
    history = engine.gap_history()
    assert len(history) == 2
    assert history[-1]["required_capability_name"] == "plan_tool"
    assert history[-1]["kind"] == GAP_PLANNER_BLOCK

    # non-gap noise is ignored
    assert engine.note_gap("not a gap") is None
    assert engine.note_gap(None) is None
    assert engine.stats["gaps_recorded"] == 2
    engine.close()


def test_engine_gap_log_is_bounded():
    engine = SelfEvolutionEngine(store_path=":memory:")
    for i in range(250):
        engine.note_gap(CapabilityGap(GAP_EXECUTION_FAILURE,
                                      tool_name="tool_%d" % i))
    assert engine.stats["gaps_recorded"] == 250
    assert len(engine.gap_log) <= 200
    # most recent survives
    assert engine.gap_log[-1].tool_name == "tool_249"
    assert engine.gap_history(limit=3)[-1]["tool_name"] == "tool_249"
    engine.close()


def test_engine_swallows_raising_callback():
    def boom(gap):
        raise RuntimeError("callback boom")
    engine = SelfEvolutionEngine(store_path=":memory:", on_gap=boom)
    gap = CapabilityGap(GAP_MISSING_TOOL, "b64_encode")
    assert engine.note_gap(gap) is gap   # recorded despite callback crash
    assert engine.stats["gaps_recorded"] == 1
    engine.close()


# --------------------------------------------------------------------------
# SelfEvolutionEngine: observe() full pipeline
# --------------------------------------------------------------------------

def _make_engine(tmp_path, hot_reload=None):
    return SelfEvolutionEngine(
        store_path=str(tmp_path / "synth.db"),
        hot_reload=hot_reload or (lambda spec: spec["name"]))


def test_engine_observe_synthesize_persist_and_reload(tmp_path):
    registered = []
    engine = _make_engine(tmp_path, hot_reload=lambda spec: (
        registered.append(spec["name"]) or spec["name"]))

    out = engine.observe(result=UNKNOWN_TOOL_RESULT)
    assert out is not None
    assert out["status"] == "synthesized"
    assert out["name"] == "b64_encode"
    assert out["registered"] is True
    assert out["description"] and out["detail"].startswith("rule=")
    assert registered == ["b64_encode"]
    tool = out["tool"]
    assert tool["name"] == "b64_encode"
    assert tool["parameters"]["required"] == ["data"]
    assert engine.stats["synthesized"] == 1
    assert engine.stats["observed"] == 1

    # persisted tool actually runs (rebuilt from source)
    func = engine.validator.validate(
        engine.synthesizer.synthesize("b64_encode"),
        run_probes=False)["func"]
    assert func(data="hello") == "aGVsbG8="

    # identical gap later -> reloaded from the store, hit counted
    out2 = engine.observe(result=UNKNOWN_TOOL_RESULT)
    assert out2["status"] == "reloaded"
    assert out2["registered"] is True
    assert engine.stats["reloaded"] == 1
    assert engine.stats["synthesized"] == 1
    stats = engine._store.stats()
    assert stats["count"] == 1
    assert stats["total_hits"] == 1
    engine.close()


def test_engine_observe_no_signal_and_invalid_name(tmp_path):
    engine = _make_engine(tmp_path)
    # benign text / empty / non-str observations produce no events
    benign = engine.observe(result="everything went fine")
    assert benign is not None and benign["status"] == "no_match"
    assert engine.observe(result=None, planner_state=None) is None
    assert engine.observe(result={"a": 1}) is None
    assert engine.stats["no_match"] == 1

    # reserved names are filtered by the real detector -> no_match, no synth
    out = engine.observe(result="Unknown tool: execute_tool")
    assert out is not None and out["status"] == "no_match"
    assert engine.stats["synthesized"] == 0
    assert engine.stats["reloaded"] == 0

    # ...but the engine still defends invalid names from custom detectors
    class FakeDetector:
        def parse(self, result=None, planner_state=None):
            return [CapabilityGap(GAP_MISSING_TOOL, "execute_tool")]
    engine2 = SelfEvolutionEngine(store_path=str(tmp_path / "s2.db"),
                                  detector=FakeDetector(),
                                  hot_reload=lambda spec: spec["name"])
    out = engine2.observe(result="whatever")
    assert out["status"] == "invalid_name"
    assert out["registered"] is False
    assert engine2.stats["invalid_name"] == 1

    # unknown-but-valid tool name with no rule generator -> no_match
    engine3 = _make_engine(tmp_path)
    out = engine3.observe(result="Unknown tool: totally_unknown_tool_zz")
    assert out is not None and out["status"] == "no_match"
    assert "no rule generator" in out["detail"]
    engine.close()
    engine2.close()
    engine3.close()


def test_engine_observe_unknown_planner_tool_is_no_match(tmp_path):
    """Planner prose naming a tool that has no rule generator reports
    no_match and synthesises nothing."""
    engine = _make_engine(tmp_path)
    out = engine.observe(planner_state="GOAP: we need portscan_quick for step 1")
    assert out is not None and out["status"] == "no_match", out
    assert "no rule generator" in out["detail"]
    assert engine.stats["synthesized"] == 0
    engine.close()


# --------------------------------------------------------------------------
# Agent._evolution_watch glue (real catalog fan-out)
# --------------------------------------------------------------------------

def _stub_agent():
    agent = type("StubAgent", (), {})()
    agent._evolution_enabled = True
    agent._tools_by_name = register_live_catalog({})
    agent._tool_list = []
    agent.messages = []
    absorb = core_main.Agent._absorb_synthesized_tool.__get__(agent,
                                                              type(agent))
    agent._absorb_synthesized_tool = absorb
    return agent


def test_agent_evolution_watch_absorbs_hot_loaded_tool(tmp_path, monkeypatch):
    remove_synthesized_tool("b64_encode")  # clean slate
    try:
        assert "b64_encode" not in synthesized_tool_catalog()
        engine = SelfEvolutionEngine(
            store_path=str(tmp_path / "synth.db"),
            hot_reload=hot_reload_tool)
        monkeypatch.setattr(core_main, "_evolution_engine", engine)
        monkeypatch.setattr(core_main, "_evolution_detector",
                            CapabilityGapDetector())
        agent = _stub_agent()
        watch = core_main.Agent._evolution_watch.__get__(agent,
                                                         type(agent))

        # capability gap -> tool synthesised + absorbed into live catalog
        event = watch(result=UNKNOWN_TOOL_RESULT)
        assert event is not None
        assert event["type"] == "self_evolution"
        assert event["status"] == "synthesized"
        assert event["name"] == "b64_encode"
        # schema is the OpenAI-style Tool.schema(): nested under "function"
        assert event["schema"]["type"] == "function"
        fn_schema = event["schema"]["function"]
        assert fn_schema["name"] == "b64_encode"
        assert fn_schema["parameters"]["required"] == ["data"]
        assert "b64_encode" in agent._tools_by_name
        assert any(t.name == "b64_encode" for t in agent._tool_list)
        assert "b64_encode" in synthesized_tool_catalog()
        assert agent.messages
        assert "[SELF-EVOLUTION]" in agent.messages[-1]["content"]
        assert "b64_encode" in agent.messages[-1]["content"]

        # duplicate gap while already live -> dedupe, no second event
        assert watch(result=UNKNOWN_TOOL_RESULT) is None

        # benign tool output -> no event
        assert watch(result="success: all checks passed") is None

        # disabled agents never observe anything
        agent._evolution_enabled = False
        assert watch(result=UNKNOWN_TOOL_RESULT) is None
    finally:
        remove_synthesized_tool("b64_encode")
# --------------------------------------------------------------------------
# PHASE 2: code-model synthesis tier + isolated sandbox micro unit tests
# --------------------------------------------------------------------------

_CODE_MODEL_SOURCE = (
    "def run(**kw):\n"
    "    text = str(kw.get(\"text\", \"\"))\n"
    "    return text.lower()\n"
)
_CODE_MODEL_PROBE = [{"args": {"text": "HELLO"}, "expect": "hello"}]


def _fake_code_model(gap, source=_CODE_MODEL_SOURCE,
                     probe=_CODE_MODEL_PROBE):
    def model(record):
        assert record.tool_name == gap.tool_name
        spec = {
            "name": record.tool_name,
            "description": "Code-model generated: %s" % record.detail,
            "source": source,
            "parameters": {"type": "object",
                           "properties": {"text": {"type": "string"}},
                           "required": ["text"]},
        }
        if probe is not None:
            spec["probe"] = probe
        return spec
    return model


def _unmatched_gap(name="lowercase_text", detail="planner asked for it"):
    return CapabilityGap(kind=GAP_MISSING_TOOL, tool_name=name,
                         detail=detail)


def test_synthesizer_code_model_generates_spec_from_gap():
    gap = _unmatched_gap()
    synth = ToolSynthesizer(code_model=_fake_code_model(gap))
    spec = synth.synthesize("lowercase_text", gap=gap)
    assert spec is not None
    assert set(spec) == {"name", "rule", "description", "parameters",
                         "source", "probe"}
    assert spec["rule"] == "code-model"
    assert spec["name"] == "lowercase_text"
    assert "def run(**kw)" in spec["source"]
    assert spec["probe"][0]["expect"] == "hello"
    # rule path still wins when a declarative rule matches
    assert synth.synthesize("b64_encode")["rule"] == "b64_encode"


def test_synthesizer_code_model_not_called_without_gap():
    def boom(gap):
        raise AssertionError("code_model must not run without a gap")
    synth = ToolSynthesizer(code_model=boom)
    assert synth.synthesize("some_unknown_tool_qq") is None
    assert synth.synthesize(None) is None


def test_synthesizer_handles_bad_model_outputs():
    gap = _unmatched_gap()
    # raises -> None
    def raise_model(record):
        raise RuntimeError("boom")
    assert ToolSynthesizer(code_model=raise_model).synthesize(
        "lowercase_text", gap=gap) is None
    # returns None / garbage / empty source -> None
    assert ToolSynthesizer(code_model=lambda g: None).synthesize(
        "lowercase_text", gap=gap) is None
    assert ToolSynthesizer(code_model=lambda g: 42).synthesize(
        "lowercase_text", gap=gap) is None
    assert ToolSynthesizer(code_model=lambda g: {"source": ""}).synthesize(
        "lowercase_text", gap=gap) is None


def test_code_model_spec_without_micro_tests_fails_closed():
    gap = _unmatched_gap()
    synth = ToolSynthesizer(code_model=_fake_code_model(gap, probe=None))
    spec = synth.synthesize("lowercase_text", gap=gap)
    assert spec is not None and spec["rule"] == "code-model"
    assert spec["probe"] == []
    # even without a sandbox the gate refuses untested generated code
    verdict = SynthesizedToolValidator().validate(spec, run_probes=True)
    assert verdict["ok"] is False
    assert any("micro unit tests" in e for e in verdict["errors"])
    # the sandboxed path refuses it as well
    verdict = SynthesizedToolValidator(
        sandbox=IsolatedExecutionSandbox()).validate(spec, run_probes=True)
    assert verdict["ok"] is False


def test_build_micro_test_script_is_self_contained():
    script = build_micro_test_script()
    assert isinstance(script, str)
    assert "def main()" in script
    assert "json.load(sys.stdin)" in script
    assert "json.dump" in script


def test_sandbox_runs_probes_and_reports_failures():
    sandbox = IsolatedExecutionSandbox()
    spec = ToolSynthesizer().synthesize("b64_encode")
    result = sandbox.run(spec)
    assert isinstance(result, SandboxResult)
    assert result.ok is True, result.error
    assert result.returncode == 0
    assert result.probe_failures == []

    broken = dict(spec)
    broken["probe"] = [{"args": {"data": "hello"}, "expect": "WRONG"}]
    result = sandbox.run(broken)
    assert result.ok is False
    assert result.probe_failures
    assert result.probe_failures[0]["expected"] == "WRONG"


def test_sandbox_times_out_and_kills_runaway_tool():
    sandbox = IsolatedExecutionSandbox()
    spec = {
        "name": "endless",
        "description": "never returns",
        "parameters": {"type": "object", "properties": {}, "required": []},
        "source": "def run(**kw):\n    while True:\n        pass\n",
        "probe": [{"args": {}, "expect": None}],
    }
    result = sandbox.run(spec, timeout=2)
    assert result.ok is False
    assert result.timed_out is True
    assert "exceeded" in result.error


def test_validator_with_sandbox_never_hangs_the_engine():
    validator = SynthesizedToolValidator(
        sandbox=IsolatedExecutionSandbox(timeout=2))
    spec = {
        "name": "endless",
        "description": "never returns",
        "parameters": {"type": "object", "properties": {}, "required": []},
        # AST-clean (no forbidden imports/calls) but behaviourally stuck
        "source": "def run(**kw):\n    while True:\n        pass\n",
        "probe": [{"args": {}, "expect": None}],
    }
    verdict = validator.validate(spec, run_probes=True)
    assert verdict["ok"] is False
    assert any("sandbox" in e.lower() for e in verdict["errors"])


def test_validator_sandbox_mode_still_accepts_good_tool():
    validator = SynthesizedToolValidator(sandbox=IsolatedExecutionSandbox())
    spec = ToolSynthesizer().synthesize("b64_encode")
    verdict = validator.validate(spec, run_probes=True)
    assert verdict["ok"] is True, verdict["errors"]
    assert verdict["probe_failures"] == []


def test_engine_code_model_synthesizes_persists_and_registers(tmp_path):
    gap = _unmatched_gap(detail="planner needs a lowercase helper")
    registered = []
    engine = SelfEvolutionEngine(
        store_path=str(tmp_path / "gen.db"),
        hot_reload=lambda spec: registered.append(spec["name"]) or spec["name"],
        synthesizer=ToolSynthesizer(code_model=_fake_code_model(gap)))
    with engine:
        response = engine.observe(result="Unknown tool: lowercase_text")
        assert response is not None
        assert response["status"] == "synthesized", response["detail"]
        assert response["tool"]["rule"] == "code-model"
        assert registered == ["lowercase_text"]
        stored = engine._ensure_store().get("lowercase_text")
        assert stored is not None and stored["rule"] == "code-model"

        # second observation reloads from the persistent store
        response = engine.observe(result="Unknown tool: lowercase_text")
        assert response["status"] == "reloaded"
        assert registered == ["lowercase_text", "lowercase_text"]


def test_engine_rejects_generated_tool_without_micro_tests(tmp_path):
    gap = _unmatched_gap()
    engine = SelfEvolutionEngine(
        store_path=str(tmp_path / "gen.db"),
        hot_reload=lambda spec: spec["name"],
        synthesizer=ToolSynthesizer(
            code_model=_fake_code_model(gap, probe=None)))
    with engine:
        response = engine.observe(result="Unknown tool: lowercase_text")
        assert response["status"] == "rejected"
        assert "micro unit tests" in response["detail"]
        assert engine.stats["rejected"] == 1
        assert engine._ensure_store().get("lowercase_text") is None
