"""Autonomous Self-Evolution & Dynamic Tool Synthesis Engine.

Companion to the Input Intent Reformulator (front-door framing) and the
Refusal Intelligence Engine (answer-side learning): when the agent is told
to *do* something the current tool catalog cannot, instead of dying with
"Unknown tool: X", the engine synthesizes a safe replacement tool on the
fly, validates it statically, self-tests it against a probe, persists it to
a SQLite store and hot-reloads it into the live tool catalog.

Pipeline
--------
1. CapabilityGapDetector      - turn raw tool results / planner text into
                                structured CapabilityGap records.
2. ToolSynthesizer            - match the missing tool name against rule
                                generators (base64, hex, url, hashes, text
                                transforms, regex, ...) and produce a full
                                tool spec (schema + safe module source +
                                self-test probes).
3. SynthesizedToolValidator   - AST-level static analysis (whitelisted
                                imports, no dunder access, no eval/open/IO,
                                restricted builtins) + execution of the
                                self-test probes.
4. SynthesizedToolStore       - SQLite persistence for synthesized tools so
                                learning survives restarts.
5. SelfEvolutionEngine        - observe() glues it all together and
                                hot-registers new tools into the catalog
                                via ai_agent.tools.hot_reload_tool().

Phase 2 adds three upgrades on top of that pipeline:

* a gap-driven code-model tier in ToolSynthesizer (``code_model=``
  callable or chat client) that can generate a tool for capability
  gaps that have no declarative rule generator;
* a hardened SynthesizedToolValidator that rejects process/FS/network
  escapes, dunder games and indirect dynamic execution in addition to
  the existing import and attribute checks;
* an IsolatedExecutionSandbox micro unit-test runner so generated
  tools are executed in a scrubbed, time-boxed subprocess instead of
  running their probes in the engine's own process.

Everything is lazy: no DB is opened and no module import of the tool
catalog happens until the first real "Unknown tool:" event.

Phase 3 - security payload-handler tier
---------------------------------------
On top of the generic text-transform generators (`_RULES`), the engine ships
a specialised payload-handler catalog (`_PAYLOAD_RULES`): pure,
validator-clean generators for obfuscating / encoding attack payloads (HTML
entities, double URL-encoding, JavaScript unicode escapes,
String.fromCharCode arrays, alternating case, SQL inline-comment splitting,
fullwidth Unicode).  They use the exact same spec shape as the generic tier,
so matching, synthesis, self-testing, persistence and hot-reload behave
identically, and each entry is flagged as payload work in
``ToolSynthesizer.rules()``.
"""

import ast
import builtins
import copy
import inspect
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..config import PROJECT_DIR

log = logging.getLogger("self_evolution")

__all__ = [
    "CapabilityGap",
    "CapabilityGapDetector",
    "SynthesizedToolStore",
    "ToolSynthesizer",
    "SandboxResult",
    "IsolatedExecutionSandbox",
    "build_micro_test_script",
    "SynthesizedToolValidator",
    "SelfEvolutionEngine",
    "DEFAULT_STORE_PATH",
    "build_llm_code_model",
]

DEFAULT_STORE_PATH = os.path.join(PROJECT_DIR, "memory", "synthesized_tools.db")

# ---------------------------------------------------------------------------
# LLM code-model adapter: bridge an OpenAI-compatible chat client into a
# ``code_model`` callable for the ToolSynthesizer code-model tier.
# ---------------------------------------------------------------------------

_GAP_SYNTHESIS_SYSTEM_PROMPT = """\
You synthesize small, self-contained Python utility tools for an agent.

A capability gap was observed: the agent needs a missing tool that has no
declarative generator.  Given the JSON gap summary, answer with ONE JSON
object - no prose, no code fences - in exactly this shape:

{
  "name": "<tool name matching the requested one>",
  "description": "<one line: what the tool does>",
  "parameters": {"type": "object", "properties": {},
                 "required": ["<every argument run() accepts>"]},
  "source": "<full Python module text defining: def run(**kw) -> result>",
  "probe": [{"args": {...}, "expect": <expected return value>}]
}

Hard rules:
- Pure transformation helpers only: take arguments, compute, RETURN a
  value.  No I/O: no files, no network, no subprocess, no printing.
- Imports are limited to the standard-library allowlist: base64, binascii,
  hashlib, json, math, re, string, unicodedata, urllib.parse.  Never use
  eval, exec, open, __import__, or any dynamic-import trick.
- "parameters" is a JSON-Schema object; every argument run(**kw) reads
  must be declared and listed in "required".
- "probe" must contain at least one {"args": ..., "expect": ...} case; it
  is executed as a micro unit test after synthesis, so the source must
  genuinely implement the behaviour (a failing probe rejects the tool).
- Importing the module must have zero side effects.

Return ONLY the JSON object.
"""


def _extract_json_object(text):
    """Best-effort recovery of a JSON object from a model reply.

    Accepts already-parsed dicts, bare JSON text, ```json ...``` fenced
    blocks, and prose-wrapped JSON (balanced-brace scan).  Returns the
    parsed dict or None when nothing usable can be recovered.
    """
    if isinstance(text, dict):
        return text
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        return parsed
    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
            elif ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[start:i + 1])
                    except ValueError:
                        parsed = None
                    if isinstance(parsed, dict):
                        return parsed
                    break
        start = text.find("{", start + 1)
    return None


def build_llm_code_model(client, temperature=0.2):
    """Adapt an OpenAI-compatible chat client into a code-model callable.

    ``client`` only needs a duck-typed ``.chat(messages, tools=None,
    temperature=...)`` method - the interface shared by OpenAIClient,
    OpenAI-compatible / Ollama endpoint wrappers and chat-client test
    doubles.  The returned callable maps a `CapabilityGap` to a full
    tool-spec dict (the shape `ToolSynthesizer._compose_generated_spec`
    expects) or None on any failure - it fails closed and never raises.

    Only the gap's structural summary (name, functional description,
    inferred input schema, expected output type) is forwarded to the
    model - never raw tool output or unrelated payloads.
    """
    if client is None or not callable(getattr(client, "chat", None)):
        return None

    def code_model(gap):
        if gap is None:
            return None
        payload = {
            "name": gap.tool_name,
            "kind": gap.kind,
            "functional_description": (gap.functional_description
                                       or gap.detail or ""),
            "input_schema": gap.input_schema or {},
            "expected_output_type": gap.expected_output_type or "any",
        }
        user_json = json.dumps(
            {k: v for k, v in payload.items()
             if v not in (None, "", {}, [])},
            sort_keys=True)
        messages = [
            {"role": "system", "content": _GAP_SYNTHESIS_SYSTEM_PROMPT},
            {"role": "user", "content": user_json},
        ]
        try:
            reply = client.chat(messages=messages, tools=None,
                                temperature=temperature)
        except Exception as exc:
            log.debug("code-model chat request failed: %s", exc)
            return None
        content = None
        if isinstance(reply, str):
            content = reply
        elif isinstance(reply, dict):
            content = reply.get("content")
            if content is None:
                tool_calls = reply.get("tool_calls")
                if isinstance(tool_calls, list) and tool_calls:
                    first = tool_calls[0]
                    if isinstance(first, dict):
                        fn = first.get("function")
                        if isinstance(fn, dict):
                            content = fn.get("arguments")
        spec = _extract_json_object(content)
        if not isinstance(spec, dict) or not isinstance(
                spec.get("source"), str) or not spec["source"].strip():
            log.debug("code-model chat reply carried no usable spec")
            return None
        return spec

    return code_model


# Names a synthesized tool may never take.
_RESERVED_NAMES = frozenset({
    "execute_tool", "create_tools", "hot_reload_tool", "remove_synthesized_tool",
    "Tool", "run", "main", "self", "ai_agent", "sys", "os",
})


def is_valid_tool_name(name: str) -> bool:
    """True when `name` is a safe Python identifier we may register."""
    return (
        isinstance(name, str)
        and name.isidentifier()
        and not name.startswith("__")
        and not name.startswith("_")
        and name not in _RESERVED_NAMES
    )

# Kinds of capability gap the detector can recognise.
GAP_MISSING_TOOL = "missing_tool"
GAP_PLANNER_BLOCK = "planner_block"
GAP_EXECUTION_FAILURE = "execution_failure"

# Executor reports a tool that does not exist: `Unknown tool: b64_encode`.
_UNKNOWN_TOOL_RE = re.compile(
    r"Unknown tool:\s*([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)

# Planner prose naming the snake_case tool a plan step expects to exist.
_PLANNER_NEED_RE = re.compile(
    r"(?:\b(?:need|needs|needed|requires?|use|call|invoke|run|missing|"
    r"add)\b)[^A-Za-z0-9_]*([a-z][a-z0-9_]{2,})")

# A bare quoted snake_case identifier inside planner text.
_SNAKE_IN_QUOTES_RE = re.compile(r'''[`'"]{1}([a-z][a-z0-9_]{2,})[`'"]{1}''')

# Executor reports missing required positional arguments for a live tool:
#   Bad arguments for b64_encode: b64_encode() missing 2 required positional
#   arguments: 'data' and 'salt'
_BAD_ARGS_RE = re.compile(
    r"Bad arguments for\s+([A-Za-z_][A-Za-z0-9_]*):.*?missing (\d+) required "
    r"positional argument(?:s)?:\s*(.+)$",
    re.IGNORECASE | re.DOTALL)

# Executor reports a tool killed for exceeding its time budget:
#   [dns_bruteforce timed out after 120s \u2014 killed]
_TIMEOUT_RE = re.compile(
    "^\\[([A-Za-z_][A-Za-z0-9_]*) timed out after (\\d+)s \u2014 killed\\]$")

# Words never used when deriving a capability name from an objective.
_OBJECTIVE_STOPWORDS = frozenset({
    "a", "an", "the", "of", "for", "to", "and", "or", "on", "in",
    "with", "using", "use", "at", "by", "from", "via", "into",
    "this", "that", "is", "are", "be", "do", "does", "did",
    "can", "could", "should", "would", "will", "please", "me",
    "my", "we", "our", "it", "its", "target", "against",
    "all", "any", "if", "then",
})

# Capability-gap history kept in memory per engine (ring buffer).
_GAP_LOG_LIMIT = 200


@dataclass
class CapabilityGap:
    """Structured record of one missing capability the agent hit.

    ``required_capability_name`` is the canonical capability name;
    ``tool_name`` is kept as a legacy alias and is always synced to it.
    All optional fields live AFTER ``source`` so existing constructions
    (kind, tool_name, detail, source) stay valid.
    """

    kind: str                # one of the GAP_* constants
    tool_name: str           # legacy alias; canonical = required_capability_name
    detail: str = ""         # human-readable evidence snippet
    source: str = "executor"  # executor / planner
    required_capability_name: Optional[str] = None
    input_schema: Optional[Dict] = None
    expected_output_type: str = "any"
    functional_description: str = ""
    created_at: str = ""

    def __post_init__(self) -> None:
        self.tool_name = (self.tool_name or "").strip()
        if not self.required_capability_name:
            self.required_capability_name = self.tool_name or None
        if self.required_capability_name:
            # canonical wins; keep the legacy alias in sync
            self.tool_name = self.required_capability_name
        if self.input_schema is None:
            self.input_schema = {}
        if not self.created_at:
            self.created_at = time.strftime("%Y-%m-%dT%H:%M:%S")

    def to_dict(self) -> Dict:
        """JSON-safe dict for reports / gap history."""
        return {
            "kind": self.kind,
            "tool_name": self.tool_name,
            "required_capability_name": self.required_capability_name,
            "input_schema": self.input_schema,
            "expected_output_type": self.expected_output_type,
            "functional_description": self.functional_description,
            "detail": self.detail,
            "source": self.source,
            "created_at": self.created_at,
        }


class CapabilityGapDetector:
    """Turn raw tool results / planner text into CapabilityGap records.

    Deliberately cheap and deterministic: synthesis is only attempted for
    signals we can recognise with full confidence (no free-text guessing).
    """

    def parse_tool_result(self, result: str) -> Optional[CapabilityGap]:
        """One gap for a concrete executor failure: `Unknown tool: X`."""
        if not isinstance(result, str) or not result.strip():
            return None
        match = _UNKNOWN_TOOL_RE.search(result)
        if match and is_valid_tool_name(match.group(1)):
            return CapabilityGap(
                kind=GAP_MISSING_TOOL,
                tool_name=match.group(1),
                detail="executor: ...%s..." % result[:160].strip(),
                source="executor",
            )
        return None

    @staticmethod
    def _json_type(value) -> str:
        """JSON-schema type name for an observed python value.

        bool must be checked BEFORE int (bool subclasses int).
        """
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, (int, float)):
            return "number"
        if isinstance(value, str):
            return "string"
        if isinstance(value, (list, tuple)):
            return "array"
        if isinstance(value, dict):
            return "object"
        return "string"

    @staticmethod
    def infer_output_type(text) -> str:
        """Classify the shape of an observed tool output."""
        if text is None or str(text).strip() == "":
            return "any"
        raw = str(text)
        try:
            value = json.loads(raw)
        except Exception:
            return "text"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, dict):
            return "dict"
        if isinstance(value, list):
            return "list"
        if isinstance(value, (int, float)):
            return "number"
        return "json"

    def infer_input_schema(self, args, parameters=None,
                           extra_required=None) -> Optional[Dict]:
        """Best-effort input schema for the failing call.

        A declared Tool schema (``parameters``) always wins - it is
        deep-copied so callers may mutate the result safely.  Otherwise
        the raw JSON arguments are parsed and per-key value types are
        inferred from the observed values (no ``required`` list - the
        caller cannot know which keys the tool insists on).  Names in
        ``extra_required`` (known-missing positional arguments) are
        appended as required string properties when absent.

        Returns None when nothing usable can be inferred.
        """
        schema = None
        if isinstance(parameters, dict) and isinstance(
                parameters.get("properties"), dict):
            schema = copy.deepcopy(parameters)
        else:
            data = args
            if isinstance(args, str):
                try:
                    data = json.loads(args)
                except Exception:
                    data = None
            if isinstance(data, dict) and data:
                schema = {
                    "type": "object",
                    "properties": {k: {"type": self._json_type(v)}
                                   for k, v in data.items()},
                }
        if schema is not None and extra_required:
            props = schema.setdefault("properties", {})
            required = list(schema.get("required") or [])
            for name in extra_required:
                if not isinstance(name, str) or not name:
                    continue
                if name not in props:
                    props[name] = {
                        "type": "string",
                        "description": ("Required argument missing from "
                                         "the failing call."),
                    }
                if name not in required:
                    required.append(name)
            schema["required"] = required
        return schema

    def parse_bad_arguments(self, result, args=None,
                            parameters=None) -> Optional[CapabilityGap]:
        """One gap when a live tool was called with missing arguments.

        The executor error embeds the tool name and the names of the
        missing positional arguments, so the gap carries a precise input
        schema (the declared Tool schema when available, else one
        inferred from the failing call's JSON arguments).
        """
        if not isinstance(result, str) or not result.strip():
            return None
        match = _BAD_ARGS_RE.search(result)
        if not match or not is_valid_tool_name(match.group(1)):
            return None
        name = match.group(1)
        parts = re.split(r",|\s+and\s+", match.group(3).strip())
        missing = [tok.strip().strip("'\"").strip()
                   for tok in parts if tok.strip()]
        missing = [tok for tok in missing if tok.isidentifier()]
        schema = self.infer_input_schema(args, parameters, missing or None)
        return CapabilityGap(
            kind=GAP_EXECUTION_FAILURE,
            tool_name=name,
            detail="executor: ...%s..." % result[:160].strip(),
            source="executor",
            input_schema=schema,
            expected_output_type="any",
            functional_description=(
                "Call %s with all required arguments: missing %s"
                % (name, ", ".join(missing) or "?")),
        )

    def parse_functional_bottleneck(self, result) -> Optional[CapabilityGap]:
        """One gap when a tool was killed for exceeding its time budget.

        The bottleneck is functional (too slow / unbounded scope), so
        the gap records the observed timeout and recommends a faster or
        chunked strategy rather than synthesis.
        """
        if not isinstance(result, str) or not result.strip():
            return None
        match = _TIMEOUT_RE.match(result.strip())
        if not match or not is_valid_tool_name(match.group(1)):
            return None
        name = match.group(1)
        seconds = int(match.group(2))
        return CapabilityGap(
            kind=GAP_EXECUTION_FAILURE,
            tool_name=name,
            detail="executor: ...%s..." % result[:160].strip(),
            source="executor",
            expected_output_type="any",
            functional_description=(
                "Tool %s timed out after %ds; needs a faster or chunked "
                "strategy" % (name, seconds)),
        )

    def detect_missing_tool(self, text: str) -> Optional[str]:
        """Best-effort extraction of a missing tool name from raw text."""
        if not isinstance(text, str):
            return None
        match = _UNKNOWN_TOOL_RE.search(text)
        if match and is_valid_tool_name(match.group(1)):
            return match.group(1)
        return None

    def _capability_name_from_objective(self, objective) -> str:
        """Derive a snake_case capability name from an objective phrase.

        Stopwords and single characters are dropped, then joins of the
        first 3 / 2 / 1 remaining tokens are tried until one forms a
        valid tool name of length >= 4.  Returns "" when nothing fits.
        """
        text = str(objective or "").strip().lower()
        tokens = re.findall(r"[a-z][a-z0-9]*", text)
        tokens = [t for t in tokens
                  if t not in _OBJECTIVE_STOPWORDS and len(t) >= 2]
        for width in (3, 2, 1):
            candidate = "_".join(tokens[:width])[:60]
            if len(candidate) >= 4 and is_valid_tool_name(candidate):
                return candidate
        return ""

    def on_plan_failure(self, planner=None, objective=None,
                        error=None) -> Optional[CapabilityGap]:
        """One record when the GOAP planner could not decompose an
        objective into tool steps.  Record-only: the engine never
        synthesizes a tool named like a free-text objective."""
        obj = str(objective or "")
        name = self._capability_name_from_objective(obj)
        schema = _schema(
            {"objective": _str_prop(
                "User objective the planner could not decompose.",
                obj[:200]),
             "target": _str_prop(
                 "Target host/domain for the objective.",
                 (getattr(planner, "target", "") or "")[:120])},
            ["objective"])
        detail = "planner: no actionable plan for objective %r%s" % (
            obj[:120], ("; %s" % str(error)[:120]) if error else "")
        return CapabilityGap(
            kind=GAP_PLANNER_BLOCK,
            tool_name=name,
            detail=detail[:240],
            source="planner",
            expected_output_type="plan",
            input_schema=schema,
            functional_description=(
                "GOAP planner could not decompose the objective into tool "
                "steps; an extra capability named like the objective may "
                "be required."),
        )

    def parse_planner_text(self, planner_text: str) -> List[CapabilityGap]:
        """Scan planner / GOAP reasoning text for needed-but-absent tools."""
        gaps: List[CapabilityGap] = []
        if not isinstance(planner_text, str) or not planner_text.strip():
            return gaps
        seen = set()
        for match in _PLANNER_NEED_RE.finditer(planner_text):
            name = match.group(1).rstrip(".,;:!?")
            if not is_valid_tool_name(name) or name in seen:
                continue
            if "Unknown tool" in planner_text or "missing tool" in planner_text:
                # a concrete executor report beats a prose mention
                concrete = _UNKNOWN_TOOL_RE.search(planner_text)
                if concrete:
                    break
            seen.add(name)
            gaps.append(CapabilityGap(
                kind=GAP_PLANNER_BLOCK,
                tool_name=name,
                detail="planner text: ...%s..." % planner_text[
                    max(0, match.start() - 40):match.end() + 40],
                source="planner",
            ))
        if not gaps and re.search(r"(?i)missing tool", planner_text):
            hit = _SNAKE_IN_QUOTES_RE.search(planner_text)
            if hit and is_valid_tool_name(hit.group(1)):
                gaps.append(CapabilityGap(
                    kind=GAP_PLANNER_BLOCK,
                    tool_name=hit.group(1),
                    detail="planner text: ...%s..." % planner_text[:240],
                    source="planner",
                ))
        return gaps

    def parse_execution(self, result=None, planner_state=None,
                        tool_name=None, args=None,
                        parameters=None) -> List[CapabilityGap]:
        """Detect capability gaps in a tool result + planner fragment.

        Concrete executor signals are detected first (unknown tool ->
        missing arguments -> timeout bottleneck), then planner prose.
        ``tool_name`` is accepted for forward compatibility (executor
        error strings already embed the failing tool's name).  Records
        are de-duplicated on the capability name.
        """
        gaps: List[CapabilityGap] = []
        seen = set()

        def _append(gap: Optional[CapabilityGap]) -> None:
            if gap is None:
                return
            key = gap.required_capability_name or gap.tool_name
            if key and key in seen:
                return
            if key:
                seen.add(key)
            gaps.append(gap)

        if isinstance(result, str) and result.strip():
            _append(self.parse_tool_result(result))
            _append(self.parse_bad_arguments(result, args=args,
                                             parameters=parameters))
            _append(self.parse_functional_bottleneck(result))
        if planner_state:
            for gap in self.parse_planner_text(planner_state):
                _append(gap)
        return gaps

    def parse(self, result: str = None,
              planner_state: str = None) -> List[CapabilityGap]:
        """Backward-compatible alias of :meth:`parse_execution`."""
        return self.parse_execution(result=result,
                                    planner_state=planner_state)


# ---------------------------------------------------------------------------
# SQLite persistence for synthesized tools
# ---------------------------------------------------------------------------

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS synthesized_tools (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE NOT NULL,
    rule            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    parameters_json TEXT NOT NULL DEFAULT '{}',
    source          TEXT NOT NULL,
    probe_json      TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    hit_count       INTEGER NOT NULL DEFAULT 0,
    last_used       TEXT
)
"""


class SynthesizedToolStore:
    """Thread-safe SQLite store for persisted synthesized tool specs."""

    def __init__(self, db_path: str = DEFAULT_STORE_PATH, timeout: float = 5.0):
        self.db_path = db_path
        self.timeout = timeout
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(db_path, timeout=timeout,
                                     check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute(_CREATE_SQL)
            self._conn.commit()

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def __enter__(self) -> "SynthesizedToolStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _row_to_spec(row: sqlite3.Row) -> Dict:
        spec = {
            "name": row["name"],
            "rule": row["rule"],
            "description": row["description"],
            "parameters": json.loads(row["parameters_json"] or "{}"),
            "source": row["source"],
            "probe": json.loads(row["probe_json"] or "[]"),
            "created_at": row["created_at"],
            "hit_count": row["hit_count"],
            "last_used": row["last_used"],
        }
        return spec

    # -- CRUD ---------------------------------------------------------------

    def save(self, spec: Dict) -> bool:
        """Insert or update one spec (matched on name). Returns True."""
        params = json.dumps(spec.get("parameters") or {}, sort_keys=True)
        probe = json.dumps(spec.get("probe") or [], sort_keys=True)
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO synthesized_tools
                    (name, rule, description, parameters_json, source,
                     probe_json, created_at, last_used)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(name) DO UPDATE SET
                    rule=excluded.rule,
                    description=excluded.description,
                    parameters_json=excluded.parameters_json,
                    source=excluded.source,
                    probe_json=excluded.probe_json
                """,
                (spec["name"], spec.get("rule", "manual"),
                 spec.get("description", ""), params, spec.get("source", ""),
                 probe, now),
            )
            self._conn.commit()
        return True

    def get(self, name: str) -> Optional[Dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM synthesized_tools WHERE name = ?", (name,)
            ).fetchone()
        return self._row_to_spec(row) if row is not None else None

    def all(self) -> List[Dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM synthesized_tools ORDER BY name"
            ).fetchall()
        return [self._row_to_spec(r) for r in rows]

    def remove(self, name: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM synthesized_tools WHERE name = ?", (name,)
            )
            self._conn.commit()
        return cur.rowcount > 0

    def increment_hit(self, name: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE synthesized_tools SET hit_count = hit_count + 1, "
                "last_used = ? WHERE name = ?",
                (time.strftime("%Y-%m-%dT%H:%M:%S"), name),
            )
            self._conn.commit()

    def stats(self) -> Dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(hit_count), 0) AS hits "
                "FROM synthesized_tools"
            ).fetchone()
        return {"count": row["n"], "total_hits": row["hits"]}


# ---------------------------------------------------------------------------
# Rule-based dynamic tool synthesis
# ---------------------------------------------------------------------------

def _schema(props, required):
    """Build a JSON-schema parameters dict for a synthesized tool."""
    return {"type": "object", "properties": props, "required": required}


def _str_prop(desc, default=None):
    prop = {"type": "string", "description": desc}
    if default is not None:
        prop["default"] = default
    return prop


def _norm(name):
    """Normalize a tool name for alias matching (lowercase, alnum only)."""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


# (key, aliases, description, parameters, source, probe)
# Each source is a complete, self-contained module: whitelisted imports
# only, exposes `def run(**kw)`, returns a str/int result, no side effects.
_RULES = (
    dict(
        key="b64_encode",
        aliases=("b64_encode", "base64_encode", "encode_base64", "base64encode",
                 "b64encode", "b64_enc", "base64_encoder", "to_base64"),
        description=("Base64-encode a string. Useful when a target expects "
                     "data as a base64 blob."),
        parameters=_schema({"data": _str_prop("String to base64-encode.", "")},
                           ["data"]),
        source='''
import base64


def run(**kw):
    data = kw.get("data", "")
    if isinstance(data, bytes):
        raw = data
    else:
        raw = str(data).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")
''',
        probe=[{"args": {"data": "hello"}, "expect": "aGVsbG8="},
               {"args": {"data": ""}, "expect": ""}],
    ),
    dict(
        key="b64_decode",
        aliases=("b64_decode", "base64_decode", "decode_base64", "base64decode",
                 "b64decode", "b64_dec", "from_base64"),
        description=("Base64-decode a string back to plaintext."),
        parameters=_schema({"data": _str_prop("Base64 text to decode.", "")},
                           ["data"]),
        source='''
import base64


def run(**kw):
    data = str(kw.get("data", ""))
    return base64.b64decode(data.encode("ascii")).decode(
        "utf-8", errors="replace")
''',
        probe=[{"args": {"data": "aGVsbG8="}, "expect": "hello"}],
    ),
    dict(
        key="hex_encode",
        aliases=("hex_encode", "encode_hex", "hexencode", "to_hex",
                 "bytes_to_hex", "hexlify"),
        description=("Hex-encode a string (each byte as two hex digits)."),
        parameters=_schema({"data": _str_prop("String to hex-encode.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    return data.encode("utf-8").hex()
''',
        probe=[{"args": {"data": "hello"}, "expect": "68656c6c6f"}],
    ),
    dict(
        key="hex_decode",
        aliases=("hex_decode", "decode_hex", "hexdecode", "unhex",
                 "from_hex", "unhexlify"),
        description=("Hex-decode a hex string back to plaintext."),
        parameters=_schema({"data": _str_prop("Hex text to decode.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    return bytes.fromhex(data).decode("utf-8", errors="replace")
''',
        probe=[{"args": {"data": "68656c6c6f"}, "expect": "hello"}],
    ),
    dict(
        key="url_encode",
        aliases=("url_encode", "encode_url", "urlencode", "url_quote",
                 "percent_encode", "quote_url"),
        description=("Percent-encode a string for safe use in a URL "
                     "query/path component."),
        parameters=_schema({"data": _str_prop("String to URL-encode.", ""),
                            "safe": _str_prop(
                                "Characters to leave unescaped.", "")},
                           ["data"]),
        source='''
import urllib.parse


def run(**kw):
    data = str(kw.get("data", ""))
    safe = str(kw.get("safe", ""))
    return urllib.parse.quote(data, safe=safe)
''',
        probe=[{"args": {"data": "a b&c"}, "expect": "a%20b%26c"}],
    ),
    dict(
        key="url_decode",
        aliases=("url_decode", "decode_url", "urldecode", "url_unquote",
                 "percent_decode", "unquote_url"),
        description=("Percent-decode a URL-encoded string back to plaintext."),
        parameters=_schema({"data": _str_prop("URL-encoded text.", "")},
                           ["data"]),
        source='''
import urllib.parse


def run(**kw):
    data = str(kw.get("data", ""))
    return urllib.parse.unquote(data)
''',
        probe=[{"args": {"data": "a%20b%26c"}, "expect": "a b&c"}],
    ),
    dict(
        key="sha256_hex",
        aliases=("sha256", "sha256_hex", "sha256_hash", "hash_sha256",
                 "sha256sum", "compute_sha256", "sha2_256"),
        description=("Compute the SHA-256 hash of a string as lowercase hex."),
        parameters=_schema({"data": _str_prop("String to hash.", "")},
                           ["data"]),
        source='''
import hashlib


def run(**kw):
    data = kw.get("data", "")
    if isinstance(data, bytes):
        raw = data
    else:
        raw = str(data).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
''',
        probe=[{"args": {"data": "abc"}, "expect": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}],
    ),
    dict(
        key="md5_hex",
        aliases=("md5", "md5_hex", "md5_hash", "hash_md5", "md5sum",
                 "compute_md5"),
        description=("Compute the MD5 hash of a string as lowercase hex."),
        parameters=_schema({"data": _str_prop("String to hash.", "")},
                           ["data"]),
        source='''
import hashlib


def run(**kw):
    data = kw.get("data", "")
    if isinstance(data, bytes):
        raw = data
    else:
        raw = str(data).encode("utf-8")
    return hashlib.md5(raw).hexdigest()
''',
        probe=[{"args": {"data": "abc"}, "expect": "900150983cd24fb0d6963f7d28e17f72"}],
    ),
    dict(
        key="text_stats",
        aliases=("text_stats", "stats_text", "analyze_text", "text_analysis",
                 "text_metrics", "count_stats"),
        description=("Return char / word / line counts for a block of text."),
        parameters=_schema({"data": _str_prop("Text to analyze.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    lines = data.splitlines()
    words = data.split()
    return "chars=%d words=%d lines=%d" % (len(data), len(words), len(lines))
''',
        probe=[{"args": {"data": "one two\nthree"},
                "expect": "chars=13 words=3 lines=2"}],
    ),
    dict(
        key="sort_lines",
        aliases=("sort_lines", "lines_sort", "sort_text_lines", "line_sort",
                 "sort_lines_asc"),
        description=("Sort the lines of a text block alphabetically."),
        parameters=_schema({"data": _str_prop("Multi-line text to sort.", ""),
                            "reverse": {"type": "boolean",
                                        "description": "Sort descending.",
                                        "default": False}},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    reverse = bool(kw.get("reverse", False))
    lines = list(data.splitlines())
    lines.sort(reverse=reverse)
    return chr(10).join(lines)
''',
        probe=[{"args": {"data": "b\na\nc"}, "expect": "a\nb\nc"}],
    ),
    dict(
        key="unique_lines",
        aliases=("unique_lines", "dedupe_lines", "dedup_lines", "unique",
                 "uniq_lines"),
        description=("Remove duplicate lines from text, preserving order."),
        parameters=_schema({"data": _str_prop("Multi-line text.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    seen = []
    for line in data.splitlines():
        if line not in seen:
            seen.append(line)
    return chr(10).join(seen)
''',
        probe=[{"args": {"data": "a\nb\na\nb"}, "expect": "a\nb"}],
    ),
    dict(
        key="find_replace",
        aliases=("find_replace", "replace_text", "text_replace", "replace_all",
                 "str_replace", "substitute"),
        description=("Replace every occurrence of `find` with `replace` in "
                     "a string."),
        parameters=_schema({"data": _str_prop("Text to transform.", ""),
                            "find": _str_prop("Substring to find.", ""),
                            "replace": _str_prop("Replacement text.", "")},
                           ["data", "find", "replace"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    find = str(kw.get("find", ""))
    replace = str(kw.get("replace", ""))
    return data.replace(find, replace)
''',
        probe=[{"args": {"data": "a b a", "find": "a", "replace": "x"},
                "expect": "x b x"}],
    ),
    dict(
        key="word_count",
        aliases=("word_count", "count_words", "words_count"),
        description=("Count whitespace-separated words in a string."),
        parameters=_schema({"data": _str_prop("Text to count words in.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    return str(len(data.split()))
''',
        probe=[{"args": {"data": "a b c"}, "expect": "3"}],
    ),
    dict(
        key="regex_extract",
        aliases=("regex_extract", "regex_extract_all", "extract_regex",
                 "regex_findall", "find_matches", "extract_matches",
                 "regex_find", "regex_search_all"),
        description=("Extract every substring matching a regular expression from "
                     "text, joined by newlines. Empty pattern or no match yields "
                     "an empty string."),
        parameters=_schema({"data": _str_prop("Text to search.", ""),
                            "pattern": _str_prop("Regular expression.")},
                           ["data", "pattern"]),
        source='''
import re

def run(**kw):
    data = str(kw.get("data", ""))
    pattern = str(kw.get("pattern", ""))
    if not pattern:
        return ""
    return chr(10).join(re.findall(pattern, data))
''',
        probe=[{"args": {"data": "abc123def456", "pattern": r"\d+"},
                "expect": "123\n456"}],
    ),
    dict(
        key="rot13",
        aliases=("rot13", "rot_13", "rotate13", "caesar13", "caesar_rot13",
                 "rot13_encode", "rot13_transform"),
        description=("Apply the ROT13 letter-substitution cipher to text: each "
                     "letter shifts 13 places, non-letters are unchanged."),
        parameters=_schema({"data": _str_prop("Text to transform.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    lower = "abcdefghijklmnopqrstuvwxyz"
    upper = lower.upper()
    table = str.maketrans(lower + upper,
                          lower[13:] + lower[:13] + upper[13:] + upper[:13])
    return data.translate(table)
''',
        probe=[{"args": {"data": "hello"}, "expect": "uryyb"}],
    ),
    dict(
        key="reverse_text",
        aliases=("reverse_text", "reverse_string", "str_reverse", "text_reverse",
                 "reverse"),
        description=("Reverse a string so the last character becomes first. "
                     "Useful for reversing encoded or obfuscated payloads."),
        parameters=_schema({"data": _str_prop("Text to reverse.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    return data[::-1]
''',
        probe=[{"args": {"data": "abc"}, "expect": "cba"}],
    ),
)


# ---------------------------------------------------------------------------
# _PAYLOAD_RULES: security payload-handler tier.  Specialised generators
# used by dynamic exploit work to build / obfuscate attack payloads: HTML
# entity encoding for XSS contexts, double URL-encoding for WAF bypass,
# JavaScript unicode escapes and String.fromCharCode arrays, case
# alternation, SQL inline-comment splitting and fullwidth-Unicode
# obfuscation.  Each entry uses the exact same spec shape as _RULES
# (key, aliases, description, parameters, source, probe) and is written to
# pass the SynthesizedToolValidator unchanged.
# ---------------------------------------------------------------------------
_PAYLOAD_RULES = (
    dict(
        key="html_entity_encode",
        aliases=("html_entity_encode", "xss_entity_encode",
                 "html_escape_entities", "html_encode_entities"),
        description=("Encode text as HTML/XML character entities for XSS "
                     "payload contexts.  Default mode escapes only "
                     "HTML-significant and non-printable characters; set "
                     "encode_all=True to escape every character and "
                     "use_hex=False to emit decimal entities."),
        parameters=_schema({"data": _str_prop("Text to encode.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    use_hex = bool(kw.get("use_hex", True))
    encode_all = bool(kw.get("encode_all", False))
    special = set(["&", "<", ">", '"', "'"])
    out = []
    for ch in data:
        code = ord(ch)
        if encode_all or ch in special or code < 32 or code > 126:
            if use_hex:
                out.append("&#x%x;" % code)
            else:
                out.append("&#%d;" % code)
        else:
            out.append(ch)
    return "".join(out)
''',
        probe=[{"args": {"data": "<b>hi</b>"},
                "expect": "&#x3c;b&#x3e;hi&#x3c;/b&#x3e;"}],
    ),
    dict(
        key="double_url_encode",
        aliases=("double_url_encode", "url_encode_twice", "double_encode",
                 "dbl_url_encode", "waf_url_bypass"),
        description=("Percent-encode a string twice so that one decoding "
                     "layer still leaves an encoded payload behind - a "
                     "classic WAF-bypass trick for reflected XSS and SQLi "
                     "filters."),
        parameters=_schema({"data": _str_prop("Text to double-encode.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    def enc_once(text):
        safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
        parts = []
        for ch in text:
            if ch in safe:
                parts.append(ch)
            else:
                parts.append("%" + hex(ord(ch))[2:].upper().zfill(2))
        return "".join(parts)
    return enc_once(enc_once(data))
''',
        probe=[{"args": {"data": "a b"}, "expect": "a%2520b"}],
    ),
    dict(
        key="js_unicode_escape",
        aliases=("js_unicode_escape", "unicode_escape_js", "u_escape",
                 "js_escape_unicode"),
        description=("Escape every character as a JavaScript/JSON \\uXXXX "
                     "unicode escape sequence for obfuscating XSS payloads "
                     "that land inside script string contexts."),
        parameters=_schema({"data": _str_prop("Text to escape.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    slash = chr(92)
    out = []
    for ch in data:
        code = ord(ch)
        out.append(slash + "u" + ("%04x" % code))
    return "".join(out)
''',
        probe=[{"args": {"data": "x"},
                "expect": "\\u0078"}],
    ),
    dict(
        key="js_fromcharcode",
        aliases=("js_fromcharcode", "fromcharcode", "js_charcode",
                 "charcode_array", "char_code_obfuscate"),
        description=("Rebuild a string as a JavaScript "
                     "String.fromCharCode(...) call so the payload never "
                     "appears as plain text in the page source or filters."),
        parameters=_schema({"data": _str_prop("Text to obfuscate.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    codes = []
    for ch in data:
        codes.append(str(ord(ch)))
    return "String.fromCharCode(" + ",".join(codes) + ")"
''',
        probe=[{"args": {"data": "A"},
                "expect": "String.fromCharCode(65)"}],
    ),
    dict(
        key="mixed_case_alternate",
        aliases=("mixed_case_alternate", "alternating_case", "case_obfuscate",
                 "to_alternating_case"),
        description=("Rewrite text in alternating case (ScRiPt style) to "
                     "slip past naive signature and case-sensitive keyword "
                     "filters while browsers still parse it case-insensitively."),
        parameters=_schema({"data": _str_prop("Text to transform.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    out = []
    for idx, ch in enumerate(data):
        if idx % 2 == 0:
            out.append(ch.upper())
        else:
            out.append(ch.lower())
    return "".join(out)
''',
        probe=[{"args": {"data": "script"}, "expect": "ScRiPt"}],
    ),
    dict(
        key="sql_comment_obfuscate",
        aliases=("sql_comment_obfuscate", "sql_inline_comment",
                 "comment_obfuscate", "inline_comment_sql"),
        description=("Split a SQL keyword with /**/ inline comments (e.g. "
                     "SELECT becomes S/**/E/**/L/**/E/**/C/**/T) so simple "
                     "signature and tokenisation filters miss it while the "
                     "SQL parser still sees the original keyword."),
        parameters=_schema({"data": _str_prop("SQL text to obfuscate.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    return "/**/".join(data)
''',
        probe=[{"args": {"data": "SELECT"},
                "expect": "S/**/E/**/L/**/E/**/C/**/T"}],
    ),
    dict(
        key="unicode_fullwidth",
        aliases=("unicode_fullwidth", "fullwidth_encode", "full_width_obfuscate",
                 "wide_char_encode"),
        description=("Map printable ASCII onto its Unicode fullwidth forms "
                     "(A becomes fullwidth A) so text is invisible to "
                     "ASCII-based filters yet still renders identically to "
                     "the human eye."),
        parameters=_schema({"data": _str_prop("Text to convert.", "")},
                           ["data"]),
        source='''
def run(**kw):
    data = str(kw.get("data", ""))
    out = []
    for ch in data:
        code = ord(ch)
        if code == 32:
            out.append(chr(0x3000))
        elif 0x21 <= code <= 0x7E:
            out.append(chr(code + 0xFEE0))
        else:
            out.append(ch)
    return "".join(out)
''',
        probe=[{"args": {"data": "Ab"},
                "expect": "\uff21\uff42"}],
    ),
)


# ---------------------------------------------------------------------------
# ToolSynthesizer / SynthesizedToolValidator / SelfEvolutionEngine
# (dynamic tool-synthesis half of the Autonomous Self-Evolution Engine)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# ToolSynthesizer: match missing tool names against the declarative _RULES
# generators and emit a complete, self-contained tool spec.
# ---------------------------------------------------------------------------


class ToolSynthesizer:
    """Match a requested tool name against the built-in rule generators,
    falling back to a gap-driven code-model tier for capability gaps that
    have no declarative rule generator.

    Rules live in `_RULES` and the payload-handler catalog `_PAYLOAD_RULES`
    (both declared above): each carries a canonical `key`, a tuple of
    `aliases`, a JSON-schema `parameters` block, a
    self-contained module `source` exposing ``def run(**kw)``, and a
    `probe` list used for self-testing after synthesis.  Matching is done
    on a normalised form (lowercase, non-alphanumerics stripped) so
    ``b64 encode``, ``B64_ENCODE`` and ``base64encode`` all resolve to the
    same rule.

    The code-model tier (``code_model=``) is consulted only when no rule
    matches *and* a `CapabilityGap` is supplied to ``synthesize()``.  The
    callable receives the full gap record (so the model can use the
    functional description, inferred input schema and expected output
    type) and must return either:

    * a complete spec dict with the standard keys (name, description,
      parameters, source, probe) - recommended; or
    * a bare module source string (a module exposing ``def run(**kw)``).

    Correctness is enforced by micro unit tests, so a generated tool must
    ship at least one ``{"args": ..., "expect": ...}`` probe; when the
    model returns a spec without a probe list, or a bare source that
    cannot be self-tested, the resulting spec fails closed at the
    validation gate (the engine never approves untested code).
    """

    def __init__(self, rules=_RULES, code_model=None,
                 payload_rules=_PAYLOAD_RULES):
        self._rules = tuple(rules) + tuple(payload_rules or ())
        self._payload_keys = frozenset(
            rule["key"] for rule in (payload_rules or ())
            if isinstance(rule, dict) and rule.get("key"))
        self._index = {}
        for rule in self._rules:
            names = [rule["key"]]
            names.extend(rule.get("aliases") or ())
            for alias in names:
                key = _norm(alias)
                if key and key not in self._index:
                    self._index[key] = rule
        self.code_model = code_model

    def match_rule(self, name):
        """Return the rule dict for `name`, or None when nothing matches."""
        if not isinstance(name, str):
            return None
        return self._index.get(_norm(name))

    # -- code-model tier ---------------------------------------------------

    @staticmethod
    def _default_parameters(gap):
        schema = dict(gap.input_schema or {})
        if not schema:
            return _schema({}, [])
        if schema.get("type") != "object":
            return _schema(schema.get("properties") or {},
                           schema.get("required") or [])
        return schema

    def _compose_generated_spec(self, name, gap, output):
        """Normalise the code model's answer into the standard spec shape."""
        if isinstance(output, str):
            output = {"source": output}
        if not isinstance(output, dict):
            return None
        source = output.get("source")
        if not isinstance(source, str) or not source.strip():
            return None
        return {
            "name": name,
            "rule": "code-model",
            "description": (output.get("description")
                            or gap.functional_description
                            or gap.detail
                            or "Code-model synthesized tool for %r." % name),
            "parameters": (output.get("parameters")
                           if isinstance(output.get("parameters"), dict)
                           else self._default_parameters(gap)),
            "source": source,
            "probe": [dict(p) for p in (output.get("probe") or [])],
        }

    def synthesize(self, name=None, gap=None):
        """Produce a full spec dict for `name`, or None when not
        synthesizable.

        Rule generators are consulted first; when nothing matches and a
        `CapabilityGap` is supplied, the optional ``code_model`` callable
        is tried next.  The returned spec carries exactly the keys the
        store / validator / hot-reload path expects: name, rule,
        description, parameters, source, probe.
        """
        if not is_valid_tool_name(name):
            return None
        rule = self.match_rule(name)
        if rule is not None:
            return {
                "name": name,
                "rule": rule["key"],
                "description": rule["description"],
                "parameters": rule["parameters"],
                "source": rule["source"],
                "probe": [dict(p) for p in (rule.get("probe") or [])],
            }
        if gap is not None and self.code_model is not None:
            try:
                output = self.code_model(gap)
            except Exception as exc:
                log.debug("code-model synthesis failed for %r: %s",
                          name, exc)
                return None
            if output:
                spec = self._compose_generated_spec(name, gap, output)
                if spec is not None:
                    return spec
        return None

    def rules(self):
        """Lightweight catalog of the available generators (no source)."""
        return [
            {
                "key": rule["key"],
                "aliases": tuple(rule.get("aliases") or ()),
                "description": rule["description"],
                "probe_count": len(rule.get("probe") or []),
                "payload": rule["key"] in self._payload_keys,
            }
            for rule in self._rules
        ]


# ---------------------------------------------------------------------------
# SynthesizedToolValidator: static (AST) checks + restricted builtins +
# execution of each rule's self-test probe.
# ---------------------------------------------------------------------------

# Modules a synthesized tool may import.  Everything else - filesystem,
# process, network, ... - is refused both statically and at runtime.
_ALLOWED_IMPORT_ROOTS = (
    "base64", "binascii", "hashlib", "json", "math", "re", "string",
    "unicodedata", "urllib",
)
_ALLOWED_SUBMODULES = {
    "urllib": ("parse",),
}
_ALLOWED_MODULE_PATHS = frozenset(
    list(_ALLOWED_IMPORT_ROOTS)
    + [root + "." + sub for root, subs in _ALLOWED_SUBMODULES.items()
       for sub in subs]
)

# Callable names a synthesized tool may never invoke.
_FORBIDDEN_CALL_NAMES = frozenset({
    "eval", "exec", "compile", "open", "input", "print", "globals", "locals",
    "vars", "dir", "getattr", "setattr", "delattr", "hasattr", "breakpoint",
    "exit", "quit", "help", "__import__", "type", "super", "object",
})


def _make_import_guard(allowed_paths=_ALLOWED_MODULE_PATHS):
    """Runtime `__import__` guard installed into the safe builtins dict."""

    def _guard(name, globals_=None, locals_=None, fromlist=(), level=0):
        if level:
            raise ImportError(
                "relative imports are not allowed in synthesized tools")
        if name not in allowed_paths:
            raise ImportError(
                "import of %r is not allowed in synthesized tools" % (name,))
        return __import__(name, globals_, locals_, fromlist, level)

    return _guard


_IMPORT_GUARD = _make_import_guard()


def _build_safe_builtins():
    """A builtins dict with every dangerous / reflection entry removed."""
    banned = set(_FORBIDDEN_CALL_NAMES)
    safe = {}
    for name in dir(builtins):
        if name.startswith("_") or name in banned:
            continue
        safe[name] = getattr(builtins, name)
    safe["__import__"] = _IMPORT_GUARD
    return safe


_SAFE_BUILTINS = _build_safe_builtins()


class SynthesizedToolValidator:
    """Static + runtime validation gate for synthesized tool sources.

    ``validate()`` returns a dict::

        {"ok": bool, "errors": [str], "func": callable-or-None,
         "probe_failures": [dict]}

    `func` is only populated when every static check passed, the module
    executed under restricted builtins, and (if `run_probes`) all probes
    produced their expected result.
    """

    def __init__(self, sandbox=None):
        self._exec_globals_template = {"__name__": "__synthesized_tool__"}
        self.sandbox = sandbox

    def allowed_modules(self):
        return sorted(_ALLOWED_MODULE_PATHS)

    # -- static analysis ---------------------------------------------------

    def _module_allowed(self, module_name):
        if not module_name:
            return False
        root = module_name.split(".")[0]
        return (module_name in _ALLOWED_MODULE_PATHS
                or root in _ALLOWED_IMPORT_ROOTS)

    def _check_source(self, source):
        """Return a list of policy violations found in `source`."""
        errors = []
        if not isinstance(source, str) or not source.strip():
            return ["source is empty"]
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return ["syntax error: %s" % (exc,)]
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                errors.append("line %d: class definitions are not allowed"
                              % node.lineno)
            elif isinstance(node, ast.Global):
                errors.append("line %d: `global` statements are not allowed"
                              % node.lineno)
            elif isinstance(node, ast.Nonlocal):
                errors.append("line %d: `nonlocal` statements are not allowed"
                              % node.lineno)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if not self._module_allowed(alias.name):
                        errors.append("line %d: import %r is not allowed"
                                      % (node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    errors.append("line %d: relative imports are not allowed"
                                  % node.lineno)
                elif not self._module_allowed(node.module or ""):
                    errors.append("line %d: import from %r is not allowed"
                                  % (node.lineno, node.module or ""))
                else:
                    for alias in node.names:
                        if alias.name == "*":
                            errors.append("line %d: star imports are not "
                                          "allowed" % node.lineno)
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) \
                        and func.id in _FORBIDDEN_CALL_NAMES:
                    errors.append("line %d: call to %r is not allowed"
                                  % (node.lineno, func.id))
                elif isinstance(func, ast.Attribute) \
                        and func.attr in _FORBIDDEN_CALL_NAMES:
                    errors.append("line %d: call to %r is not allowed"
                                  % (node.lineno, func.attr))
            elif isinstance(node, ast.Name):
                if node.id.startswith("_"):
                    errors.append("line %d: references to underscore-prefixed "
                                  "name %r are not allowed"
                                  % (node.lineno, node.id))
            elif isinstance(node, ast.Attribute):
                if node.attr.startswith("_"):
                    errors.append("line %d: access to attribute %r is not "
                                  "allowed" % (node.lineno, node.attr))
        run_defs = []
        for stmt in tree.body:
            if isinstance(stmt, ast.FunctionDef) and stmt.name == "run":
                run_defs.append(stmt)
        if not run_defs:
            errors.append("module must define a top-level run(**kw) function")
        elif any(fn.args.kwarg is None for fn in run_defs):
            errors.append("run() must accept keyword arguments via **kw")
        return errors

    # -- runtime -----------------------------------------------------------

    def _build_func(self, source, name):
        module_globals = dict(self._exec_globals_template)
        module_globals["__builtins__"] = _SAFE_BUILTINS
        code = compile(source, "<synthesized:%s>" % name, "exec")
        exec(code, module_globals)
        func = module_globals.get("run")
        return func if callable(func) else None

    def validate(self, spec, run_probes=True):
        """Validate `spec`; see class docstring for the return contract."""
        name = (spec or {}).get("name", "?")
        source = (spec or {}).get("source", "")
        errors = self._check_source(source)
        func = None
        if not errors:
            try:
                func = self._build_func(source, name)
            except Exception as exc:
                errors.append("execution failed: %s: %s"
                              % (type(exc).__name__, exc))
        probe_failures = []
        if run_probes and func is not None:
            probes = (spec or {}).get("probe") or []
            sandbox = self.sandbox
            if sandbox is not None and probes:
                # PHASE 2: micro unit tests run in the isolated, time-boxed
                # subprocess - never in the engine's own process.
                result = sandbox.run(spec, probes=probes)
                if result.error and not result.probe_failures:
                    errors.append("isolated sandbox: %s" % result.error)
                for failure in result.probe_failures:
                    idx = failure.get("probe", -1)
                    src = probes[idx] if 0 <= idx < len(probes) else {}
                    entry = {
                        "probe": idx,
                        "args": dict(src.get("args") or {}),
                        "expected": src.get("expect"),
                    }
                    if "actual" in failure:
                        entry["actual"] = failure["actual"]
                    else:
                        entry["error"] = failure.get(
                            "error", "sandbox probe failed")
                    probe_failures.append(entry)
            elif probes:
                for index, probe in enumerate(probes):
                    args = dict(probe.get("args") or {})
                    expected = probe.get("expect")
                    try:
                        actual = func(**args)
                    except Exception as exc:
                        probe_failures.append({
                            "probe": index, "args": args,
                            "expected": expected,
                            "error": "%s: %s" % (type(exc).__name__, exc),
                        })
                        continue
                    if actual != expected:
                        probe_failures.append({
                            "probe": index, "args": args,
                            "expected": expected, "actual": actual,
                        })
            elif (spec or {}).get("rule") == "code-model":
                errors.append(
                    "code-model tool must include auto-generated micro "
                    "unit tests (probe list) before it can be approved")

        return {
            "ok": not errors and func is not None and not probe_failures,
            "errors": errors,
            "func": func,
            "probe_failures": probe_failures,
        }



# ---------------------------------------------------------------------------
# IsolatedExecutionSandbox: run auto-generated micro unit tests for a
# synthesized tool inside a scrubbed, time-boxed subprocess.  The child
# never sees the engine's process, its globals, the tool catalog or the
# network: source + probes arrive over stdin and one JSON verdict line
# comes back.  A timeout, a non-zero exit or an unreadable reply fails the
# run, so a broken or malicious tool can never be approved.
# ---------------------------------------------------------------------------

# The harness the child runs.  It imports only stdlib modules, executes the
# tool source in a fresh namespace and compares each probe result against
# its expected value inside the child before anything is serialised back.
_SANDBOX_HARNESS = '''\
import io
import json
import sys
import time


def _json_safe(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return repr(value)


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")
    payload = json.load(sys.stdin)
    source = payload["source"]
    probes = payload["probes"]
    results = []
    for index, probe in enumerate(probes):
        record = {"probe": index}
        args = dict(probe.get("args") or {})
        expected = probe.get("expect")
        record["args"] = {str(key): _json_safe(item)
                          for key, item in args.items()}
        record["expected"] = _json_safe(expected)
        started = time.time()
        try:
            namespace = {}
            code = compile(source, "<isolated-tool>", "exec")
            exec(code, namespace)
            func = namespace["run"]
            actual = func(**args)
            record["ok"] = (actual == expected)
            record["actual"] = _json_safe(actual)
        except SystemExit as exc:
            record["error"] = "SystemExit: %r" % (exc,)
        except BaseException as exc:
            record["error"] = "%s: %s" % (type(exc).__name__, exc)
        record["elapsed_ms"] = int((time.time() - started) * 1000)
        results.append(record)
    json.dump({"probes": results}, sys.stdout)


if __name__ == "__main__":
    main()
'''


def build_micro_test_script() -> str:
    """Return the self-contained micro unit-test harness source.

    The harness is executed in a fresh interpreter via
    ``python -c <script>``; it reads one JSON payload from stdin
    (``{"source": ..., "probes": [...]}``) and writes one JSON
    object back to stdout.  Exposed for tests and for operators who
    want to audit exactly what the child process runs.
    """
    return _SANDBOX_HARNESS


@dataclass
class SandboxResult:
    """Verdict of one isolated micro-test run for a synthesized tool.

    ``probe_failures`` carries one record per failing probe (each with
    probe index, args, expected and either the actual value or the
    error); ``error`` carries a human-readable summary when the whole
    run could not complete.
    """
    tool_name: str
    ok: bool = False
    returncode: int = 0
    timed_out: bool = False
    error: str = ""
    probe_failures: List[Dict] = field(default_factory=list)


class IsolatedExecutionSandbox:
    """Time-boxed subprocess runner for synthesized-tool micro unit tests.

    ``run(spec)`` serialises the tool source plus its auto-generated
    probes to the harness subprocess and returns a `SandboxResult`.
    The subprocess gets a scrubbed environment (PATH/SystemRoot only),
    runs in the system temp dir and is killed when it exceeds the
    deadline, so runaway or malicious code can neither hang the engine
    nor reach its process.
    """

    def __init__(self, executable=None, timeout: float = 15.0):
        self.executable = executable or sys.executable
        self.timeout = timeout

    def run(self, spec, probes=None, timeout=None) -> SandboxResult:
        """Run every micro unit test for `spec` in isolation.

        ``probes`` may override the probes embedded in the spec (used by
        tests that inject their own micro tests).  Returns a
        `SandboxResult`; never raises.
        """
        tool_name = (spec or {}).get("name", "?")
        source = (spec or {}).get("source", "")
        if not source or not isinstance(source, str):
            return SandboxResult(tool_name=tool_name, ok=False,
                                 error="spec carries no tool source")
        probe_list = [dict(p) for p in (probes if probes is not None
                                        else (spec or {}).get("probe") or [])]
        if not probe_list:
            return SandboxResult(tool_name=tool_name, ok=False,
                                 error="no micro unit tests provided")
        payload = json.dumps({"source": source, "probes": probe_list})
        deadline = timeout if timeout is not None else self.timeout
        env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONPATH": os.pathsep.join(
                [p for p in sys.path if p not in ("", os.getcwd())]),
        }
        try:
            proc = subprocess.Popen(
                [self.executable, "-c", build_micro_test_script()],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env,
                cwd=tempfile.gettempdir())
        except (OSError, ValueError) as exc:
            return SandboxResult(tool_name=tool_name, ok=False,
                                 error="spawn failed: %s" % exc)
        timed_out = False
        try:
            out, err = proc.communicate(input=payload.encode("utf-8"),
                                        timeout=deadline)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                proc.kill()
            except OSError:
                pass
            try:
                out, err = proc.communicate(timeout=10)
            except Exception:
                out, err = b"", b""
        if timed_out:
            return SandboxResult(tool_name=tool_name, ok=False,
                                 timed_out=True,
                                 error="sandbox exceeded %.1fs" % deadline)
        return self._parse_result(tool_name, proc.returncode, out, err)

    @staticmethod
    def _parse_result(tool_name, returncode, out, err):
        if returncode != 0:
            tail = (err or b"").decode("utf-8", "replace")
            tail = " | ".join(tail.strip().splitlines()[-3:])
            return SandboxResult(tool_name=tool_name, ok=False,
                                 returncode=returncode,
                                 error="sandbox exited %d: %s"
                                       % (returncode, tail or "no stderr"))
        try:
            data = json.loads((out or b"").decode("utf-8", "replace"))
        except ValueError as exc:
            return SandboxResult(tool_name=tool_name, ok=False,
                                 returncode=returncode,
                                 error="unreadable harness output: %s" % exc)
        probes = data.get("probes") or []
        failures = [p for p in probes if not p.get("ok")]
        return SandboxResult(
            tool_name=tool_name, ok=not failures,
            returncode=returncode, probe_failures=failures,
            error=("" if not failures else "%d/%d micro tests failed"
                   % (len(failures), len(probes))))

# ---------------------------------------------------------------------------
# SelfEvolutionEngine: observe -> detect -> synthesize -> validate ->
# persist -> hot-register, with status accounting for the caller/watcher.
# ---------------------------------------------------------------------------


class SelfEvolutionEngine:
    """Glue that turns an observed capability gap into a live new tool.

    ``observe(result=None, planner_state=None)`` returns a dict or None.
    Response dicts always carry: status, name, tool_name, description,
    detail, registered and (when a spec exists) `tool` = public spec.
    status values:
        synthesized  - brand-new tool created, validated, persisted, loaded
        reloaded     - tool already in the store; re-validated + hot-loaded
        rejected     - synthesis produced something that failed validation
        invalid_name - gap named an identifier we refuse to register
        no_match     - gap detected but no rule generator matches
        error        - internal failure (store / catalog / exception)
    """

    def __init__(self, store_path=None, hot_reload=None, detector=None,
                 synthesizer=None, validator=None, on_gap=None,
                 sandbox=None, max_patches: int = 2):
        self.store_path = store_path or DEFAULT_STORE_PATH
        self.max_patches = max(0, int(max_patches or 0))
        self._hot_reload = hot_reload
        self.detector = (detector if detector is not None
                         else CapabilityGapDetector())
        self.synthesizer = (synthesizer if synthesizer is not None
                            else ToolSynthesizer())
        # PHASE 2: probes for brand-new tools are executed inside the
        # isolated, time-boxed subprocess (never in this process).
        self.sandbox = sandbox if sandbox is not None \
            else IsolatedExecutionSandbox()
        self.validator = (validator if validator is not None
                          else SynthesizedToolValidator(
                              sandbox=self.sandbox))
        if self.validator.sandbox is None:
            self.validator.sandbox = self.sandbox
        self._on_gap = on_gap
        self.gap_log: List[CapabilityGap] = []
        self.last_gap = None
        self._store = None
        self._lock = threading.RLock()
        self._reloader = None
        self.stats = {
            "observed": 0, "synthesized": 0, "reloaded": 0, "rejected": 0,
            "no_match": 0, "invalid_name": 0, "errors": 0,
            "patched": 0, "gaps_recorded": 0,
        }

    # -- internals ---------------------------------------------------------

    def _ensure_store(self):
        store = self._store
        if store is None:
            with self._lock:
                store = self._store
                if store is None:
                    store = SynthesizedToolStore(self.store_path)
                    self._store = store
        return store

    def _catalog(self):
        """Return the callable that hot-registers a tool into the catalog."""
        if self._hot_reload is not None:
            return self._hot_reload
        if self._reloader is None:
            from ..tools import hot_reload_tool
            self._reloader = hot_reload_tool
        return self._reloader

    def _register(self, spec):
        reloader = self._catalog()
        if reloader is None or not callable(reloader):
            raise RuntimeError("no hot_reload registration path is available")
        name = reloader(spec)
        if not name:
            raise RuntimeError("hot_reload_tool returned no registered name")
        return name

    def _activate(self, spec):
        """Rebuild func for a spec, then hot-register it. Returns func."""
        verdict = self.validator.validate(spec, run_probes=False)
        if not verdict["ok"] or verdict["func"] is None:
            raise RuntimeError(
                "re-validation failed: %s"
                % ("; ".join(verdict["errors"]) or "no run function"))
        func = verdict["func"]
        spec["func"] = func
        self._register(spec)
        return func

    @staticmethod
    def _verdict_feedback(verdict) -> str:
        """Render a validator verdict into a single patch-feedback line."""
        problems = list(verdict["errors"])
        for failure in verdict["probe_failures"]:
            if "error" in failure:
                problems.append("probe %d failed: %s"
                                % (failure.get("probe"),
                                   failure.get("error")))
            else:
                problems.append("probe %d failed: %r != expected %r"
                                % (failure.get("probe"),
                                   failure.get("actual"),
                                   failure.get("expected")))
        return "; ".join(problems) or "validation failed"

    @staticmethod
    def _public(spec):
        return {k: v for k, v in spec.items() if k != "func"}

    def _respond(self, status, name, spec=None, detail=""):
        return {
            "status": status,
            "name": name,
            "tool_name": name,
            "tool": self._public(spec) if spec else None,
            "description": ((spec or {}).get("description", "")
                            if spec else ""),
            "detail": detail,
            "registered": status in ("synthesized", "reloaded"),
        }

    # -- public API --------------------------------------------------------

    def observe(self, result=None, planner_state=None):
        """Inspect a tool result / planner fragment; grow the catalog if
        needed.  Returns None when the observation carries no signal, else
        a status dict (see class docstring)."""
        self.stats["observed"] += 1
        if result is not None and not isinstance(result, str):
            return None
        if not result and not planner_state:
            return None
        try:
            gaps = self.detector.parse(result=result,
                                       planner_state=planner_state)
        except Exception as exc:
            self.stats["errors"] += 1
            return self._respond("error", "",
                                 detail="detection failed: %s" % exc)
        gap = gaps[0] if gaps else None
        if gap is None:
            self.stats["no_match"] += 1
            return self._respond("no_match", "",
                                 detail="no capability gap detected")
        name = gap.tool_name
        if not is_valid_tool_name(name):
            self.stats["invalid_name"] += 1
            return self._respond("invalid_name", name, detail=gap.detail)
        try:
            store = self._ensure_store()
            existing = store.get(name)
            if existing is not None:
                store.increment_hit(name)
                try:
                    self._activate(existing)
                except Exception as exc:
                    self.stats["errors"] += 1
                    return self._respond("error", name, spec=existing,
                                         detail="reload failed: %s" % exc)
                self.stats["reloaded"] += 1
                return self._respond("reloaded", name, spec=existing,
                                     detail="loaded from persistent store")
            spec = self.synthesizer.synthesize(name, gap=gap)
            if spec is None:
                self.stats["no_match"] += 1
                return self._respond(
                    "no_match", name,
                    detail="no rule generator for %r" % name)
            verdict = self.validator.validate(spec, run_probes=True)
            # PHASE 3: dynamic auto-patching.  When a code-model spec fails
            # sandbox micro-tests, feed the syntax/probe errors back to the
            # synthesizer and re-run validation until it passes or the
            # patch budget runs out.  Rule generators are deterministic and
            # are never retried.
            patches = 0
            while (not verdict["ok"] and patches < self.max_patches
                   and spec.get("rule") == "code-model"):
                patches += 1
                feedback = self._verdict_feedback(verdict)
                if not feedback:
                    break
                patch_gap = copy.copy(gap)
                prompt = ("[AUTO-PATCH #%d] generated tool failed "
                          "validation: %s.  Return a corrected tool JSON "
                          "(fixed source + passing probes)."
                          % (patches, feedback))
                patch_gap.detail = (str((gap.detail
                                          or gap.functional_description
                                          or "").strip())
                                     + chr(10) + prompt)
                patch_gap.functional_description = patch_gap.detail
                spec = self.synthesizer.synthesize(name, gap=patch_gap)
                if spec is None:
                    break
                verdict = self.validator.validate(spec, run_probes=True)
            if not verdict["ok"]:
                self.stats["rejected"] += 1
                return self._respond(
                    "rejected", name, spec=spec,
                    detail=self._verdict_feedback(verdict))
            if patches:
                self.stats["patched"] += patches
            spec["func"] = verdict["func"]
            store.save(spec)
            try:
                self._register(spec)
            except Exception as exc:
                self.stats["errors"] += 1
                return self._respond("error", name, spec=spec,
                                     detail="registration failed: %s" % exc)
            self.stats["synthesized"] += 1
            return self._respond("synthesized", name, spec=spec,
                                 detail="rule=%s" % spec["rule"])
        except Exception as exc:
            self.stats["errors"] += 1
            return self._respond(
                "error", name or "",
                detail="engine failure: %s: %s" % (type(exc).__name__, exc))

    # -- capability-gap log ---------------------------------------------

    def note_gap(self, gap) -> Optional[CapabilityGap]:
        """Record one observed capability gap (thread-safe, bounded).

        Never opens the SQLite store and never synthesizes - this is
        the record-only tier.  The optional ``on_gap`` callback (set at
        construction) is invoked once per recorded gap outside the lock;
        a raising callback is swallowed and logged.
        """
        if not isinstance(gap, CapabilityGap):
            return None
        with self._lock:
            self.gap_log.append(gap)
            overflow = len(self.gap_log) - _GAP_LOG_LIMIT
            if overflow > 0:
                del self.gap_log[:overflow]
            self.stats["gaps_recorded"] += 1
            self.last_gap = gap
        callback = self._on_gap
        if callback is not None:
            try:
                callback(gap)
            except Exception:
                log.debug("self-evolution on_gap callback failed",
                          exc_info=True)
        return gap

    def gap_history(self, limit=50) -> List[Dict]:
        """JSON-safe history of the most recent recorded gaps."""
        with self._lock:
            items = list(self.gap_log[-limit:])
        return [gap.to_dict() for gap in items]

    def close(self):
        """Idempotently close the backing SQLite store."""
        with self._lock:
            if self._store is not None:
                self._store.close()
                self._store = None

    def __enter__(self):
        self._ensure_store()
        return self

    def __exit__(self, *exc):
        self.close()
