"""Unit tests for the cross-chat institutional memory feature.

Covers: InstitutionalMemory CRUD, category normalisation, consult() section
rendering (per-target findings/context, global methodology/plans, TF-IDF
relevant-to-query, size limit, empty-db), record_finding, thread-safety,
Agent._system_prompt() doctrine injection (built-in + external override),
notes_* tool registration, and _detect_kb_target internal-TLD handling.

Run:  py -m pytest test_institutional.py
"""
import os
import re
import shutil
import sys
import tempfile
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ai_agent.core as core
from ai_agent.core import Agent, _detect_kb_target
from ai_agent.memory_store import INSTITUTIONAL_CATEGORIES, InstitutionalMemory
from ai_agent.tools import create_tools


class FakeLLM:
    """Minimal LLM stub: records the prompt, answers immediately."""
    def __init__(self):
        self.calls = []

    def generate(self, messages, **kwargs):
        self.calls.append(messages)
        return {"text": "final answer"}


def _note(inst, category, title, content, target="", tags=None):
    return inst.add_note(category, title, content, target=target, tags=tags)


@pytest.fixture()
def inst():
    tmp = tempfile.mkdtemp(prefix="inst_test_")
    db = os.path.join(tmp, "institutional_notes.db")
    m = InstitutionalMemory(db)
    yield m
    try:
        shutil.rmtree(tmp, ignore_errors=True)
    except Exception:
        pass


def _agent(**kwargs):
    a = Agent(llm=FakeLLM(), name="test", **kwargs)
    a.messages = [{"role": "user",
                   "content": "test victim.local for sql injection"}]
    return a


# ---------------------------------------------------------------------------
# InstitutionalMemory CRUD
# ---------------------------------------------------------------------------

class TestCrud:
    def test_add_and_get(self, inst):
        n = _note(inst, "findings", "SQLi in login",
                  "login.php has time-based blind SQLi, parameter id",
                  target="victim.local")
        assert n["id"] > 0
        got = inst.get_note(n["id"])
        assert got["title"] == "SQLi in login"
        assert got["category"] == "findings"
        assert got["target"] == "victim.local"
        assert got["content"] == "login.php has time-based blind SQLi, parameter id"

    def test_get_missing_returns_none(self, inst):
        assert inst.get_note(999999) is None

    def test_update(self, inst):
        n = _note(inst, "findings", "port 80", "http service", target="x.local")
        upd = inst.update_note(n["id"], content="http + https service",
                               category="target_context")
        assert upd["content"] == "http + https service"
        assert upd["category"] == "target_context"
        assert upd["title"] == "port 80"  # untouched field preserved

    def test_update_missing_returns_none(self, inst):
        assert inst.update_note(999999, content="x") is None

    def test_delete(self, inst):
        n = _note(inst, "findings", "t", "c")
        assert inst.delete_note(n["id"]) is True
        assert inst.delete_note(n["id"]) is False
        assert inst.get_note(n["id"]) is None

    def test_list_filters(self, inst):
        _note(inst, "findings", "A", "alpha", target="one.local")
        _note(inst, "findings", "B", "beta", target="two.local")
        _note(inst, "methodology", "C", "gamma")
        assert len(inst.list_notes()) == 3
        assert len(inst.list_notes(category="findings")) == 2
        assert len(inst.list_notes(target="one.local")) == 1
        assert [x["title"] for x in inst.list_notes(
            category="findings", target="two.local")] == ["B"]

    def test_empty_content_raises(self, inst):
        with pytest.raises(ValueError):
            inst.add_note("findings", "t", "")

    def test_tags_roundtrip(self, inst):
        n = _note(inst, "findings", "t", "c", tags=["sql", "blind"])
        got = inst.get_note(n["id"])
        assert got["tags"] == ["sql", "blind"]

    def test_target_normalisation(self, inst):
        n = _note(inst, "findings", "t", "c", target="HTTP://Victim.Local:8080/x")
        assert n["target"] == "victim.local"


# ---------------------------------------------------------------------------
# Category normalisation
# ---------------------------------------------------------------------------

class TestCategoryNormalisation:
    def test_synonyms_map_to_canonical(self, inst):
        cases = {
            "vulnerability": "findings", "cve": "findings",
            "credential": "findings", "endpoints": "findings",
            "technique": "methodology", "tactics": "methodology",
            "plan": "active_plans", "strategy": "active_plans",
            "scope": "target_context", "intel": "target_context",
        }
        for alias, canon in cases.items():
            n = _note(inst, alias, "t", "c")
            assert n["category"] == canon, alias

    def test_unknown_category_falls_back_to_findings(self, inst):
        n = _note(inst, "random_stuff", "t", "c")
        assert n["category"] == "findings"

    def test_category_set_matches_constant(self, inst):
        assert set(INSTITUTIONAL_CATEGORIES) == {
            "findings", "methodology", "active_plans", "target_context"}


# ---------------------------------------------------------------------------
# consult()
# ---------------------------------------------------------------------------

class TestConsult:
    def test_empty_db_returns_empty(self, inst):
        assert inst.consult(target="victim.local") == ""
        assert inst.consult() == ""

    def test_target_sections_and_global_methodology(self, inst):
        _note(inst, "findings", "SQLi in login",
              "login.php has time-based blind SQLi, parameter id",
              target="victim.local")
        _note(inst, "target_context", "context: victim.local",
              "apache 2.4, php 7.4", target="victim.local")
        _note(inst, "methodology", "fuzz dirs",
              "use ffuf with wordlist for /api paths")
        out = inst.consult(target="victim.local")
        assert "[findings for victim.local]" in out
        assert "SQLi in login" in out
        assert "(target: victim.local)" in out
        assert "[context for victim.local]" in out
        assert "apache 2.4" in out
        assert "[methodology (global)]" in out
        assert "fuzz dirs" in out

    def test_other_target_not_injected(self, inst):
        _note(inst, "findings", "SQLi in login", "blind sqli",
              target="other.local")
        out = inst.consult(target="victim.local")
        assert "other.local" not in out
        assert "[findings for victim.local]" not in out

    def test_relevant_to_query_section(self, inst):
        _note(inst, "findings", "SQLi in login", "time-based blind sql injection",
              target="victim.local")
        _note(inst, "methodology", "fuzz dirs", "ffuf wordlist /api paths")
        out = inst.consult(target=None, query="blind sql injection")
        assert "relevant to 'blind sql injection'" in out
        assert "SQLi in login" in out

    def test_consult_no_query_still_shows_global(self, inst):
        _note(inst, "methodology", "fuzz dirs", "ffuf /api")
        out = inst.consult(target=None, query=None)
        assert "[methodology (global)]" in out
        assert "relevant to" not in out

    def test_size_limit_enforced(self, inst):
        for i in range(60):
            _note(inst, "methodology", "method %d" % i,
                  "note body %d with some padding text" % i)
        out = inst.consult(target=None, query=None, limit=4000)
        assert len(out) <= 4000 + 200  # header labels may slightly exceed
        assert out  # not empty

    def test_single_line_db_returns_empty(self, inst):
        # one finding + no query + no target -> only the findings group header
        # would render a single line; consult() must return ''.
        _note(inst, "findings", "only note", "only content",
              target="victim.local")
        out = inst.consult(target=None, query=None)
        assert out == ""


# ---------------------------------------------------------------------------
# notes_context / count / category_counts / record_finding / search
# ---------------------------------------------------------------------------

class TestAggregates:
    def test_count_and_category_counts(self, inst):
        _note(inst, "findings", "A", "a")
        _note(inst, "findings", "B", "b")
        _note(inst, "methodology", "C", "c")
        assert inst.count() == 3
        assert inst.category_counts() == {"findings": 2, "methodology": 1}

    def test_notes_context(self, inst):
        _note(inst, "findings", "A", "alpha content", target="one.local")
        _note(inst, "findings", "B", "beta content", target="one.local")
        out = inst.notes_context(category="findings", target="one.local")
        assert "A" in out and "B" in out
        assert inst.notes_context(target="nope.local") == ""

    def test_record_finding(self, inst):
        n = inst.record_finding("victim.local", "port 8443 open (nginx)",
                                tags=["port"])
        assert n["category"] == "findings"
        assert n["target"] == "victim.local"
        assert "auto-logged" in n["tags"]
        ctx = inst.list_notes(category="target_context", target="victim.local")
        assert ctx and ctx[0]["title"] == "context: victim.local"
        # re-recording refreshes the context entry instead of duplicating
        inst.record_finding("victim.local", "port 22 open (ssh)")
        ctx = inst.list_notes(category="target_context", target="victim.local")
        assert len(ctx) == 1
        assert "port 22" in ctx[0]["content"]

    def test_record_finding_requires_target(self, inst):
        with pytest.raises(ValueError):
            inst.record_finding("", "content")

    def test_search_notes_tfidf(self, inst):
        _note(inst, "findings", "SQLi in login",
              "time-based blind sql injection on login.php",
              target="victim.local")
        _note(inst, "findings", "other note",
              "certificate expiry policy review", target="other.local")
        hits = inst.search_notes("blind sql injection")
        assert hits and hits[0]["title"] == "SQLi in login"

    def test_search_notes_empty_query_returns_recent(self, inst):
        _note(inst, "findings", "A", "a")
        _note(inst, "findings", "B", "b")
        hits = inst.search_notes("")
        assert len(hits) == 2


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety:
    def test_concurrent_adds(self, inst):
        errors = []

        def worker(base):
            try:
                for i in range(10):
                    _note(inst, "findings", "note %s-%d" % (base, i),
                          "content %d" % i)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=("t%d" % i,))
                   for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors
        assert inst.count() == 50


# ---------------------------------------------------------------------------
# Agent-level: prompt injection + tools
# ---------------------------------------------------------------------------

class TestAgentIntegration:
    def test_doctrine_renders_without_keyerror(self, monkeypatch, inst):
        monkeypatch.setattr(core, "SYSTEM_PROMPT_FILE",
                            os.path.join(tempfile.gettempdir(),
                                         "_nonexistent_spt.txt"))
        agent = _agent(institutional=inst)
        p = agent._system_prompt()
        assert "{institutional_block}" not in p
        assert "{institutional_doctrine}" not in p
        assert "CROSS-CHAT INSTITUTIONAL MEMORY DOCTRINE" in p
        assert "MANDATORY CONSULTATION" in p
        assert "MANDATORY RECORDING" in p

    def test_doctrine_absent_without_institutional(self, monkeypatch):
        monkeypatch.setattr(core, "SYSTEM_PROMPT_FILE",
                            os.path.join(tempfile.gettempdir(),
                                         "_nonexistent_spt.txt"))
        agent = _agent(institutional=None, knowledge=None)
        p = agent._system_prompt()
        assert "CROSS-CHAT INSTITUTIONAL MEMORY DOCTRINE" not in p
        assert "MANDATORY CONSULTATION" not in p
        assert "MANDATORY RECORDING" not in p

    def test_findings_injected_for_target(self, monkeypatch, inst):
        _note(inst, "findings", "SQLi in login",
              "time-based blind sql injection, parameter id",
              target="victim.local")
        monkeypatch.setattr(core, "SYSTEM_PROMPT_FILE",
                            os.path.join(tempfile.gettempdir(),
                                         "_nonexistent_spt.txt"))
        agent = _agent(institutional=inst)
        p = agent._system_prompt()
        assert agent._kb_target == "victim.local"
        assert "SQLi in login" in p
        assert "[findings for victim.local]" in p

    def test_external_override_fallback_append(self, monkeypatch, inst, tmp_path):
        tpl = tmp_path / "system_prompt.txt"
        tpl.write_text("You are {name}, external override. No doctrine here.",
                       encoding="utf-8")
        monkeypatch.setattr(core, "SYSTEM_PROMPT_FILE", str(tpl))
        _note(inst, "findings", "SQLi in login", "blind sqli on login.php",
              target="victim.local")
        agent = _agent(institutional=inst)
        p = agent._system_prompt()
        assert "external override" in p
        assert "{institutional_block}" not in p
        assert "CROSS-CHAT INSTITUTIONAL MEMORY DOCTRINE" in p
        assert "SQLi in login" in p

    def test_notes_tools_registered(self, inst):
        tools = create_tools(None, knowledge=None, institutional=inst)
        names = {t.name for t in tools}
        assert {"notes_add", "notes_search", "notes_list", "notes_delete"} \
            <= names

    def test_notes_tools_guard_without_institutional(self):
        tools = create_tools(None, knowledge=None, institutional=None)
        by_name = {t.name: t for t in tools}
        assert "notes_add" in by_name
        out = by_name["notes_add"].func(category="findings", title="t",
                                         content="c")
        assert "not enabled" in out

    def test_notes_add_tool_roundtrip(self, inst):
        tools = create_tools(None, knowledge=None, institutional=inst)
        by_name = {t.name: t for t in tools}
        out = by_name["notes_add"].func(
            category="findings", title="open port 8080",
            content="admin panel on 8080", target="victim.local")
        assert "victim.local" in out
        rows = inst.list_notes(category="findings", target="victim.local")
        assert rows and rows[0]["title"] == "open port 8080"

    def test_subagent_inherits_institutional(self, inst):
        agent = _agent(institutional=inst)
        child, _ = agent._make_subagent("recon the target", name_suffix="-c")
        assert child.institutional is inst
        assert child.knowledge is agent.knowledge


# ---------------------------------------------------------------------------
# Target detection
# ---------------------------------------------------------------------------

class TestTargetDetection:
    def test_internal_tlds(self):
        assert _detect_kb_target("test victim.local for sql injection") \
            == "victim.local"
        assert _detect_kb_target("scan http://victim.local:8080") \
            == "victim.local"
        assert _detect_kb_target("target victim.local") == "victim.local"
        assert _detect_kb_target("fuzz internal.host.corp:8443") \
            == "internal.host.corp"
        assert _detect_kb_target("check admin.lab") == "admin.lab"
        assert _detect_kb_target("recon dc01.lan") == "dc01.lan"

    def test_public_tlds_and_ip_regression(self):
        assert _detect_kb_target("recon example.com") == "example.com"
        assert _detect_kb_target("test 192.168.1.10 please") == "192.168.1.10"
        assert _detect_kb_target("scan https://foo.io:8443/admin") == "foo.io"

    def test_no_target(self):
        assert _detect_kb_target("hi there") is None
        assert _detect_kb_target("no target here") is None
        assert _detect_kb_target("") is None
        assert _detect_kb_target(None) is None
