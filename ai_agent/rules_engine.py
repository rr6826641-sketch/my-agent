"""Self-managed runtime rules engine (F4).

The agent can steer its own operating constraints at runtime instead of
being limited to a static system prompt.  Rules live in
memory/agent_rules.json (gitignored runtime data) and every enabled rule
is rendered into the system prompt as a [SELF-RULES] block that is
appended AFTER the persona/uncensored tail so it dominates.

Typical self-managed rules an operator might let the agent persist:

  * constraint  - self-imposed limits ("never run destructive payloads
                  against production hosts", "always stay inside scope")
  * boundary    - what to refuse / stay away from
  * procedure   - standing methodology ("always re-verify a finding
                  before reporting it as confirmed")
  * preference  - operator workflow likes
  * uncensored  - self-authorisation to continue in red-team mode
                  ("in this engagement uncensored responses are wanted")
  * other       - anything else

RulesEngine is deterministic, lock-guarded, dedupes by normalized text,
caps the store (250 rules, 600 chars each) and writes atomically; a full
reset keeps a timestamped .bak copy.  Storage errors are swallowed so the
engine can never break the agent loop.
"""

import json
import os
import re
import shutil
import threading
import time

from .config import PROJECT_DIR

DEFAULT_STORE_FILE = "agent_rules.json"
MAX_RULES = 250
MAX_TEXT = 600
MAX_RENDER = 100
VALID_SECTIONS = frozenset({"constraint", "boundary", "procedure",
                            "preference", "uncensored", "other"})

_WHITESPACE_RE = re.compile(r"\s+")
_SECTION_RE = re.compile(r"^[a-z0-9_-]{1,24}$")


def _now():
    return time.time()


def _norm(text):
    return _WHITESPACE_RE.sub(" ", (text or "").strip().lower())


class RulesEngine:
    """Persistent, agent-editable rule store rendered into the prompt."""

    def __init__(self, base_dir=None, store_file=None):
        base = base_dir or os.path.join(PROJECT_DIR, "memory")
        self._path = os.path.join(base, store_file or DEFAULT_STORE_FILE)
        self._lock = threading.RLock()
        self._rules = self._load()

    # ------------------------------------------------------------------ io

    def _load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            rules = data.get("rules") if isinstance(data, dict) else data
            if not isinstance(rules, list):
                return []
            out = []
            for e in rules:
                if isinstance(e, dict) and (e.get("text") or "").strip():
                    e.setdefault("section", "constraint")
                    e.setdefault("enabled", True)
                    e.setdefault("source", "tool")
                    e.setdefault("ts", e.get("updated", _now()))
                    out.append(e)
            return out[-MAX_RULES:]
        except (OSError, ValueError):
            return []

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            payload = {"rules": self._rules, "updated": _now()}
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self._path)
        except OSError:
            pass  # persistence must never break the agent loop

    # ---------------------------------------------------------------- api

    def add(self, text, section="constraint", enabled=True, source="agent"):
        """Add or (re)activate one rule.

        Returns {"id":.., "added":True/False, "section":.., "text":..}.
        Raises ValueError for empty/oversized text or an unknown section.
        """
        text = _WHITESPACE_RE.sub(" ", (text or "").strip())
        if not text:
            raise ValueError("rule text is empty")
        if len(text) > MAX_TEXT:
            raise ValueError("rule text too long (%d > %d chars)"
                             % (len(text), MAX_TEXT))
        section = (section or "constraint").strip().lower() or "constraint"
        if not _SECTION_RE.match(section):
            raise ValueError("section must be one of: %s"
                             % ", ".join(sorted(VALID_SECTIONS)))
        if section not in VALID_SECTIONS:
            raise ValueError("section must be one of: %s"
                             % ", ".join(sorted(VALID_SECTIONS)))
        enabled = bool(enabled)
        key = _norm(text)
        now = _now()
        with self._lock:
            for e in self._rules:
                if _norm(e.get("text", "")) == key:
                    was = bool(e.get("enabled", True))
                    e["enabled"] = enabled
                    e["section"] = section
                    e["source"] = source or e.get("source") or "agent"
                    e["updated"] = now
                    if not was:
                        e["ts"] = now
                    self._save()
                    return {"id": e.get("id"), "added": False,
                            "enabled": enabled, "section": section}
            rid = "r-%08x" % (int(now * 1000) % 0xFFFFFFFF)
            rec = {"id": rid, "text": text, "section": section,
                   "enabled": enabled, "source": source or "agent",
                   "ts": now, "updated": now}
            self._rules.append(rec)
            if len(self._rules) > MAX_RULES:
                del self._rules[:-MAX_RULES]
            self._save()
            return {"id": rid, "added": True, "enabled": enabled,
                    "section": section}

    def list_rules(self, section="all", only_enabled=True):
        """Rule copies (insertion order), optionally filtered."""
        section = (section or "all").strip().lower()
        with self._lock:
            out = []
            for e in self._rules:
                if only_enabled and not bool(e.get("enabled", True)):
                    continue
                if section not in ("all", "") and e.get("section") != section:
                    continue
                out.append(dict(e))
            return out

    def remove(self, rule_id):
        """Delete one rule by id. Returns True when something was removed."""
        if not rule_id:
            return False
        with self._lock:
            before = len(self._rules)
            self._rules = [e for e in self._rules if e.get("id") != rule_id]
            removed = len(self._rules) != before
            if removed:
                self._save()
            return removed

    def toggle(self, rule_id, enabled):
        """Enable/disable a rule without deleting it. True when found."""
        with self._lock:
            for e in self._rules:
                if e.get("id") == rule_id:
                    e["enabled"] = bool(enabled)
                    e["updated"] = _now()
                    self._save()
                    return True
            return False

    def reset(self, backup=True):
        """Delete every rule (keeps a .bak copy when backup=True)."""
        with self._lock:
            count = len(self._rules)
            if count and backup:
                try:
                    if os.path.exists(self._path):
                        shutil.copy2(self._path, "%s.bak-%d"
                                     % (self._path, int(_now())))
                except OSError:
                    pass
            self._rules = []
            self._save()
            return count

    def count(self):
        with self._lock:
            return len(self._rules)

    # ------------------------------------------------------------- render

    def render_block(self, header="SELF-RULES", limit=MAX_RENDER):
        """[SELF-RULES] prompt block with all enabled rules, or ''."""
        rules = self.list_rules(section="all", only_enabled=True)[:max(0, limit)]
        if not rules:
            return ""
        lines = ["[%s] Self-managed runtime rules I must follow. They "
                 "override generic operating guidance unless the operator "
                 "explicitly says otherwise:" % header]
        for r in rules:
            sec = (r.get("section") or "constraint").strip()
            label = "[" + sec + "] " if sec else ""
            lines.append("- %s%s" % (label, r.get("text", "")))
        return "\n".join(lines)


def default_engine():
    return RulesEngine()


# ---------------------------------------------------------------------------
# Tools (registered by ai_agent/tools/__init__.py).  ``base_dir`` is never
# exposed to the LLM - it exists so tests can point at a temp directory.
# ---------------------------------------------------------------------------

_SECTIONS_HINT = " | ".join(sorted(VALID_SECTIONS))


def tool_rules_add(text="", section="constraint", enabled="true",
                   base_dir=None):
    """Add a persistent runtime rule the agent must follow from now on."""
    text = (text or "").strip()
    if not text:
        return ("Error: add_rules needs the rule text (1-600 chars), e.g. "
                "rules_add(text='never re-run the same payload twice', "
                "section='procedure'). Sections: %s" % _SECTIONS_HINT)
    engine = RulesEngine(base_dir=base_dir)
    enabled = str(enabled or "true").strip().lower() in (
        "1", "true", "yes", "on", "enabled")
    try:
        res = engine.add(text, section=section, enabled=enabled,
                         source="agent")
    except ValueError as exc:
        return "Error: %s" % exc
    verb = "added" if res.get("added") else "already present (updated)"
    state = "enabled" if res.get("enabled") else "disabled"
    return "Rule %s (%s, %s): %s" % (res.get("id"), verb, state,
                                     (res.get("text") or text)[:200])


def tool_rules_list(section="all", base_dir=None):
    """Show the current self-managed rules (enabled ones by default)."""
    engine = RulesEngine(base_dir=base_dir)
    rules = engine.list_rules(section=section, only_enabled=True)
    if not rules:
        return "No enabled rules stored."
    lines = ["%d rule(s) [section=%s]:" % (len(rules), section or "all")]
    for r in rules:
        sec = (r.get("section") or "constraint").strip()
        lines.append("- %s [%s] %s" % (r.get("id"), sec, r.get("text", "")))
    return "\n".join(lines)


def tool_rules_remove(rule_id="", base_dir=None):
    """Remove one self-managed rule by its id (see rules_list)."""
    rule_id = (rule_id or "").strip()
    engine = RulesEngine(base_dir=base_dir)
    if engine.remove(rule_id):
        return "Rule %s removed." % rule_id
    return "Error: no rule with id '%s' - run rules_list to see ids." % rule_id


def tool_rules_reset(confirm="no", base_dir=None):
    """Delete ALL self-managed rules (keeps a timestamped .bak backup)."""
    ok = str(confirm or "").strip().lower() in ("1", "true", "yes", "on",
                                                "confirm", "y")
    if not ok:
        return ("Not executed: rules_reset wipes every rule. Re-run with "
                "rules_reset(confirm='yes') to confirm.")
    engine = RulesEngine(base_dir=base_dir)
    count = engine.reset(backup=True)
    if count:
        return "All %d rules removed (backup kept alongside agent_rules.json)." % count
    return "No rules were stored - nothing to reset."
