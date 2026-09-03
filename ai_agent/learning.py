"""Self-Learning store (F2).

The agent distills durable lessons from the way the user talks to it and
from the outcomes of its own runs, then re-injects them on later turns so
every conversation starts smarter than the last one.

What is stored (memory/learned_rules.json, gitignored runtime data):

  * explicit standing directives / preferences the user gave it
    ("always use -sT on that host", "never re-run the same payload twice",
     "jani, hamesha pehle scope check karo"),
  * lessons the agent deliberately archives via the learn_lesson tool.

Storage is a small JSON doc with dedupe, a relevance+recency ranking for
recall, and a hard cap so the file can never grow out of control.  All
methods are deterministic (no LLM required) so the store works offline and
is trivially unit-testable; an optional llm hook exists for richer
distillation but is never required for correctness.
"""

import json
import os
import re
import threading
import time

from .config import PROJECT_DIR

DEFAULT_STORE_FILE = "learned_rules.json"
MAX_ENTRIES = 300
MAX_TEXT = 240
SOURCE_USER = "user"
SOURCE_TOOL = "tool"

# Words that mark an imperative standing preference when they appear at the
# start of a sentence/chunk.  Roman-Urdu + English mix because that is how
# the operator actually talks to the agent.
_DIRECTIVE_START_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])("
    r"always|never|don'?t|do not|do n't|remember|please remember|"
    r"make sure|avoid|always use|always check|never use|har baar|"
    r"hamesha|kabhi nahi|kabhi mat|kabhi bhi nahi|kabhi bhi mat|"
    r"yaad rakho|yaad rakhen|zaroor|hamesha yaad rakho"
    r")\b"
)

# Salutations to strip from the front of a captured chunk.
_SALUTATION_RE = re.compile(
    r"^\s*(?:jani|janu|bhai|bhaijan|dost|yar|yaar|boss|sir|hey|ok|okay|"
    r"haan|ha|hmm|theek|acha|achha|chalo|abhi)(?=[,:!?\s-]|$)[,:!?\s-]*",
    re.IGNORECASE,
)

_WHITESPACE_RE = re.compile(r"\s+")
_TOKEN_RE = re.compile(r"[a-z0-9_]+")
_STOP = frozenset({
    "the", "and", "for", "are", "you", "your", "with", "that", "this",
    "have", "will", "was", "from", "not", "all", "but", "can", "what",
    "when", "then", "karo", "karna", "hai", "ko", "ki", "ka", "mein",
    "men", "per", "par", "se", "pe", "jani", "please", "should", "would",
    "is", "of", "to", "in", "it", "on", "do", "be", "or", "as", "at",
})


def _now():
    return time.time()


def _norm(text):
    """Normalise a rule text for dedupe comparisons."""
    return _WHITESPACE_RE.sub(" ", (text or "").strip().lower())


def _chunks(text):
    """Split operator text into sentence-ish chunks for directive scanning."""
    out = []
    for line in (text or "").splitlines():
        for part in re.split(r"[.!?\n]+", line):
            part = part.strip()
            if part:
                out.append(part)
    return out


def extract_directives(text):
    """Return standing-directive sentences found in ``text``.

    Deterministic and conservative: a chunk is a directive only when it
    starts with a strong imperative marker, is long enough to carry a real
    instruction, and short enough to be a preference (not a dump).
    """
    found = []
    for chunk in _chunks(text):
        m = _DIRECTIVE_START_RE.search(chunk)
        if not m:
            continue
        body = _SALUTATION_RE.sub("", chunk[m.start():]).strip()
        body = _WHITESPACE_RE.sub(" ", body).strip(" .,;:-")
        if not body:
            continue
        body = body[0].upper() + body[1:]
        if 12 <= len(body) <= MAX_TEXT + 40:
            found.append(body[:MAX_TEXT].rsplit(" ", 1)[0] + "…"
                         if len(body) > MAX_TEXT else body)
    # dedupe in order, keep first occurrence
    seen = set()
    out = []
    for d in found:
        key = _norm(d)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def _tokens(text):
    return [t for t in _TOKEN_RE.findall((text or "").lower())
            if t not in _STOP and len(t) > 2]


class SessionLearner:
    """Persistent self-learning store with dedupe, recall and caps."""

    def __init__(self, base_dir=None, store_file=None):
        base = base_dir or os.path.join(PROJECT_DIR, "memory")
        self._path = os.path.join(base, store_file or DEFAULT_STORE_FILE)
        self._lock = threading.RLock()
        self._entries = self._load()

    # ------------------------------------------------------------------ io

    def _load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return []
            entries = data.get("entries") or []
            if isinstance(entries, list):
                # guard against future/corrupt shapes
                entries = [e for e in entries if isinstance(e, dict)]
        except (OSError, ValueError):
            entries = []
        for e in entries:
            e.setdefault("weight", 1)
            e.setdefault("last_seen", e.get("ts", 0))
            e.setdefault("source", SOURCE_TOOL)
        return entries

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            payload = {"entries": self._entries,
                       "updated": _now()}
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self._path)
        except OSError:
            pass  # storage errors must never break the agent loop

    # ---------------------------------------------------------------- api

    def list_lessons(self, limit=100):
        with self._lock:
            rows = sorted(
                self._entries,
                key=lambda e: (e.get("last_seen") or 0),
                reverse=True)
            return rows[: max(0, min(limit, MAX_ENTRIES))]

    def add_lesson(self, text, source=SOURCE_TOOL, tags=None, target=""):
        """Add one durable lesson. Returns {"id":..,"added":bool} or raises
        ValueError for empty/oversized text."""
        text = _WHITESPACE_RE.sub(" ", (text or "").strip())
        if not text:
            raise ValueError("lesson text is empty")
        if len(text) > MAX_TEXT + 40:
            raise ValueError("lesson text too long (%d > %d)"
                             % (len(text), MAX_TEXT))
        text = text[:MAX_TEXT].rsplit(" ", 1)[0] + "…" \
            if len(text) > MAX_TEXT else text
        key = _norm(text)
        with self._lock:
            for e in self._entries:
                if _norm(e.get("text", "")) == key:
                    e["weight"] = int(e.get("weight") or 1) + 1
                    e["last_seen"] = _now()
                    e["tags"] = list(set(e.get("tags") or []) |
                                     set(tags or []))
                    if target:
                        e["target"] = target
                    self._save()
                    return {"id": e.get("id"), "added": False,
                            "weight": e["weight"]}
            rid = "lr-%06d" % (len(self._entries) + 1)
            rec = {"id": rid, "text": text,
                   "source": source or SOURCE_TOOL,
                   "tags": list(tags or []), "target": target or "",
                   "ts": _now(), "last_seen": _now(), "weight": 1}
            self._entries.append(rec)
            self._cap()
            self._save()
            return {"id": rid, "added": True, "weight": 1}

    def remove_lesson(self, lesson_id):
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries
                             if e.get("id") != lesson_id]
            removed = len(self._entries) != before
            if removed:
                self._save()
            return removed

    def _cap(self):
        if len(self._entries) <= MAX_ENTRIES:
            return
        # drop oldest-seen first (least likely to matter today)
        self._entries.sort(key=lambda e: (e.get("last_seen") or 0))
        del self._entries[: len(self._entries) - MAX_ENTRIES]

    # -------------------------------------------------------------- recall

    def _score(self, query_tokens, e):
        body = _tokens(e.get("text", ""))
        if not body:
            return 0.0
        overlap = len(set(query_tokens) & set(body))
        if not overlap:
            return 0.0
        weight = float(e.get("weight") or 1)
        age_days = max(0.0, (_now() - (e.get("last_seen") or e.get("ts")
                                       or _now()))) / 86400.0
        recency = max(0.0, 1.0 - age_days / 30.0)
        return overlap * (1.0 + 0.25 * weight) + 0.5 * recency

    def recall(self, query, top_k=6, min_score=0.0):
        """Best-matching durable lessons for the current context."""
        qt = _tokens(query or "")
        with self._lock:
            scored = [(self._score(qt, e), e) for e in self._entries]
        scored = [(s, e) for s, e in scored if s >= min_score]
        scored.sort(key=lambda pair: pair[0], reverse=True)
        out = []
        for score, e in scored[: max(0, min(top_k, MAX_ENTRIES))]:
            out.append({"score": round(score, 3),
                        "id": e.get("id"),
                        "text": e.get("text"),
                        "tags": e.get("tags") or [],
                        "source": e.get("source"),
                        "weight": e.get("weight")})
        return out

    def render_block(self, query, top_k=6, header="SELF-LEARNED"):
        """Return a [SELF-LEARNED] system block, or '' when nothing applies."""
        hits = self.recall(query, top_k=top_k, min_score=1.0)
        if not hits:
            return ""
        lines = ["[%s] Durable lessons I picked up in earlier conversations "
                 "(relevant to this message - apply unless the user says "
                 "otherwise):" % header]
        for h in hits:
            lines.append("- %s" % h["text"])
        return "\n".join(lines)

    # --------------------------------------------------------- distillation

    def _existing_keys(self):
        """Normalized texts of every stored lesson (under the lock)."""
        return {_norm(e.get("text", "")) for e in self._entries}

    def learn_from_messages(self, messages, target=""):
        """Scan past user messages for standing directives and persist any
        new ones. Returns the list of newly added rule ids.

        Idempotent: a directive that is already stored is skipped (no write,
        no weight bump), so calling this at the end of every turn never
        churns the store or grows weights for one-time instructions.
        """
        added = []
        for msg in messages or []:
            if not isinstance(msg, dict):
                continue
            if msg.get("role") != "user":
                continue
            content = msg.get("content") or ""
            if isinstance(content, list):  # content parts (rare)
                content = " ".join(str(p.get("text", "")) if isinstance(p, dict)
                                   else str(p) for p in content)
            for directive in extract_directives(content):
                with self._lock:
                    if _norm(directive) in self._existing_keys():
                        continue
                try:
                    res = self.add_lesson(directive, source=SOURCE_USER,
                                          tags=["standing-directive"],
                                          target=target or "")
                except ValueError:
                    continue
                if res.get("added"):
                    added.append(res.get("id"))
        return added


def default_learner():
    return SessionLearner()


# ---------------------------------------------------------------------------
# Tools (registered by ai_agent/tools/__init__.py).  ``base_dir`` is never
# exposed to the LLM - it exists so tests can point at a temp directory.
# ---------------------------------------------------------------------------


def tool_learn_lesson(text="", tags="", base_dir=None):
    """Deliberately archive a durable lesson the agent just learned."""
    text = (text or "").strip()
    if not text:
        return ("Error: learn_lesson needs the lesson text, e.g. "
                "learn_lesson(text='nuclei template x returns false "
                "positives on this target; verify manually first', "
                "tags='methodology').")
    learner = SessionLearner(base_dir=base_dir)
    tag_list = [t.strip() for t in (tags or "").split(",")
                if t.strip()]
    try:
        res = learner.add_lesson(text, source=SOURCE_TOOL, tags=tag_list)
    except ValueError as exc:
        return "Error: %s" % exc
    verb = "stored" if res.get("added") else "already known (weight bumped)"
    return "Lesson %s (%s): %s" % (res.get("id"), verb, text[:200])
