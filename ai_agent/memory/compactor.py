"""Context Auto-Compaction Engine (Phase 1).

The agent's working window is finite, but its missions are not.  This module
implements the compactor layer that lets a session run indefinitely:

1. A sliding token-window manager measures live context usage and flags the
   moment it crosses the 70% threshold (``DEFAULT_COMPACTION_THRESHOLD``).
2. When the threshold is crossed, an automated summarization pipeline distills
   the older raw turns into *structured key-finding nodes* (kind:
   ``finding`` / ``decision`` / ``action`` / ``context``) so the high-signal
   substance survives compaction in a machine-usable shape.
3. A condensed system note (rendered from those nodes) is injected at the head
   of the prompt while the old raw messages are purged, keeping the agent
   coherent across arbitrarily long engagements.

The deterministic digest never depends on the network; an optional
``llm_summarizer`` callback may be supplied to upgrade synthesis quality when a
model is reachable.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Callable, Dict, List, Optional

from ..config import PROJECT_DIR

# --------------------------------------------------------------------------
# Tunables
# --------------------------------------------------------------------------
DEFAULT_MAX_TOKENS = 32000            # sliding-window working budget (tokens)
DEFAULT_COMPACTION_THRESHOLD = 0.70   # 70% watermark -> compact

_STORE_FILE = "compaction_history.json"
_MAX_PER_TARGET = 4      # ring size per target
_MAX_TARGETS = 12        # hard cap so the store can never grow unbounded
_DEFAULT_BUDGET = 1200   # chars for the deterministic digest

_TOKENS_PER_CHAR = 4.0
_MSG_OVERHEAD_CHARS = 40  # per-message framing overhead proxy

# High-signal tokens used by the deterministic node builder (findings,
# decisions, commands and results survive even when no LLM is reachable).
_SIGNAL_RE = re.compile(
    r"https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|cve-|port \d+|\bopen\b|"
    r"\bfound\b|password|token|session|key=|cracked|logged|FOUND|SUMMARY|"
    r"vulnerab|\bdenied\b|success|fail|conclusion|decision|decided|"
    r"\bchosen\b|\bchose\b",
    re.IGNORECASE,
)
_DECISION_RE = re.compile(
    r"\b(decision|decided|conclusion|concluded|chosen|chose|final answer|"
    r"next step|plan:)\b",
    re.IGNORECASE,
)

Node = Dict[str, object]  # {"kind": str, "text": str}


# --------------------------------------------------------------------------
# Token accounting helpers
# --------------------------------------------------------------------------
def estimate_tokens(text: str) -> int:
    """Cheap deterministic token estimate (~4 chars per token)."""
    return max(1, len(str(text or "")) // _TOKENS_PER_CHAR)


def estimate_chars(messages) -> int:
    """Char-weight of a message list (kept for legacy callers)."""
    total = 0
    for m in messages or []:
        content = _content_of(m)
        total += len(content) + _MSG_OVERHEAD_CHARS
    return total


def estimate_tokens_for_messages(messages) -> int:
    """Token weight of a message list, including framing overhead."""
    total = 0
    for m in messages or []:
        total += estimate_tokens(_content_of(m))
        total += _MSG_OVERHEAD_CHARS // 4
    return total


def _content_of(message) -> str:
    """Normalise a message dict/str to its text payload."""
    if isinstance(message, dict):
        content = message.get("content") or ""
    elif isinstance(message, str):
        content = message
    else:
        content = ""
    if isinstance(content, list):  # content parts (rare: vision/tool images)
        content = " ".join(
            str(p.get("text", "")) if isinstance(p, dict) else str(p)
            for p in content)
    return str(content)


# --------------------------------------------------------------------------
# Structured summarization pipeline -> key-finding nodes
# --------------------------------------------------------------------------
def _node(kind: str, text: str) -> Node:
    return {"kind": kind, "text": text.strip()[:400]}


def build_keyfinding_nodes(messages) -> List[Node]:
    """Distill raw turns into structured nodes.

    Classification is deterministic and high-recall: findings carry evidence
    (URLs, ports, creds, results), decisions carry the operator's conclusions,
    actions carry what was executed, and the rest becomes lightweight context.
    """
    nodes: List[Node] = []
    tools: List[str] = []
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        role = m.get("role", "")
        content = _content_of(m).strip()
        if not content or role == "system":
            continue
        if role == "tool":
            name = (m.get("name") or "").strip()
            if name and name not in tools:
                tools.append(name)
            continue
        # pick the most signal-dense line of a long message
        lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
        chosen = next((ln[:300] for ln in lines if _SIGNAL_RE.search(ln)),
                      (lines[0] if lines else content)[:220])
        if role == "user":
            nodes.append(_node("context", "asked: %s" % chosen[:180]))
        elif role == "assistant":
            if _DECISION_RE.search(chosen):
                nodes.append(_node("decision", chosen))
            elif _SIGNAL_RE.search(chosen):
                nodes.append(_node("finding", chosen))
            else:
                nodes.append(_node("context", chosen[:160]))
    for name in tools:
        nodes.append(_node("action", "tool invoked: %s" % name))
    return nodes


def render_nodes(nodes: List[Node], budget: int = _DEFAULT_BUDGET) -> str:
    """Render structured nodes into one condensed prompt-head system note."""
    lines = ["[AUTO-COMPACTED HISTORY — prior turns distilled; act on these]"]
    size = len(lines[0])
    for nd in nodes:
        kind = nd.get("kind", "context")
        text = str(nd.get("text", "")).strip()
        if not text:
            continue
        line = "- [%s] %s" % (kind, text)
        if size + len(line) > budget:
            break
        lines.append(line)
        size += len(line) + 1
    return "\n".join(lines)


def summarize_history(messages, budget: int = _DEFAULT_BUDGET,
                      llm_summarizer: Optional[Callable] = None):
    """Automated summarization pipeline.

    Returns ``(nodes, note)``.  When ``llm_summarizer`` is provided it is
    called with the raw messages and its output is used as the note; the
    deterministic node pipeline always remains as the fallback.
    """
    nodes = build_keyfinding_nodes(messages)
    if llm_summarizer is not None:
        try:
            note = str(llm_summarizer(messages) or "").strip()
            if note:
                return nodes, note[:budget * 4]
        except Exception:
            pass  # network/model failure must never stall the loop
    return nodes, render_nodes(nodes, budget=budget)


# --------------------------------------------------------------------------
# Sliding-window token manager
# --------------------------------------------------------------------------
class Compactor:
    """Owns the sliding window, the threshold check and the prune+inject step.

    Typical flow inside the agent loop::

        if compactor.should_compact(history):
            history = compactor.compact(history)["messages"]
    """

    def __init__(self, max_tokens: int = DEFAULT_MAX_TOKENS,
                 threshold: float = DEFAULT_COMPACTION_THRESHOLD,
                 store: Optional["CompactionStore"] = None,
                 target: Optional[str] = None,
                 llm_summarizer: Optional[Callable] = None,
                 keep_recent_ratio: float = 0.55,
                 min_keep_messages: int = 4):
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        if not 0.0 < threshold <= 1.0:
            raise ValueError("threshold must be in (0, 1]")
        self.max_tokens = max_tokens
        self.threshold = threshold
        self.store = store
        self.target = target
        self.llm_summarizer = llm_summarizer
        self.keep_recent_ratio = keep_recent_ratio
        self.min_keep_messages = min_keep_messages
        self._stats = {"compactions": 0, "purged": 0}

    # -- window accounting -------------------------------------------------
    def usage_ratio(self, messages) -> float:
        """Active context usage vs. the window budget, in [0, 1]."""
        used = estimate_tokens_for_messages(messages)
        return min(1.0, used / self.max_tokens)

    def should_compact(self, messages, threshold: Optional[float] = None) -> bool:
        """True once active context usage reaches the watermark."""
        return self.usage_ratio(messages) >= (threshold or self.threshold)

    # -- compaction --------------------------------------------------------
    def _sliding_cut(self, messages) -> int:
        """Index where history ends and the live tail begins.

        Keeps the newest ``min_keep_messages`` turns unconditionally, then
        grows the tail until the post-compaction budget (max_tokens) is full.
        Everything before the cut is what gets distilled and purged.
        """
        msgs = list(messages or [])
        n = len(msgs)
        if n <= self.min_keep_messages:
            return 0
        budget = int(self.max_tokens * self.keep_recent_ratio)
        used = 0
        cut = n
        for i in range(n - 1, -1, -1):
            tok = estimate_tokens(_content_of(msgs[i])) + _MSG_OVERHEAD_CHARS // 4
            # always protect the most recent min_keep_messages turns
            if i < n - self.min_keep_messages and used + tok > budget:
                cut = i + 1
                break
            used += tok
        # never summarise more than 90% of the window in one pass
        return max(0, min(cut - 1, int(n * 0.9))) if cut > 0 else 0

    def compact(self, messages, force: bool = False) -> Dict[str, object]:
        """Prune + inject.

        Distills the overflowing older turns into structured nodes, injects
        the condensed system note at the prompt head, and returns the pruned
        history alongside full statistics.
        """
        msgs = list(messages or [])
        usage_before = self.usage_ratio(msgs)
        if not force and not self.should_compact(msgs):
            return {"messages": msgs, "system_note": "", "nodes": [],
                    "purged": 0, "usage_before": usage_before,
                    "usage_after": usage_before, "compacted": False}

        cut = self._sliding_cut(msgs) if len(msgs) > self.min_keep_messages else 0
        old = msgs[:cut] if cut else msgs[:max(0, len(msgs) - self.min_keep_messages)]
        if not old:
            return {"messages": msgs, "system_note": "", "nodes": [],
                    "purged": 0, "usage_before": usage_before,
                    "usage_after": usage_before, "compacted": False}

        nodes, note = summarize_history(old, llm_summarizer=self.llm_summarizer)
        tail = msgs[len(old):]
        pruned = [{"role": "system", "content": note}] + tail
        if self.store is not None:
            try:
                self.store.record(self.target, note)
            except Exception:
                pass  # persistence failure must never break the agent loop
        self._stats["compactions"] += 1
        self._stats["purged"] += len(old)
        return {"messages": pruned, "system_note": note, "nodes": nodes,
                "purged": len(old), "usage_before": usage_before,
                "usage_after": self.usage_ratio(pruned), "compacted": True}


# --------------------------------------------------------------------------
# Persistence (per-target rolling digest store)
# --------------------------------------------------------------------------
class CompactionStore:
    """Per-target rolling digest store (memory/compaction_history.json).

    Follow-up sessions consult the latest digest so long missions survive
    process restarts.  File size is ring-capped and every write is atomic.
    """

    def __init__(self, base_dir: Optional[str] = None):
        base = base_dir or os.path.join(PROJECT_DIR, "memory")
        self._dir = base
        self._path = os.path.join(base, _STORE_FILE)
        self._data = self._load()

    def _load(self) -> Dict[str, object]:
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and isinstance(data.get("targets"), dict):
                return data
        except (OSError, ValueError):
            pass
        return {"targets": {}, "updated": time.time()}

    def _save(self) -> None:
        try:
            os.makedirs(self._dir, exist_ok=True)
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self._path)
        except OSError:
            pass  # storage failure must never break the agent loop

    def record(self, target: Optional[str], digest: str) -> None:
        """Append one digest for a target (ring-capped, size guarded)."""
        if not digest or not digest.strip():
            return
        key = (target or "default").strip() or "default"
        bucket = self._data["targets"].setdefault(key, [])  # type: ignore
        bucket.append({"ts": time.time(), "digest": digest[:1500]})
        self._data["targets"][key] = bucket[-_MAX_PER_TARGET:]  # type: ignore
        targets = self._data["targets"]  # type: ignore
        if len(targets) > _MAX_TARGETS:
            order = sorted(targets.items(),
                           key=lambda kv: kv[1][-1].get("ts", 0))
            self._data["targets"] = dict(order[-_MAX_TARGETS:])  # type: ignore
        self._data["updated"] = time.time()
        self._save()

    def consult(self, target: Optional[str], max_chars: int = 800) -> str:
        """Latest digest for a target (falls back to the 'default' bucket)."""
        key = (target or "default").strip() or "default"
        bucket = (self._data["targets"].get(key)  # type: ignore
                  or self._data["targets"].get("default") or [])  # type: ignore
        if not bucket:
            return ""
        return (bucket[-1].get("digest") or "")[:max_chars]

    def count(self, target: Optional[str] = None) -> int:
        key = (target or "default").strip() or "default"
        if target is None:
            return sum(len(v) for v in self._data["targets"].values())  # type: ignore
        return len(self._data["targets"].get(key, []))  # type: ignore


def extractive_digest(messages, budget: int = _DEFAULT_BUDGET) -> str:
    """Deterministic digest (legacy callers).  Now routed through nodes."""
    nodes = build_keyfinding_nodes(messages)
    return render_nodes(nodes, budget=budget)


__all__ = [
    "Compactor", "CompactionStore", "DEFAULT_MAX_TOKENS",
    "DEFAULT_COMPACTION_THRESHOLD", "estimate_tokens",
    "estimate_tokens_for_messages", "estimate_chars", "build_keyfinding_nodes",
    "render_nodes", "summarize_history", "extractive_digest",
]
