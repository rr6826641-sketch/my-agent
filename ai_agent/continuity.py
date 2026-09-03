"""Mission continuity store (F3).

Long red-team engagements routinely exceed a single conversation turn:
the max-iteration budget runs out, the web UI is closed, or the operator
just stops answering.  Without extra machinery that progress is lost.

This module gives the agent an auto-maintained checkpoint file
(memory/checkpoints.json, gitignored runtime data) so a paused mission
can be resumed in a later turn - including after a process restart:

  * when a run hits max iterations the Agent auto-saves a compact
    progress log (objective + recent messages) into the store;
  * on a later message that reads like a continuation ("continue",
    "jari rakho", "aage barhao", "next step" ...) the Agent injects a
    [MISSION RESUME] block that tells the LLM exactly where it stopped;
  * when the resumed turn completes normally the mission is archived as
    finished; a second exhaustion just refreshes the checkpoint.

Only ONE mission is active at a time (single active slot + bounded
history) so the behaviour is predictable: starting a different task
supersedes the old paused mission, which is preserved in the archive.

All methods are deterministic, lock-guarded and swallow storage errors,
so the continuity engine can never break the agent loop.
"""

import json
import os
import re
import threading
import time

from .config import PROJECT_DIR

DEFAULT_STORE_FILE = "checkpoints.json"
MAX_ACTIVE_OBJECTIVE = 500
MAX_NEXT_STEPS = 1200
MAX_PROGRESS_CHARS = 6000
MAX_MESSAGE_CHARS = 500
MAX_HISTORY = 20

# Words/phrases that mark a follow-up message as a continuation request
# (English + Roman-Urdu, because that is how the operator talks to it).
_CONTINUATION_RE = re.compile(
    r"(?i)(?:^|[^a-z])("
    r"continue|continuing|proceed|resume|keep going|keep on|carry on|"
    r"go ahead|go on|pick up where|pick up from|where were we|where did we|"
    r"next step|next steps|next part|remaining|rest of the|what next|"
    r"whats next|part 2|part two|"
    r"jari|jaari|jari rakho|jaari rakho|jari karo|aage|agay|"
    r"aage barhao|agay barhao|aage se|agla|agla step|agla kaam|agli|"
    r"phir|phir se|phir karo|phir wahi|wahi kaam|wahi task|same task|"
    r"same kaam|kahan tak|kahan tk|kahan pohanch|resume karo|"
    r"continue karo|proceed karo"
    r")(?:[^a-z]|$)"
)

_WHITESPACE_RE = re.compile(r"\s+")


def _now():
    return time.time()


def looks_like_continuation(text):
    """Heuristic: does this operator message ask to continue earlier work?"""
    return bool(_CONTINUATION_RE.search(text or ""))


def _compact(text, limit):
    text = _WHITESPACE_RE.sub(" ", (text or "").strip())
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "…"


class MissionCheckpointStore:
    """Single-active-mission checkpoint store with a bounded archive."""

    def __init__(self, base_dir=None, store_file=None):
        base = base_dir or os.path.join(PROJECT_DIR, "memory")
        self._path = os.path.join(base, store_file or DEFAULT_STORE_FILE)
        self._lock = threading.RLock()
        self._active, self._history = self._load()

    # ------------------------------------------------------------------ io

    def _load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            active = data.get("active")
            history = data.get("history") or []
            if not isinstance(active, dict):
                active = None
            if not isinstance(history, list):
                history = []
            return active, [h for h in history if isinstance(h, dict)]
        except (OSError, ValueError):
            return None, []

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            payload = {"active": self._active,
                       "history": self._history[-MAX_HISTORY:],
                       "updated": _now()}
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self._path)
        except OSError:
            pass  # persistence must never break the agent loop

    # ---------------------------------------------------------------- api

    def active(self):
        with self._lock:
            return dict(self._active) if self._active else None

    def active_id(self):
        with self._lock:
            return (self._active or {}).get("id")

    def save(self, objective, progress="", next_steps="", context=None,
             status="active"):
        """Persist/refresh the active mission checkpoint.

        Same objective  -> refresh the active record in place.
        New objective   -> the old paused mission is archived as
                           'stopped' (superseded) and the new one becomes
                           active, so the store never silently mixes two
                           missions.  Returns the active record id.
        """
        objective = _compact(objective, MAX_ACTIVE_OBJECTIVE)
        progress = _compact(progress or "", MAX_PROGRESS_CHARS)
        next_steps = _compact(next_steps or "", MAX_NEXT_STEPS)
        if not objective and not progress:
            raise ValueError("checkpoint needs an objective or progress text")
        if not objective:
            objective = "[task in progress]"
        now = _now()
        with self._lock:
            act = self._active
            if act is not None and act.get("objective") != objective:
                self._archive_locked(act.get("id"), "stopped",
                                     reason="superseded by a new objective")
                act = None
            if act is None:
                rid = "m-%08x" % (int(now * 1000) % 0xFFFFFFFF)
                act = {"id": rid, "objective": objective,
                       "progress": progress, "next_steps": next_steps,
                       "context": dict(context or {}),
                       "status": status or "active",
                       "created": now, "updated": now}
                self._active = act
            else:
                act["objective"] = objective
                act["progress"] = progress
                act["next_steps"] = next_steps
                if context:
                    act["context"] = dict(context or {})
                act["status"] = status or "active"
                act["updated"] = now
            self._save()
            return {"id": act["id"], "objective": objective, "status": act["status"]}

    def _archive_locked(self, cid, status, reason=""):
        act = self._active
        if act is None or (cid is not None and act.get("id") != cid):
            return False
        if cid is None:
            cid = act.get("id")
        act["status"] = status
        act["finished"] = _now()
        act["finish_reason"] = reason
        self._history.append(act)
        self._history = self._history[-MAX_HISTORY:]
        self._active = None
        return True

    def finish(self, cid=None, status="finished"):
        """Archive the active mission (finished/done). True if one was active."""
        with self._lock:
            if self._active is None:
                return False
            done = self._archive_locked(cid, status or "finished",
                                        reason="mission completed")
            if done:
                self._save()
            return done

    # ------------------------------------------------------------- render

    def render_resume_block(self, cid=None, query=""):
        """Return a [MISSION RESUME] system block, or '' when nothing to resume."""
        act = self.active()
        if act is None or (cid is not None and act.get("id") != cid):
            return ""
        lines = [
            "[MISSION RESUME] You started this task in an earlier session "
            "and it was paused before completion. Resume it NOW - read the "
            "progress log below, pick up exactly where it stops, and do NOT "
            "restart the work from scratch.",
            "Objective  : %s" % (act.get("objective") or "(unspecified)"),
        ]
        progress = act.get("progress") or ""
        if progress:
            lines.append("Progress so far (auto-compacted log of what already "
                         "ran / was decided):\n%s" % progress)
        next_steps = act.get("next_steps") or ""
        lines.append("Next steps: %s" % (next_steps or
                     "- continue from the end of the progress log above"))
        return "\n".join(lines)

    def status_text(self):
        """Human/LLM-readable status line for the mission_status tool."""
        act = self.active()
        if act is None:
            return ("No paused mission. Long tasks that exhaust the iteration "
                    "budget are auto-checkpointed and can be resumed with "
                    "'continue'.")
        return ("Active mission %s | objective: %s | paused at %s | progress "
                "bytes: %d | send 'continue' to resume it."
                % (act.get("id"), (act.get("objective") or "")[:160],
                   time.strftime("%Y-%m-%d %H:%M:%S",
                                 time.localtime(act.get("updated") or _now())),
                   len(act.get("progress") or "")))

    def history_count(self):
        with self._lock:
            return len(self._history)

    # ------------------------------------------------------------ helpers

    @staticmethod
    def progress_from_messages(messages, max_messages=40,
                               char_budget=MAX_PROGRESS_CHARS):
        """Compact the recent conversation into a resume-able progress log.

        Returns (progress_text, next_steps_text).  Deterministic, bounded:
        only the last ``max_messages`` entries are used, each line is
        truncated, and the total never exceeds ``char_budget``.
        """
        lines = []
        used = 0
        prefix = {"user": "U", "assistant": "A", "tool": "T",
                  "system": "S"}
        for msg in (messages or [])[-max_messages:]:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content") or ""
            if isinstance(content, list):
                content = " ".join(
                    str(p.get("text", "")) if isinstance(p, dict)
                    else str(p) for p in content)
            content = _compact(content, MAX_MESSAGE_CHARS)
            if not content:
                continue
            role = prefix.get(msg.get("role"), "?")
            line = "%s| %s" % (role, content)
            room = char_budget - used
            if room <= 0:
                break
            if len(line) > room:
                line = _compact(line, room)
            lines.append(line)
            used += len(line) + 1
        return "\n".join(lines), ""


def default_store():
    return MissionCheckpointStore()


# ---------------------------------------------------------------------------
# Tools (registered by ai_agent/tools/__init__.py).  ``base_dir`` is never
# exposed to the LLM - it exists so tests can point at a temp directory.
# ---------------------------------------------------------------------------


def tool_save_progress(objective="", progress="", next_steps="", base_dir=None):
    """Persist a manual progress checkpoint for the current task."""
    store = MissionCheckpointStore(base_dir=base_dir)
    try:
        res = store.save(objective or "", progress or "", next_steps or "",
                         context={"source": "tool"})
    except ValueError as exc:
        return "Error: %s" % exc
    return ("Checkpoint saved: mission %s active - objective: %s. If the "
            "task later gets stopped/exhausted, say 'continue' and the "
            "agent will resume from here."
            % (res["id"], (res["objective"] or "")[:200]))


def tool_mission_status(base_dir=None):
    """Show whether a paused mission exists and what it contains."""
    store = MissionCheckpointStore(base_dir=base_dir)
    return store.status_text()


def tool_finish_mission(base_dir=None):
    """Mark the currently paused mission as finished/complete."""
    store = MissionCheckpointStore(base_dir=base_dir)
    if store.finish():
        return "Paused mission archived as finished. Checkpoint cleared."
    return "No paused mission to finish."
