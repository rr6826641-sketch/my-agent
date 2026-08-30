"""On-demand skill library: search and load pentest methodology guides.

The library lives in ai_agent/skills/. Each skill is a folder containing a
skill.json (metadata) and a guide.md (methodology). Skills are discovered
dynamically on every call, so adding a new skill needs no registry change.

The agent is instructed to load at most 1-5 relevant skills per task context
instead of relying on a bloated static system prompt.
"""

import json
import re
from pathlib import Path

from .base import truncate

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"
MAX_GUIDE_CHARS = 24000
DEFAULT_SEARCH_LIMIT = 5
MAX_SEARCH_LIMIT = 10

_STOPWORDS = frozenset(
    "the a an and or of to in on for with by at from is are was were be been "
    "being it its this that these those as but not no you your i we they he "
    "she them their will would can could should may might do does did has have "
    "had which who whom what when where how why then than so such only also "
    "other new more most some any all each few both own same about into over "
    "under between after before".split()
)


def _tokenize(text: str) -> set:
    """Lowercased alphanumeric tokens minus stopwords (len > 1)."""
    if not text:
        return set()
    tokens = re.findall(r"[a-z0-9]+", str(text).lower())
    return {t for t in tokens if len(t) > 1 and t not in _STOPWORDS}


def _iter_skills():
    """Yield (skill_id, meta) for every folder containing a skill.json."""
    if not SKILLS_DIR.is_dir():
        return
    for entry in sorted(SKILLS_DIR.iterdir()):
        if not entry.is_dir():
            continue
        meta_path = entry / "skill.json"
        if not meta_path.is_file():
            continue
        try:
            with meta_path.open("r", encoding="utf-8") as fh:
                meta = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(meta, dict):
            continue
        skill_id = meta.get("id") or entry.name
        yield skill_id, meta


def _load_skill_meta(skill_id):
    """Return the meta dict for skill_id, or None if unknown."""
    base = SKILLS_DIR / str(skill_id)
    meta_path = base / "skill.json"
    if not meta_path.is_file():
        return None
    try:
        with meta_path.open("r", encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    return meta if isinstance(meta, dict) else None


def _guide_preview(skill_id, max_chars=400):
    """First max_chars of guide.md (whitespace-collapsed) for search preview."""
    guide_path = SKILLS_DIR / str(skill_id) / "guide.md"
    if not guide_path.is_file():
        return ""
    try:
        text = guide_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_chars] + ("..." if len(text) > max_chars else "")


def _score_skill(query_tokens, skill_id, meta, guide_text):
    """Token-overlap score over id/title/description/tags/keywords + guide."""
    score = 0.0
    text = (
        skill_id + " " + str(meta.get("title", "")) + " "
        + str(meta.get("description", "")) + " "
        + " ".join(meta.get("tags", [])) + " "
        + " ".join(meta.get("keywords", [])) + " "
        + " ".join(meta.get("phases", []))
    ).lower()
    tokens = _tokenize(text)
    for qt in query_tokens:
        if qt in tokens:
            score += 2.0
        elif any(qt in t for t in tokens if len(t) > len(qt)):
            score += 1.0
    gtok = _tokenize(guide_text)
    for qt in query_tokens:
        if qt in gtok:
            score += 0.5
    return score


def tool_search_skills(query="", limit=None):
    """Search the on-demand skill library.

    Args:
        query: free-text search (title/description/tags/keywords/guide). Empty
            query lists all available skills.
        limit: max results to return (clamped to 1..MAX_SEARCH_LIMIT).

    Returns:
        Ranked text report of matching skills with id, title, tags, relevance
        score and a short guide preview.
    """
    try:
        parsed = int(limit) if limit is not None else DEFAULT_SEARCH_LIMIT
    except (TypeError, ValueError):
        parsed = DEFAULT_SEARCH_LIMIT
    parsed = max(1, min(parsed, MAX_SEARCH_LIMIT))

    query_tokens = _tokenize(query or "")
    results = []
    for skill_id, meta in _iter_skills():
        guide_text = ""
        guide_path = SKILLS_DIR / skill_id / "guide.md"
        if guide_path.is_file():
            try:
                guide_text = guide_path.read_text(encoding="utf-8")
            except OSError:
                guide_text = ""
        score = _score_skill(query_tokens, skill_id, meta, guide_text)
        if query_tokens and score <= 0:
            continue
        results.append((score, skill_id, meta, guide_text))

    results.sort(key=lambda r: (-r[0], r[1]))
    if query_tokens:
        results = [r for r in results if r[0] > 0]
    results = results[:parsed]

    if not results:
        if query_tokens:
            return ("No skills matched query: %r. Try broader terms or list all "
                    "skills with an empty query." % (query or ""))
        return "Skill library is empty. Add folders with skill.json under ai_agent/skills/."

    lines = ["Skill library search: %d match(es)" % len(results)]
    if query_tokens:
        lines[0] += " for %r" % (query or "")
    lines.append("")
    for score, skill_id, meta, guide_text in results:
        tags = ", ".join(meta.get("tags", [])) or "-"
        preview = _guide_preview(skill_id) or guide_text[:200]
        lines.append("## %s  (relevance %.1f)" % (skill_id, score))
        lines.append("title: %s" % meta.get("title", ""))
        lines.append("tags: %s" % tags)
        lines.append("preview: %s" % preview)
        lines.append("load:  use load_skill(%r) to load the full guide" % skill_id)
        lines.append("")
    return "\n".join(lines)


def tool_load_skill(skill_id):
    """Load one skill's full methodology guide into context.

    Args:
        skill_id: the skill id (folder name under ai_agent/skills/).

    Returns:
        Metadata header + full guide.md content, truncated to MAX_GUIDE_CHARS.
        Clear error message when the skill is unknown or its files are missing.
    """
    skill_id = (skill_id or "").strip()
    if not skill_id:
        return ("Usage: load_skill(skill_id). Available skills:\n"
                + tool_search_skills())
    base = SKILLS_DIR / skill_id
    meta = _load_skill_meta(skill_id)
    if meta is None:
        return ("Skill not found: %r. Run search_skills() with an empty query to "
                "list all available skills." % skill_id)
    guide_path = base / "guide.md"
    if not guide_path.is_file():
        return ("Skill %r found but guide.md is missing. Re-add the file under "
                "ai_agent/skills/%s/guide.md." % (skill_id, skill_id))
    try:
        guide = guide_path.read_text(encoding="utf-8")
    except OSError as exc:
        return "Failed to read guide for %r: %s" % (skill_id, exc)

    tags = ", ".join(meta.get("tags", [])) or "-"
    header = (
        "=== SKILL: %s ===\n"
        "title: %s\n"
        "category: %s\n"
        "tags: %s\n"
        "version: %s\n"
        "======================\n"
    ) % (
        skill_id,
        meta.get("title", ""),
        meta.get("category", ""),
        tags,
        meta.get("version", ""),
    )
    body = guide if len(guide) <= MAX_GUIDE_CHARS else (
        guide[:MAX_GUIDE_CHARS] + "\n\n[... truncated: guide exceeds %d chars; "
        "load a narrower skill or read the file directly]"
        % MAX_GUIDE_CHARS
    )
    return header + body
