"""Persistent cross-session memory (JSON store, survives agent restarts)."""

import json
import os
import threading

_MEM_LOCK = threading.Lock()
_MEM_DIRNAME = ".hackerai"
_MEM_FILENAME = "memory.json"


def _memory_path():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, _MEM_DIRNAME, _MEM_FILENAME)


def _load():
    try:
        with open(_memory_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(mem):
    path = _memory_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(mem, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def tool_memory_save(key, value):
    """Persist a fact/note under a key (overwrites existing key)."""
    key = str(key or "").strip()
    if not key:
        return "Error: empty key"
    mem = _load()
    mem[key] = str(value)
    try:
        _save(mem)
    except Exception as exc:
        return "memory_save error: %s" % exc
    return "memory saved: %s" % key


def tool_memory_get(key):
    key = str(key or "").strip()
    mem = _load()
    if key in mem:
        return mem[key]
    # prefix match fallback
    hits = {k: v for k, v in mem.items() if k.startswith(key)}
    if hits:
        return "\n".join("%s: %s" % (k, v) for k, v in sorted(hits.items()))
    return "(no memory for key: %s)" % key


def tool_memory_list(query=None):
    mem = _load()
    if not mem:
        return "(memory is empty)"
    if query:
        q = str(query).lower()
        mem = {k: v for k, v in mem.items()
               if q in k.lower() or q in str(v).lower()}
        if not mem:
            return "(no memory matching %r)" % query
    return "\n".join("%s: %s" % (k, v) for k, v in sorted(mem.items()))


def tool_memory_delete(key):
    key = str(key or "").strip()
    mem = _load()
    if key not in mem:
        return "(no memory for key: %s)" % key
    del mem[key]
    _save(mem)
    return "deleted memory key: %s" % key
