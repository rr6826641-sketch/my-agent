"""Persistent memory store (thread-safe, JSON file on disk)."""

import datetime
import json
import os
import threading


class MemoryStore:
    """Key-value notes that survive across sessions."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._data = {"notes": {}}
        self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._data = json.load(f)
        except Exception:
            self._data = {"notes": {}}
        if not isinstance(self._data, dict) or "notes" not in self._data:
            self._data = {"notes": {}}

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except Exception as exc:
            print("[memory] save failed: %s" % exc)

    def add(self, key, text):
        with self._lock:
            self._data["notes"][key] = {
                "text": text,
                "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            }
            self._save()

    def delete(self, key):
        with self._lock:
            removed = self._data["notes"].pop(key, None)
            self._save()
            return removed is not None

    def clear(self):
        with self._lock:
            self._data["notes"] = {}
            self._save()

    def recall(self, query=None):
        with self._lock:
            notes = self._data["notes"]
            if not notes:
                return "(memory is empty)"
            lines = []
            for key in sorted(notes):
                entry = notes[key]
                if query and query.lower() not in key.lower() \
                        and query.lower() not in entry.get("text", "").lower():
                    continue
                lines.append("- %s: %s (saved %s)"
                             % (key, entry.get("text", ""), entry.get("ts", "?")))
            if not lines:
                return "(nothing found for '%s')" % query
            return "\n".join(lines)

    def snapshot(self, limit=2000):
        with self._lock:
            notes = self._data["notes"]
            if not notes:
                return ""
            lines = ["- %s: %s" % (k, v.get("text", "")) for k, v in notes.items()]
        out = "\n".join(lines)
        return out[:limit]
