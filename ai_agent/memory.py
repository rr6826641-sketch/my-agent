"""Persistent memory store (thread-safe, JSON file on disk).

RAG support: pure-Python TF-IDF + cosine-similarity vector search over
notes and indexed document chunks - no numpy / embedding API required.
"""

import datetime
import json
import math
import os
import re
import sqlite3
import threading


TOKEN_RE = re.compile(r"[a-z0-9]+(?:[-_][a-z0-9]+)*")


def _tokenize(text):
    return TOKEN_RE.findall((text or "").lower())


def _tfidf_vectors(docs):
    """docs: list of texts -> (vectors, idf); vectors are {term: tfidf}."""
    corpus = [_tokenize(d) for d in docs]
    df = {}
    for toks in corpus:
        for t in set(toks):
            df[t] = df.get(t, 0) + 1
    n = max(1, len(corpus))
    idf = {t: math.log((1.0 + n) / (1.0 + c)) + 1.0 for t, c in df.items()}
    vectors = []
    for toks in corpus:
        tf = {}
        for t in toks:
            tf[t] = tf.get(t, 0) + 1
        denom = max(1.0, len(toks))
        vectors.append({t: (cnt / denom) * idf.get(t, 1.0)
                        for t, cnt in tf.items()})
    return vectors, idf


def _cosine(a, b):
    """Cosine similarity of two {term: weight} dicts."""
    if not a or not b:
        return 0.0
    common = set(a) & set(b)
    if not common:
        return 0.0
    dot = sum(a[t] * b.get(t, 0.0) for t in common)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class MemoryStore:
    """Key-value notes that survive across sessions."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._data = {"notes": {}, "docs": {}}
        self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._data = json.load(f)
        except Exception:
            self._data = {"notes": {}, "docs": {}}
        if not isinstance(self._data, dict) or "notes" not in self._data:
            self._data = {"notes": {}}
        if "docs" not in self._data:
            self._data["docs"] = {}

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

    # ------------------------------------------------------------ RAG

    @staticmethod
    def _chunk_text(text, chunk_words=400, overlap_words=60):
        """Split text into overlapping chunks of ~chunk_words words."""
        words = (text or "").split()
        if len(words) <= chunk_words:
            return [" ".join(words)] if words else []
        step = chunk_words - overlap_words
        return [" ".join(words[i:i + chunk_words])
                for i in range(0, len(words), step)]

    def _index_doc(self, doc_key, text):
        chunks = self._chunk_text(text)
        if not chunks:
            return 0
        for i, chunk in enumerate(chunks):
            self._data["docs"]["%s#%d" % (doc_key, i)] = {
                "text": chunk,
                "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            }
        return len(chunks)

    def index_documents(self, folder, extensions=(".txt", ".md", ".csv",
                                                  ".json", ".log")):
        """Index every matching file under folder as searchable chunks.

        Returns a summary string: how many files and chunks were indexed.
        """
        if not folder or not os.path.isdir(folder):
            return "Error: folder not found: %s" % folder
        added_files = 0
        added_chunks = 0
        with self._lock:
            self._data.setdefault("docs", {})
            for root, _dirs, files in os.walk(folder):
                for fn in sorted(files):
                    if not fn.lower().endswith(extensions):
                        continue
                    path = os.path.join(root, fn)
                    try:
                        with open(path, "r", encoding="utf-8",
                                  errors="ignore") as f:
                            text = f.read()
                    except Exception:
                        continue
                    rel = os.path.relpath(path, folder)
                    doc_key = rel.replace("\\", "/")
                    # drop stale chunks for this doc
                    prefix = doc_key + "#"
                    for k in [k for k in self._data["docs"]
                              if k.startswith(prefix)]:
                        del self._data["docs"][k]
                    n = self._index_doc(doc_key, text)
                    if n:
                        added_files += 1
                        added_chunks += n
            self._save()
        return "Indexed %d files, %d chunks from %s" % (added_files,
                                                        added_chunks,
                                                        folder)

    def vector_search(self, query, top_k=5):
        """TF-IDF cosine search over notes + indexed doc chunks.

        Returns a ranked, labeled list of matches with similarity scores.
        """
        query = (query or "").strip()
        if not query:
            return "Error: empty query."
        with self._lock:
            notes = self._data.get("notes", {})
            docs = self._data.get("docs", {})
            items = []
            for key, entry in notes.items():
                items.append(("note", key, entry.get("text", "")))
            for key, entry in docs.items():
                items.append(("doc", key, entry.get("text", "")))
        if not items:
            return "(nothing indexed yet - use rag_index to add documents)"
        texts = [it[2] for it in items]
        vectors, _idf = _tfidf_vectors(texts)
        qvec, _ = _tfidf_vectors([query])
        qv = qvec[0] if qvec else {}
        scored = [(k, key, _cosine(qv, vectors[i]))
                  for i, (k, key, _t) in enumerate(items)]
        scored.sort(key=lambda x: x[2], reverse=True)
        top = [s for s in scored if s[2] > 0.0][:max(1, int(top_k or 5))]
        if not top:
            return "(no matches found for '%s')" % query
        lines = []
        for kind, key, score in top:
            text = dict((it[1], it[2]) for it in items)[key]
            snippet = " ".join(text.split())[:220]
            lines.append("[%s] %s (score %.3f)\n    %s"
                         % (kind.upper(), key, score, snippet))
        return "Top %d matches for '%s':\n%s" % (len(top), query,
                                                  "\n".join(lines))

    def doc_stats(self):
        with self._lock:
            return (len(self._data.get("docs", {})),
                    len(self._data.get("notes", {})))

# ---------------------------------------------------------------------------
# Lorebook: SQLite-backed campaign lore with pure-Python TF-IDF recall
# ---------------------------------------------------------------------------


def _norm_tags(tags):
    """Accept a list or a comma-separated string; return a clean list."""
    if tags is None:
        return []
    if isinstance(tags, str):
        parts = tags.split(",")
    else:
        parts = tags
    return [str(t).strip() for t in parts if str(t).strip()]


class Lorebook:
    """Persistent campaign lorebook for RPG sessions.

    Entries live in a single SQLite database (table `lore`). Recall uses the
    same tokenizer / TF-IDF / cosine machinery as MemoryStore, so no
    embeddings or numpy are required. Every method is thread-safe.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".",
                    exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS lore ("
            " entry_id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " category TEXT NOT NULL DEFAULT 'general',"
            " title TEXT NOT NULL,"
            " content TEXT NOT NULL,"
            " tags TEXT NOT NULL DEFAULT '',"
            " ts TEXT NOT NULL)"
        )
        self._conn.commit()

    def _row_to_entry(self, row):
        return {
            "id": row["entry_id"],
            "category": row["category"],
            "title": row["title"],
            "content": row["content"],
            "tags": [t for t in (row["tags"] or "").split(",") if t],
            "ts": row["ts"],
        }

    def add(self, category="general", title="", content="", tags=None):
        """Insert a new entry and return it as a dict."""
        category = (category or "general").strip()[:40]
        title = (title or "untitled").strip()[:200]
        content = (content or "").strip()
        tags = ",".join(_norm_tags(tags))[:400]
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO lore (category, title, content, tags, ts)"
                " VALUES (?, ?, ?, ?, ?)",
                (category, title, content, tags, ts))
            self._conn.commit()
            entry_id = cur.lastrowid
        return self.get(entry_id)

    def update(self, entry_id, category=None, title=None, content=None,
               tags=None):
        """Update fields of an existing entry; None fields are kept."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM lore WHERE entry_id = ?",
                (int(entry_id),)).fetchone()
            if row is None:
                return None
            tags_str = row["tags"]
            if tags is not None:
                tags_str = ",".join(_norm_tags(tags))[:400]
            self._conn.execute(
                "UPDATE lore SET category = ?, title = ?, content = ?,"
                " tags = ? WHERE entry_id = ?",
                ((category or row["category"]).strip()[:40],
                 (title or row["title"]).strip()[:200],
                 content if content is not None else row["content"],
                 tags_str, int(entry_id)))
            self._conn.commit()
        return self.get(entry_id)

    def delete(self, entry_id):
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM lore WHERE entry_id = ?", (int(entry_id),))
            self._conn.commit()
            return cur.rowcount > 0

    def get(self, entry_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM lore WHERE entry_id = ?",
                (int(entry_id),)).fetchone()
        return self._row_to_entry(row) if row else None

    def list(self, category=None, limit=100):
        with self._lock:
            if category:
                rows = self._conn.execute(
                    "SELECT * FROM lore WHERE category = ?"
                    " ORDER BY entry_id DESC LIMIT ?",
                    (category, int(limit))).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM lore ORDER BY entry_id DESC LIMIT ?",
                    (int(limit),)).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def search(self, query, top_k=5):
        """TF-IDF cosine recall over title + content. Best-first results."""
        query = (query or "").strip()
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM lore ORDER BY entry_id").fetchall()
        if not rows:
            return []
        entries = [self._row_to_entry(r) for r in rows]
        if not query:
            return entries[: max(1, int(top_k or 5))]
        texts = ["%s %s %s" % (e["title"], e["content"],
                               " ".join(e["tags"])) for e in entries]
        vectors, _idf = _tfidf_vectors(texts)
        qv, _ = _tfidf_vectors([query])
        qv = qv[0] if qv else {}
        scored = [(e, _cosine(qv, vectors[i])) for i, e in enumerate(entries)]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [e for e, s in scored if s > 0.0][: max(1, int(top_k or 5))]

    def to_context(self, limit=4000):
        """Render recent lore as a compact block for the GM prompt."""
        rows = self.list(limit=50)
        if not rows:
            return ""
        lines = []
        used = 0
        for e in rows:
            block = "- [%s] %s: %s" % (
                e["category"], e["title"],
                " ".join(e["content"].split()))
            if used + len(block) > limit:
                break
            lines.append(block)
            used += len(block)
        return "\n".join(lines)

    def count(self):
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM lore").fetchone()
        return row["n"] if row else 0


# ---------------------------------------------------------------------------
# GameState: persistent world state (location, inventory, stats, quests...)
# ---------------------------------------------------------------------------


class GameState:
    """JSON-file world state for one RPG campaign.

    The state dict is the single source of truth:

        game_id, title, genre, created, updated
        player:   {name, stats {hp, hp_max, gold, xp, level, ...}}
        location: {name, description}
        inventory: [item names]
        flags:    {name: True/False or short text}
        quests:   {quest_id: {title, desc, status, progress}}
        npcs:     {npc_id: {name, desc, location, state}}
        counters: {name: number}
        log:      [ {turn, player, narrative} ... ]

    apply_patch() accepts a JSON patch with dotted paths and a few special
    keys (inventory.add / inventory.remove) so the GM tool stays simple.
    """

    DEFAULT_STATS = {"hp": 10, "hp_max": 10, "gold": 0, "xp": 0, "level": 1}

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._data = self._new()
        self._load()

    @staticmethod
    def _new():
        now = datetime.datetime.now().isoformat(timespec="seconds")
        return {
            "game_id": "",
            "title": "",
            "genre": "",
            "player": {"name": "", "stats": dict(GameState.DEFAULT_STATS)},
            "location": {"name": "", "description": ""},
            "inventory": [],
            "flags": {},
            "quests": {},
            "npcs": {},
            "counters": {},
            "log": [],
            "created": now,
            "updated": now,
        }

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._data = self._merge(self._new(), data)
        except Exception:
            self._data = self._new()

    @staticmethod
    def _merge(base, extra):
        """Deep-merge extra into base so missing keys get defaults."""
        out = dict(base)
        for k, v in (extra or {}).items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = GameState._merge(out[k], v)
            else:
                out[k] = v
        return out

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except Exception as exc:
            print("[gamestate] save failed: %s" % exc)

    # ------------------------------------------------------------ accessors

    def get_data(self):
        with self._lock:
            return json.loads(json.dumps(self._data))

    def to_payload(self):
        """Full state dict (JSON-safe copy) for the web API."""
        data = self.get_data()
        return {
            "game_id": data["game_id"],
            "title": data["title"],
            "genre": data["genre"],
            "player": data["player"],
            "location": data["location"],
            "inventory": data["inventory"],
            "flags": data["flags"],
            "quests": data["quests"],
            "npcs": data["npcs"],
            "counters": data["counters"],
            "turn": len(data["log"]),
            "log": data["log"][-20:],
            "created": data["created"],
            "updated": data["updated"],
        }

    def to_context(self):
        """Compact text rendering for the GM system prompt."""
        d = self._data
        stats = d["player"].get("stats", {})
        stat_line = ", ".join("%s %s" % (k.replace("_", " ").title(), v)
                              for k, v in stats.items())
        lines = [
            "Player: %s (%s)" % (d["player"].get("name", "?"), d["genre"]),
            "Stats: %s" % stat_line,
            "Location: %s - %s" % (d["location"].get("name", "?"),
                                   d["location"].get("description", "")),
            "Inventory: %s" % (", ".join(d["inventory"]) if d["inventory"]
                               else "empty"),
        ]
        if d["quests"]:
            quest_lines = []
            for qid, q in d["quests"].items():
                quest_lines.append("%s [%s%s]" % (
                    q.get("title", qid), q.get("status", "active"),
                    " - %s" % q.get("progress", "") if q.get("progress")
                    else ""))
            lines.append("Quests: " + "; ".join(quest_lines))
        if d["flags"]:
            lines.append("Flags: " + ", ".join(
                "%s=%s" % (k, v) for k, v in d["flags"].items()))
        if d["npcs"]:
            npc_lines = []
            for nid, n in d["npcs"].items():
                npc_lines.append("%s (%s, %s)" % (
                    n.get("name", nid), n.get("location", "?"),
                    n.get("state", "?")))
            lines.append("NPCs: " + "; ".join(npc_lines))
        return "\n".join(lines)

    def story_log(self, limit=6, max_chars=3500):
        """Recent story events (player input + GM narrative) for auto-recall.

        Returns a compact text block of the last `limit` turns so the Game
        Master prompt can stay continuous with what already happened without
        re-reading the whole log. This is the "story memory" that keeps
        characters, consequences and loose ends consistent across turns.
        """
        d = self._data
        log = d.get("log") or []
        if not log:
            return ""
        lines = []
        used = 0
        for entry in log[-int(limit):]:
            player = " ".join((entry.get("player") or "").split())
            narrative = " ".join((entry.get("narrative") or "").split())
            if len(player) > 220:
                player = player[:220] + "..."
            if len(narrative) > 320:
                narrative = narrative[:320] + "..."
            block = "Turn %s - Player: %s\n  -> %s" % (
                entry.get("turn", "?"), player or "(opening)", narrative)
            if used + len(block) > max_chars and lines:
                break
            lines.append(block)
            used += len(block)
        return "\n".join(lines)

    def record_turn(self, player_input, narrative):
        """Append a turn to the log and bump the updated timestamp."""
        with self._lock:
            self._data["log"].append({
                "turn": len(self._data["log"]) + 1,
                "player": player_input,
                "narrative": narrative,
                "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            })
            if len(self._data["log"]) > 200:
                self._data["log"] = self._data["log"][-200:]
            self._data["updated"] = datetime.datetime.now().isoformat(
                timespec="seconds")
            self._save()

    # ------------------------------------------------------------ patching

    def apply_patch(self, patch):
        """Apply a world-state patch and return the updated state context.

        Supported patch keys (all optional):
          title, genre, location (name), location_desc, player_name,
          stats {k: v}, inventory {add: [...], remove: [...]},
          flags {k: v}, quests {id: {title, desc, status, progress}},
          npcs {id: {name, desc, location, state}},
          counters {k: number}
        Dotted paths like "stats.gold" or "flags.entered_tavern" also work.
        """
        if not isinstance(patch, dict):
            return "Error: patch must be a JSON object."
        with self._lock:
            for key, value in patch.items():
                self._apply_one(key, value)
            self._data["updated"] = datetime.datetime.now().isoformat(
                timespec="seconds")
            self._save()
        return self.to_context()

    def _apply_one(self, key, value):
        key = str(key)
        if "." in key:
            head, _, tail = key.partition(".")
            if head == "stats":
                self._data["player"].setdefault("stats", {})
                self._data["player"]["stats"][tail] = self._coerce_number(
                    tail, value)
            elif head == "inventory":
                if tail == "add" and isinstance(value, list):
                    for item in value:
                        if str(item) not in self._data["inventory"]:
                            self._data["inventory"].append(str(item))
                elif tail == "remove" and isinstance(value, list):
                    for item in value:
                        if str(item) in self._data["inventory"]:
                            self._data["inventory"].remove(str(item))
                elif tail == "clear":
                    self._data["inventory"] = []
            elif head == "flags":
                self._data["flags"][tail] = value
            elif head == "counters":
                self._data["counters"][tail] = self._coerce_number(
                    tail, value)
            elif head in ("quests", "npcs") and isinstance(value, dict):
                self._data[head].setdefault(tail, {})
                self._data[head][tail] = self._merge(
                    self._data[head][tail], value)
            else:
                self._data[head] = value
            return

        if key == "title":
            self._data["title"] = str(value)
        elif key == "genre":
            self._data["genre"] = str(value)
        elif key == "location":
            self._data["location"]["name"] = str(value)
        elif key == "location_desc":
            self._data["location"]["description"] = str(value)
        elif key == "player_name":
            self._data["player"]["name"] = str(value)
        elif key == "stats" and isinstance(value, dict):
            for k, v in value.items():
                self._data["player"].setdefault("stats", {})
                self._data["player"]["stats"][k] = self._coerce_number(k, v)
        elif key == "inventory":
            if isinstance(value, list):
                self._data["inventory"] = [str(i) for i in value]
            elif isinstance(value, dict):
                for op, items in value.items():
                    if op == "add" and isinstance(items, list):
                        for item in items:
                            if str(item) not in self._data["inventory"]:
                                self._data["inventory"].append(str(item))
                    elif op == "remove" and isinstance(items, list):
                        for item in items:
                            if str(item) in self._data["inventory"]:
                                self._data["inventory"].remove(str(item))
                    elif op == "clear":
                        self._data["inventory"] = []
        elif key == "flags" and isinstance(value, dict):
            self._data["flags"].update(value)
        elif key == "quests" and isinstance(value, dict):
            for qid, q in value.items():
                self._data["quests"].setdefault(str(qid), {})
                if isinstance(q, dict):
                    self._data["quests"][str(qid)] = self._merge(
                        self._data["quests"][str(qid)], q)
                else:
                    self._data["quests"][str(qid)]["status"] = str(q)
        elif key == "npcs" and isinstance(value, dict):
            for nid, n in value.items():
                self._data["npcs"].setdefault(str(nid), {})
                if isinstance(n, dict):
                    self._data["npcs"][str(nid)] = self._merge(
                        self._data["npcs"][str(nid)], n)
                else:
                    self._data["npcs"][str(nid)]["name"] = str(n)
        elif key == "counters" and isinstance(value, dict):
            for k, v in value.items():
                self._data["counters"][k] = self._coerce_number(k, v)
        elif key == "log":
            return  # log is append-only via record_turn
        else:
            self._data[key] = value

    @staticmethod
    def _coerce_number(key, value):
        if key in ("hp", "hp_max", "gold", "xp", "level"):
            try:
                return int(value)
            except (TypeError, ValueError):
                return value
        return value
