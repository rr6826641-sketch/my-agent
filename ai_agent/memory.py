"""Persistent memory store (thread-safe, JSON file on disk).

RAG support: pure-Python TF-IDF + cosine-similarity vector search over
notes and indexed document chunks - no numpy / embedding API required.
"""

import datetime
import json
import math
import os
import re
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
