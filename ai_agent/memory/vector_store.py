"""Unified semantic vector memory (the "brain").

Phase-2 overhaul of the episodic store into a *unified semantic brain*:

1. **Dense semantic embeddings.**  Embeddings are produced by a real dense
   pipeline, selected automatically at import time:

   - ``sentence-transformers`` (if installed) - a local transformer model,
   - ``chromadb`` (if installed) - Chroma's native ONNX MiniLM embedding
     pipeline,
   - otherwise a built-in numpy **TF-IDF dense** embedder (L2-normalised,
     sublinear term weighting).  The old *hash n-gram bag* embedder is
     deprecated and used only as a last-resort when numpy is unavailable.

2. **Unified index.**  ``chats.json`` conversations, operational notes,
   execution lessons, and target methodologies are all archived into ONE
   semantically searchable collection, each carrying ``kind`` + ``source``
   metadata so recall can filter per domain while searching one index.

3. **Recall.**  ``recall(text, top_k)`` runs a top-k cosine-similarity query
   against the single index - the same API the agent calls before response
   generation.

Storage stays on disk (``memory/episodic_vectors.json`` or a Chroma
``PersistentClient`` collection) so memory survives restarts.  Legacy
hash-vector files are transparently migrated to dense vectors on load.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import threading
import time

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Embedder availability detection (import-time, best-effort)
# --------------------------------------------------------------------------
try:  # Level 1: real transformer sentence embeddings
    import sentence_transformers  # noqa: F401
    _HAVE_ST = True
except Exception:
    _HAVE_ST = False

try:  # Level 2: ChromaDB native embedding pipeline (ONNX MiniLM)
    import chromadb  # type: ignore
    _HAVE_CHROMA = True
except Exception:
    chromadb = None
    _HAVE_CHROMA = False

try:  # numpy -> deterministic dense TF-IDF fallback
    import numpy as _np  # type: ignore
    _HAVE_NUMPY = True
except Exception:
    _np = None
    _HAVE_NUMPY = False

_TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")

# Dense fallback embedding space (used only when no model is installed).
_DENSE_DIM = 768
# Sparse legacy space (pure-python last resort, deprecated).
_EMBED_DIM = 1024
_NGRAM_RANGE = (2, 5)

MAX_TEXT_CHARS = 8000
_DEFAULT_PERSIST_FILE = "episodic_vectors.json"
def _atomic_replace_retry(src, dst, attempts=4, delay=0.2):
    """Windows file locks (WinError 32) are usually transient: retry
    os.replace with backoff before giving up to the sidecar fallback.
    Raises the last OSError when all attempts fail."""
    attempts = max(1, int(attempts))
    last = None
    for i in range(attempts):
        try:
            os.replace(src, dst)
            return True
        except OSError as exc:
            last = exc
            if i < attempts - 1:
                logger.warning(
                    "episodic store save locked (%s); retry %d/%d",
                    exc, i + 1, attempts)
                time.sleep(delay * 2 ** i)
    raise last if last is not None else OSError("replace failed")


def _sidecar_fallback(store, exc):
    """Reliability net for a permanently locked main file: write the
    full vector state to a timestamped sidecar so ZERO memory is
    lost.  The lock usually belongs to a running webui instance that
    holds memory/episodic_vectors.json open; once it closes, the
    sidecar merges automatically on next load."""
    try:
        os.makedirs(store._persist_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        base = str(store._local_path)
        if base.endswith(".json"):
            base = base[:-5]
        side = "%s.locked-%s.json" % (base, ts)
        with open(side, "w", encoding="utf-8") as fh:
            json.dump(store._snapshot_docs(), fh, ensure_ascii=False,
                      separators=(",", ":"))
        logger.warning(
            "episodic store save failed (%s); state backed up to %s - "
            "close the locking process (agent webui) to unlock the "
            "main file; sidecar merges automatically on next load",
            exc, side)
    except Exception as e2:
        logger.warning("episodic store sidecar fallback failed too: %s",
                       e2)


# Bump whenever the numeric embedding scheme changes so persisted dense
# vectors are transparently re-embedded on next load (v1/v2 = old).
_EMBED_VERSION = 3

# Module-level singletons (created lazily, guarded by a lock).
_st_model = None
_st_model_name = None
_embedder_lock = threading.Lock()


def _now() -> float:
    return time.time()


def get_embedding_engine() -> str:
    """Name of the active embedding pipeline.

    Returns one of ``sentence-transformers``, ``chroma``,
    ``tfidf-dense`` or ``hash-legacy``.
    """
    if _HAVE_ST:
        return "sentence-transformers"
    if _HAVE_CHROMA:
        return "chroma"
    if _HAVE_NUMPY:
        return "tfidf-dense"
    return "hash-legacy"


# --------------------------------------------------------------------------
# Dense embedding pipeline
# --------------------------------------------------------------------------
def _sentence_transformer():
    global _st_model, _st_model_name
    with _embedder_lock:
        if _st_model is None:
            import sentence_transformers as _st
            # smallest general-purpose default; falls back gracefully if the
            # exact name is not cached locally by trying the encoder family.
            _st_model_name = getattr(
                _st, "__version__", "") and "all-MiniLM-L6-v2"
            try:
                _st_model = _st.SentenceTransformer(_st_model_name)
            except Exception:
                _st_model = _st.SentenceTransformer("paraphrase-MiniLM-L3-v2")
        return _st_model


def _encode_with_model(text: str):
    """Encode one text through the active model into a dense vector."""
    text = (text or "")[:MAX_TEXT_CHARS]
    if _HAVE_ST:
        return _sentence_transformer().encode(
            [text], normalize_embeddings=True)[0]
    if _HAVE_CHROMA:
        from chromadb.utils import embedding_functions  # type: ignore
        ef = embedding_functions.DefaultEmbeddingFunction()
        return ef([text])[0]
    raise RuntimeError("no dense model available")


def _tfidf_token_weights(text: str):
    """Word tokens with sublinear term-frequency weights (no hashing)."""
    words = _TOKEN_RE.findall((text or "").lower()[:MAX_TEXT_CHARS])
    tf = {}
    for w in words:
        tf[w] = tf.get(w, 0.0) + 1.0
    # sublinear tf: 1 + log(tf)
    return {w: 1.0 + math.log(c) for w, c in tf.items()}


def _dense_tfidf(text: str):
    """Deterministic dense TF-IDF embedding over a word vocabulary.

    Uses signed random features (Rademacher): each token maps to one
    fixed hash bucket with a token-fixed sign.  Unrelated tokens that
    collide therefore cancel on average instead of accumulating positive
    noise, so top-k cosine ranking is far less polluted by hash collisions.
    Normalised to unit length so cosine similarity is a plain dot product.
    (Replaces the deprecated n-gram hash bag.)
    """
    w = _np.zeros(_DENSE_DIM, dtype="float32")
    weights = _tfidf_token_weights(text)
    for tok, weight in weights.items():
        raw = hashlib.sha256(tok.encode("utf-8", "ignore")).digest()
        idx = int.from_bytes(raw[:4], "big") % _DENSE_DIM
        sign = 1.0 if (raw[4] & 1) else -1.0
        w[idx] += sign * weight
    if not weights:
        w[0] = 1.0
    n = float(_np.linalg.norm(w))
    if n > 0:
        w /= n
    return w


def embed(text: str):
    """Embed ``text`` through the active dense pipeline.

    Returns a numpy float32 vector (model or TF-IDF dense).  Only when numpy
    itself is unavailable does it fall back to the deprecated hash n-gram
    bag (a dict of {index: weight}) so the module still works anywhere.
    """
    if _HAVE_ST or _HAVE_CHROMA:
        try:
            return _encode_with_model(text)
        except Exception as exc:  # pragma: no cover - model load failure
            logger.warning("model embed failed (%s); dense fallback", exc)
    if _HAVE_NUMPY:
        return _dense_tfidf(text)
    return _embed_hash_bag(text)


# --------------------------------------------------------------------------
# Deprecated hash-bag embedder (pure-python last resort)
# --------------------------------------------------------------------------
def _hash_index(token: str) -> int:
    return int(hashlib.md5(token.encode("utf-8", "ignore")).hexdigest(), 16) \
        % _EMBED_DIM


def _embed_hash_bag(text: str):
    """DEPRECATED: hash n-gram bag used only when numpy is unavailable."""
    text = (text or "").lower()[:MAX_TEXT_CHARS]
    vec = {}
    words = _TOKEN_RE.findall(text)
    for w in words:
        i = _hash_index("w:" + w)
        vec[i] = vec.get(i, 0.0) + 1.0
    joined = " " + " ".join(words) + " "
    for n in range(_NGRAM_RANGE[0], _NGRAM_RANGE[1] + 1):
        if len(joined) < n:
            break
        seen = set()
        for k in range(len(joined) - n + 1):
            gram = joined[k:k + n]
            if gram.strip() == "" or gram in seen:
                continue
            seen.add(gram)
            i = _hash_index("g:" + gram)
            vec[i] = vec.get(i, 0.0) + 0.35
    if not vec:  # never return an all-zero vector
        vec[_hash_index("w:empty")] = 1.0
    return vec


def _is_sparse(vec) -> bool:
    return isinstance(vec, dict)


def _vectorise(vec):
    """Normalise any stored vector into a numpy float32 vector."""
    if vec is None:
        return None
    if _HAVE_NUMPY:
        if _is_sparse(vec):
            dense = _np.zeros(_EMBED_DIM, dtype="float32")
            for i, v in vec.items():
                dense[int(i) % _EMBED_DIM] = float(v)
            n = float(_np.linalg.norm(dense))
            if n > 0:
                dense /= n
            return dense
        if isinstance(vec, list):
            return _np.asarray(vec, dtype="float32")
        return _np.asarray(vec, dtype="float32")
    return vec


def _cosine(a, b) -> float:
    """Cosine similarity between two stored/embed vectors."""
    if a is None or b is None:
        return 0.0
    if _HAVE_NUMPY:
        va, vb = _vectorise(a), _vectorise(b)
        if va is None or vb is None:
            return 0.0
        try:
            denom = float(_np.linalg.norm(va) * _np.linalg.norm(vb))
            if denom == 0.0:
                return 0.0
            return float(float(va @ vb) / denom)
        except Exception:
            return 0.0
    # pure-python sparse cosine (legacy path)
    if isinstance(a, dict) and isinstance(b, dict):
        if len(b) < len(a):
            a, b = b, a
        dot = 0.0
        for i, w in a.items():
            if b.get(i):
                dot += w * b[i]
        if dot == 0.0:
            return 0.0
        na = math.sqrt(sum(w * w for w in a.values()))
        nb = math.sqrt(sum(w * w for w in b.values()))
        if na == 0.0 or nb == 0.0:
            return 0.0
        return dot / (na * nb)
    return 0.0


def _sha(text: str, meta) -> str:
    """Stable content digest for dedupe.

    Volatile fields (``ts``) are excluded so identical records ingested in
    later runs (fresh timestamps) still deduplicate against stored ones.
    """
    stable = {k: v for k, v in (meta or {}).items() if k != "ts"}
    return hashlib.sha256(
        ("%s|%s" % (text, json.dumps(stable, sort_keys=True))).encode()
    ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Unified semantic brain
# ---------------------------------------------------------------------------
class EpisodicVectorMemory:
    """Unified semantic archive: payloads, bypasses, methodologies,
    operational notes, execution lessons, and chat knowledge - all in one
    semantically searchable index."""

    #: archive record kinds (also accepted: anything short & lowercase)
    KIND_PAYLOAD = "payload"
    KIND_BYPASS = "bypass"
    KIND_METHODOLOGY = "methodology"
    KIND_LESSON = "lesson"
    KIND_CHAT = "chat"
    KIND_NOTE = "note"

    def __init__(self, persist_dir: str = None,
                 collection: str = "episodic_memory") -> None:
        base = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
        self._persist_dir = persist_dir or os.path.join(base, "memory")
        self._collection = collection
        self._lock = threading.RLock()
        self._backend = "local"
        self._col = None
        self._local_path = os.path.join(self._persist_dir,
                                        _DEFAULT_PERSIST_FILE)
        self._docs = []  # local state
        self._embed_version = _EMBED_VERSION
        self._known_hashes = set()
        # optional per-store vocabulary overlay (tfidf mode): kept in-memory
        self._engine = get_embedding_engine()
        if _HAVE_CHROMA and self._engine == "chroma":
            try:
                client = chromadb.PersistentClient(
                    path=os.path.join(self._persist_dir, "chroma"))
                self._col = client.get_or_create_collection(collection)
                self._backend = "chroma"
            except Exception as exc:  # pragma: no cover
                logger.warning("ChromaDB unavailable (%s); using local "
                               "dense store", exc)
        if self._backend == "local":
            self._load_local()
            self._upgrade_embeddings()
            self._migrate_legacy()
            self._known_hashes = {
                _sha(d.get("text", ""), d.get("meta") or {})
                for d in self._docs}

    # -- backend / engine ---------------------------------------------------

    @property
    def backend(self) -> str:
        return self._backend

    @property
    def embedding_engine(self) -> str:
        return self._engine

    @property
    def vector_dim(self) -> int:
        """Dimension of stored dense vectors (0 for the legacy store)."""
        if _HAVE_ST or _HAVE_CHROMA or _HAVE_NUMPY:
            return _DENSE_DIM if not (_HAVE_ST or _HAVE_CHROMA) else -1
        return 0

    # -- write API ----------------------------------------------------------

    def archive(self, kind: str, text: str, tags=None, target: str = "",
                outcome: str = "", metadata=None, source: str = "",
                dedupe: bool = True) -> str:
        """Persist one unified memory record and return its id."""
        text = (text or "").strip()[:MAX_TEXT_CHARS]
        if not text:
            return ""
        meta = {
            "kind": (kind or "note").lower(),
            "tags": list(tags or []),
            "target": target or "",
            "outcome": outcome or "",
            "source": source or "",
            "ts": _now(),
        }
        if metadata:
            for k, v in metadata.items():
                meta.setdefault(str(k), v)
        if dedupe:
            digest = _sha(text, meta)
            with self._lock:
                if digest in self._known_hashes:
                    return ""
        with self._lock:
            if self._backend == "chroma" and self._col is not None:
                doc_id = "em-%d-%s" % (int(_now() * 1000),
                                       hashlib.md5(
                                           (text + str(meta)).encode()
                                       ).hexdigest()[:8])
                try:
                    self._col.add(ids=[doc_id], documents=[text],
                                  metadatas=[meta])
                    if dedupe:
                        self._known_hashes.add(_sha(text, meta))
                    return doc_id
                except Exception as exc:
                    logger.warning("chroma add failed (%s); storing locally",
                                   exc)
            doc_id = "em-%06d" % (len(self._docs) + 1)
            vec = embed(text)
            self._docs.append({
                "id": doc_id,
                "text": text,
                "meta": meta,
                "vec": vec.tolist() if _HAVE_NUMPY and hasattr(
                    vec, "tolist") else vec,
            })
            if dedupe:
                self._known_hashes.add(_sha(text, meta))
            self._save_local()
            return doc_id

    # Kinded convenience wrappers -------------------------------------------

    def archive_payload(self, text, tags=None, target="", outcome="success"):
        return self.archive(self.KIND_PAYLOAD, text, tags=tags,
                            target=target, outcome=outcome)

    def archive_bypass(self, text, tags=None, target="", outcome="success"):
        return self.archive(self.KIND_BYPASS, text, tags=tags,
                            target=target, outcome=outcome)

    def archive_methodology(self, text, tags=None, target="", outcome=""):
        return self.archive(self.KIND_METHODOLOGY, text, tags=tags,
                            target=target, outcome=outcome)

    def archive_lesson(self, text, tags=None, target="", outcome=""):
        return self.archive(self.KIND_LESSON, text, tags=tags,
                            target=target, outcome=outcome)

    def archive_note(self, text, tags=None, target="", source="",
                     outcome=""):
        return self.archive(self.KIND_NOTE, text, tags=tags,
                            target=target, outcome=outcome, source=source)

    # -- unified indexing ----------------------------------------------------

    def index_documents(self, records, kind: str = None,
                        source: str = "") -> int:
        """Bulk-archive many records into the single index.

        ``records`` may be strings or dicts with any of
        ``{text, kind, tags, target, outcome, source}``.
        """
        added = 0
        for rec in records or []:
            if isinstance(rec, str):
                text, rkind = rec, kind
                tags = target = outcome = src = None
            elif isinstance(rec, dict):
                text = rec.get("text") or rec.get("content") or ""
                rkind = rec.get("kind") or kind
                tags = rec.get("tags")
                target = rec.get("target", "")
                outcome = rec.get("outcome", "")
                src = rec.get("source") or source
            else:
                continue
            if not text or not str(text).strip():
                continue
            if self.archive(rkind or "note", str(text).strip(),
                            tags=tags, target=target or "",
                            outcome=outcome or "", source=src or ""):
                added += 1
        return added

    def index_chats(self, path: str, max_turns: int = 400) -> int:
        """Index a ``chats.json`` export into chat-knowledge records.

        Every message (user, assistant, tool) of every session is archived
        as a ``chat`` record carrying the session id as its source, so recall
        can answer questions from past conversations.
        """
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError) as exc:
            logger.warning("chats index failed (%s): %s", path, exc)
            return 0
        sessions = raw
        if isinstance(raw, dict):
            sessions = raw.get("sessions") or raw.get("chats") or raw
        if isinstance(sessions, dict):
            sessions = list(sessions.values())
        added = 0
        turn = 0
        for sess in sessions or []:
            if not isinstance(sess, dict):
                continue
            sid = str(sess.get("id") or sess.get("session_id")
                      or sess.get("title") or "chat")
            msgs = sess.get("messages")
            if isinstance(msgs, dict):
                msgs = list(msgs.values())
            if not isinstance(msgs, list):
                continue
            for msg in msgs:
                if not isinstance(msg, dict):
                    continue
                role = msg.get("role", "")
                content = msg.get("content")
                if isinstance(content, list):
                    content = " ".join(
                        str(p.get("text", "")) if isinstance(p, dict)
                        else str(p) for p in content)
                content = str(content or "").strip()
                if not content or role == "system":
                    continue
                turn += 1
                if turn > max_turns:
                    break
                text = ("%s: %s" % (role, content))[:MAX_TEXT_CHARS]
                if self.archive(self.KIND_CHAT, text, source=sid):
                    added += 1
            if turn > max_turns:
                break
        if added:
            self._save_local()
        return added

    def index_file(self, path: str, kind: str = None, source: str = "") -> int:
        """Index one file (json corpus / markdown / text) into the brain."""
        src = source or os.path.basename(path)
        ext = os.path.splitext(path)[1].lower()
        if ext == ".json":
            # chats-like structure is handled by index_chats; other json
            # corpora (notes/lessons lists or dicts of strings) generic.
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
            except (OSError, ValueError) as exc:
                logger.warning("json index failed (%s): %s", path, exc)
                return 0
            if isinstance(raw, dict) and any(
                    k in raw for k in ("sessions", "chats", "messages")):
                return self.index_chats(path)
            records = []
            if isinstance(raw, list):
                records = raw
            elif isinstance(raw, dict):
                for k, v in raw.items():
                    if isinstance(v, str):
                        records.append({"text": "%s: %s" % (k, v),
                                        "kind": kind or "note"})
                    elif isinstance(v, list):
                        records.extend(
                            {"text": str(x), "kind": kind or "note"}
                            for x in v if isinstance(x, str))
            return self.index_documents(records, kind=kind, source=src)
        # text / markdown: split into meaningful paragraphs
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            logger.warning("text index failed (%s): %s", path, exc)
            return 0
        paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
        records = [{"text": p, "kind": kind or "note"} for p in paras]
        return self.index_documents(records, kind=kind, source=src)

    # -- read API (top-k cosine recall) -------------------------------------

    def recall(self, text: str, top_k: int = 5, kinds=None,
               target: str = None):
        """Top-k cosine-similarity recall across the unified index.

        This is the method the agent calls *before* response generation to
        surface archived payloads, bypasses, lessons and prior-chat knowledge
        relevant to the current query.
        """
        return self.query(text, top_k=top_k, kind=kinds, target=target)

    def query(self, text: str, top_k: int = 5, kind=None,
              target: str = None, where=None):
        """Return [{id, text, meta, score}] most similar to ``text``."""
        text = (text or "").strip()
        if not text:
            return []
        meta_filter = dict(where or {})
        if kind:
            kinds = {kind} if isinstance(kind, str) else set(kind or [])
            meta_filter["kind"] = sorted(kinds) if len(kinds) > 1 \
                else next(iter(kinds))
        if target:
            meta_filter.setdefault("target", target)
        with self._lock:
            if self._backend == "chroma" and self._col is not None:
                try:
                    count = self._col.count()
                    if not count:
                        return []
                    res = self._col.query(
                        query_texts=[text],
                        n_results=min(max(1, top_k), count),
                        where=self._chroma_where(meta_filter),
                    )
                    out = []
                    ids = (res.get("ids") or [[]])[0]
                    docs = (res.get("documents") or [[]])[0]
                    metas = (res.get("metadatas") or [[]])[0]
                    dists = (res.get("distances") or [[]])[0]
                    for i, doc_id in enumerate(ids):
                        dist = dists[i] if i < len(dists) else 1.0
                        out.append({
                            "id": doc_id,
                            "text": docs[i] if i < len(docs) else "",
                            "meta": metas[i] if i < len(metas) else {},
                            "score": max(0.0, 1.0 - float(dist)),
                        })
                    return out
                except Exception as exc:
                    logger.warning("chroma query failed (%s); local", exc)
            qv = embed(text)
            hits = []
            for rec in self._docs:
                meta = rec.get("meta") or {}
                if meta_filter:
                    ok = True
                    for k, v in meta_filter.items():
                        mv = meta.get(k)
                        if isinstance(v, list):
                            if mv not in v:
                                ok = False
                                break
                        elif mv != v:
                            ok = False
                            break
                    if not ok:
                        continue
                score = _cosine(qv, rec.get("vec"))
                if score > 0.02:
                    hits.append({"id": rec["id"], "text": rec["text"],
                                 "meta": meta, "score": round(float(score),
                                                              4)})
            hits.sort(key=lambda h: h["score"], reverse=True)
            return hits[:max(1, top_k)]

    def count(self, kind=None) -> int:
        with self._lock:
            if self._backend == "chroma" and self._col is not None:
                try:
                    if not kind:
                        return self._col.count()
                    res = self._col.get(
                        where=self._chroma_where({"kind": kind.lower()}),
                        include=[])
                    return len(res.get("ids") or [])
                except Exception:
                    return 0
            if not kind:
                return len(self._docs)
            k = kind.lower()
            return sum(1 for r in self._docs
                       if (r.get("meta") or {}).get("kind") == k)

    def snapshot(self, limit: int = 12, kinds=None) -> str:
        """Human-readable digest of the most recent episodes."""
        with self._lock:
            docs = list(self._docs) if self._backend == "local" else []
        if self._backend == "chroma" and self._col is not None:
            try:
                res = self._col.get(include=["documents", "metadatas"])
                docs = [{"id": i, "text": d, "meta": m} for i, d, m in zip(
                    res.get("ids") or [], res.get("documents") or [],
                    res.get("metadatas") or [])]
            except Exception:
                docs = []
        if kinds:
            kinds = {k.lower() for k in kinds}
            docs = [d for d in docs
                    if (d.get("meta") or {}).get("kind") in kinds]
        docs.sort(key=lambda d: (d.get("meta") or {}).get("ts", 0),
                  reverse=True)
        if not docs:
            return ""
        lines = []
        for d in docs[:max(1, limit)]:
            meta = d.get("meta") or {}
            tags = ",".join(meta.get("tags") or [])
            lines.append("- [%s%s] %s" % (
                meta.get("kind", "note"),
                (" | " + tags) if tags else "",
                (d.get("text") or "")[:220].replace("\n", " ")))
        return "\n".join(lines)

    # -- persistence (local backend) -----------------------------------------

    @staticmethod
    def _chroma_where(meta_filter):
        """Translate {field: value} into a Chroma ``where`` clause."""
        if not meta_filter:
            return None
        if len(meta_filter) == 1:
            (k, v), = meta_filter.items()
            return {k: {"$eq": v}}
        return {"$and": [{k: {"$eq": v}} for k, v in meta_filter.items()]}

    def _upgrade_embeddings(self):
        """Re-embed every local doc when the numeric embedding scheme changed."""
        if self._embed_version == _EMBED_VERSION:
            return
        if not (_HAVE_NUMPY or _HAVE_ST or _HAVE_CHROMA):
            return
        reembedded = 0
        for rec in self._docs:
            if rec.get("vec") is None:
                continue
            vec = embed(rec.get("text", ""))
            rec["vec"] = vec.tolist() if hasattr(vec, "tolist") else vec
            reembedded += 1
        self._embed_version = _EMBED_VERSION
        if reembedded:
            self._save_local()

    def _migrate_legacy(self):
        """Re-embed any legacy sparse hash vectors into the dense space."""
        migrated = 0
        for rec in self._docs:
            vec = rec.get("vec")
            if _is_sparse(vec) and (_HAVE_NUMPY or _HAVE_ST or _HAVE_CHROMA):
                rec["vec"] = embed(rec.get("text", "")).tolist() \
                    if hasattr(embed(rec.get("text", "")), "tolist") \
                    else embed(rec.get("text", ""))
                migrated += 1
        if migrated:
            self._save_local()

    def _load_local(self):
        try:
            with open(self._local_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._embed_version = int(data.get("embed_version", 0))                 if isinstance(data, dict) else 0
            docs = data.get("docs") if isinstance(data, dict) else data
            if isinstance(docs, list):
                for rec in docs:
                    vec = rec.get("vec")
                    # JSON object keys are strings; restore legacy sparse
                    # vectors to {int_index: float_weight}.
                    if isinstance(vec, dict):
                        rec["vec"] = {int(k): float(v)
                                      for k, v in vec.items()}
            self._docs = docs if isinstance(docs, list) else []
        except FileNotFoundError:
            self._embed_version = _EMBED_VERSION
            self._docs = []
        except Exception as exc:
            logger.warning("episodic store load failed: %s", exc)
            self._embed_version = _EMBED_VERSION
            self._docs = []
        self._merge_sidecars()

    def _snapshot_docs(self):
        return {"version": 2, "backend": self._backend,
                "engine": self._engine,
                "embed_version": _EMBED_VERSION,
                "docs": self._docs}

    def _save_local(self):
        try:
            os.makedirs(self._persist_dir, exist_ok=True)
            tmp = self._local_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._snapshot_docs(), fh, ensure_ascii=False,
                          separators=(",", ":"))
            _atomic_replace_retry(tmp, self._local_path)
        except Exception as exc:
            _sidecar_fallback(self, exc)

    def _merge_sidecars(self):
        """Bring records that were parked in a locked-sidecar backup
        (WinError 32 from a process holding the main file open) back into
        the in-memory index.  Hash-deduped, so no record is ever doubled
        and none is ever lost across sessions."""
        merged = 0
        try:
            files = sorted(
                f for f in os.listdir(self._persist_dir)
                if f.startswith("episodic_vectors.locked-")
                and f.endswith(".json"))
        except OSError:
            return 0
        for fn in files:
            try:
                with open(os.path.join(self._persist_dir, fn),
                          "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                continue
            for rec in (data.get("docs") if isinstance(data, dict)
                        else data) or []:
                digest = _sha(rec.get("text", ""), rec.get("meta") or {})
                if digest in self._known_hashes:
                    continue
                self._known_hashes.add(digest)
                self._docs.append(rec)
                merged += 1
        if merged:
            logger.warning(
                "episodic store: merged %d record(s) from locked sidecar "
                "backup(s) - main file was locked (WinError 32) the last "
                "time it was written", merged)
        return merged


# ---------------------------------------------------------------------------
# Unified Brain facade: chats.json + notes + lessons + methodologies
# ---------------------------------------------------------------------------
class UnifiedBrain:
    """Convenience facade over the single vector index.

    ``build()`` ingests the agent's chats.json export plus operational notes,
    execution lessons and target methodologies from disk into one semantic
    index, then ``recall()`` searches all of it with top-k cosine similarity.
    """

    def __init__(self, store: EpisodicVectorMemory = None):
        self.store = store or EpisodicVectorMemory()

    # -- ingestion -----------------------------------------------------------
    def index_chats(self, chats_path: str) -> int:
        return self.store.index_chats(chats_path)

    def index_files(self, paths, kind: str = "note") -> int:
        total = 0
        for p in paths or []:
            total += self.store.index_file(p, kind=kind)
        return total

    def index_memory_dir(self, memory_dir: str,
                         suffixes=(".md", ".json", ".txt")) -> int:
        """Ingest every report/note/lesson methodology file in a directory."""
        total = 0
        if not os.path.isdir(memory_dir):
            return 0
        for name in sorted(os.listdir(memory_dir)):
            if not name.lower().endswith(suffixes):
                continue
            path = os.path.join(memory_dir, name)
            if not os.path.isfile(path):
                continue
            total += self.store.index_file(path)
        return total

    # -- recall --------------------------------------------------------------
    def recall(self, query: str, top_k: int = 5, kinds=None):
        return self.store.recall(query, top_k=top_k, kinds=kinds)

    def build(self, chats_path: str = None, notes_dir: str = None) -> dict:
        """One-shot ingestion of all knowledge sources."""
        counts = {"chats": 0, "notes": 0, "total": 0}
        if chats_path and os.path.isfile(chats_path):
            counts["chats"] = self.index_chats(chats_path)
        if notes_dir and os.path.isdir(notes_dir):
            counts["notes"] = self.index_memory_dir(notes_dir)
        counts["total"] = counts["chats"] + counts["notes"]
        return counts


__all__ = [
    "EpisodicVectorMemory", "UnifiedBrain", "embed", "get_embedding_engine",
    "_cosine",  # used by tests
]
