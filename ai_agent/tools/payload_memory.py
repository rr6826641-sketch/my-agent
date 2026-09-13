"""Cross-tool, cross-session payload effectiveness memory.

Every adaptive/feedback tool that sends payloads at a target records what
happened here: which payload produced a signal (SQL error, WAF block,
reflection, stack trace, time delay ...) and which came back cold. The
store persists as JSON on disk (project root, payload_memory.json) so the
learning survives sessions, targets and agent restarts.

API
---
PayloadMemory
    record(host, payload, hit, vuln_class="", db="", waf="", source="")
        - one observation per (host, payload); hits/misses accumulate
    seed(host, limit)
        - ranked payload strings to prepend to a fresh fuzz run
    top(host, vuln_class, top_k)
        - ranked entries with score + signal breakdown (for the agent)
    forget(host)
        - drop one host (or everything)
    stats()
        - quick counts for the prompt

Ranking: smoothed effectiveness (Laplace) x exponential recency decay,
so recently-productive payloads win and stale ones fade out. Thread-safe;
writes are atomic (temp file + os.replace). A module-level singleton
(PAYLOAD_MEMORY) is shared by adaptive_fuzz and the payload_memory_* tools.
"""

import datetime
import json
import math
import os
import re
import threading

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "payload_memory.json",
)

MAX_ENTRIES_PER_HOST = 500
RECENCY_HALFLIFE_DAYS = 45.0
KNOWN_SIGNALS = ("sql_error", "waf_block", "reflection", "stack_trace",
                 "time_delay", "server_error", "redirect", "auth_change",
                 "content_delta")


def _norm_host(host):
    host = str(host or "").strip().lower()
    host = re.sub(r"^https?://", "", host)
    host = host.split("/")[0].split("?")[0]
    return host


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


class PayloadMemory:
    """Thread-safe persistent payload-effectiveness store (JSON on disk)."""

    def __init__(self, path=DEFAULT_PATH):
        self.path = path
        self._lock = threading.Lock()
        self._data = {"payloads": {}}
        self._load()

    # ------------------------------------------------------------- io
    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and isinstance(
                    data.get("payloads"), dict):
                self._data = data
        except Exception:
            self._data = {"payloads": {}}

    def _save_locked(self):
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
        except Exception:
            pass

    # -------------------------------------------------------- ranking
    @staticmethod
    def _score(entry, now_dt):
        hits = int(entry.get("hits", 0))
        misses = int(entry.get("misses", 0))
        base = (hits + 1.0) / (hits + misses + 2.0)   # Laplace-smoothed
        try:
            last = datetime.datetime.fromisoformat(
                entry.get("last_seen") or _now())
        except ValueError:
            last = now_dt
        days = max(0.0, (now_dt - last).total_seconds() / 86400.0)
        recency = math.exp(-days / RECENCY_HALFLIFE_DAYS)
        return round(base * (0.35 + 0.65 * recency), 4)

    def _entries_for(self, host, vuln_class=None):
        buckets = self._data["payloads"]
        if host:
            rows = list(buckets.get(_norm_host(host), []))
        else:
            rows = [e for rows in buckets.values() for e in rows]
        if vuln_class:
            vc = str(vuln_class).strip().lower()
            rows = [e for e in rows
                    if (e.get("vuln_class") or "").lower() == vc]
        return rows

    @staticmethod
    def _prune_locked(rows):
        if len(rows) > MAX_ENTRIES_PER_HOST:
            rows.sort(key=lambda e: (int(e.get("hits", 0)),
                                     e.get("last_seen", "")),
                      reverse=True)
            del rows[MAX_ENTRIES_PER_HOST:]

    # ------------------------------------------------------------ api
    def record(self, host, payload, hit, vuln_class="", db="", waf="",
               source=""):
        """Record one observation. hit=True when the payload produced a
        usable signal. Returns the updated entry summary."""
        host = _norm_host(host)
        payload = str(payload or "").strip()
        if not host or not payload:
            return "payload_memory_record: host and payload are required"
        ts = _now()
        with self._lock:
            rows = self._data["payloads"].setdefault(host, [])
            entry = None
            for e in rows:
                if e.get("payload") == payload:
                    entry = e
                    break
            if entry is None:
                entry = {"payload": payload, "hits": 0, "misses": 0,
                         "vuln_class": "", "db": "", "waf": "",
                         "source": "", "first_seen": ts, "last_seen": ts}
                rows.append(entry)
            if hit:
                entry["hits"] = int(entry.get("hits", 0)) + 1
            else:
                entry["misses"] = int(entry.get("misses", 0)) + 1
            entry["last_seen"] = ts
            if vuln_class:
                entry["vuln_class"] = str(vuln_class)[:60]
            if db:
                entry["db"] = str(db)[:40]
            if waf:
                entry["waf"] = str(waf)[:40]
            if source:
                entry["source"] = str(source)[:40]
            self._prune_locked(rows)
            self._save_locked()
            score = self._score(entry, datetime.datetime.now())
        return ("recorded: host=%s hit=%s hits=%d misses=%d score=%.3f "
                "payload=%s" % (host, bool(hit), entry["hits"],
                                entry["misses"], score, payload[:80]))

    def seed(self, host, limit=8):
        """Ranked payload strings for a host (hits>0 only)."""
        host = _norm_host(host)
        if not host:
            return []
        now_dt = datetime.datetime.now()
        with self._lock:
            rows = [e for e in self._entries_for(host) if e.get("hits", 0) > 0]
            ranked = sorted(rows, key=lambda e: self._score(e, now_dt),
                            reverse=True)[:max(1, int(limit or 8))]
            return [e["payload"] for e in ranked]

    def top(self, host="", vuln_class="", top_k=10):
        """Human-readable ranked table for the agent."""
        now_dt = datetime.datetime.now()
        with self._lock:
            rows = self._entries_for(_norm_host(host),
                                     vuln_class=vuln_class)
            if not rows:
                cond = ("host=%s " % host) if host else ""
                cond += ("vuln_class=%s" % vuln_class) if vuln_class else ""
                return "(no payload memory yet %s- run adaptive_fuzz first)" \
                    % (cond + (" " if cond else ""))
            ranked = sorted(rows, key=lambda e: self._score(e, now_dt),
                            reverse=True)[:max(1, int(top_k or 10))]
        lines = ["Top %d payload(s) by effectiveness%s:"
                 % (len(ranked), (" for %s" % _norm_host(host)) if host
                    else "")]
        for e in ranked:
            bits = ["hits=%d" % e.get("hits", 0),
                    "misses=%d" % e.get("misses", 0),
                    "score=%.3f" % self._score(e, now_dt)]
            if e.get("db"):
                bits.append("db=%s" % e["db"])
            if e.get("waf"):
                bits.append("waf=%s" % e["waf"])
            if e.get("vuln_class"):
                bits.append("class=%s" % e["vuln_class"])
            lines.append("  %s | %s | last_seen=%s | %s"
                         % (" | ".join(bits), e.get("payload", "")[:90],
                            e.get("last_seen", "?"), e.get("source", "")))
        return "\n".join(lines)

    def rank_global(self, vuln_class="", top_k=10, min_samples=1):
        """CROSS-CAMPAIGN ranking: aggregate payload effectiveness across
        every host/campaign ever touched.  A payload that produced signals
        on many distinct hosts beats a single-host fluke, so campaigns
        share what actually works."""
        now_dt = datetime.datetime.now()
        try:
            min_samples = max(1, int(min_samples or 1))
            top_k = max(1, int(top_k or 10))
        except (TypeError, ValueError):
            min_samples, top_k = 1, 10
        vc = str(vuln_class or "").strip().lower()
        with self._lock:
            buckets = self._data["payloads"]
            agg = {}
            for host, rows in buckets.items():
                for e in rows:
                    if vc and (e.get("vuln_class") or "").lower() != vc:
                        continue
                    p = str(e.get("payload") or "").strip()
                    if not p:
                        continue
                    a = agg.setdefault(p, {
                        "payload": p, "hits": 0, "misses": 0,
                        "hosts": set(), "scores": [], "vuln_class": "",
                        "db": "", "waf": "", "last_seen": "",
                        "source": ""})
                    a["hits"] += int(e.get("hits", 0))
                    a["misses"] += int(e.get("misses", 0))
                    a["hosts"].add(host)
                    a["scores"].append(self._score(e, now_dt))
                    for k in ("vuln_class", "db", "waf", "source"):
                        if e.get(k) and not a.get(k):
                            a[k] = e[k]
                    if e.get("last_seen", "") > a["last_seen"]:
                        a["last_seen"] = e["last_seen"]
            ranked = []
            for a in agg.values():
                if len(a["hosts"]) < min_samples:
                    continue
                n = len(a["scores"])
                gscore = round(sum(a["scores"]) / n, 4)
                ranked.append({
                    "payload": a["payload"],
                    "hits": a["hits"],
                    "misses": a["misses"],
                    "hosts": len(a["hosts"]),
                    "score": gscore,
                    "vuln_class": a["vuln_class"],
                    "db": a["db"],
                    "waf": a["waf"],
                    "last_seen": a["last_seen"],
                    "source": a["source"],
                })
            ranked.sort(key=lambda r: (r["hosts"], r["score"],
                                       r["hits"]), reverse=True)
        return ranked[:top_k]

    def forget(self, host=""):
        with self._lock:
            if host:
                removed = self._data["payloads"].pop(_norm_host(host), None)
                self._save_locked()
                n = len(removed or [])
                return "forgot %d remembered payload(s) for host %s" \
                    % (n, _norm_host(host))
            n = sum(len(v) for v in self._data["payloads"].values())
            self._data = {"payloads": {}}
            self._save_locked()
            return "reset payload memory (%d entries removed)" % n

    def stats(self):
        with self._lock:
            hosts = len(self._data["payloads"])
            entries = sum(len(v) for v in self._data["payloads"].values())
            hits = sum(int(e.get("hits", 0))
                       for v in self._data["payloads"].values() for e in v)
        return "payload memory: %d host(s), %d payload(s), %d hit(s)" \
            % (hosts, entries, hits)


PAYLOAD_MEMORY = PayloadMemory()


def tool_payload_memory_top(host="", vuln_class="", top_k=10):
    """Query the cross-session payload effectiveness memory."""
    return PAYLOAD_MEMORY.top(host=host, vuln_class=vuln_class,
                              top_k=top_k)


def tool_payload_memory_record(host="", payload="", signal="", vuln_class="",
                               db="", waf=""):
    """Manually record a payload observation (adaptive_fuzz records
    automatically). signal: any non-empty anomaly name = hit."""
    sig = str(signal or "").strip()
    hit = bool(sig) and sig.lower() not in ("none", "no", "", "miss",
                                            "no_signal")
    if sig and sig.lower() not in KNOWN_SIGNALS and hit:
        vuln_class = vuln_class or sig[:60]
    return PAYLOAD_MEMORY.record(host, payload, hit, vuln_class=vuln_class,
                                 db=db, waf=waf, source="manual")


def tool_payload_memory_reset(host=""):
    """Forget remembered payloads for one host, or everything when host
    is omitted."""
    return PAYLOAD_MEMORY.forget(host)


def tool_payload_memory_ranking(vuln_class="", top_k=10, min_samples=1):
    """CROSS-CAMPAIGN payload ranking: payloads that produced signals on
    MULTIPLE hosts/campaigns, ranked. min_samples = minimum distinct hosts
    before a payload enters the global leaderboard (default 1)."""
    try:
        top_k = max(1, int(top_k or 10))
        min_samples = max(1, int(min_samples or 1))
    except (TypeError, ValueError):
        top_k, min_samples = 10, 1
    rows = PAYLOAD_MEMORY.rank_global(vuln_class=vuln_class,
                                      top_k=top_k, min_samples=min_samples)
    if not rows:
        return ("(no cross-campaign payload ranking yet - run missions/"
                "adaptive_fuzz against multiple hosts first)")
    lines = ["Cross-campaign payload leaderboard (top %d, min %d host(s)%s):"
             % (len(rows), min_samples,
                (" class=%s" % vuln_class) if vuln_class else "")]
    for r in rows:
        bits = ["hits=%d" % r["hits"], "misses=%d" % r["misses"],
                "hosts=%d" % r["hosts"], "score=%.3f" % r["score"]]
        if r.get("db"):
            bits.append("db=%s" % r["db"])
        if r.get("waf"):
            bits.append("waf=%s" % r["waf"])
        if r.get("vuln_class"):
            bits.append("class=%s" % r["vuln_class"])
        lines.append("  %s | %s | last_seen=%s | %s"
                     % (" | ".join(bits), r["payload"][:90],
                        r.get("last_seen", "?"), r.get("source", "")))
    return "\n".join(lines)
