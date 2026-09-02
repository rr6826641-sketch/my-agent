"""Game-Master World-State Engine.

A centralized, live structured representation of the target environment -
the single source of truth every sub-agent (Recon, Analyzer, Exploiter),
GOAP planner and hypothesis generator reads from and writes to, so nobody
re-scans what the campaign already knows.

Four tracked layers:

1. Hosts & network topology  - IPs, open ports, OS fingerprints,
   reachability, first/last-seen.
2. Assets & services         - web apps, databases, cloud buckets, APIs,
   shares - each tied to its host with tech fingerprint.
3. Compromise state          - per-host access level ladder
   (unauthenticated -> user -> root/admin) with evidence and the
   credential/loot notes that came with the escalation.
4. Security controls map     - active WAFs, EDR indicators, network
   segmentation observations, rate limiters.

Persistence: the full world snapshot is serialized to JSON and mirrored
into ``rpg/lorebook.db`` (tables ``world_state`` + ``world_events``)
after every mutation, with an append-only event log for the audit trail.
The in-memory layer is authoritative at run time; SQLite is the
durable, cross-session mirror that GOAP/hypothesis engines query.

Example::

    wm = WorldStateManager("rpg/lorebook.db")
    wm.record_host("10.0.0.5", ports=[22, 80], os_fingerprint="Ubuntu 22.04")
    wm.record_asset("10.0.0.5", "webapp", "http://10.0.0.5/admin")
    wm.escalate("10.0.0.5", "user", evidence="CVE-2024-1234 shell")
    wm.record_control("waf", target="10.0.0.5", detail="Cloudflare detected")
    print(json.dumps(wm.snapshot(), indent=2))
"""

import json
import os
import sqlite3
import threading
import time
from datetime import datetime

# Canonical access-level ladder, lowest -> highest.
ACCESS_LEVELS = ("unauthenticated", "user", "root")

_DEFAULT_DB = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "rpg", "lorebook.db")

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS world_state ("
    " id INTEGER PRIMARY KEY CHECK (id = 1),"
    " snapshot TEXT NOT NULL DEFAULT '{}',"
    " version INTEGER NOT NULL DEFAULT 0,"
    " updated_at TEXT NOT NULL DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS world_events ("
    " event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " ts TEXT NOT NULL,"
    " actor TEXT NOT NULL DEFAULT '',"
    " kind TEXT NOT NULL,"
    " target TEXT NOT NULL DEFAULT '',"
    " detail TEXT NOT NULL DEFAULT '')",
    "CREATE INDEX IF NOT EXISTS idx_world_events_ts"
    " ON world_events(ts)",
)


def _now_iso():
    return datetime.now().isoformat(timespec="seconds")


def _norm_host(host):
    return (host or "").strip().lower()


def _norm_ports(ports):
    out = []
    for p in (ports or []):
        try:
            p = int(p)
            if 1 <= p <= 65535:
                out.append(p)
        except (TypeError, ValueError):
            continue
    return sorted(set(out))


class WorldStateManager:
    """Live world-state + SQLite mirror. All methods are thread-safe."""

    MAX_EVENTS = 500          # event log cap per query
    MAX_EVENT_KEEP = 2000     # rows retained in SQLite

    def __init__(self, db_path=None):
        self.db_path = db_path or _DEFAULT_DB
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        for stmt in _SCHEMA:
            self._conn.execute(stmt)
        self._conn.commit()
        self._world = self._load_or_init()

    # -- persistence ---------------------------------------------------------

    def _load_or_init(self):
        row = self._conn.execute(
            "SELECT snapshot FROM world_state WHERE id = 1").fetchone()
        if row:
            try:
                return json.loads(row["snapshot"])
            except (ValueError, TypeError):
                pass
        world = self._empty_world()
        self._persist(world)
        return world

    def _empty_world(self):
        return {"hosts": {}, "assets": {}, "controls": {},
                "version": 0, "updated_at": _now_iso(),
                "meta": {"created": _now_iso()}}

    def _persist(self, world=None):
        world = world or self._world
        world["version"] = int(world.get("version", 0)) + 1
        world["updated_at"] = _now_iso()
        self._conn.execute(
            "INSERT INTO world_state (id, snapshot, version, updated_at)"
            " VALUES (1, ?, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET snapshot = excluded.snapshot,"
            " version = excluded.version, updated_at = excluded.updated_at",
            (json.dumps(world, ensure_ascii=False), world["version"],
             world["updated_at"]))
        self._conn.commit()

    def _log_event(self, kind, target="", detail="", actor=""):
        self._conn.execute(
            "INSERT INTO world_events (ts, actor, kind, target, detail)"
            " VALUES (?, ?, ?, ?, ?)",
            (_now_iso(), (actor or "agent")[:60], (kind or "update")[:40],
             (target or "")[:120], (detail or "")[:500]))
        self._conn.execute(
            "DELETE FROM world_events WHERE event_id NOT IN"
            " (SELECT event_id FROM world_events"
            "  ORDER BY event_id DESC LIMIT ?)", (self.MAX_EVENT_KEEP,))
        self._conn.commit()

    # -- 1. hosts & network topology ------------------------------------------

    def record_host(self, ip, ports=None, os_fingerprint="", hostname="",
                    reachable=True, source="", actor=""):
        """Register/update a discovered host. Returns the host record."""
        ip = _norm_host(ip)
        if not ip:
            return {"error": "host ip required"}
        with self._lock:
            h = self._world["hosts"].setdefault(ip, {
                "ip": ip, "hostname": "", "ports": [], "os_fingerprint": "",
                "reachable": True, "access": "unauthenticated",
                "first_seen": _now_iso(), "last_seen": _now_iso(),
                "sources": []})
            if ports:
                merged = _norm_ports(list(h.get("ports") or []) + list(ports))
                h["ports"] = merged
            if hostname:
                h["hostname"] = hostname
            if os_fingerprint:
                h["os_fingerprint"] = os_fingerprint
            h["reachable"] = bool(reachable)
            h["last_seen"] = _now_iso()
            if source and source not in h["sources"]:
                h["sources"].append(str(source)[:60])
            self._persist()
            self._log_event("host_recorded", ip,
                            "ports=%s os=%s%s" % (
                                h["ports"], os_fingerprint,
                                " via %s" % source if source else ""),
                            actor=actor)
            return dict(h)

    def link_hosts(self, ip_a, ip_b, relation="connected", actor=""):
        """Record a network-topology edge between two hosts."""
        a, b = _norm_host(ip_a), _norm_host(ip_b)
        if not a or not b or a == b:
            return {"error": "two distinct hosts required"}
        with self._lock:
            edge_id = " | ".join(sorted((a, b)))
            edges = self._world.setdefault("topology", {})
            edges[edge_id] = {"a": a, "b": b,
                              "relation": relation[:40],
                              "ts": _now_iso()}
            self._persist()
            self._log_event("topology_link", edge_id, relation, actor=actor)
            return edges[edge_id]

    # -- 2. assets & services --------------------------------------------------

    def record_asset(self, host, kind, identifier, tech="", notes="",
                     actor=""):
        """Register a discovered asset/service bound to a host.

        ``kind`` is free-form but commonly: webapp, db, bucket, api,
        share, mail, vpn, iot.
        """
        host = _norm_host(host)
        kind = (kind or "service").strip().lower()[:30]
        identifier = (identifier or "").strip()[:300]
        if not identifier:
            return {"error": "asset identifier required"}
        asset_id = "%s:%s:%s" % (host or "global", kind, identifier)
        with self._lock:
            self._world["assets"][asset_id] = {
                "asset_id": asset_id, "host": host, "kind": kind,
                "identifier": identifier, "tech": tech[:120],
                "notes": notes[:400], "first_seen": _now_iso()}
            self._persist()
            self._log_event("asset_recorded", identifier,
                            "%s @ %s%s" % (kind, host,
                                           " tech=%s" % tech if tech else ""),
                            actor=actor)
            return dict(self._world["assets"][asset_id])

    # -- 3. compromise state -----------------------------------------------------

    def escalate(self, host, level, evidence="", creds="", actor=""):
        """Raise (or set) the compromise level of a host.

        ``level``: unauthenticated | user | root (root == admin/root).
        Never silently lowers an already-earned level unless ``force``.
        Returns dict(level, changed, previous).
        """
        host = _norm_host(host)
        level = (level or "").strip().lower()
        if level not in ACCESS_LEVELS:
            return {"error": "level must be one of %s" % (ACCESS_LEVELS,)}
        with self._lock:
            h = self._world["hosts"].get(host)
            if h is None:
                h = self.record_host(host, actor=actor)
            prev = h.get("access", "unauthenticated")
            changed = False
            if ACCESS_LEVELS.index(level) > ACCESS_LEVELS.index(prev):
                h["access"] = level
                h["access_evidence"] = (evidence or "")[:400]
                h["access_ts"] = _now_iso()
                changed = True
                self._persist()
                self._log_event("escalation", host,
                                "%s -> %s%s" % (prev, level,
                                                " | %s" % evidence
                                                if evidence else ""),
                                actor=actor)
            if creds:
                loot = self._world.setdefault("loot", {})
                loot.setdefault(host, [])
                entry = {"creds": creds[:300], "level": level,
                         "ts": _now_iso()}
                if entry not in loot[host]:
                    loot[host].append(entry)
                    self._persist()
                    self._log_event("creds_captured", host,
                                    "level=%s" % level, actor=actor)
            return {"host": host, "level": h.get("access"),
                    "changed": changed, "previous": prev}

    # -- 4. security controls map -------------------------------------------------

    def record_control(self, kind, target="", detail="", actor=""):
        """Record an observed security control.

        ``kind`` commonly: waf, edr, segmentation, ratelimit,
        antivirus, ids, mfa, hardening.
        """
        kind = (kind or "control").strip().lower()[:30]
        target = _norm_host(target) or "global"
        if not detail:
            return {"error": "detail required"}
        ctrl_id = "%s:%s" % (kind, target)
        with self._lock:
            self._world["controls"][ctrl_id] = {
                "kind": kind, "target": target, "detail": detail[:400],
                "ts": _now_iso()}
            self._persist()
            self._log_event("control_recorded", target,
                            "%s: %s" % (kind, detail[:120]), actor=actor)
            return dict(self._world["controls"][ctrl_id])

    # -- queries (for GOAP planners & hypothesis generators) -----------------------

    def snapshot(self, include_events=0):
        """Full world snapshot; optional tail of the event log."""
        with self._lock:
            snap = json.loads(json.dumps(self._world, ensure_ascii=False))
        if include_events:
            rows = self._conn.execute(
                "SELECT ts, actor, kind, target, detail FROM world_events"
                " ORDER BY event_id DESC LIMIT ?",
                (min(int(include_events), self.MAX_EVENTS),)).fetchall()
            snap["recent_events"] = [dict(r) for r in rows]
        return snap

    def known_hosts(self, reachable_only=True):
        """Host list for planners: no re-scan needed for these."""
        with self._lock:
            hosts = [dict(h) for h in self._world["hosts"].values()]
        if reachable_only:
            hosts = [h for h in hosts if h.get("reachable")]
        return hosts

    def compromised(self, min_level="user"):
        """Hosts at or above ``min_level`` access."""
        if min_level not in ACCESS_LEVELS:
            min_level = "user"
        floor = ACCESS_LEVELS.index(min_level)
        with self._lock:
            return [dict(h) for h in self._world["hosts"].values()
                    if ACCESS_LEVELS.index(h.get("access",
                                                  "unauthenticated")) >= floor]

    def assets_for(self, host=None, kind=None):
        """Assets filtered by host and/or kind."""
        host = _norm_host(host) if host else None
        kind = kind.strip().lower() if kind else None
        with self._lock:
            out = [dict(a) for a in self._world["assets"].values()]
        if host:
            out = [a for a in out if a["host"] == host]
        if kind:
            out = [a for a in out if a["kind"] == kind]
        return out

    def controls_for(self, target=None):
        """Controls map filtered by target (None = all)."""
        target = _norm_host(target) if target else None
        with self._lock:
            out = [dict(c) for c in self._world["controls"].values()]
        if target:
            out = [c for c in out
                   if c["target"] == target or c["target"] == "global"]
        return out

    def planning_facts(self):
        """Flat world-fact strings in the planner's fact vocabulary.

        Feeds the GOAP planner (``surface_mapped``, ``foothold``,
        ``elevated``, ...) plus per-host facts, so plans are built from
        the world model instead of raw re-scan output.
        """
        facts = set()
        with self._lock:
            hosts = list(self._world["hosts"].values())
            assets = list(self._world["assets"].values())
            controls = list(self._world["controls"].values())
        if hosts:
            facts.add("surface_mapped")
        for h in hosts:
            facts.add("host:%s" % h["ip"])
            if h.get("ports"):
                facts.add("ports_known:%s" % h["ip"])
            acc = h.get("access", "unauthenticated")
            if acc in ("user", "root"):
                facts.add("foothold")
                facts.add("access:%s:%s" % (h["ip"], acc))
            if acc == "root":
                facts.add("elevated")
        if any(a["kind"] == "db" for a in assets):
            facts.add("db_found")
        if any(a["kind"] == "webapp" for a in assets):
            facts.add("webapp_found")
        if controls:
            facts.add("controls_mapped")
        return sorted(facts)

    def events(self, limit=50):
        rows = self._conn.execute(
            "SELECT ts, actor, kind, target, detail FROM world_events"
            " ORDER BY event_id DESC LIMIT ?",
            (min(int(limit or 50), self.MAX_EVENTS),)).fetchall()
        return [dict(r) for r in rows]

    def stats(self):
        with self._lock:
            return {
                "hosts": len(self._world["hosts"]),
                "assets": len(self._world["assets"]),
                "controls": len(self._world["controls"]),
                "topology_edges": len(self._world.get("topology", {})),
                "compromised": len(self.compromised("user")),
                "version": self._world.get("version", 0),
                "updated_at": self._world.get("updated_at"),
                "db": self.db_path,
            }


# Module-level singleton management -------------------------------------

_manager = None
_manager_lock = threading.Lock()


def get_manager(db_path=None):
    """Process-wide WorldStateManager singleton (lazily created)."""
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = WorldStateManager(db_path)
        return _manager


def reset_manager():
    """Drop the singleton (used by tests)."""
    global _manager
    with _manager_lock:
        _manager = None
