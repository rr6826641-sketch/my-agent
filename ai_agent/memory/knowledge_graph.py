"""Persistent Target Knowledge Graph.

A dependency-light, SQLite-backed property graph that maps everything the
agent fleet learns about an engagement target: IPs, open ports, active
services, tech-stack fingerprints and identified CVEs - plus the edges
between them and a per-asset scan ledger used to kill duplicate work.

Why a graph?
  A flat "findings" log cannot answer the questions a swarm actually asks
  while working, e.g. *"which services on 10.0.0.8 were fingerprinted and
  which are still un-scanned?"* or *"is CVE-2024-3094 already attached to
  this host?"*. Nodes + typed edges answer those queries in one hop, and
  because everything is persisted to a single SQLite file on disk the graph
  survives process restarts and is shared by the Main Agent and every
  Sub-Agent - which is exactly what eliminates duplicate scans across
  sessions.

Design
-------
* Every node is ``(kind, key)`` unique. Re-observing an asset *updates* the
  node and bumps ``last_seen``; it never creates a second node, so repeated
  recon phases converge instead of duplicating.
* Edges are ``(src, rel, dst)`` unique with a hit ``count``. ``link()``
  auto-creates missing endpoint nodes, so a sub-agent can record a bare CVE
  attachment without first re-inserting its host.
* Node kinds: ``target``, ``domain``, ``ip``, ``port``, ``service``,
  ``tech``, ``cve``. Canonical relationship vocabulary (see ``RELS``):
  ``CONTAINS`` (target/domain -> ip), ``HAS_PORT`` (ip -> port),
  ``RUNS_SERVICE`` (ip -> service), ``SERVES_ON`` (service -> port),
  ``USES_TECH`` (service -> tech), ``RUNS_TECH`` (ip -> tech) and
  ``AFFECTED_BY`` (ip|service|tech -> cve).
* A separate ``scans`` ledger stores one row per (scope, asset, tool).
  ``note_scan()``/``last_scan()``/``scan_needed()`` give Recon sub-agents a
  cheap "has this already been scanned?" check before they fire a single
  packet - the duplicate-scan eliminator.

SQLite is the storage engine (stdlib, transactional, one shared file).
ChromaDB can be layered behind the same API later if vector similarity
over tech/CVE text is required; nothing in this module assumes either
backend beyond a plain relational store.

Example::

    kg = KnowledgeGraph()                      # memory/knowledge_graph.db
    kg.add_ip("10.0.0.8", target="acme")
    kg.add_port("10.0.0.8", 443, proto="tcp")
    svc = kg.add_service("10.0.0.8", "nginx", version="1.18.0",
                          port=443)
    kg.add_tech("service", svc["key"], "nginx", version="1.18.0")
    kg.add_cve("service", svc["key"], "CVE-2024-3094", severity="critical")
    kg.target_snapshot("acme")                 # everything about acme
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

log = logging.getLogger("my-agent.knowledge_graph")

# ---------------------------------------------------------------------------
# Constants: canonical kinds & relationship vocabulary
# ---------------------------------------------------------------------------

KIND_TARGET = "target"
KIND_DOMAIN = "domain"
KIND_IP = "ip"
KIND_PORT = "port"
KIND_SERVICE = "service"
KIND_TECH = "tech"
KIND_CVE = "cve"

KINDS = (KIND_TARGET, KIND_DOMAIN, KIND_IP, KIND_PORT,
         KIND_SERVICE, KIND_TECH, KIND_CVE)

CONTAINS = "CONTAINS"            # target/domain -> ip
HAS_PORT = "HAS_PORT"            # ip -> port
RUNS_SERVICE = "RUNS_SERVICE"    # ip -> service
SERVES_ON = "SERVES_ON"          # service -> port
USES_TECH = "USES_TECH"          # service -> tech
RUNS_TECH = "RUNS_TECH"          # ip -> tech  (stack fingerprint w/o service)
AFFECTED_BY = "AFFECTED_BY"      # ip|service|tech -> cve

RELS = (CONTAINS, HAS_PORT, RUNS_SERVICE, SERVES_ON,
        USES_TECH, RUNS_TECH, AFFECTED_BY)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _now() -> float:
    return time.time()


def _jenc(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _jdec(raw: Optional[str], default: Any = None) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default


def default_db_path() -> str:
    """Resolve the shared graph file next to the memory package.

    ``<project>/memory/knowledge_graph.db`` - the same on-disk file is used
    by the Main Agent and every spawned sub-agent, which is what makes the
    graph a cross-session, cross-agent shared brain.
    """
    here = os.path.dirname(os.path.abspath(__file__))      # .../ai_agent/memory
    return os.path.join(os.path.dirname(os.path.dirname(here)),
                        "memory", "knowledge_graph.db")


class KnowledgeGraphError(Exception):
    """Base error for the knowledge graph."""


class UnsupportedKind(KnowledgeGraphError):
    """Raised when a caller uses a node kind outside the canonical set."""


def _require_kind(kind: str) -> str:
    if kind not in KINDS:
        raise UnsupportedKind(
            f"unsupported node kind {kind!r}; expected one of {KINDS}")
    return kind


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class KnowledgeGraph:
    """Thread-safe property graph persisted to SQLite.

    All mutations and reads go through a single ``RLock``-protected
    connection; ``check_same_thread=False`` lets Main-Agent and sub-agent
    threads share one instance, and the on-disk file lets *separate
    processes* share the same graph across sessions.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or default_db_path()
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._ensure_schema()

    # -- schema ------------------------------------------------------------

    def _ensure_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS nodes(
                  kind TEXT NOT NULL,
                  key TEXT NOT NULL,
                  label TEXT NOT NULL DEFAULT '',
                  props TEXT NOT NULL DEFAULT '{}',
                  tags TEXT NOT NULL DEFAULT '[]',
                  source TEXT NOT NULL DEFAULT '',
                  first_seen REAL NOT NULL,
                  last_seen REAL NOT NULL,
                  PRIMARY KEY (kind, key)
                );
                CREATE TABLE IF NOT EXISTS edges(
                  src_kind TEXT NOT NULL,
                  src_key TEXT NOT NULL,
                  rel TEXT NOT NULL,
                  dst_kind TEXT NOT NULL,
                  dst_key TEXT NOT NULL,
                  props TEXT NOT NULL DEFAULT '{}',
                  count INTEGER NOT NULL DEFAULT 1,
                  first_seen REAL NOT NULL,
                  last_seen REAL NOT NULL,
                  PRIMARY KEY (src_kind, src_key, rel, dst_kind, dst_key)
                );
                CREATE TABLE IF NOT EXISTS scans(
                  scope TEXT NOT NULL DEFAULT '',
                  subject_type TEXT NOT NULL,
                  subject_key TEXT NOT NULL,
                  tool TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'ok',
                  summary TEXT NOT NULL DEFAULT '',
                  meta TEXT NOT NULL DEFAULT '{}',
                  ts REAL NOT NULL,
                  PRIMARY KEY (scope, subject_type, subject_key, tool)
                );
                CREATE INDEX IF NOT EXISTS idx_edges_src
                  ON edges(src_kind, src_key);
                CREATE INDEX IF NOT EXISTS idx_edges_dst
                  ON edges(dst_kind, dst_key);
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "KnowledgeGraph":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- low-level helpers -------------------------------------------------

    def _get_node_row(self, kind: str, key: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM nodes WHERE kind=? AND key=?", (kind, key)
        ).fetchone()

    def _row_to_node(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "kind": row["kind"],
            "key": row["key"],
            "label": row["label"],
            "props": _jdec(row["props"], {}),
            "tags": _jdec(row["tags"], []),
            "source": row["source"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        }

    @staticmethod
    def _merge_props(old: Dict[str, Any], new: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        merged = dict(old or {})
        if new:
            merged.update({k: v for k, v in new.items() if v is not None})
        return merged

    # -- nodes -------------------------------------------------------------

    def upsert_node(
        self,
        kind: str,
        key: str,
        label: Optional[str] = None,
        props: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        source: Optional[str] = None,
        update_props: bool = True,
    ) -> Dict[str, Any]:
        """Insert or refresh a node.

        Re-discovery updates ``label``/``props``/``tags`` and bumps
        ``last_seen`` instead of inserting a duplicate - the core
        anti-duplication guarantee for both nodes and scans.
        """
        kind = _require_kind(kind)
        now = _now()
        with self._lock, self._conn:
            row = self._get_node_row(kind, key)
            if row is None:
                self._conn.execute(
                    "INSERT INTO nodes(kind,key,label,props,tags,source,"
                    " first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
                    (kind, key, label or key, _jenc(props or {}),
                     _jenc(tags or []), source or "", now, now),
                )
            else:
                merged_props = (
                    self._merge_props(_jdec(row["props"], {}), props)
                    if update_props else (props or _jdec(row["props"], {}))
                )
                old_tags = set(_jdec(row["tags"], []))
                new_tags = old_tags | set(tags or [])
                self._conn.execute(
                    "UPDATE nodes SET label=?, props=?, tags=?, source=?,"
                    " last_seen=? WHERE kind=? AND key=?",
                    (label if label is not None else row["label"],
                     _jenc(merged_props), _jenc(sorted(new_tags)),
                     source or row["source"], now, kind, key),
                )
        return self.node(kind, key)  # type: ignore[return-value]

    def node(self, kind: str, key: str) -> Optional[Dict[str, Any]]:
        _require_kind(kind)
        with self._lock:
            row = self._get_node_row(kind, key)
        return self._row_to_node(row) if row else None

    def has_node(self, kind: str, key: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM nodes WHERE kind=? AND key=?", (kind, key)
            ).fetchone()
        return row is not None

    def nodes_by_kind(self, kind: str, limit: int = 500) -> List[Dict[str, Any]]:
        _require_kind(kind)
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM nodes WHERE kind=? ORDER BY last_seen DESC"
                " LIMIT ?", (kind, limit)
            ).fetchall()
        return [self._row_to_node(r) for r in rows]

    def search_nodes(self, text: str, kinds: Optional[List[str]] = None,
                     limit: int = 20) -> List[Dict[str, Any]]:
        """Naive LIKE search over node key/label (graph-native substring
        match keeps the store dependency-light)."""
        pattern = f"%{text.strip().lower()}%"
        sql = ("SELECT * FROM nodes WHERE (lower(key) LIKE ? OR lower(label)"
               " LIKE ?)")
        args: List[Any] = [pattern, pattern]
        if kinds:
            sql += f" AND kind IN ({','.join('?' for _ in kinds)})"
            args.extend(kinds)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._row_to_node(r) for r in rows]

    def delete_node(self, kind: str, key: str) -> bool:
        """Remove a node and every edge touching it."""
        _require_kind(kind)
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM nodes WHERE kind=? AND key=?", (kind, key))
            self._conn.execute(
                "DELETE FROM edges WHERE (src_kind=? AND src_key=?)"
                " OR (dst_kind=? AND dst_key=?)",
                (kind, key, kind, key))
            self._conn.execute(
                "DELETE FROM scans WHERE subject_type=? AND subject_key=?",
                (kind, key))
        return cur.rowcount > 0

    def clear(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM nodes")
            self._conn.execute("DELETE FROM edges")
            self._conn.execute("DELETE FROM scans")

    # -- edges -------------------------------------------------------------

    def link(self, src_kind: str, src_key: str, rel: str,
             dst_kind: str, dst_key: str,
             props: Optional[Dict[str, Any]] = None,
             auto_create: bool = True) -> Dict[str, Any]:
        """Create or re-hit a directed edge.

        ``rel`` must be one of the canonical relationship labels. Missing
        endpoint nodes are auto-created as bare nodes so sub-agents can
        attach facts without re-inserting their whole chain first.
        """
        src_kind = _require_kind(src_kind)
        dst_kind = _require_kind(dst_kind)
        if rel not in RELS:
            raise KnowledgeGraphError(
                f"unsupported relationship {rel!r}; expected one of {RELS}")
        now = _now()
        with self._lock, self._conn:
            if auto_create:
                if self._get_node_row(src_kind, src_key) is None:
                    self._conn.execute(
                        "INSERT INTO nodes(kind,key,label,props,tags,source,"
                        " first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
                        (src_kind, src_key, src_key, "{}", "[]", "", now, now))
                if self._get_node_row(dst_kind, dst_key) is None:
                    self._conn.execute(
                        "INSERT INTO nodes(kind,key,label,props,tags,source,"
                        " first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
                        (dst_kind, dst_key, dst_key, "{}", "[]", "", now, now))
            row = self._conn.execute(
                "SELECT * FROM edges WHERE src_kind=? AND src_key=? AND rel=?"
                " AND dst_kind=? AND dst_key=?",
                (src_kind, src_key, rel, dst_kind, dst_key),
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO edges(src_kind,src_key,rel,dst_kind,dst_key,"
                    " props,count,first_seen,last_seen)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (src_kind, src_key, rel, dst_kind, dst_key,
                     _jenc(props or {}), 1, now, now))
            else:
                merged = self._merge_props(_jdec(row["props"], {}), props)
                self._conn.execute(
                    "UPDATE edges SET props=?, count=count+1, last_seen=?"
                    " WHERE src_kind=? AND src_key=? AND rel=? AND dst_kind=?"
                    " AND dst_key=?",
                    (_jenc(merged), now,
                     src_kind, src_key, rel, dst_kind, dst_key))
        return {
            "src_kind": src_kind, "src_key": src_key, "rel": rel,
            "dst_kind": dst_kind, "dst_key": dst_key,
            "props": props or {},
        }

    def edges(self, kind: str, key: str,
              rel: Optional[str] = None) -> List[Dict[str, Any]]:
        """Outgoing edges of a node, each enriched with the destination
        node's label."""
        sql = ("SELECT e.rel AS rel, e.dst_kind AS dst_kind,"
               " e.dst_key AS dst_key, e.props AS props, e.count AS count,"
               " e.last_seen AS last_seen, n.label AS label"
               " FROM edges e LEFT JOIN nodes n"
               "  ON n.kind=e.dst_kind AND n.key=e.dst_key"
               " WHERE e.src_kind=? AND e.src_key=?")
        args: List[Any] = [kind, key]
        if rel:
            sql += " AND e.rel=?"
            args.append(rel)
        sql += " ORDER BY e.last_seen DESC"
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        out = []
        for r in rows:
            item = {
                "rel": r["rel"], "kind": r["dst_kind"], "key": r["dst_key"],
                "label": r["label"] or r["dst_key"],
                "count": r["count"], "last_seen": r["last_seen"],
                "props": _jdec(r["props"], {}),
            }
            out.append(item)
        return out

    def incoming(self, kind: str, key: str,
                 rel: Optional[str] = None) -> List[Dict[str, Any]]:
        """Incoming edges of a node (who points at it)."""
        sql = ("SELECT e.src_kind AS kind, e.src_key AS key, e.rel AS rel,"
               " e.count AS count, n.label AS label"
               " FROM edges e LEFT JOIN nodes n"
               "  ON n.kind=e.src_kind AND n.key=e.src_key"
               " WHERE e.dst_kind=? AND e.dst_key=?")
        args: List[Any] = [kind, key]
        if rel:
            sql += " AND e.rel=?"
            args.append(rel)
        sql += " ORDER BY e.last_seen DESC"
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [{
            "kind": r["kind"], "key": r["key"], "rel": r["rel"],
            "count": r["count"], "label": r["label"] or r["key"],
        } for r in rows]

    def unlink(self, src_kind: str, src_key: str, rel: str,
               dst_kind: str, dst_key: str) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM edges WHERE src_kind=? AND src_key=? AND rel=?"
                " AND dst_kind=? AND dst_key=?",
                (src_kind, src_key, rel, dst_kind, dst_key))
        return cur.rowcount > 0

    # -- domain recording helpers ------------------------------------------

    def add_target(self, name: str, props: Optional[Dict[str, Any]] = None,
                   source: str = "manual") -> Dict[str, Any]:
        return self.upsert_node(KIND_TARGET, name, label=name,
                                props=props, source=source)

    def add_ip(self, ip: str, target: Optional[str] = None,
               props: Optional[Dict[str, Any]] = None,
               source: str = "recon") -> Dict[str, Any]:
        node = self.upsert_node(KIND_IP, ip, label=ip,
                                props=props, source=source)
        if target:
            self.add_target(target)
            self.link(KIND_TARGET, target, CONTAINS, KIND_IP, ip)
        return node

    @staticmethod
    def _port_key(ip: str, port: int, proto: str) -> str:
        return f"{ip}:{port}/{proto}"

    def add_port(self, ip: str, port: int, proto: str = "tcp",
                 state: str = "open",
                 props: Optional[Dict[str, Any]] = None,
                 source: str = "recon") -> Dict[str, Any]:
        port_props = {"port": int(port), "proto": proto, "state": state}
        port_props.update(props or {})
        key = self._port_key(ip, port, proto)
        node = self.upsert_node(KIND_PORT, key,
                                label=f"{port}/{proto}",
                                props=port_props, source=source)
        self.link(KIND_IP, ip, HAS_PORT, KIND_PORT, key)
        return node

    def _service_key(self, ip: str, port: Optional[int], proto: str,
                     name: str) -> str:
        if port is None:
            return f"{ip}/{name}"
        return f"{ip}:{port}/{proto}/{name}"

    def add_service(self, ip: str, name: str, version: Optional[str] = None,
                    port: Optional[int] = None, proto: str = "tcp",
                    state: str = "open",
                    props: Optional[Dict[str, Any]] = None,
                    source: str = "fingerprint") -> Dict[str, Any]:
        svc_props = {"name": name, "state": state}
        if version:
            svc_props["version"] = version
        svc_props.update(props or {})
        key = self._service_key(ip, port, proto, name)
        label = f"{name} {version}".strip() if version else name
        node = self.upsert_node(KIND_SERVICE, key, label=label,
                                props=svc_props, source=source)
        self.link(KIND_IP, ip, RUNS_SERVICE, KIND_SERVICE, key)
        if port is not None:
            self.link(KIND_SERVICE, key, SERVES_ON, KIND_PORT,
                      self._port_key(ip, port, proto))
        return node

    @staticmethod
    def _tech_key(name: str) -> str:
        return name.strip().lower()

    def add_tech(self, owner_kind: str, owner_key: str, name: str,
                 version: Optional[str] = None,
                 props: Optional[Dict[str, Any]] = None,
                 source: str = "fingerprint") -> Dict[str, Any]:
        """Attach a tech-stack fingerprint to a service (USES_TECH) or an
        ip (RUNS_TECH). The tech node itself is global by lowercased name,
        so the same framework/version seen on ten hosts is one node."""
        tech_props = {"name": name}
        if version:
            tech_props["version"] = version
        tech_props.update(props or {})
        key = self._tech_key(name)
        label = f"{name} {version}".strip() if version else name
        node = self.upsert_node(KIND_TECH, key, label=label,
                                props=tech_props, source=source)
        rel = USES_TECH if owner_kind == KIND_SERVICE else RUNS_TECH
        self.link(owner_kind, owner_key, rel, KIND_TECH, key)
        return node

    def add_cve(self, owner_kind: str, owner_key: str, cve_id: str,
                severity: Optional[str] = None, cvss: Optional[float] = None,
                description: Optional[str] = None,
                props: Optional[Dict[str, Any]] = None,
                source: str = "nvd") -> Dict[str, Any]:
        """Attach an identified CVE to any asset (ip/service/tech).

        ``cve_id`` is canonicalized to uppercase ``CVE-YYYY-NNNN`` so the
        same advisory is stored exactly once regardless of casing used by
        the caller.
        """
        match = _CVE_RE.search(cve_id or "")
        if not match:
            raise KnowledgeGraphError(f"malformed CVE identifier {cve_id!r}")
        cve = match.group(0).upper()
        cve_props = {"cve_id": cve}
        if severity:
            cve_props["severity"] = severity
        if cvss is not None:
            cve_props["cvss"] = float(cvss)
        if description:
            cve_props["description"] = description
        cve_props.update(props or {})
        node = self.upsert_node(KIND_CVE, cve, label=cve,
                                props=cve_props, source=source)
        self.link(owner_kind, owner_key, AFFECTED_BY, KIND_CVE, cve)
        return node

    # -- query / traversal -------------------------------------------------

    def neighbors(self, kind: str, key: str,
                  rel: Optional[str] = None) -> List[Dict[str, Any]]:
        """One-hop neighbors of a node (outgoing edges, enriched)."""
        return self.edges(kind, key, rel=rel)

    def cves_for(self, kind: str, key: str) -> List[Dict[str, Any]]:
        """Every CVE attached to an asset, directly or via its service."""
        _require_kind(kind)
        direct = self.edges(kind, key, rel=AFFECTED_BY)
        out: Dict[str, Dict[str, Any]] = {}
        for edge in direct:
            out[edge["key"]] = self.node(KIND_CVE, edge["key"])  # type: ignore[assignment]
        if kind == KIND_IP:
            for svc_edge in self.edges(KIND_IP, key, rel=RUNS_SERVICE):
                svc_key = svc_edge["key"]
                for cve_edge in self.edges(KIND_SERVICE, svc_key,
                                           rel=AFFECTED_BY):
                    if cve_edge["key"] not in out:
                        out[cve_edge["key"]] = self.node(
                            KIND_CVE, cve_edge["key"])
        return [n for n in out.values() if n is not None]

    def known_ips(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """All ip nodes, optionally restricted to one target scope."""
        if target is None:
            return self.nodes_by_kind(KIND_IP)
        rows = self.edges(KIND_TARGET, target, rel=CONTAINS)
        return [self.node(KIND_IP, e["key"])  # type: ignore[misc]
                for e in rows if self.node(KIND_IP, e["key"])]

    def target_snapshot(self, target: str) -> Dict[str, Any]:
        """One-call picture of a target for Main/Sub agents.

        Returns the target node plus every known ip with its open ports,
        active services, tech fingerprints and CVEs - the exact context a
        recon sub-agent needs before deciding what still has to be scanned.
        """
        target_node = self.node(KIND_TARGET, target)
        snapshot: Dict[str, Any] = {
            "target": target_node,
            "ips": [],
            "cve_ids": [],
            "scanned_tools": [],
        }
        if target_node is None:
            return snapshot
        cve_seen: set = set()
        for ip_edge in self.edges(KIND_TARGET, target, rel=CONTAINS):
            ip_key = ip_edge["key"]
            ip_node = self.node(KIND_IP, ip_key) or {"kind": KIND_IP,
                                                     "key": ip_key}
            ports = [e for e in self.edges(KIND_IP, ip_key, rel=HAS_PORT)]
            services = []
            for svc_edge in self.edges(KIND_IP, ip_key, rel=RUNS_SERVICE):
                svc_key = svc_edge["key"]
                # authoritative detail lives on the service NODE props
                # (name/version/state), not on the edge row
                svc_node = self.node(KIND_SERVICE, svc_key) or {}
                svc_props = svc_node.get("props") or {}
                techs = [e["label"] for e in
                         self.edges(KIND_SERVICE, svc_key, rel=USES_TECH)]
                svc_cves = [e["key"] for e in
                            self.edges(KIND_SERVICE, svc_key,
                                       rel=AFFECTED_BY)]
                cve_seen.update(svc_cves)
                services.append({
                    "key": svc_key,
                    "name": svc_props.get("name") or svc_node.get("label")
                    or svc_edge["label"],
                    "port": (svc_edge.get("props") or {}).get("port")
                    or svc_props.get("port"),
                    "version": svc_props.get("version"),
                    "state": svc_props.get("state")
                    or (svc_edge.get("props") or {}).get("state"),
                    "techs": techs,
                    "cves": list(svc_cves),
                })
            ip_cves = [e["key"] for e in
                       self.edges(KIND_IP, ip_key, rel=AFFECTED_BY)]
            cve_seen.update(ip_cves)
            snapshot["ips"].append({
                "ip": ip_key,
                "hostname": (ip_node.get("props") or {}).get("hostname"),
                "os": (ip_node.get("props") or {}).get("os"),
                "ports": [e["key"] for e in ports],
                "port_states": {e["key"]: e["props"] for e in ports},
                "services": services,
                "cves": list(ip_cves),
            })
        snapshot["cve_ids"] = sorted(cve_seen)
        for row in self.scan_summary(scope=target):
            if row["tool"] not in snapshot["scanned_tools"]:
                snapshot["scanned_tools"].append(row["tool"])
        return snapshot

    def path_between(self, start_kind: str, start_key: str,
                     end_kind: str, end_key: str,
                     max_depth: int = 6) -> Optional[List[Dict[str, Any]]]:
        """BFS shortest path between two nodes (list of hop dicts) or None."""
        from collections import deque
        start = (start_kind, start_key)
        end = (end_kind, end_key)
        queue: deque = deque([(start, [])])
        seen = {start}
        while queue:
            (kind, key), hops = queue.popleft()
            if len(hops) >= max_depth:
                continue
            for edge in self.edges(kind, key):
                nxt = (edge["kind"], edge["key"])
                if nxt in seen:
                    continue
                seen.add(nxt)
                new_hops = hops + [{"src": f"{kind}:{key}",
                                    "rel": edge["rel"],
                                    "dst": f"{edge['kind']}:{edge['key']}"}]
                if nxt == end:
                    return new_hops
                queue.append((nxt, new_hops))
        return None

    # -- scan ledger (duplicate-scan eliminator) ---------------------------

    def note_scan(self, subject_type: str, subject_key: str, tool: str,
                  status: str = "ok", summary: str = "",
                  meta: Optional[Dict[str, Any]] = None,
                  scope: str = "") -> Dict[str, Any]:
        """Record that a tool already covered an asset inside a scope.

        Recon sub-agents call this when they finish a sweep; the same
        (asset, tool) pair is one row, so a later agent asking
        ``last_scan()`` learns the work was already done and skips it.
        """
        if status not in ("ok", "partial", "failed"):
            raise KnowledgeGraphError(f"invalid scan status {status!r}")
        now = _now()
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO scans(scope,subject_type,subject_key,tool,"
                " status,summary,meta,ts) VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(scope,subject_type,subject_key,tool)"
                " DO UPDATE SET status=excluded.status,"
                "  summary=excluded.summary, meta=excluded.meta,"
                "  ts=excluded.ts",
                (scope, subject_type, subject_key, tool, status,
                 summary, _jenc(meta or {}), now))
        return {"subject_type": subject_type, "subject_key": subject_key,
                "tool": tool, "status": status, "summary": summary,
                "scope": scope, "ts": now}

    def last_scan(self, subject_type: str, subject_key: str,
                  tool: Optional[str] = None,
                  scope: str = "") -> Optional[Dict[str, Any]]:
        sql = ("SELECT * FROM scans WHERE scope=? AND subject_type=?"
               " AND subject_key=?")
        args: List[Any] = [scope, subject_type, subject_key]
        if tool:
            sql += " AND tool=?"
            args.append(tool)
        sql += " ORDER BY ts DESC LIMIT 1"
        with self._lock:
            row = self._conn.execute(sql, args).fetchone()
        if row is None:
            return None
        return {"scope": row["scope"], "subject_type": row["subject_type"],
                "subject_key": row["subject_key"], "tool": row["tool"],
                "status": row["status"], "summary": row["summary"],
                "meta": _jdec(row["meta"], {}), "ts": row["ts"]}

    def scan_needed(self, subject_type: str, subject_key: str, tool: str,
                    max_age_s: float = 0.0,
                    scope: str = "") -> bool:
        """True when (asset, tool) has no fresh-enough successful scan.

        ``max_age_s`` is the staleness window: a scan inside the window
        means "skip". A failed scan never counts as coverage regardless of
        age.
        """
        last = self.last_scan(subject_type, subject_key, tool=tool,
                              scope=scope)
        if last is None or last["status"] == "failed":
            return True
        if max_age_s > 0 and (_now() - last["ts"]) > max_age_s:
            return True
        return False

    def scan_summary(self, scope: str = "",
                     limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT scope,subject_type,subject_key,tool,status,summary,"
                " ts FROM scans WHERE scope=? ORDER BY ts DESC LIMIT ?",
                (scope, limit)).fetchall()
        return [dict(r) for r in rows]

    # -- graph health ------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            node_rows = self._conn.execute(
                "SELECT kind, COUNT(*) AS n FROM nodes GROUP BY kind"
            ).fetchall()
            edge_count = self._conn.execute(
                "SELECT COUNT(*) AS n FROM edges").fetchone()["n"]
            scan_count = self._conn.execute(
                "SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        return {
            "nodes": {r["kind"]: r["n"] for r in node_rows},
            "edges": int(edge_count),
            "scans": int(scan_count),
            "db_path": self.db_path,
        }


class AsyncKnowledgeGraph:
    """Async facade over :class:`KnowledgeGraph` for asyncio sub-agents.

    Every awaited method hops onto a worker thread through
    ``asyncio.to_thread`` so the blocking SQLite calls never stall the
    swarm event loop. Shares the same on-disk file as the sync store, so
    Main Agent and Sub-Agents always see one consistent graph.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._sync = KnowledgeGraph(db_path=db_path)

    @property
    def db_path(self) -> str:
        return self._sync.db_path

    async def node(self, kind: str, key: str) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._sync.node, kind, key)

    async def upsert_node(self, kind: str, key: str,
                          label: Optional[str] = None,
                          props: Optional[Dict[str, Any]] = None,
                          tags: Optional[List[str]] = None,
                          source: Optional[str] = None) -> Dict[str, Any]:
        return await asyncio.to_thread(self._sync.upsert_node, kind, key,
                                       label, props, tags, source)

    async def link(self, src_kind: str, src_key: str, rel: str,
                   dst_kind: str, dst_key: str,
                   props: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await asyncio.to_thread(self._sync.link, src_kind, src_key,
                                       rel, dst_kind, dst_key, props)

    async def target_snapshot(self, target: str) -> Dict[str, Any]:
        return await asyncio.to_thread(self._sync.target_snapshot, target)

    async def cves_for(self, kind: str, key: str) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._sync.cves_for, kind, key)

    async def last_scan(self, subject_type: str, subject_key: str,
                        tool: Optional[str] = None,
                        scope: str = "") -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._sync.last_scan, subject_type,
                                       subject_key, tool, scope)

    async def note_scan(self, subject_type: str, subject_key: str, tool: str,
                        status: str = "ok", summary: str = "",
                        meta: Optional[Dict[str, Any]] = None,
                        scope: str = "") -> Dict[str, Any]:
        return await asyncio.to_thread(self._sync.note_scan, subject_type,
                                       subject_key, tool, status, summary,
                                       meta, scope)

    async def scan_needed(self, subject_type: str, subject_key: str,
                          tool: str, max_age_s: float = 0.0,
                          scope: str = "") -> bool:
        return await asyncio.to_thread(self._sync.scan_needed, subject_type,
                                       subject_key, tool, max_age_s, scope)

    async def close(self) -> None:
        await asyncio.to_thread(self._sync.close)
