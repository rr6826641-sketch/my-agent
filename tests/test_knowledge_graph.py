"""Unit tests for the persistent target knowledge graph.

Covers node insertion (upsert idempotence & dedup), typed edge
relationships, the recon recording helpers, scan-ledger duplicate
elimination, traversal/snapshot queries, and multi-session persistence
(the graph written by one process/instance is fully retrievable by a
fresh instance on the same SQLite file).
"""

import asyncio
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_agent.memory.knowledge_graph import (  # noqa: E402
    AFFECTED_BY,
    CONTAINS,
    HAS_PORT,
    KIND_CVE,
    KIND_IP,
    KIND_PORT,
    KIND_SERVICE,
    KIND_TARGET,
    KIND_TECH,
    RUNS_SERVICE,
    RUNS_TECH,
    SERVES_ON,
    USES_TECH,
    AsyncKnowledgeGraph,
    KnowledgeGraph,
    KnowledgeGraphError,
    UnsupportedKind,
)


@pytest.fixture
def kg(tmp_path):
    """A KnowledgeGraph on an isolated temp DB file (auto-closed)."""
    graph = KnowledgeGraph(db_path=str(tmp_path / "kg.db"))
    yield graph
    graph.close()


# ---------------------------------------------------------------------------
# Node insertion / upsert dedup
# ---------------------------------------------------------------------------

class TestNodeInsertion:
    def test_insert_and_retrieve(self, kg):
        node = kg.upsert_node(KIND_IP, "10.0.0.8", label="10.0.0.8",
                              props={"os": "linux"}, source="recon")
        assert node["kind"] == KIND_IP
        assert node["key"] == "10.0.0.8"
        assert node["props"] == {"os": "linux"}
        assert node["source"] == "recon"
        fetched = kg.node(KIND_IP, "10.0.0.8")
        assert fetched == node
        assert kg.has_node(KIND_IP, "10.0.0.8")

    def test_upsert_is_idempotent_no_duplicates(self, kg):
        kg.upsert_node(KIND_IP, "10.0.0.8", props={"os": "linux"})
        kg.upsert_node(KIND_IP, "10.0.0.8", props={"os": "windows"})
        assert len(kg.nodes_by_kind(KIND_IP)) == 1
        # props merge: later discovery updates rather than duplicates
        assert kg.node(KIND_IP, "10.0.0.8")["props"] == {"os": "windows"}

    def test_upsert_bumps_last_seen_and_merges_tags(self, kg):
        first = kg.upsert_node(KIND_IP, "10.0.0.9", tags=["scanned"])
        time.sleep(0.01)
        second = kg.upsert_node(KIND_IP, "10.0.0.9", tags=["fingerprinted"])
        assert second["last_seen"] >= first["last_seen"]
        assert set(second["tags"]) == {"scanned", "fingerprinted"}

    def test_unsupported_kind_rejected(self, kg):
        with pytest.raises(UnsupportedKind):
            kg.upsert_node("gadget", "x")
        with pytest.raises(UnsupportedKind):
            kg.node("gadget", "x")

    def test_delete_node_cascades_edges(self, kg):
        kg.add_ip("10.0.0.8", target="acme")
        kg.add_port("10.0.0.8", 443)
        assert kg.delete_node(KIND_IP, "10.0.0.8") is True
        assert kg.node(KIND_IP, "10.0.0.8") is None
        # port node remains orphan-free? edge gone
        assert kg.incoming(KIND_PORT, "10.0.0.8:443/tcp") == []

    def test_search_nodes(self, kg):
        kg.add_service("10.0.0.8", "nginx", version="1.18.0", port=443)
        hits = kg.search_nodes("nginx")
        assert any(n["kind"] == KIND_SERVICE for n in hits)


# ---------------------------------------------------------------------------
# Edge relationships
# ---------------------------------------------------------------------------

class TestEdges:
    def test_link_creates_edge_and_counts_hits(self, kg):
        kg.add_ip("10.0.0.8")
        kg.add_port("10.0.0.8", 443)
        edges = kg.edges(KIND_IP, "10.0.0.8", rel=HAS_PORT)
        assert len(edges) == 1
        assert edges[0]["rel"] == HAS_PORT
        assert edges[0]["key"] == "10.0.0.8:443/tcp"
        # re-link bumps hit count, no duplicate row
        kg.link(KIND_IP, "10.0.0.8", HAS_PORT, KIND_PORT,
                "10.0.0.8:443/tcp")
        edges = kg.edges(KIND_IP, "10.0.0.8", rel=HAS_PORT)
        assert len(edges) == 1
        assert edges[0]["count"] == 2

    def test_link_auto_creates_endpoints(self, kg):
        # attach a CVE to an ip that was never explicitly inserted
        kg.link(KIND_IP, "172.16.5.1", AFFECTED_BY, KIND_CVE,
                "CVE-2021-44228")
        assert kg.has_node(KIND_IP, "172.16.5.1")
        assert kg.node(KIND_CVE, "CVE-2021-44228") is not None

    def test_invalid_rel_rejected(self, kg):
        with pytest.raises(KnowledgeGraphError):
            kg.link(KIND_IP, "10.0.0.8", "WIGGLES", KIND_CVE, "CVE-2024-0001")

    def test_incoming_and_unlink(self, kg):
        kg.add_ip("10.0.0.8", target="acme")
        inc = kg.incoming(KIND_IP, "10.0.0.8", rel=CONTAINS)
        assert len(inc) == 1 and inc[0]["key"] == "acme"
        assert kg.unlink(KIND_TARGET, "acme", CONTAINS, KIND_IP,
                         "10.0.0.8") is True
        assert kg.incoming(KIND_IP, "10.0.0.8") == []

    def test_recon_recording_chain(self, kg):
        kg.add_ip("10.0.0.8", target="acme",
                  props={"hostname": "web01.acme.test"})
        kg.add_port("10.0.0.8", 80, state="open")
        kg.add_port("10.0.0.8", 443, state="open")
        svc = kg.add_service("10.0.0.8", "nginx", version="1.18.0", port=443)
        kg.add_tech(KIND_SERVICE, svc["key"], "nginx", version="1.18.0")
        kg.add_cve("service", svc["key"], "cve-2024-3094",
                   severity="critical", cvss=10.0)
        stats = kg.stats()
        assert stats["nodes"][KIND_IP] == 1
        assert stats["nodes"][KIND_PORT] == 2
        assert stats["nodes"][KIND_SERVICE] == 1
        assert stats["nodes"][KIND_TECH] == 1
        assert stats["nodes"][KIND_CVE] == 1
        assert stats["edges"] == 7  # 1 contains + 2 has_port + 1 runs_svc
        # + 1 serves_on + 1 uses_tech + 1 affected_by

    def test_cve_malformed_rejected(self, kg):
        with pytest.raises(KnowledgeGraphError):
            kg.add_cve(KIND_IP, "10.0.0.8", "not-a-cve")

    def test_tech_global_key_case_insensitive(self, kg):
        s1 = kg.add_service("10.0.0.1", "openssh", port=22)
        s2 = kg.add_service("10.0.0.2", "openssh", port=22)
        kg.add_tech(KIND_SERVICE, s1["key"], "OpenSSH", version="9.8")
        kg.add_tech(KIND_SERVICE, s2["key"], "openssh", version="9.8")
        assert len(kg.nodes_by_kind(KIND_TECH)) == 1
        # ip without service uses RUNS_TECH
        kg.add_tech(KIND_IP, "10.0.0.3", "linux-kernel", version="6.6")
        assert len(kg.edges(KIND_IP, "10.0.0.3", rel=RUNS_TECH)) == 1


# ---------------------------------------------------------------------------
# Traversal / query
# ---------------------------------------------------------------------------

class TestQueries:
    def _seed_acme(self, kg):
        kg.add_ip("10.0.0.8", target="acme",
                  props={"hostname": "web01.acme.test"})
        kg.add_port("10.0.0.8", 80)
        kg.add_port("10.0.0.8", 443)
        svc = kg.add_service("10.0.0.8", "nginx", version="1.18.0", port=443)
        kg.add_cve(KIND_SERVICE, svc["key"], "CVE-2024-3094",
                   severity="critical")
        kg.add_ip("10.0.0.9", target="acme")
        kg.add_ip("192.168.1.5", target="other")

    def test_known_ips_scoped_to_target(self, kg):
        self._seed_acme(kg)
        acme_ips = {n["key"] for n in kg.known_ips("acme")}
        assert acme_ips == {"10.0.0.8", "10.0.0.9"}
        assert len(kg.known_ips()) == 3

    def test_target_snapshot_groups_assets(self, kg):
        self._seed_acme(kg)
        snap = kg.target_snapshot("acme")
        assert snap["target"]["key"] == "acme"
        assert len(snap["ips"]) == 2
        web = next(i for i in snap["ips"] if i["ip"] == "10.0.0.8")
        assert web["hostname"] == "web01.acme.test"
        assert set(web["ports"]) == {"10.0.0.8:80/tcp", "10.0.0.8:443/tcp"}
        assert web["services"][0]["name"] == "nginx"
        assert web["services"][0]["version"] == "1.18.0"
        assert "CVE-2024-3094" in snap["cve_ids"]
        assert "CVE-2024-3094" in web["services"][0]["cves"]

    def test_snapshot_unknown_target_is_empty(self, kg):
        snap = kg.target_snapshot("ghost")
        assert snap["target"] is None and snap["ips"] == []

    def test_cves_for_direct_and_via_service(self, kg):
        self._seed_acme(kg)
        kg.add_cve(KIND_IP, "10.0.0.8", "CVE-2024-0001", severity="high")
        ids = {c["key"] for c in kg.cves_for(KIND_IP, "10.0.0.8")}
        # direct ip CVE + CVE hanging off the nginx service
        assert ids == {"CVE-2024-0001", "CVE-2024-3094"}

    def test_path_between_target_and_cve(self, kg):
        self._seed_acme(kg)
        path = kg.path_between(KIND_TARGET, "acme",
                               KIND_CVE, "CVE-2024-3094")
        assert path is not None
        rels = [hop["rel"] for hop in path]
        assert rels == [CONTAINS, RUNS_SERVICE, AFFECTED_BY]
        assert kg.path_between(KIND_TARGET, "acme",
                               KIND_CVE, "CVE-9999-9999") is None


# ---------------------------------------------------------------------------
# Scan ledger / duplicate-scan elimination
# ---------------------------------------------------------------------------

class TestScanLedger:
    def test_note_and_last_scan(self, kg):
        kg.note_scan(KIND_IP, "10.0.0.8", "nmap", status="ok",
                     summary="22,80,443 open", meta={"ports": 3},
                     scope="acme")
        last = kg.last_scan(KIND_IP, "10.0.0.8", tool="nmap", scope="acme")
        assert last is not None
        assert last["status"] == "ok"
        assert last["meta"]["ports"] == 3

    def test_scan_needed_skips_fresh_successful_scan(self, kg):
        kg.note_scan(KIND_IP, "10.0.0.8", "nmap", scope="acme")
        # fresh scan inside the 3600s window -> no duplicate needed
        assert kg.scan_needed(KIND_IP, "10.0.0.8", "nmap",
                              max_age_s=3600, scope="acme") is False
        # different tool still needs its own run
        assert kg.scan_needed(KIND_IP, "10.0.0.8", "nuclei",
                              max_age_s=3600, scope="acme") is True

    def test_scan_needed_stale_or_failed(self, kg):
        kg.note_scan(KIND_IP, "10.0.0.8", "nmap", scope="acme")
        assert kg.scan_needed(KIND_IP, "10.0.0.8", "nmap",
                              max_age_s=0.0001, scope="acme") is True
        kg.note_scan(KIND_IP, "10.0.0.8", "nmap", status="failed",
                     scope="acme")
        assert kg.scan_needed(KIND_IP, "10.0.0.8", "nmap",
                              max_age_s=3600, scope="acme") is True

    def test_scan_scoped_per_target(self, kg):
        kg.note_scan(KIND_IP, "10.0.0.8", "nmap", scope="acme")
        # same asset scanned under another engagement is NOT reused
        assert kg.scan_needed(KIND_IP, "10.0.0.8", "nmap",
                              max_age_s=3600, scope="other-corp") is True


# ---------------------------------------------------------------------------
# Multi-session retrieval
# ---------------------------------------------------------------------------

class TestMultiSessionPersistence:
    def test_graph_survives_instance_restart(self, tmp_path):
        db = str(tmp_path / "shared.db")
        # session one: recon agent populates the graph
        kg1 = KnowledgeGraph(db_path=db)
        kg1.add_ip("10.0.0.8", target="acme", source="recon")
        kg1.add_port("10.0.0.8", 22)
        svc = kg1.add_service("10.0.0.8", "openssh", version="9.8", port=22)
        kg1.add_cve(KIND_SERVICE, svc["key"], "CVE-2024-6387",
                    severity="high")
        kg1.note_scan(KIND_IP, "10.0.0.8", "nmap", scope="acme")
        kg1.close()

        # session two: brand new instance, same file - fresh process memory
        kg2 = KnowledgeGraph(db_path=db)
        assert kg2.node(KIND_IP, "10.0.0.8") is not None
        assert kg2.node(KIND_CVE, "CVE-2024-6387")["props"]["severity"] == "high"
        snap = kg2.target_snapshot("acme")
        assert snap["ips"][0]["services"][0]["name"] == "openssh"
        assert "CVE-2024-6387" in snap["cve_ids"]
        # scan ledger survived too -> next recon skips the duplicate
        assert kg2.scan_needed(KIND_IP, "10.0.0.8", "nmap",
                               max_age_s=3600, scope="acme") is False
        kg2.close()

    def test_snapshot_queryable_during_active_task(self, kg):
        """Main + sub agents can update mid-task and immediately re-query."""
        kg.add_ip("10.0.0.8", target="acme")
        first = kg.target_snapshot("acme")
        assert len(first["ips"]) == 1 and first["ips"][0]["ports"] == []
        kg.add_port("10.0.0.8", 443)  # sub-agent finishes a sweep
        second = kg.target_snapshot("acme")
        assert len(second["ips"][0]["ports"]) == 1


# ---------------------------------------------------------------------------
# Async facade (swarm sub-agents)
# ---------------------------------------------------------------------------

class TestAsyncFacade:
    def test_async_facade_roundtrip(self, tmp_path):
        db = str(tmp_path / "async.db")

        async def run():
            akg = AsyncKnowledgeGraph(db_path=db)
            try:
                await akg.upsert_node(KIND_IP, "10.0.0.8",
                                      props={"os": "linux"})
                await akg.link(KIND_IP, "10.0.0.8", AFFECTED_BY, KIND_CVE,
                               "CVE-2024-3094")
                node = await akg.node(KIND_IP, "10.0.0.8")
                assert node["props"]["os"] == "linux"
                await akg.note_scan(KIND_IP, "10.0.0.8", "nmap",
                                    scope="acme")
                assert await akg.scan_needed(KIND_IP, "10.0.0.8", "nmap",
                                             max_age_s=3600,
                                             scope="acme") is False
                cves = await akg.cves_for(KIND_IP, "10.0.0.8")
                assert [c["key"] for c in cves] == ["CVE-2024-3094"]
            finally:
                await akg.close()

        asyncio.run(run())
