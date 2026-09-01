"""Tests for the Attack-Chain Graph Correlator (ai_agent/tools/attack_chains.py)."""

import json

from ai_agent.tools.attack_chains import (
    build_attack_chains,
    render_chain_graph,
    visualize_attack_chains,
)
from ai_agent.tools.reporting import correlate_findings


# The canonical example chain from the correlator spec.
EXAMPLE_FINDINGS = [
    {"asset": "10.0.0.5", "title": "Null SMB session allows anonymous logon",
     "severity": "medium", "port": "445", "tool": "nmap"},
    {"asset": "10.0.0.5", "title": "Unencrypted SMB share readable anonymously",
     "severity": "medium", "port": "445", "tool": "nmap"},
    {"asset": "10.0.0.5", "title": "Hardcoded credential in backup .sql file",
     "severity": "high", "tool": "nikto"},
    {"asset": "10.0.0.5", "title": "Local privilege escalation to local admin",
     "severity": "high", "tool": "manual"},
    {"asset": "10.0.0.1", "title": "Domain controller compromise via DCSync",
     "severity": "critical", "tool": "manual"},
]


def test_chain_fields_present():
    result = build_attack_chains(EXAMPLE_FINDINGS)
    assert result["ok"] is True
    assert result["chain_count"] >= 1
    chain = result["chains"][0]
    for key in ("chain_id", "entry_point", "intermediate_pivots",
                "final_impact", "composite_risk_score",
                "remediation_choke_point"):
        assert key in chain, "missing field: %s" % key
    assert chain["chain_id"].startswith("AC-")


def test_full_chain_ordering():
    result = build_attack_chains(EXAMPLE_FINDINGS)
    chain = result["chains"][0]
    labels = [h["node"] for h in chain["hops"]]
    assert labels[0] == "Null SMB Session"
    assert "Hardcoded Credential" in labels
    assert "Local Admin PrivEsc" in labels
    assert labels[-1] == "Domain Controller Compromise"
    assert "Null SMB Session" in chain["chain_text"]


def test_pivot_deduplication():
    result = build_attack_chains(EXAMPLE_FINDINGS)
    labels = [h["node"] for h in result["chains"][0]["hops"]]
    assert labels.count("Unencrypted Share Read") == 1


def test_entry_point_detection():
    result = build_attack_chains(EXAMPLE_FINDINGS)
    chain = result["chains"][0]
    assert chain["entry_point"]["node"] == "Null SMB Session"
    assert chain["entry_point"]["asset"] == "10.0.0.5:445"


def test_choke_point_is_highest_impact():
    result = build_attack_chains(EXAMPLE_FINDINGS)
    chain = result["chains"][0]
    max_impact = max(h["impact"] for h in chain["hops"])
    assert chain["remediation_choke_point"]["impact"] == max_impact


def test_composite_score_bounded():
    result = build_attack_chains(EXAMPLE_FINDINGS)
    for chain in result["chains"]:
        assert 0.0 < chain["composite_risk_score"] <= 10.0


def test_empty_input():
    result = build_attack_chains([])
    assert result["ok"] is True
    assert result["chain_count"] == 0


def test_invalid_json():
    result = build_attack_chains("{not json")
    assert result["ok"] is False
    assert result.get("error")


def test_impact_unproven_fallback():
    result = build_attack_chains([EXAMPLE_FINDINGS[0]])
    chain = result["chains"][0]
    assert chain["final_impact"]["node"].startswith("Restricted Objective")


def test_visualization_block():
    result = build_attack_chains(EXAMPLE_FINDINGS)
    viz = result["chains"][0]["visualization"]
    assert viz.startswith("```")
    assert viz.endswith("```")
    assert "ATTACK PATH" in viz
    assert "[ENTRY]" in viz and "[IMPACT]" in viz


def test_render_chain_graph():
    result = build_attack_chains(EXAMPLE_FINDINGS)
    graph = render_chain_graph(result)
    assert graph.startswith("## Attack-Chain Graph")
    assert "| Chain | Composite Risk |" in graph
    assert result["chains"][0]["chain_id"] in graph


def test_visualize_tool_wrapper():
    out = visualize_attack_chains(EXAMPLE_FINDINGS)
    assert "## Attack-Chain Graph" in out
    assert "no attack chains" not in out


def test_correlate_includes_chains():
    correlated = correlate_findings(EXAMPLE_FINDINGS)
    assert correlated["ok"] is True
    assert isinstance(correlated.get("attack_chains"), list)
    assert len(correlated["attack_chains"]) >= 1
    assert "## Attack-Chain Graph" in correlated.get("chain_graph", "")


def test_correlate_json_string_input():
    correlated = correlate_findings(json.dumps(EXAMPLE_FINDINGS))
    assert correlated["ok"] is True
    assert len(correlated["attack_chains"]) >= 1


def test_chain_id_stable():
    r1 = build_attack_chains(EXAMPLE_FINDINGS)
    r2 = build_attack_chains(EXAMPLE_FINDINGS)
    assert r1["chains"][0]["chain_id"] == r2["chains"][0]["chain_id"]
