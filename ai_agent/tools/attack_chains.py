"""Attack-Chain Graph Correlator.

Builds linked attack paths from raw findings instead of flat lists:

    Null SMB Session -> Unencrypted Share Read -> Hardcoded Credential
        -> Local Admin PrivEsc -> Domain Controller Compromise

  build_attack_chains(findings_list) -> dict:
      {ok, total_input, unique, chain_count, chains: [...]}

Each chain dict carries:
  chain_id              - stable AC-XXXXXXXX id (sha1 of member hop ids)
  entry_point           - first-hop node label + source finding id + asset
  intermediate_pivots   - ordered middle-hop node labels
  final_impact          - terminal node label + impact weight
  composite_risk_score  - series-system risk 10*(1 - prod(1 - impact/10)),
                          scaled by the fraction of hops evidenced from
                          real findings
  remediation_choke_point - the single highest-impact hop; fixing it
                          collapses every path through it
  hops                  - [{node, kind, impact, finding_id, asset, title}]

Chain logic: each deduped finding is matched onto a graph-node template
by semantic signals in title/evidence/service (entry / pivot / final).
A chain is an ordered walk entry -> pivots -> final impact. The highest
impact entry starts each chain; pivots are ordered by impact weight so
the path reads like a realistic escalation (foothold -> creds ->
privilege -> crown jewels).

Visualization: render_chain_graph() returns an ASCII/Markdown graph
block embedded directly in generated reports.
"""

import hashlib

from .reporting import correlate_findings

# ---------------------------------------------------------------------------
# graph-node templates (strongest/most-specific signals first)
# ---------------------------------------------------------------------------

_NODE_TEMPLATES = [
    {"kind": "entry", "node": "SQL Injection Foothold", "impact": 7.5,
     "signals": ("sql injection", "sqli")},
    {"kind": "entry", "node": "Null SMB Session", "impact": 4.0,
     "signals": ("null session", "anonymous logon", "anonymous session")},
    {"kind": "entry", "node": "Default Credential Login", "impact": 6.0,
     "signals": ("default credential", "default password",
                 "default login")},

    {"kind": "pivot", "node": "Credential in Source/Backup",
     "impact": 6.5,
     "signals": (".bak", ".sql", ".env", "source disclosure",
                 "directory listing", "file disclosure", "backup file")},

    {"kind": "pivot", "node": "Hardcoded Credential", "impact": 7.0,
     "signals": ("hardcoded", "hard-coded", "embedded credential",
                 "plaintext credential", "api key", "api token",
                 "private key", "secret key")},

    {"kind": "final", "node": "Domain Controller Compromise", "impact": 10.0,
     "signals": ("domain controller", "domain admin", "dcsync", "krbtgt",
                 "kerberoast", "as-rep", "ntlm relay", "smb signing",
                 "llmnr", "wpad", "responder")},

    {"kind": "final", "node": "Full System Compromise (RCE)", "impact": 9.5,
     "signals": ("remote code execution", "web shell", "command "
                 "injection", "rce")},

    {"kind": "pivot", "node": "Local Admin PrivEsc", "impact": 8.0,
     "signals": ("privilege escalation", "privesc", "elevation of "
                 "privilege", "local admin")},

    {"kind": "pivot", "node": "Sensitive File Disclosure", "impact": 6.0,
     "signals": ("sensitive file", "config disclosure", "credential "
                 "disclosure", "api key", "private key", "secret key",
                 "password file")},

    {"kind": "entry", "node": "Unauthenticated Access", "impact": 6.5,
     "signals": ("unauthenticated", "anonymous read", "public read",
                 "world readable", "publicly accessible")},

    {"kind": "pivot", "node": "Unencrypted Share Read", "impact": 5.0,
     "signals": ("share", "ftp", "smb", "ftp anonymous", "nfs")},

    {"kind": "entry", "node": "Exposed Admin Interface", "impact": 5.5,
     "signals": ("admin panel", "management console", "admin console",
                 "management interface", "login page")},
]

_ENTRY_HINTS = ("null session", "anonymous", "default credential",
                "sql injection", "upload", "rce", "command injection",
                "exposed", "unauthenticated")
_FINAL_HINTS = ("domain", "dc ", "crown", "payment", "c2", "root",
                "admin", "database", "hypervisor")


def _text_blob(f):
    return " ".join(str(f.get(k) or "") for k in
                    ("title", "evidence", "url", "path", "service")).lower()


def _sev_weight(sev):
    return {"critical": 8.0, "high": 6.0, "medium": 5.0,
            "low": 2.0}.get(str(sev or "medium").lower(), 4.0)


def _node_for(finding):
    """Map one finding onto the strongest matching graph node.

    Returns (node_label, kind, impact). Falls back to a Generic Weakness
    node weighted from severity when no template signal matches.
    """
    try:
        blob = _text_blob(finding)
        best = None
        best_rank = (-1, -1.0)
        for tmpl in _NODE_TEMPLATES:
            hits = sum(1 for s in tmpl["signals"] if s in blob)
            if hits == 0:
                continue
            # specificity: more signal hits + higher impact wins
            rank = (hits, tmpl["impact"])
            if rank > best_rank:
                best, best_rank = tmpl, rank
        if best is None:
            sev_w = _sev_weight(finding.get("severity"))
            return "Generic Weakness (%s)" % finding.get("severity", "medium"), \
                   "pivot", max(4.0, sev_w / 2)
        return best["node"], best["kind"], best["impact"]
    except Exception:
        return "Generic Weakness (unknown)", "pivot", 4.0


def _asset_of(f):
    host = str(f.get("asset") or "").strip() or "unknown"
    if f.get("port"):
        return "%s:%s" % (host, f["port"])
    return host


def _composite_score(hops):
    """10 * (1 - prod(1 - impact/10)) - classic series-system risk.

    Every hop compounds: one 10.0-impact hop alone scores 10, two 5.0
    hops also compound to 10, five 2.0 hops compound to ~6.7. A per-hop
    impact floor keeps weak chains from scoring zero. The result is
    scaled by the fraction of hops backed by real findings so partially
    evidenced chains score honestly.
    """
    if not hops:
        return 0.0
    total = 1.0
    for step in hops:
        p = min(1.0, max(0.05, step["impact"] / 10.0))
        total *= (1.0 - p)
    base = 10.0 * (1.0 - total)
    hop_factor = sum(1 for h in hops if h.get("finding_id")) / float(len(hops))
    return round(base * (0.4 + 0.6 * hop_factor), 1)


def build_attack_chains(findings_list=""):
    """Build linked attack paths from raw findings.

    Accepts raw scanner JSON (auto-correlated/deduped via
    correlate_findings) or a list of finding dicts. Returns a dict:
      {ok, total_input, unique, chain_count, chains}
    """
    try:
        correlated = correlate_findings(findings_list or "")
        if not correlated.get("ok"):
            return {"ok": False,
                    "error": correlated.get("error", "correlation failed")}
        findings = correlated["findings"]
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    entries, pivots, finals = [], [], []
    for f in findings:
        node, kind, impact = _node_for(f)
        hop = {"node": node, "kind": kind, "impact": impact,
               "finding_id": f.get("id") or "", "asset": _asset_of(f),
               "title": f.get("title") or ""}
        if kind == "entry":
            entries.append(hop)
        elif kind == "final":
            finals.append(hop)
        else:
            pivots.append(hop)

    if not entries and not pivots and not finals:
        return {"ok": True, "total_input": correlated.get("total_input", 0),
                "unique": 0, "chain_count": 0, "chains": []}

    # highest-impact entry first; pivots ordered impact-desc so the path
    # reads foothold -> credential -> privilege -> impact
    entries = sorted(entries, key=lambda h: -h["impact"])
    pivots = sorted(pivots, key=lambda h: -h["impact"])
    finals = sorted(finals, key=lambda h: -h["impact"])

    chains = []
    # one chain per entry point; with no entry findings the top pivot is
    # promoted so unmatched-only results still produce a path
    start_hops = entries or [{
        "node": "Unknown Entry Point", "kind": "entry", "impact": 5.0,
        "finding_id": (pivots[0].get("finding_id") if pivots else ""),
        "asset": (pivots[0]["asset"] if pivots else "unknown"),
        "title": "Unmapped initial access"}]
    for entry in start_hops:
        chain_pivots = [p for p in pivots if p is not entry]
        final = finals[0] if finals else {
            "node": "Restricted Objective (Impact Unproven)", "kind": "final",
            "impact": max(6.0, entry["impact"]),
            "finding_id": entry.get("finding_id", ""),
            "asset": entry.get("asset", "unknown"),
            "title": "Potential escalation beyond demonstrated access",
        }
        hops = [entry] + list(chain_pivots) + [final]
        chain_id = "AC-" + hashlib.sha1(
            ("|".join("%s|%s" % (h["node"], h.get("finding_id") or "")
                      for h in hops)).encode("utf-8", "replace")
        ).hexdigest()[:8].upper()
        chain_text = " -> ".join(h["node"] for h in hops)
        evidenced = sum(1 for h in hops if h.get("finding_id"))
        score = _composite_score(hops)
        choke = max(hops, key=lambda h: h["impact"])
        chains.append({
            "chain_id": chain_id,
            "entry_point": {"node": entry["node"],
                            "finding_id": entry.get("finding_id"),
                            "asset": entry["asset"]},
            "intermediate_pivots": [{"node": p["node"],
                                     "finding_id": p.get("finding_id"),
                                     "asset": p["asset"]}
                                    for p in chain_pivots],
            "final_impact": {"node": final["node"],
                             "impact": final["impact"]},
            "composite_risk_score": score,
            "remediation_choke_point": {
                "node": choke["node"], "impact": choke["impact"],
                "finding_id": choke.get("finding_id") or "",
                "note": "Fixing this single hop collapses every path "
                        "through it - highest-leverage remediation."},
            "hops": hops,
            "hops_evidenced": evidenced,
            "hops_total": len(hops),
            "chain_text": chain_text,
            "visualization": _visualize(chain_id, hops, score),
        })

    chains.sort(key=lambda c: -c["composite_risk_score"])
    return {
        "ok": True,
        "total_input": correlated.get("total_input", 0),
        "unique": correlated.get("unique", len(findings)),
        "duplicates_removed": correlated.get("duplicates_removed", 0),
        "chain_count": len(chains),
        "chains": chains,
    }


def _visualize(chain_id, hops, score):
    """ASCII/Markdown graph block for one attack chain."""
    lines = ["```",
             "ATTACK PATH %s  (composite risk: %.1f/10)" % (chain_id, score),
             ""]
    for i, h in enumerate(hops):
        marker = {"entry": "[ENTRY]", "pivot": "[PIVOT]",
                  "final": "[IMPACT]"}.get(h["kind"], "[     ]")
        indent = "  " if i == 0 else ""
        lines.append("%s%s %s" % (indent, marker, h["node"]))
        meta = []
        if h.get("finding_id"):
            meta.append(str(h["finding_id"]))
        if h.get("asset"):
            meta.append(str(h["asset"]))
        if meta:
            lines.append("        %s" % " | ".join(meta))
        if i < len(hops) - 1:
            lines.append("          |")
            lines.append("          v")
    lines.append("```")
    return "\n".join(lines)


def render_chain_graph(chains_result):
    """Render the full Attack-Chain Graph section for a report.

    Accepts the dict returned by build_attack_chains() and returns a
    Markdown block: chain table + per-chain ASCII graph visualization.
    """
    try:
        if not isinstance(chains_result, dict) or not chains_result.get("ok"):
            return ""
        chains = chains_result.get("chains") or []
        if not chains:
            return ""
        out = ["## Attack-Chain Graph", "",
               "Linked attack paths reconstructed from the raw findings -",
               "each path shows how a low-severity entry point escalates "
               "toward critical impact.", ""]
        out.append("| Chain | Composite Risk | Entry Point | Final Impact | Choke Point |")
        out.append("|-------|----------------|-------------|--------------|-------------|")
        for c in chains:
            out.append("| `%s` | %.1f | %s | %s | %s |"
                       % (c["chain_id"], c["composite_risk_score"],
                          c["entry_point"]["node"],
                          c["final_impact"]["node"],
                          c["remediation_choke_point"]["node"]))
        out.append("")
        for c in chains:
            out.append(_visualize(c["chain_id"], c["hops"],
                                  c["composite_risk_score"]))
            out.append("")
        return "\n".join(out).rstrip() + "\n"
    except Exception:
        return ""


def visualize_attack_chains(findings_list=""):
    """Tool wrapper: build chains from findings and return the Markdown
    graph visualization block."""
    result = build_attack_chains(findings_list)
    if not result.get("ok"):
        return "visualize_attack_chains: %s" % result.get("error")
    if not result.get("chain_count"):
        return "visualize_attack_chains: no attack chains could be built."
    return render_chain_graph(result)
