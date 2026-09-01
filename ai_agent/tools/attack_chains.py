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

CVE enrichment: known CVE ids in finding text (or well-known CVEs
mapped in _CVE_NODES) upgrade hops into CVE-specific pivots (EternalBlue,
Zerologon, PrintNightmare, ...); unknown CVE ids fall back to a generic
exploit pivot. Every hop carries cve_refs and every chain carries an
ordered cve_chain so reports can cite the exact exploit path.

Visualization: render_chain_graph(fmt=...) returns a graph block embedded
directly in generated reports. fmt accepts "ascii" (default ASCII/Markdown
graph), "mermaid" (```mermaid flowchart) or "graphviz" (```dot digraph).
"""

import hashlib
import json
import os
import re
import threading
import time
import urllib.request

from .reporting import correlate_findings

# ---------------------------------------------------------------------------
# graph-node templates (strongest/most-specific signals first)
# ---------------------------------------------------------------------------

_NODE_TEMPLATES = [
    {"kind": "entry", "node": "SQL Injection Foothold", "impact": 7.5,
     "signals": ("sql injection", "sqli")},
    {"kind": "entry", "node": "Null SMB Session", "impact": 4.0,
     "signals": ("null session", "null smb", "anonymous logon",
                 "anonymous session")},
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

# ---------------------------------------------------------------------------
# CVE enrichment: well-known CVEs -> chain hops (CVSS-weighted impact).
# Unknown CVE-* strings fall back to a generic exploit pivot.
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_CVE_NODES = {
    "CVE-2021-44228": {"node": "Log4Shell RCE Foothold (CVE-2021-44228)", "kind": "entry", "impact": 9.8},
    "CVE-2021-45046": {"node": "Log4Shell RCE Foothold (CVE-2021-45046)", "kind": "entry", "impact": 9.5},
    "CVE-2017-0143": {"node": "EternalBlue SMB RCE (CVE-2017-0143)", "kind": "pivot", "impact": 9.5},
    "CVE-2017-0144": {"node": "EternalBlue SMB RCE (CVE-2017-0144)", "kind": "pivot", "impact": 9.5},
    "CVE-2017-0145": {"node": "EternalBlue SMB RCE (CVE-2017-0145)", "kind": "pivot", "impact": 9.5},
    "CVE-2017-0146": {"node": "EternalBlue SMB RCE (CVE-2017-0146)", "kind": "pivot", "impact": 9.5},
    "CVE-2017-0147": {"node": "EternalRomance/Synergy SMB RCE (CVE-2017-0147)", "kind": "pivot", "impact": 9.5},
    "CVE-2017-0148": {"node": "EternalBlue SMB RCE (CVE-2017-0148)", "kind": "pivot", "impact": 9.5},
    "CVE-2020-0796": {"node": "SMBGhost RCE (CVE-2020-0796)", "kind": "pivot", "impact": 9.5},
    "CVE-2019-0708": {"node": "BlueKeep RDP RCE (CVE-2019-0708)", "kind": "entry", "impact": 9.0},
    "CVE-2020-1472": {"node": "Zerologon Domain Escalation (CVE-2020-1472)", "kind": "pivot", "impact": 9.8},
    "CVE-2021-1675": {"node": "PrintNightmare LPE (CVE-2021-1675)", "kind": "pivot", "impact": 8.8},
    "CVE-2021-34527": {"node": "PrintNightmare LPE (CVE-2021-34527)", "kind": "pivot", "impact": 8.8},
    "CVE-2021-36934": {"node": "HiveNightmare SAM Dump (CVE-2021-36934)", "kind": "pivot", "impact": 7.5},
    "CVE-2021-26855": {"node": "ProxyLogon Exchange RCE (CVE-2021-26855)", "kind": "entry", "impact": 9.5},
    "CVE-2021-34473": {"node": "ProxyShell Exchange RCE (CVE-2021-34473)", "kind": "entry", "impact": 9.5},
    "CVE-2020-0688": {"node": "Exchange Validation Key RCE (CVE-2020-0688)", "kind": "entry", "impact": 9.0},
    "CVE-2022-22965": {"node": "Spring4Shell RCE (CVE-2022-22965)", "kind": "entry", "impact": 9.5},
    "CVE-2017-5638": {"node": "Struts2 RCE Foothold (CVE-2017-5638)", "kind": "entry", "impact": 9.5},
    "CVE-2014-6271": {"node": "Shellshock Command Injection (CVE-2014-6271)", "kind": "entry", "impact": 8.5},
    "CVE-2014-6287": {"node": "RCE Foothold (CVE-2014-6287)", "kind": "entry", "impact": 9.5},
    "CVE-2023-23397": {"node": "Outlook NTLM Leak (CVE-2023-23397)", "kind": "pivot", "impact": 8.5},
    "CVE-2017-0213": {"node": "COM Aggregate Marshaler PrivEsc (CVE-2017-0213)", "kind": "pivot", "impact": 7.5},
    "CVE-2019-1388": {"node": "UAC PrivEsc (CVE-2019-1388)", "kind": "pivot", "impact": 7.0},
    "CVE-2016-0128": {"node": "Kerberos Forging (MS14-068)", "kind": "pivot", "impact": 9.5},
}

_ENTRY_HINTS = ("null session", "anonymous", "default credential",
                "sql injection", "upload", "rce", "command injection",
                "exposed", "unauthenticated")
_FINAL_HINTS = ("domain", "dc ", "crown", "payment", "c2", "root",
                "admin", "database", "hypervisor")


def _text_blob(f):
    return " ".join(str(f.get(k) or "") for k in
                    ("title", "evidence", "url", "path", "service",
                     "cve")).lower()


# ---------------------------------------------------------------------------
# NVD CVSS auto-lookup: real CVSS v3.1 base scores for CVEs not in the
# curated _CVE_NODES table. Cached on disk (nvd_cache.json) so repeated
# engagements don't re-fetch; offline/network failures fall back to the
# generic 7.0-impact Exploit Pivot, never raise.
# ---------------------------------------------------------------------------

_NVD_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "nvd_cache.json")
_NVD_LOCK = threading.Lock()
_NVD_CACHE_TTL = 7 * 24 * 3600  # 7 days
_NVD_TIMEOUT = 5.0


def _load_nvd_cache():
    try:
        with open(_NVD_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            now = time.time()
            return {k: v for k, v in data.items()
                    if isinstance(v, dict) and now - float(v.get("ts", 0)) < _NVD_CACHE_TTL}
    except Exception:
        pass
    return {}


def _save_nvd_cache(cache):
    try:
        with open(_NVD_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
    except Exception:
        pass


def _nvd_fetch(cve_id):
    """Fetch one CVE's CVSS v3.1 base score from the NVD API (never raises)."""
    try:
        import urllib.request
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s" % cve_id
        req = urllib.request.Request(url, headers={"User-Agent": "HackerAI-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=_NVD_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        for item in (data.get("vulnerabilities") or []):
            cve = item.get("cve") or {}
            metrics = cve.get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV30"):
                arr = metrics.get(key) or []
                if arr:
                    base = float(arr[0]["cvssData"]["baseScore"])
                    sev = (arr[0]["cvssData"].get("baseSeverity") or "").lower()
                    return {"cvss": base, "severity": sev}
            arr = metrics.get("cvssMetricV2") or []
            if arr:
                base = float(arr[0]["cvssData"]["baseScore"])
                # v2 scores run lower; normalize into the v3 band
                return {"cvss": round(min(10.0, max(base, base * 1.25)), 1),
                        "severity": (arr[0].get("baseSeverity") or "").lower()}
    except Exception:
        return None
    return None


def _nvd_lookup(cve_id):
    """Cached NVD lookup for one CVE; returns {cvss, severity} or None."""
    with _NVD_LOCK:
        cache = _load_nvd_cache()
        hit = cache.get(cve_id)
        if hit:
            return {"cvss": float(hit["cvss"]), "severity": hit["severity"]}
        fresh = _nvd_fetch(cve_id)
        if fresh:
            cache[cve_id] = {"cvss": fresh["cvss"], "severity": fresh["severity"],
                             "ts": time.time()}
            _save_nvd_cache(cache)
            return fresh
    return None


def _sev_weight(sev):
    return {"critical": 8.0, "high": 6.0, "medium": 5.0,
            "low": 2.0}.get(str(sev or "medium").lower(), 4.0)


def _node_for(finding):
    """Map one finding onto the strongest matching graph node.

    Returns (node_label, kind, impact, cve_refs). Known CVE ids in the
    finding text upgrade the hop to a CVE-specific template when that CVE
    outweighs the best semantic template; unknown CVE ids fall back to a
    generic exploit pivot. Falls back to a Generic Weakness
    node weighted from severity when no template signal matches.
    """
    try:
        blob = _text_blob(finding)
        cves = [c.upper() for c in _CVE_RE.findall(blob)]
        known = [_CVE_NODES[c] for c in cves if c in _CVE_NODES]
        best = None
        best_rank = (-1, -1, -1.0)
        for tmpl in _NODE_TEMPLATES:
            matched = [s for s in tmpl["signals"] if s in blob]
            if not matched:
                continue
            # specificity wins: longer matched signals (more precise) beat
            # shorter generic ones (e.g. 'anonymous logon' beats 'smb'),
            # then hit count, then template impact
            specificity = sum(len(s) for s in matched)
            rank = (specificity, len(matched), tmpl["impact"])
            if rank > best_rank:
                best, best_rank = tmpl, rank
        if known:
            # strongest known CVE wins when it outweighs the semantic match
            top = max(known, key=lambda c: c["impact"])
            if best is None or top["impact"] > best["impact"]:
                return top["node"], top["kind"], top["impact"], cves
        elif cves:
            # CVE not in the curated table: try a real NVD CVSS score,
            # offline/network failure falls back to the generic pivot
            nvd = _nvd_lookup(cves[0])
            if nvd:
                return "CVE Exploit (%s, CVSS %.1f)" % (cves[0], nvd["cvss"]), \
                       "pivot", max(7.0, nvd["cvss"]), cves
            return "Exploit Pivot (%s)" % cves[0], "pivot", 7.0, cves
        if best is None:
            sev_w = _sev_weight(finding.get("severity"))
            return "Generic Weakness (%s)" % finding.get("severity", "medium"), \
                   "pivot", max(4.0, sev_w / 2), cves
        return best["node"], best["kind"], best["impact"], cves
    except Exception:
        return "Generic Weakness (unknown)", "pivot", 4.0, []


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


def build_attack_chains(findings_list="", per_asset=False):
    """Build linked attack paths from raw findings.

    Accepts raw scanner JSON (auto-correlated/deduped via
    correlate_findings) or a list of finding dicts. Returns a dict:
      {ok, total_input, unique, chain_count, chains}
    per_asset - when True each chain branches only through hops evidenced
    on the entry point's own asset (single-asset escalation paths).
    """
    try:
        _extend_cve_nodes()
        correlated = correlate_findings(findings_list or [])
        if not correlated.get("ok"):
            return {"ok": False,
                    "error": correlated.get("error", "correlation failed")}
        findings = correlated["findings"]
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    entries, pivots, finals = [], [], []
    for f in findings:
        node, kind, impact, cves = _node_for(f)
        hop = {"node": node, "kind": kind, "impact": impact,
               "finding_id": f.get("id") or "", "asset": _asset_of(f),
               "title": f.get("title") or "", "cve_refs": cves}
        if kind == "entry":
            entries.append(hop)
        elif kind == "final":
            finals.append(hop)
        else:
            pivots.append(hop)

    if not entries and not pivots and not finals:
        return {"ok": True, "total_input": correlated.get("total_input", 0),
                "unique": 0, "chain_count": 0, "chains": []}

    # highest-impact entry first; pivots ordered impact-ASC so the path
    # reads foothold -> creds -> privilege -> impact (escalation order)
    entries = sorted(entries, key=lambda h: -h["impact"])
    finals = sorted(finals, key=lambda h: -h["impact"])
    # deduplicate pivots by node label (keep the highest-impact/evidenced
    # instance of each hop) and order impact-desc
    deduped = []
    for p in sorted(pivots, key=lambda h: -h["impact"]):
        if any(d["node"] == p["node"] for d in deduped):
            continue
        deduped.append(p)
    pivots = deduped
    pivots = sorted(pivots, key=lambda h: h["impact"])  # escalation order

    chains = []
    # one chain per entry point; with no entry findings the top pivot is
    # promoted so unmatched-only results still produce a path
    start_hops = entries or ([{
        "node": pivots[0]["node"], "kind": "entry",
        "impact": max(5.0, pivots[0]["impact"]),
        "finding_id": pivots[0].get("finding_id", ""),
        "asset": pivots[0]["asset"],
        "title": pivots[0].get("title", ""),
        "cve_refs": pivots[0].get("cve_refs", [])}] if pivots else [{
        "node": "Unknown Entry Point", "kind": "entry", "impact": 5.0,
        "finding_id": "", "asset": "unknown",
        "title": "Unmapped initial access", "cve_refs": []}])
    for entry in start_hops:
        chain_pivots = [p for p in pivots
                        if p is not entry and p["node"] != entry["node"]]
        if per_asset:
            # per-asset branching: keep only pivots evidenced on the same
            # asset (or a host under the entry URL) as the entry point, so
            # each chain shows a single-asset escalation instead of a mixed
            # path across unrelated hosts
            e_base = str(entry["asset"]).split(":")[0].strip().lower()
            chain_pivots = [p for p in chain_pivots
                            if str(p["asset"]).split(":")[0].strip().lower()
                            == e_base]
        final = finals[0] if finals else {
            "node": "Restricted Objective (Impact Unproven)", "kind": "final",
            "impact": max(6.0, entry["impact"]),
            "finding_id": entry.get("finding_id", ""),
            "asset": entry.get("asset", "unknown"),
            "title": "Potential escalation beyond demonstrated access",
            "cve_refs": entry.get("cve_refs", []),
        }
        if per_asset and finals:
            # per-asset branching also scopes the impact node: prefer the
            # strongest final evidenced on the entry asset; if none, keep
            # the restricted (unproven) objective scoped to the entry asset
            finals_here = [x for x in finals
                           if str(x["asset"]).split(":")[0].strip().lower()
                           == e_base]
            if finals_here:
                final = finals_here[0]
            else:
                final = dict(final, asset=entry.get("asset", "unknown"),
                             title="Potential escalation on %s beyond "
                                   "demonstrated access" % e_base)
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
            "assets": sorted({str(h["asset"]).split(":")[0]
                              for h in hops}),
            "cve_chain": [{"node": h["node"],
                           "cve_refs": h.get("cve_refs", [])} for h in hops],
            "hops": hops,
            "hops_evidenced": evidenced,
            "hops_total": len(hops),
            "chain_text": chain_text,
            "visualization": _visualize(chain_id, hops, score),
            "visualization_mermaid": _visualize(chain_id, hops, score,
                                                fmt="mermaid"),
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


def _clean_label(text):
    """Strip characters that break Mermaid/Graphviz label quoting."""
    return re.sub(r'["\\\[\]{}|<>]', "'", str(text))


def _visualize(chain_id, hops, score, fmt="ascii"):
    """Graph block for one attack chain.

    fmt: "ascii" (default ASCII/Markdown), "mermaid" (```mermaid
    flowchart) or "graphviz" (```dot digraph).
    """
    if fmt == "mermaid":
        return _mermaid_graph(chain_id, hops, score)
    if fmt == "graphviz":
        return _graphviz_graph(chain_id, hops, score)
    return _ascii_graph(chain_id, hops, score)


def _ascii_graph(chain_id, hops, score):
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
        if h.get("cve_refs"):
            meta.append("CVEs: " + ", ".join(h["cve_refs"]))
        if meta:
            lines.append("        %s" % " | ".join(meta))
        if i < len(hops) - 1:
            lines.append("          |")
            lines.append("          v")
    lines.append("```")
    return "\n".join(lines)


def _mermaid_graph(chain_id, hops, score):
    """```mermaid flowchart block for one attack chain."""
    cls = {"entry": "entryNode", "pivot": "pivotNode", "final": "finalNode"}
    lines = ["```mermaid",
             "flowchart LR",
             "  %% " + ("ATTACK PATH %s (composite risk: %.1f/10)"
                         % (chain_id, score))]
    for i, h in enumerate(hops):
        label = _clean_label(h["node"])
        if h.get("cve_refs"):
            label += " (" + _clean_label(", ".join(h["cve_refs"][:3])) + ")"
        meta = []
        if h.get("finding_id"):
            meta.append(str(h["finding_id"]))
        if h.get("asset"):
            meta.append(str(h["asset"]))
        if meta:
            label += "<br/>" + " | ".join(_clean_label(m) for m in meta)
        lines.append('  H%d["%s"]:::%s'
                     % (i, label, cls.get(h["kind"], "pivotNode")))
    for i in range(len(hops) - 1):
        lines.append("  H%d --> H%d" % (i, i + 1))
    lines.append('  classDef entryNode fill:#4CAF50,stroke:#1B5E20,color:#fff')
    lines.append('  classDef pivotNode fill:#FFC107,stroke:#795548,color:#000')
    lines.append('  classDef finalNode fill:#F44336,stroke:#7F0000,color:#fff')
    lines.append("```")
    return "\n".join(lines)


def _graphviz_graph(chain_id, hops, score):
    """```dot digraph block for one attack chain."""
    colors = {"entry": "#4CAF50", "pivot": "#FFC107", "final": "#F44336"}
    lines = ["```dot",
             "digraph %s {" % chain_id.replace("-", "_"),
             "  rankdir=LR;",
             '  label="ATTACK PATH %s (composite risk: %.1f/10)";' % (chain_id, score),
             '  labelloc=t;']
    for i, h in enumerate(hops):
        label = _clean_label(h["node"])
        if h.get("cve_refs"):
            label += "\\n(" + _clean_label(", ".join(h["cve_refs"][:3])) + ")"
        lines.append('  H%d [label="%s", fillcolor="%s", style=filled, '
                     'shape=box];' % (i, label,
                                      colors.get(h["kind"], "#DDDDDD")))
    for i in range(len(hops) - 1):
        lines.append("  H%d -> H%d;" % (i, i + 1))
    lines.append("}")
    lines.append("```")
    return "\n".join(lines)


def render_chain_graph(chains_result, fmt="ascii"):
    """Render the full Attack-Chain Graph section for a report.

    Accepts the dict returned by build_attack_chains() and returns a
    Markdown block: chain table + per-chain graph visualization.
    fmt: "ascii" (default), "mermaid" or "graphviz".
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
                                  c["composite_risk_score"], fmt=fmt))
            out.append("")
        return "\n".join(out).rstrip() + "\n"
    except Exception:
        return ""


def visualize_attack_chains(findings_list="", fmt="ascii", per_asset=False):
    """Tool wrapper: build chains from findings and return the Markdown
    graph visualization block.

    fmt: "ascii" (default), "mermaid" or "graphviz".
    per_asset: when True chains branch only through the entry point's own
    asset (single-asset escalation paths).
    """
    result = build_attack_chains(findings_list, per_asset=per_asset)
    if not result.get("ok"):
        return "visualize_attack_chains: %s" % result.get("error")
    if not result.get("chain_count"):
        return "visualize_attack_chains: no attack chains could be built."
    return render_chain_graph(result, fmt=fmt)


# ---------------------------------------------------------------------------
# CVE table auto-populate: promote NVD lookups into a persistent side table
# (cve_nodes.json) so unknown CVEs encountered in one engagement enrich
# every later chain build without re-fetching.
# ---------------------------------------------------------------------------

_CVE_TABLE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "cve_nodes.json")


def _read_cve_table():
    try:
        with open(_CVE_TABLE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_cve_table(table):
    try:
        os.makedirs(os.path.dirname(_CVE_TABLE_PATH) or ".", exist_ok=True)
        with open(_CVE_TABLE_PATH, "w", encoding="utf-8") as f:
            json.dump(table, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def _extend_cve_nodes():
    """Merge persisted NVD-derived entries into _CVE_NODES (idempotent)."""
    try:
        for cid, entry in _read_cve_table().items():
            if cid in _CVE_NODES or not isinstance(entry, dict):
                continue
            if not entry.get("node"):
                continue
            _CVE_NODES[cid] = {
                "node": str(entry["node"]),
                "kind": entry.get("kind") or "pivot",
                "impact": max(1.0, min(10.0, float(entry.get("impact", 7.0)))),
            }
    except Exception:
        pass


def populate_cve_table(cve_ids="", min_cvss=7.0):
    """Fetch NVD CVSS scores for CVE ids and persist chain-hop entries to
    cve_nodes.json so every future chain build uses the real scores.

    cve_ids - 'CVE-2021-44228, CVE-2015-1631, ...' (string) or a list
    Returns {ok, added, skipped, failed, table_size}; never raises.
    """
    try:
        if isinstance(cve_ids, str):
            ids = [c.strip().upper() for c in re.split(r"[,\s]+", cve_ids)
                   if c.strip()]
        elif isinstance(cve_ids, (list, tuple)):
            ids = [str(c).strip().upper() for c in cve_ids if str(c).strip()]
        else:
            return {"ok": False, "error": "cve_ids must be a string or list"}
        table = _read_cve_table()
        added, skipped, failed = [], [], []
        for cid in ids:
            if not _CVE_RE.match(cid):
                failed.append({"cve": cid, "error": "invalid CVE id"})
                continue
            if cid in _CVE_NODES or cid in table:
                skipped.append(cid)
                continue
            nvd = _nvd_lookup(cid)
            if not nvd:
                failed.append({"cve": cid, "error": "NVD lookup failed"})
                continue
            entry = {
                "node": "CVE Exploit (%s, CVSS %.1f)" % (cid, nvd["cvss"]),
                "kind": "entry" if nvd["cvss"] >= 9.0 else "pivot",
                "impact": max(float(min_cvss), nvd["cvss"]),
                "severity": nvd.get("severity", ""),
            }
            table[cid] = entry
            added.append(dict(entry, cve=cid))
        _write_cve_table(table)
        _extend_cve_nodes()
        return {"ok": True, "added": added, "skipped": skipped,
                "failed": failed, "table_size": len(table)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Merged branch view: chains sharing pivot hops are collapsed into one
# convergence cluster (multiple entry points -> shared pivots -> impact).
# ---------------------------------------------------------------------------

def merge_chain_branches(chains_result):
    """Merge chains that share pivot nodes into multi-branch views.

    Accepts the dict returned by build_attack_chains(). Chains whose hop
    sequences share any node label are grouped (union-find over hop
    adjacency) into merged branch clusters: several entry points
    converging on shared pivots toward final impact. Returns
      {ok, merged_count, unmerged_chain_count, merged: [...]}
    """
    try:
        if not isinstance(chains_result, dict) or not chains_result.get("ok"):
            return {"ok": False, "error": "invalid chains result"}
        chains = chains_result.get("chains") or []
        if len(chains) < 2:
            return {"ok": True, "merged_count": 0, "merged": [],
                    "unmerged_chain_count": len(chains)}

        parent = {}

        def find(x):
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for c in chains:
            labels = [h["node"] for h in c.get("hops") or []]
            for a, b in zip(labels, labels[1:]):
                union(a, b)

        clusters = {}
        for c in chains:
            root = find((c.get("hops") or [{}])[0].get("node",
                                                       c["chain_id"]))
            clusters.setdefault(root, []).append(c)

        merged = []
        for members in clusters.values():
            if len(members) < 2:
                continue
            pivot_count = {}
            for c in members:
                for p in c.get("intermediate_pivots") or []:
                    lbl = p.get("node") or ""
                    if lbl:
                        pivot_count[lbl] = pivot_count.get(lbl, 0) + 1
            shared = sorted(l for l, n in pivot_count.items() if n >= 2)
            entries, finals = [], []
            assets, cves = set(), set()
            for c in members:
                e = c.get("entry_point") or {}
                if e.get("node") and all(e["node"] != x.get("node")
                                         for x in entries):
                    entries.append({"node": e["node"],
                                    "asset": e.get("asset", ""),
                                    "chain_id": c["chain_id"]})
                f = c.get("final_impact") or {}
                if f.get("node") and all(f["node"] != x.get("node")
                                         for x in finals):
                    finals.append({"node": f["node"],
                                   "impact": f.get("impact", 0.0)})
                assets.update(c.get("assets") or [])
                for ref in c.get("cve_chain") or []:
                    cves.update(ref.get("cve_refs") or [])
            merged_id = "ACM-" + hashlib.sha1(
                "|".join(sorted(c["chain_id"] for c in members))
                .encode("utf-8", "replace")).hexdigest()[:8].upper()
            merged.append({
                "merged_id": merged_id,
                "member_chains": [c["chain_id"] for c in members],
                "entry_points": entries,
                "shared_pivots": shared,
                "final_impacts": finals,
                "assets": sorted(assets),
                "cve_refs": sorted(cves),
                "composite_risk_score": max(
                    c.get("composite_risk_score", 0.0) for c in members),
                "members": members,
            })
        merged.sort(key=lambda m: -m["composite_risk_score"])
        return {
            "ok": True,
            "merged_count": len(merged),
            "unmerged_chain_count": len(chains)
            - sum(len(m["members"]) for m in merged),
            "merged": merged,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _mermaid_merged(cluster):
    """```mermaid flowchart block for one merged branch cluster."""
    lines = ["```mermaid", "flowchart TD",
             "  %% MERGED %s (composite risk: %.1f/10, chains: %s)"
             % (cluster["merged_id"], cluster["composite_risk_score"],
                ", ".join(cluster["member_chains"]))]
    ids = {}

    def nid(label):
        if label not in ids:
            ids[label] = "N%d" % len(ids)
        return ids[label]

    edges = []
    for c in cluster["members"]:
        labels = [h["node"] for h in c.get("hops") or []]
        for a, b in zip(labels, labels[1:]):
            e = (nid(a), nid(b))
            if e not in edges:
                edges.append(e)
    for label in ids:
        if any(e["node"] == label for e in cluster["entry_points"]):
            kind = "entryNode"
        elif label in cluster["shared_pivots"]:
            kind = "pivotNode"
        else:
            kind = "finalNode"
        lines.append('  %s["%s"]:::%s'
                     % (ids[label], _clean_label(label), kind))
    for a, b in edges:
        lines.append("  %s --> %s" % (a, b))
    lines.append('  classDef entryNode fill:#4CAF50,stroke:#1B5E20,color:#fff')
    lines.append('  classDef pivotNode fill:#FFC107,stroke:#795548,color:#000')
    lines.append('  classDef finalNode fill:#F44336,stroke:#7F0000,color:#fff')
    lines.append("```")
    return "\n".join(lines)


def _graphviz_merged(cluster):
    """```dot digraph block for one merged branch cluster."""
    lines = ["```dot",
             "digraph %s {" % cluster["merged_id"].replace("-", "_"),
             "  rankdir=LR;",
             '  label="MERGED %s (composite risk: %.1f/10)";'
             % (cluster["merged_id"], cluster["composite_risk_score"]),
             '  labelloc=t;']
    ids = {}

    def nid(label):
        if label not in ids:
            ids[label] = "N%d" % len(ids)
        return ids[label]

    edges = []
    for c in cluster["members"]:
        labels = [h["node"] for h in c.get("hops") or []]
        for a, b in zip(labels, labels[1:]):
            e = (nid(a), nid(b))
            if e not in edges:
                edges.append(e)
    for label in ids:
        if any(e["node"] == label for e in cluster["entry_points"]):
            color = "#4CAF50"
        elif label in cluster["shared_pivots"]:
            color = "#FFC107"
        else:
            color = "#F44336"
        lines.append('  %s [label="%s", fillcolor="%s", style=filled, '
                     'shape=box];'
                     % (ids[label], _clean_label(label), color))
    for a, b in edges:
        lines.append("  %s -> %s;" % (a, b))
    lines.append("}")
    lines.append("```")
    return "\n".join(lines)


def _ascii_merged(cluster):
    """ASCII summary block for one merged branch cluster."""
    lines = ["```",
             "MERGED %s  (composite risk: %.1f/10)"
             % (cluster["merged_id"], cluster["composite_risk_score"]),
             "member chains: %s" % ", ".join(cluster["member_chains"]),
             ""]
    for c in cluster["members"]:
        lines.append("  %s" % c.get("chain_text", ""))
    lines.append("")
    lines.append("  shared pivots: %s"
                 % (", ".join(cluster["shared_pivots"]) or "(none)"))
    lines.append("  assets: %s" % ", ".join(cluster["assets"]))
    if cluster.get("cve_refs"):
        lines.append("  CVEs: %s" % ", ".join(cluster["cve_refs"]))
    lines.append("```")
    return "\n".join(lines)


def render_merged_graph(merged_result, fmt="mermaid"):
    """Render merged chain clusters as a Markdown graph block.

    fmt: "mermaid" (default), "ascii" or "graphviz".
    """
    try:
        if not isinstance(merged_result, dict) or not merged_result.get("ok"):
            return ""
        clusters = merged_result.get("merged") or []
        if not clusters:
            return ""
        out = ["## Merged Attack-Branch View", "",
               "Chains that share pivot hops, merged into convergence "
               "views - several entry points funnelling through common "
               "stepping stones toward final impact.", ""]
        for cl in clusters:
            if fmt == "ascii":
                out.append(_ascii_merged(cl))
            elif fmt == "graphviz":
                out.append(_graphviz_merged(cl))
            else:
                out.append(_mermaid_merged(cl))
            out.append("")
        return "\n".join(out).rstrip() + "\n"
    except Exception:
        return ""


def visualize_merged_chains(findings_list="", fmt="mermaid", per_asset=False):
    """Tool wrapper: build chains, merge those sharing pivots, and return
    the Markdown merged-branch graph block.

    fmt: "mermaid" (default), "ascii" or "graphviz".
    """
    result = build_attack_chains(findings_list, per_asset=per_asset)
    if not result.get("ok"):
        return "visualize_merged_chains: %s" % result.get("error")
    if not result.get("chain_count"):
        return "visualize_merged_chains: no attack chains could be built."
    merged = merge_chain_branches(result)
    if not merged.get("merged_count"):
        return ("visualize_merged_chains: no shared pivots found - "
                "chains are independent.")
    return render_merged_graph(merged, fmt=fmt)
