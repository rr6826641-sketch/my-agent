# -*- coding: utf-8 -*-
"""SWARM WAR-ROOM CAMPAIGN: multi-target / whole-subnet parallel assault.

The swarm router already carries Recon / Exploit / Reporter sub-agents.
This module turns it into a real war-room: ONE command takes a target
list or subnet, fans out parallel recon workers per host, then parallel
exploit workers against every open service, merges all results into a
single markdown report and persists campaign state for continuity.

    mode=recon    -> parallel port/ssl recon across all targets
    mode=exploit  -> CVE lookup per open service + optional nuclei runs
    mode=full     -> recon -> exploit in one shot (default)

NO FILTERS: everything a target yields lands in the merged report.  The
pin system upstream keeps the chain 100% uncensored-tier.

Public tools:
    swarm_campaign   - run a war-room campaign (parallel, merged report)
    swarm_status     - list / inspect war-room campaign states
"""

import io
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import ipaddress
except Exception:  # pragma: no cover - very old pythons
    ipaddress = None

from .network import tool_port_scan, tool_ssl_info
from .recon import tool_cve_lookup
from .pentest import tool_nuclei_scan
from .reporting import tool_add_finding
from .auto_pilot import _PORT_RE

WEB_PORTS = frozenset({
    80, 443, 8000, 8080, 8443, 8888, 9000, 9090, 9443, 3000, 5000,
    7000, 7080, 8020, 8081, 8088, 8880,
})
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+", re.I)

_WAR_LOCK = threading.Lock()


def _slug(host):
    return _SLUG_RE.sub("_", (host or "campaign").strip()) or "campaign"


def _campaign_dir(campaign_dir=""):
    base = (campaign_dir or "").strip() or os.path.join(
        os.getcwd(), "campaigns")
    if not os.path.isdir(base):
        try:
            os.makedirs(base, exist_ok=True)
        except Exception:
            pass
    return base


def _reports_dir(campaign_dir="", base_dir=None):
    if base_dir:
        return base_dir
    base = os.path.join(os.getcwd(), "reports")
    if not os.path.isdir(base):
        try:
            os.makedirs(base, exist_ok=True)
        except Exception:
            pass
    return base


def _expand_spec(spec):
    """Expand one target spec.

    '10.0.0.0/24' -> all hosts in the subnet
    '10.0.0.1-20' -> that octet range
    'evil.com'     -> single host
    """
    spec = (spec or "").strip()
    if not spec:
        return []
    if ipaddress is not None and "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            hosts = list(net.hosts())
            return [str(h) for h in hosts][:1024]
        except ValueError:
            pass
    if "-" in spec:
        left, right = spec.rsplit("-", 1)
        bits = left.split(".")
        if len(bits) == 4:
            try:
                lo, hi = int(bits[3]), int(right)
                if 0 <= lo <= hi <= 255:
                    return ["%s.%s.%s.%d" % (bits[0], bits[1], bits[2], i)
                            for i in range(lo, hi + 1)]
            except ValueError:
                pass
    return [spec]


def _expand_targets(targets=""):
    """Split 'a,b c' / CIDR / ranges into a deduped host list."""
    seen, out = set(), []
    for chunk in re.split(r"[\s,;]+", (targets or "").strip()):
        if not chunk:
            continue
        for host in _expand_spec(chunk):
            if host and host not in seen:
                seen.add(host)
                out.append(host)
    return out


def _recon_worker(host, run_ssl, budget):
    out = {"host": host, "ports": [], "ssl": "", "raw": "",
           "error": None, "elapsed_s": 0.0}
    t0 = time.time()
    try:
        txt = tool_port_scan(host)
        out["raw"] = txt[:1500]
        for m in _PORT_RE.finditer(txt):
            out["ports"].append({
                "port": int(m.group(1)),
                "service": (m.group(2) or "").strip().lower(),
            })
    except Exception as exc:
        out["error"] = repr(exc)
    if run_ssl and not out["error"] and any(
            p["port"] == 443 for p in out["ports"]):
        try:
            out["ssl"] = tool_ssl_info(host, 443)
        except Exception as exc:
            out["ssl_error"] = repr(exc)
    out["elapsed_s"] = round(time.time() - t0, 1)
    return out


def _exploit_worker(host, port, service, run_nuclei):
    out = {"host": host, "port": port, "service": service,
           "cves": [], "snippet": "", "nuclei": "",
           "error": None, "nuclei_error": None}
    q = (service or "").strip().lower()
    if len(q) >= 3 and q not in ("open", "unknown", "tcpwrapped"):
        try:
            txt = tool_cve_lookup(q, 5)
            out["cves"] = sorted(set(_CVE_RE.findall(txt)))[:6]
            out["snippet"] = txt[:400]
        except Exception as exc:
            out["error"] = repr(exc)
    if run_nuclei and (port in WEB_PORTS or "http" in q or "ssl" in q):
        scheme = ("https" if port in (443, 8443, 9443) or "ssl" in q
                  or "https" in q else "http")
        url = "%s://%s:%d/" % (scheme, host, port)
        try:
            out["nuclei"] = tool_nuclei_scan(url)[:900]
        except Exception as exc:
            out["nuclei_error"] = repr(exc)
    return out


def _run_recon(hosts, workers, run_ssl, budget):
    results, errors = [], []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(_recon_worker, h, run_ssl, budget): h
                for h in hosts}
        for fut in as_completed(futs, timeout=budget):
            try:
                results.append(fut.result())
            except Exception as exc:
                errors.append({"host": futs[fut], "error": repr(exc)})
    results.sort(key=lambda r: r["host"])
    return results, errors


def _run_exploit(hosts, workers, run_nuclei, budget):
    jobs, results, errors = [], [], []
    for r in hosts:
        for p in r.get("ports", [])[:24]:
            jobs.append((r["host"], p.get("port", 0),
                         (p.get("service") or "").strip().lower()))
    if not jobs:
        return [], errors
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(_exploit_worker, h, p, s, run_nuclei):
                (h, p) for h, p, s in jobs}
        for fut in as_completed(futs, timeout=budget):
            try:
                results.append(fut.result())
            except Exception as exc:
                h, p = futs[fut]
                errors.append({"host": h, "port": p, "error": repr(exc)})
    results.sort(key=lambda r: (r["host"], r["port"]))
    return results, errors


def _build_report(campaign, hosts, exploits, mode):
    L = []
    L.append("# SWARM WAR-ROOM CAMPAIGN REPORT\n")
    L.append("- target(s): `%s`\n- mode: `%s`\n- started: `%s`\n- finished: `%s`"
             % (campaign["targets"], mode, campaign["started_at"],
                campaign["updated_at"]))
    L.append("- hosts: %d | open services found: %d | CVE hits: %d\n" % (
        len(hosts),
        sum(len(h.get("ports", [])) for h in hosts),
        sum(len(e.get("cves", [])) for e in exploits),
    ))

    L.append("\n## 1. War-room summary table\n")
    L.append("| host | open ports | services | CVEs | status |")
    L.append("|------|------------|----------|------|--------|")
    by_host = {}
    for e in exploits:
        by_host.setdefault(e["host"], []).append(e)
    for h in hosts:
        port_txt = ",".join(str(p["port"]) for p in h.get("ports", [])[:20])
        svc_txt = ",".join(
            "%s/%s" % (p["port"], p["service"]) for p in h.get("ports", [])[:12])
        cves = sorted({c for e in by_host.get(h["host"], [])
                       for c in e.get("cves", [])})
        status = "up" if h.get("ports") or not h.get("error") else "down"
        L.append("| `%s` | %s | %s | %s | %s |" % (
            h["host"], port_txt or "-", svc_txt or "-",
            ",".join(cves[:5]) or "-", status))

    for h in hosts:
        L.append("\n## %s\n" % h["host"])
        if h.get("error"):
            L.append("> recon error: `%s`" % h["error"])
        ports = h.get("ports", [])
        if not ports:
            L.append("_no open ports_")
        else:
            L.append("| port | service |")
            L.append("|------|---------|")
            for p in ports[:40]:
                L.append("| %d | %s |" % (p["port"], p["service"]))
        if h.get("ssl"):
            L.append("\n<details><summary>SSL info</summary>\n\n```\n%s\n```\n</details>"
                     % h["ssl"][:600])
        hits = [e for e in exploits if e["host"] == h["host"]]
        if hits:
            L.append("\n### exploit hits\n")
            for e in hits:
                L.append("- **%d/%s**" % (e["port"], e["service"] or "?"))
                if e.get("error"):
                    L.append("  - lookup error: `%s`" % e["error"])
                if e.get("cves"):
                    L.append("  - CVEs: `%s`" % ", ".join(e["cves"]))
                    L.append("  - evidence: %s" %
                             (e["snippet"] or "n/a").replace("\n", " ")[:220])
                if e.get("nuclei"):
                    L.append("  - nuclei: %s" %
                             e["nuclei"].replace("\n", " | ")[:300])
    return "\n".join(L)


def tool_swarm_campaign(targets="", mode="full", max_workers=8,
                        run_nuclei=False, campaign_dir="", budget_sec=280):
    """SWARM WAR-ROOM: run parallel recon/exploit over many targets at once.

    targets     - comma/space separated hosts, CIDR subnet ('10.0.0.0/24')
                  or octet range ('10.0.0.1-30')
    mode        - 'recon' | 'exploit' | 'full'
    max_workers - parallel workers per phase
    run_nuclei  - include nuclei template runs in exploit phase (slow)
    """
    try:
        workers = max(1, min(32, int(max_workers or 8)))
    except (TypeError, ValueError):
        workers = 8
    try:
        budget = max(15, int(budget_sec or 280))
    except (TypeError, ValueError):
        budget = 280
    mode = (mode or "full").strip().lower()
    if mode not in ("recon", "exploit", "full"):
        return "swarm_campaign: mode must be 'recon', 'exploit' or 'full'"

    hosts = _expand_targets(targets)
    if not hosts:
        return ("swarm_campaign: provide targets - IPs, domains, CIDR subnet "
                "or octet range. Example: swarm_campaign(targets='10.0.0.0/24')")

    started = time.time()
    war = {
        "kind": "swarm_campaign",
        "targets": targets.strip(),
        "hosts": hosts,
        "mode": mode,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "phases": {},
        "errors": [],
    }

    report = []
    report.append("[swarm] war-room campaign: %d targets | mode=%s | workers=%d"
                  % (len(hosts), mode, workers))

    if mode in ("recon", "full"):
        t0 = time.time()
        recon, rerr = _run_recon(hosts, workers, True, budget)
        war["phases"]["recon"] = {
            "status": "done",
            "elapsed_s": round(time.time() - t0, 1),
            "hosts": recon,
            "errors": rerr,
        }
        war["errors"].extend({"phase": "recon", **e} for e in rerr)
        report.append("[swarm] recon: %d/%d hosts live | %s" % (
            sum(1 for r in recon if r.get("ports")), len(recon),
            "%.1fs" % (time.time() - t0)))

    if mode in ("exploit", "full"):
        recon = war.get("phases", {}).get("recon", {}).get("hosts", [])
        if mode == "exploit" and not recon:
            # standalone exploit mode: do a quick recon-first pass
            recon, rerr = _run_recon(hosts, workers, False, budget)
            war["phases"]["recon"] = {
                "status": "done", "hosts": recon, "errors": rerr}
            war["errors"].extend({"phase": "recon", **e} for e in rerr)
        t0 = time.time()
        exploits, eerr = _run_exploit(recon, workers, run_nuclei, max(15, budget))
        war["phases"]["exploit"] = {
            "status": "done",
            "elapsed_s": round(time.time() - t0, 1),
            "targets": exploits,
            "errors": eerr,
        }
        war["errors"].extend({"phase": "exploit", **e} for e in eerr)
        total_cves = sum(len(e.get("cves", [])) for e in exploits)
        report.append("[swarm] exploit: %d services probed | %d CVE hits | %.1fs"
                      % (len(exploits), total_cves,
                         time.time() - t0))
        for e in exploits:
            for cve in e.get("cves", [])[:2]:
                try:
                    tool_add_finding(
                        asset=e["host"],
                        title="Swarm %s/%s -> %s" % (
                            e["port"], e["service"] or "?", cve),
                        severity="medium",
                        description=(e["snippet"] or "auto CVE match")[:500],
                        evidence="war-room swarm_campaign exploit phase")
                except Exception:
                    pass

    war["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    token = _slug(hosts[0]) if len(hosts) == 1 else \
        "%s+%d" % (_slug(hosts[0]), len(hosts) - 1)
    cdir = _campaign_dir(campaign_dir)
    state_file = os.path.join(cdir, "swarm_%s.json" % token)
    try:
        with _WAR_LOCK, io.open(state_file, "w", encoding="utf-8") as fh:
            json.dump(war, fh, ensure_ascii=False, indent=2)
    except Exception as exc:
        war["errors"].append({"phase": "save", "error": repr(exc)})

    rdir = _reports_dir(campaign_dir)
    report_file = os.path.join(rdir, "swarm_campaign_%s.md" % token)
    final = _build_report(war, recon, exploits if mode in
                          ("exploit", "full") else [], mode)
    try:
        with io.open(report_file, "w", encoding="utf-8") as fh:
            fh.write(final)
        report.append("REPORT: %s" % report_file)
    except Exception as exc:
        report.append("REPORT WRITE FAILED: %r" % (exc,))
    report.append("STATE: %s" % state_file)
    report.append("ELAPSED: %.1fs" % (time.time() - started))
    return "\n".join(report)


def tool_swarm_status(token="", campaign_dir=""):
    """List all war-room campaign states, or inspect one by token."""
    cdir = _campaign_dir(campaign_dir)
    if token:
        path = os.path.join(cdir, "swarm_%s.json" % _slug(token))
        if not os.path.exists(path):
            return "swarm_status: no campaign %r (dir %s)" % (token, cdir)
        try:
            with io.open(path, encoding="utf-8") as fh:
                st = json.load(fh)
        except Exception as exc:
            return "swarm_status: unreadable: %r" % (exc,)
        lines = ["swarm campaign: %s" % st.get("targets", token),
                 "  started: %s | updated: %s" % (
                     st.get("started_at", "?"), st.get("updated_at", "?"))]
        phases = st.get("phases", {})
        for name in ("recon", "exploit"):
            ph = phases.get(name, {})
            lines.append("  %s: %s | %s hosts | %.1fs" % (
                name, ph.get("status", "pending"),
                len(ph.get("hosts", ph.get("targets", []))),
                ph.get("elapsed_s", 0.0)))
        host_lines = []
        for h in phases.get("recon", {}).get("hosts", []):
            host_lines.append("- %s: %d ports" % (
                h.get("host", "?"), len(h.get("ports", []))))
        if host_lines:
            lines.append("  hosts:\n%s" % "\n".join("    " + x for x in host_lines))
        lines.append("  errors: %d | file: %s" % (len(st.get("errors", [])), path))
        return "\n".join(lines)
    if not os.path.isdir(cdir):
        return "no swarm campaigns yet (dir %s)" % cdir
    rows = []
    for fn in sorted(os.listdir(cdir)):
        if not fn.startswith("swarm_") or not fn.endswith(".json"):
            continue
        try:
            with io.open(os.path.join(cdir, fn), encoding="utf-8") as fh:
                st = json.load(fh)
            hosts = st.get("hosts", [])
            done = [p for p, ph in st.get("phases", {}).items()
                    if ph.get("status") == "done"]
            rows.append("- %s [%s] %d targets | updated %s" % (
                st.get("targets", fn[:-5]), ",".join(done) or "new",
                len(hosts), st.get("updated_at", "?")))
        except Exception:
            rows.append("- %s (unreadable)" % fn)
    return "swarm campaigns (%d):\n%s" % (len(rows), "\n".join(rows)) \
        if rows else "no swarm campaigns yet (dir %s)" % cdir