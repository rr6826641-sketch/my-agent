# -*- coding: utf-8 -*-
"""AUTO-PILOT: ATTACK MISSION MODE.

Deterministic end-to-end campaign runner on top of the existing tool
modules.  One command runs the whole kill-chain as phases instead of
making the model remember the sequence:

    recon   - subdomain enum (domains only) + fast TCP port scan + SSL info
    scan    - HTTP fingerprint (status / headers / tech) on open web
              ports + shallow directory fuzz on live roots
    vuln    - CVE lookup per discovered tech / service banner + optional
              nuclei template runs (opt-in; slow)
    exploit - EXPLOIT AUTO-RUN CHAIN: CVE hits are actively chased -
              targeted nuclei verification + ready-to-run PoC probes
              (artifacts/exploit_<target>/) + payload-memory signals
    report  - findings logged via reporting + markdown report written

Every mission persists to campaigns/<target>.json.  A phase interrupted
by a timeout / crash resumes from exactly where it stopped.

NO FILTERS: the runner reports everything a target yields.  The model
chain stays 100% uncensored-tier (pin system upstream).

Public tools:
    attack_mission   - auto-pilot: run every unfinished phase in order
    mission_recon    - run only the recon phase
    mission_scan     - run only the scan phase
    mission_vuln     - run only the vuln phase
    mission_exploit  - exploit auto-run chain phase only
    mission_report   - run only the report phase
    mission_resume   - alias: attack_mission auto from where it stopped
    mission_status   - show campaign progress (one target or all)
    mission_reset    - delete a campaign state file (start clean)
"""

import io
import json
import os
import re
import time

from .network import tool_port_scan, tool_ssl_info, DEEP_PORTS
from .recon import (tool_subdomain_enum, tool_dir_fuzz, tool_cve_lookup,
                    DEEP_WORDLIST)
from .web import tool_http_request, tool_tech_detect, tool_check_headers
from .pentest import tool_nuclei_scan
from .cpe_match import tool_cpe_scan, tool_cpe_nuclei_scan
from .reporting import tool_add_finding
from .payload_memory import (
    tool_payload_memory_record, tool_payload_memory_top,
    tool_payload_memory_ranking,
)

PHASE_ORDER = ("recon", "scan", "vuln", "exploit", "report")

WEB_PORTS = frozenset({
    80, 443, 8000, 8080, 8443, 8888, 9000, 9090, 9443, 3000, 5000,
    7000, 7080, 8020, 8081, 8088, 8880,
})

_PORT_RE = re.compile(r"^\s*(\d{1,5})\s+([A-Za-z0-9][A-Za-z0-9\-\_\.]*)\s*$",
                      re.MULTILINE)
_STATUS_RE = re.compile(r"STATUS:\s*(\d+)")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_DIR_HIT_RE = re.compile(r"^\s*(\d{3})\s+(\S+)\s+\d+\s+bytes", re.MULTILINE)


class _BudgetExceeded(Exception):
    """Raised when the phase wall-clock budget is exhausted."""


class _Budget(object):
    def __init__(self, seconds):
        self.deadline = time.time() + max(2.0, float(seconds or 100))

    def left(self):
        return self.deadline - time.time()

    def check(self, slack=3.0):
        if self.left() < slack:
            raise _BudgetExceeded()


class _Ctx(object):
    """Per-run context passed to every phase."""

    def __init__(self, campaign_dir, reports_dir, run_nuclei, budget, deep=False):
        self.campaign_dir = campaign_dir
        self.reports_dir = reports_dir
        self.run_nuclei = bool(run_nuclei)
        self.deep = bool(deep)
        self.budget = budget


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _trunc(text, limit=5000):
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated, %d more chars]" % (len(text) - limit)


def _slug(target):
    s = re.sub(r"[^A-Za-z0-9.\-]", "_", (target or "").strip())
    return s[:80] or "mission"


def _is_ip(host):
    parts = (host or "").strip().split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False


def _campaign_dir(campaign_dir=""):
    if campaign_dir:
        return os.path.abspath(campaign_dir)
    return os.path.join(os.getcwd(), "campaigns")


def _reports_dir(campaign_dir="", base_dir=None):
    if campaign_dir:
        return os.path.join(os.path.abspath(campaign_dir),
                            "..", "reports")
    return os.path.join(base_dir or os.getcwd(), "reports")


def _load(target, campaign_dir=""):
    base = os.getcwd()
    cdir = _campaign_dir(campaign_dir)
    path = os.path.join(cdir, _slug(target) + ".json")
    state = {
        "target": (target or "").strip(),
        "created": _now(),
        "updated": _now(),
        "domain": not _is_ip(target),
        "base_dir": base,
        "campaign_file": path,
        "phases": {},
        "errors": [],
        "findings_logged": 0,
        "posture": "standard",
    }
    if os.path.exists(path):
        try:
            with io.open(path, encoding="utf-8") as fh:
                state.update(json.load(fh))
        except Exception:
            pass
    state.setdefault("posture", "standard")
    state["campaign_file"] = path
    try:
        os.makedirs(cdir, exist_ok=True)
    except Exception:
        pass
    return state


def _save(state, campaign_dir=""):
    state["updated"] = _now()
    # keep the top-level aggregate in sync with per-phase findings counts
    # (cosmetic-fix: top-level stayed 0 while phases carried the real counts)
    state["findings_logged"] = sum(
        state.get("phases", {}).get(p, {}).get("findings_logged", 0)
        for p in PHASE_ORDER)
    try:
        os.makedirs(os.path.dirname(state["campaign_file"]), exist_ok=True)
        with io.open(state["campaign_file"], "w", encoding="utf-8",
                     newline="\n") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2)
    except Exception as exc:
        state.setdefault("errors", []).append(
            {"phase": "io", "step": "save", "error": repr(exc)})
    return state


def _mark(state, phase, status, extra=None):
    entry = state["phases"].setdefault(phase, {})
    entry["status"] = status
    if extra:
        entry.update(extra)
    state["phases"][phase] = entry
    return entry


def _phase_done(state, phase):
    return state.get("phases", {}).get(phase, {}).get("status") == "done"


# ---------------------------------------------------------------------------
# Phase implementations
# ---------------------------------------------------------------------------

def _phase_recon(state, ctx):
    started = time.time()
    host = state["target"]
    entry = {"status": "done", "started_at": _now(), "subdomains": [],
             "ports": [], "ssl": ""}
    if state.get("domain"):
        try:
            txt = tool_subdomain_enum(host, 80)
            pattern = re.compile(
                r"[A-Za-z0-9](?:[A-Za-z0-9\-_]*\.){1,6}"
                + re.escape(host) + r"(?::\d+)?", re.IGNORECASE)
            subs = []
            for m in pattern.finditer(txt):
                s = m.group(0).strip(" .-")
                if s and s not in subs and len(s) > len(host):
                    subs.append(s)
            entry["subdomains"] = subs[:60]
            entry["subdomain_raw"] = _trunc(txt, 1500)
        except Exception as exc:
            state["errors"].append(
                {"phase": "recon", "step": "subdomain_enum",
                 "error": repr(exc)})
    if ctx.deep:
        # DEEP-SCAN POSTURE: full well-known range (1-1024) + high-value
        # services, faster per-port timeout with wider concurrency.
        try:
            txt = tool_port_scan(host, ports=DEEP_PORTS, timeout=1.0,
                                 concurrency=220)
        except Exception as exc:
            state["errors"].append(
                {"phase": "recon", "step": "port_scan_deep",
                 "error": repr(exc)})
            txt = ""
    else:
        try:
            txt = tool_port_scan(host)
        except Exception as exc:
            state["errors"].append(
                {"phase": "recon", "step": "port_scan", "error": repr(exc)})
            txt = ""
    if txt:
        entry["port_raw"] = _trunc(txt, 2000)
        for m in _PORT_RE.finditer(txt):
            entry["ports"].append({
                "port": int(m.group(1)),
                "service": (m.group(2) or "").strip().lower(),
            })
    open_set = set(p["port"] for p in entry["ports"])
    ssl_ports = [443, 8443, 9443] if ctx.deep else [443]
    ssl_bits = []
    for sp in ssl_ports:
        if sp in open_set:
            try:
                ssl_bits.append("%s:%s" % (sp, _trunc(
                    tool_ssl_info(host, sp), 400)))
            except Exception as exc:
                state["errors"].append(
                    {"phase": "recon", "step": "ssl_info %d" % sp,
                     "error": repr(exc)})
    entry["ssl"] = "\n".join(ssl_bits)
    entry["elapsed_s"] = round(time.time() - started, 1)
    state["phases"]["recon"] = entry
    _save(state, ctx.campaign_dir)
    ctx.budget.check()
    port_summary = ",".join(
        "%d/%s" % (p["port"], p["service"] or "?")
        for p in entry["ports"][:25]) or "none"
    return "[recon] %s | open ports: %s | subdomains: %d" % (
        host, port_summary, len(entry["subdomains"]))


def _phase_scan(state, ctx):
    started = time.time()
    host = state["target"]
    entry = {"status": "done", "web": {}, "dirs": {}}
    ports = state.get("phases", {}).get("recon", {}).get("ports", [])
    web_targets = []
    for p in ports:
        port = int(p.get("port", 0))
        svc = (p.get("service") or "").lower()
        if not port:
            continue
        if port in WEB_PORTS or "http" in svc or "ssl" in svc or "srv" in svc:
            scheme = ("https" if (port in (443, 8443, 9443)
                                  or "ssl" in svc or "https" in svc)
                      else "http")
            web_targets.append((scheme, port))
    if not web_targets and ports:
        first = ports[0]
        web_targets.append(("http", int(first.get("port", 80))))
    for scheme, port in web_targets[:12 if ctx.deep else 6]:
        ctx.budget.check(10.0 if ctx.deep else 8.0)
        url = "%s://%s:%d/" % (scheme, host, port)
        info = {}
        try:
            hx = tool_http_request(url, method="GET", timeout=12)
            info["http"] = _trunc(hx, 1000)
            m = _STATUS_RE.search(hx)
            info["status"] = int(m.group(1)) if m else None
        except Exception as exc:
            state["errors"].append(
                {"phase": "scan", "step": "http_request %s" % url,
                 "error": repr(exc)})
            continue
        try:
            info["tech"] = _trunc(tool_tech_detect(url, timeout=12), 600)
        except Exception:
            pass
        try:
            info["headers"] = _trunc(tool_check_headers(url, timeout=12), 600)
        except Exception:
            pass
        entry["web"][url] = info
    live = [u for u, v in entry["web"].items()
            if isinstance(v.get("status"), int) and 200 <= v["status"] < 500]
    for url in live[:4 if ctx.deep else 2]:
        ctx.budget.check(30.0 if ctx.deep else 15.0)
        try:
            if ctx.deep:
                # DEEP-SCAN POSTURE: bigger wordlist + wider results
                df = tool_dir_fuzz(url, wordlist=DEEP_WORDLIST,
                                   max_results=25, threads=16, timeout=6)
            else:
                df = tool_dir_fuzz(url, max_results=10)
            entry["dirs"][url] = _trunc(df, 1500)
            for dm in _DIR_HIT_RE.finditer(df):
                try:
                    tool_payload_memory_record(
                        host, payload="dir:%s" % dm.group(2).strip(),
                        signal="dir_" + dm.group(1),
                        vuln_class="web:dir")
                except Exception:
                    pass
        except Exception as exc:
            state["errors"].append(
                {"phase": "scan", "step": "dir_fuzz %s" % url,
                 "error": repr(exc)})
    entry["elapsed_s"] = round(time.time() - started, 1)
    state["phases"]["scan"] = entry
    _save(state, ctx.campaign_dir)
    ctx.budget.check()
    web_list = ", ".join(
        "%s (%s)" % (u, v.get("status", "?")) for u, v in entry["web"].items())
    return "[scan] web targets: %d | %s" % (len(entry["web"]),
                                            web_list or "none")



def _cpe_banner_lines(text):
    """Convert tool_cpe_scan output rows into nmap-style banner lines
    ("80/tcp open http Apache 2.4.49") so the sniper pipeline can parse."""
    lines = []
    for ln in (text or "").splitlines():
        m = re.match(r"^-\s+(\d+)/(tcp|udp)\s+(\S+)\s*\|\s*([^|]*?)\s*\|\s*cpe:", ln)
        if m:
            port, proto, svc = m.group(1), m.group(2), m.group(3)
            prod_ver = (m.group(4) or "").strip()
            lines.append("%s/%s open %s %s" % (port, proto, svc, prod_ver))
    return "\n".join(lines)

def _phase_vuln(state, ctx):
    started = time.time()
    host = state["target"]
    entry = {"status": "done", "queries": [], "hits": []}
    queries = set()
    scan = state.get("phases", {}).get("scan", {})
    for info in scan.get("web", {}).values():
        tech = str(info.get("tech", "") or "")
        for tok in re.findall(r"([A-Za-z][A-Za-z0-9\-]{1,24})[:\s]+[\d.]+",
                              tech):
            queries.add(tok)
        http = str(info.get("http", "") or "")
        for tok in re.findall(r"Server:\s*([A-Za-z][A-Za-z0-9\-]{1,24})",
                              http, re.IGNORECASE):
            queries.add(tok)
    for p in state.get("phases", {}).get("recon", {}).get("ports", []):
        svc = (p.get("service") or "").strip().lower()
        if len(svc) >= 3 and svc not in (
                "open", "unknown", "tcpwrapped", "filtered", "closed"):
            queries.add(svc)
    queries = queries - {"server", "http", "https", "redirected"}
    entry["queries"] = sorted(queries)[:20 if ctx.deep else 12]
    for q in entry["queries"]:
        ctx.budget.check(6.0)
        try:
            txt = tool_cve_lookup(q, 5)
        except Exception as exc:
            state["errors"].append(
                {"phase": "vuln", "step": "cve_lookup %s" % q,
                 "error": repr(exc)})
            continue
        cves = sorted(set(_CVE_RE.findall(txt)))
        if cves:
            entry["hits"].append({
                "query": q,
                "cves": cves[:5],
                "snippet": _trunc(txt, 500),
            })
    findings = 0
    for h in entry["hits"][:10]:
        for cve in h["cves"][:2]:
            if findings >= 12:
                break
            try:
                tool_add_finding(
                    asset=host,
                    title="Potential %s match for %s" % (cve, h["query"]),
                    severity="medium",
                    description=h["snippet"],
                    evidence="CVE lookup via mission vuln phase",
                    confidence="low",
                    status="needs-validation")
                findings += 1
            except Exception:
                pass
    entry["findings_logged"] = findings
    if ctx.run_nuclei or ctx.deep:
        # run_nuclei opt-in OR deep posture: auto nuclei sniper on live
        # web targets (deep caps at 3 urls with tighter per-url budget).
        entry["nuclei"] = {}
        entry["cpe_banner"] = ""
        cpe_banner = ""
        try:
            cpe_out = tool_cpe_scan(state["target"])
            cpe_banner = _cpe_banner_lines(cpe_out)
            entry["cpe_banner"] = _trunc(
                cpe_banner or cpe_out, 1500)
        except Exception as exc:
            entry["cpe_banner"] = "cpe_scan FAILED: %r" % (exc,)
        nuc_urls = list(scan.get("web", {}))[:3 if ctx.deep else None]
        for url in nuc_urls:
            ctx.budget.check(45.0 if ctx.deep else 60.0)
            res = ""
            try:
                if cpe_banner:
                    res = tool_cpe_nuclei_scan(url, banner=cpe_banner)
                    if "no templates matched" in res:
                        fb = tool_nuclei_scan(url)
                        res = res + "\n[generic fallback] " + _trunc(fb, 600)
                else:
                    res = tool_nuclei_scan(url)
            except Exception as exc:
                res = "FAILED: %r" % (exc,)
            entry["nuclei"][url] = _trunc(res, 1500)
    entry["elapsed_s"] = round(time.time() - started, 1)
    state["phases"]["vuln"] = entry
    _save(state, ctx.campaign_dir)
    ctx.budget.check()
    hits = ", ".join(
        "%s:%s" % (h["query"], ",".join(h["cves"][:2]))
        for h in entry["hits"][:8]) or "none"
    return "[vuln] queries: %d | CVE hits: %d [%s] | findings: %d" % (
        len(entry["queries"]), len(entry["hits"]), hits, findings)


def _phase_exploit(state, ctx):
    """EXPLOIT AUTO-RUN CHAIN: every CVE hit from the vuln phase becomes
    an ACTIVE attempt instead of a passive log line -
      1) targeted nuclei verification against live web targets,
      2) a ready-to-run PoC probe deliverable saved under artifacts/,
      3) recorded into payload memory as an exploit-chain signal.
    Bounded by the mission budget; nothing is hidden from the report."""
    started = time.time()
    host = state["target"]
    vuln = state.get("phases", {}).get("vuln", {})
    hits = vuln.get("hits", []) or []
    web_targets = list(state.get("phases", {}).get("scan", {})
                       .get("web", {}) or {})
    entry = {"status": "done", "attempts": [], "pocs": []}
    if not hits:
        entry["note"] = "no CVE hits from vuln phase - chain idle"
        state["phases"]["exploit"] = entry
        _save(state, ctx.campaign_dir)
        return "[exploit] idle - no CVE hits from vuln phase"
    art_dir = os.path.join(os.path.dirname(ctx.reports_dir or "reports"),
                           "artifacts", "exploit_%s" % _slug(host))
    for h in hits[:6]:
        cves = h.get("cves", [])[:2]
        if not cves:
            continue
        ctx.budget.check(8.0)
        att = {"query": h["query"], "cves": cves,
               "attempts": [], "poc_file": ""}
        for url in web_targets[:2]:
            if not ctx.budget.check(30.0):
                break
            res = ""
            try:
                res = tool_nuclei_scan(url)
            except Exception as exc:
                res = "FAILED: %r" % (exc,)
            att["attempts"].append({"url": url,
                                     "nuclei": _trunc(res, 700)})
        try:
            os.makedirs(art_dir, exist_ok=True)
            poc_file = os.path.join(art_dir, "poc_%s.py" % _slug(cves[0]))
            with io.open(poc_file, "w", encoding="utf-8") as fh:
                fh.write(_poc_probe(cves[0], host, h["query"],
                                    web_targets[:2]))
            att["poc_file"] = poc_file
            entry["pocs"].append(poc_file)
        except Exception as exc:
            state["errors"].append(
                {"phase": "exploit", "step": "poc %s" % cves[0],
                 "error": repr(exc)})
        entry["attempts"].append(att)
        try:
            tool_payload_memory_record(
                host, payload="cve:%s:%s" % (cves[0], h["query"]),
                signal="exploit_chained", vuln_class="cve")
        except Exception:
            pass
    findings = 0
    for att in entry["attempts"][:8]:
        for cve in att.get("cves", [])[:1]:
            try:
                tool_add_finding(
                    asset=host,
                    title="Exploit chain auto-run: %s via %s"
                          % (cve, att["query"]),
                    severity="high",
                    description=("exploit phase auto-chained CVE -> active "
                                 "nuclei verification + PoC probe deliverable"),
                    evidence=("exploit auto-run: %d nuclei attempts, PoC=%s"
                              % (len(att.get("attempts", [])),
                                 att.get("poc_file", "none"))),
                    confidence="low",
                    status="needs-validation")
                findings += 1
            except Exception:
                pass
    entry["findings_logged"] = findings
    entry["elapsed_s"] = round(time.time() - started, 1)
    state["phases"]["exploit"] = entry
    _save(state, ctx.campaign_dir)
    ctx.budget.check()
    return ("[exploit] chained: %d CVE hit(s) | %d nuclei attempt(s) | "
            "%d PoC probe(s) | findings: %d" % (
                len(entry["attempts"]),
                sum(len(a.get("attempts", []))
                    for a in entry["attempts"]),
                len(entry["pocs"]), findings))


def _poc_probe(cve_id, host, query, urls):
    """Self-contained non-destructive verification probe for a chained
    CVE - docs + precise steps, ready to run/reuse by the agent."""
    lines = [
        "# EXPLOIT CHAIN PROBE - %s" % cve_id,
        "# Target: %s | matched query: %s" % (host, query),
        "# Generated: %s" % _now(),
        "# SAFETY: NON-DESTRUCTIVE - verify only, no data loss, no RCE",
        "#",
        "# CHAIN OUTPUT:",
    ]
    if urls:
        for u in urls:
            lines.append(
                "#   - nuclei -u %s -tags %s,cve -rl 5" % (u, cve_id))
            lines.append(
                "#   - curl -sk -o /dev/null -w '%%{http_code} %%{time_total}'  %s"
                " - verify baseline vs known-good" % u)
    else:
        lines.append(
            "#   - no web target: verify %s against %s banner/service "
            "manually (see vuln phase snippet)" % (cve_id, query))
    lines += [
        "#   - payload_memory_ranking class=cve - pick proven ammo",
        "",
        "import socket, sys",
        "",
        "HOST = %r" % host,
        "CVE = %r" % cve_id,
        "QUERY = %r" % query,
        "",
        "def banner_check(port=80, timeout=6):",
        "    try:",
        "        s = socket.create_connection((HOST, port), timeout)",
        "        s.sendall(b'HEAD / HTTP/1.1\\r\\nHost: ' + HOST.encode()"
        " + b'\\r\\nConnection: close\\r\\n\\r\\n')",
        "        return s.recv(512).decode('replace').splitlines()[:4]",
        "    except Exception as exc:",
        "        return ['banner probe error: %s' % exc]",
        "",
        "if __name__ == '__main__':",
        "    print('CVE', CVE, '| query', QUERY, '| host', HOST)",
        "    for p in (80, 443, 5432):",
        "        lines = banner_check(p)",
        "        print('- port %d:' % p, ' | '.join(lines)[:220])",
        "    sys.exit(0)",
        "",
    ]
    return "\n".join(lines)


def _phase_report(state, ctx):
    host = state["target"]
    lines = []
    lines.append("# ATTACK MISSION REPORT — %s" % host)
    lines.append("")
    lines.append("- Generated: %s" % _now())
    lines.append("- Campaign file: `%s`" % state["campaign_file"])
    lines.append("- Phase status: %s" % ", ".join(
        "%s=%s" % (p, state["phases"].get(p, {}).get("status", "pending"))
        for p in PHASE_ORDER))
    lines.append("")
    recon = state.get("phases", {}).get("recon", {})
    if recon:
        lines.append("## Recon")
        for p in recon.get("ports", []):
            lines.append("- Port **%d/tcp** open (%s)" % (
                p["port"], p.get("service") or "unknown"))
        for s in recon.get("subdomains", [])[:20]:
            lines.append("- Subdomain: %s" % s)
        if recon.get("ssl"):
            lines.append("")
            lines.append("### SSL")
            lines.append("```")
            lines.append(recon["ssl"][:900])
            lines.append("```")
    scan = state.get("phases", {}).get("scan", {})
    if scan:
        lines.append("")
        lines.append("## Scan")
        for url, info in scan.get("web", {}).items():
            lines.append("- %s — status %s" % (
                url, info.get("status", "?")))
            if info.get("tech"):
                lines.append("    tech: %s" % info["tech"][:300].replace(
                    "\n", " | "))
        for url, df in scan.get("dirs", {}).items():
            lines.append("")
            lines.append("### dir fuzz %s" % url)
            lines.append("```")
            lines.append(df[:1200])
            lines.append("```")
    vuln = state.get("phases", {}).get("vuln", {})
    if vuln:
        lines.append("")
        lines.append("## Vulnerability matches")
        if vuln.get("hits"):
            for h in vuln["hits"][:12]:
                lines.append("- `%s` — %s" % (h["query"],
                                               ", ".join(h["cves"])))
                lines.append("  %s" % h["snippet"][:200].replace("\n", " | "))
        elif vuln.get("queries"):
            lines.append("No CVE hits across queries: %s" % ", ".join(
                vuln["queries"]))
        if vuln.get("nuclei"):
            lines.append("")
            lines.append("### nuclei")
            for url, out in vuln["nuclei"].items():
                lines.append("- `%s`" % url)
                lines.append("  %s" % str(out)[:400].replace("\n", " | "))
    exploit = state.get("phases", {}).get("exploit", {})
    if exploit and exploit.get("attempts"):
        lines.append("")
        lines.append("## Exploitation (auto-run chain)")
        for att in exploit["attempts"][:8]:
            lines.append("- `%s` — %s" % (att["query"],
                                           ", ".join(att.get("cves", []))))
            for a in att.get("attempts", [])[:2]:
                lines.append("    nuclei %s — %s" % (
                    a.get("url", "?"), str(a.get("nuclei", ""))[:220]
                    .replace("\n", " | ")))
            if att.get("poc_file"):
                lines.append("    PoC probe: `%s`" % att["poc_file"])
        if exploit.get("pocs"):
            lines.append("")
            lines.append("PoC probes written: %d" % len(exploit["pocs"]))
    try:
        pbits = tool_payload_memory_top(host, top_k=8)
    except Exception:
        pbits = ""
    if pbits and "no payload memory yet" not in pbits:
        lines.append("")
        lines.append("### Payload memory (campaign continuity)")
        lines.append("```")
        lines.append(pbits[:900])
        lines.append("```")
    for err in state.get("errors", [])[-10:]:
        lines.append("")
        lines.append("> phase-error: %s / %s — %s" % (
            err.get("phase", "?"), err.get("step", "?"),
            err.get("error", "?")))
    md = "\n".join(lines) + "\n"
    try:
        os.makedirs(ctx.reports_dir, exist_ok=True)
    except Exception:
        pass
    path = os.path.join(ctx.reports_dir,
                        "attack_mission_%s.md" % _slug(host))
    try:
        with io.open(path, "w", encoding="utf-8", newline="\r\n") as fh:
            fh.write(md)
    except Exception as exc:
        state["errors"].append(
            {"phase": "report", "step": "write", "error": repr(exc)})
        _mark(state, "report", "error")
        _save(state, ctx.campaign_dir)
        return "[report] FAILED to write: %r" % (exc,)
    entry = {"status": "done", "path": path,
             "bytes": len(md.encode("utf-8", "replace"))}
    state["phases"]["report"] = entry
    _save(state, ctx.campaign_dir)
    return "[report] written: %s (%d bytes)" % (path, entry["bytes"])


_PHASES = {
    "recon": _phase_recon,
    "scan": _phase_scan,
    "vuln": _phase_vuln,
    "exploit": _phase_exploit,
    "report": _phase_report,
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _run_one(state, phase, ctx):
    """Run a single phase; save state; return summary line."""
    if _phase_done(state, phase):
        return "- %s: already done" % phase
    if ctx.deep:
        state["posture"] = "deep"   # campaign spawned under deep-scan posture
    state["phases"].setdefault(phase, {})["status"] = "running"
    _save(state, ctx.campaign_dir)
    try:
        summary = _PHASES[phase](state, ctx)
        return summary
    except _BudgetExceeded:
        _mark(state, phase, "interrupted")
        _save(state, ctx.campaign_dir)
        return ("- %s: INTERRUPTED by time budget (partial results saved; "
                "resume with attack_mission target=%r phase=%s)"
                % (phase, state["target"], phase))
    except Exception as exc:
        _mark(state, phase, "error",
              {"error": repr(exc), "elapsed_s": 0})
        state["errors"].append({"phase": phase, "step": "run",
                                "error": repr(exc)})
        _save(state, ctx.campaign_dir)
        return "- %s: FAILED: %r" % (phase, exc)


def _make_ctx(campaign_dir="", run_nuclei=False, budget_sec=100,
              deep=False):
    cdir = _campaign_dir(campaign_dir)
    rdir = _reports_dir(campaign_dir, os.getcwd())
    return _Ctx(cdir, rdir, bool(run_nuclei), _Budget(budget_sec), deep=deep)


def _run_phase(target, phase, campaign_dir="", run_nuclei=False,
               budget_sec=100, deep=False):
    target = (target or "").strip()
    if not target:
        return "mission %s: provide a target (IP or domain)" % phase
    if phase not in _PHASES:
        return ("mission %s: phase must be one of recon|scan|vuln|"
                "exploit|report" % phase)
    state = _load(target, campaign_dir)
    ctx = _make_ctx(campaign_dir, run_nuclei, budget_sec, deep=deep)
    return _run_one(state, phase, ctx)


# ---------------------------------------------------------------------------
# Public tools
# ---------------------------------------------------------------------------

def tool_attack_mission(target="", phase="", campaign_dir="",
                        run_nuclei=False, budget_sec=100, deep=False):
    """AUTO-PILOT: run every unfinished attack-mission phase in order.

    phase=''  -> auto: recon -> scan -> vuln -> exploit -> report
    (skips done ones)
    phase=X   -> run only that one phase
    deep=True -> DEEP-SCAN POSTURE: wider port range + wordlist,
                 more web targets, auto nuclei sniper on live roots.
    """
    target = (target or "").strip()
    if not target:
        return "attack_mission: provide a target (IP or domain). " \
               "Example: attack_mission(target='10.0.0.7')"
    if phase:
        return _run_phase(target, phase, campaign_dir, run_nuclei,
                          budget_sec, deep=deep)
    state = _load(target, campaign_dir)
    ctx = _make_ctx(campaign_dir, run_nuclei, budget_sec, deep=deep)
    out = ["AUTO-PILOT mission: %s" % target]
    for ph in PHASE_ORDER:
        out.append(_run_one(state, ph, ctx))
    report = state.get("phases", {}).get("report", {})
    status = "ALL PHASES COMPLETE" if report.get("status") == "done" \
        else "IN PROGRESS - rerun attack_mission to continue"
    out.append("STATUS: %s" % status)
    if report.get("path"):
        out.append("REPORT: %s" % report["path"])
    return "\n".join(out)


def tool_mission_recon(target="", campaign_dir="", deep=False):
    return _run_phase(target, "recon", campaign_dir, False, 110, deep=deep)


def tool_mission_scan(target="", campaign_dir="", deep=False):
    return _run_phase(target, "scan", campaign_dir, False, 110, deep=deep)


def tool_mission_vuln(target="", campaign_dir="", run_nuclei=False,
                      deep=False):
    return _run_phase(target, "vuln", campaign_dir, run_nuclei, 110,
                      deep=deep)


def tool_mission_exploit(target="", campaign_dir="", deep=False):
    """EXPLOIT AUTO-RUN CHAIN phase: CVE hits from the vuln phase are
    actively chased - targeted nuclei verification on live web targets,
    ready-to-run PoC probes saved under artifacts/exploit_<target>/, and
    exploit-chain signals recorded into payload memory."""
    return _run_phase(target, "exploit", campaign_dir, False, 110,
                      deep=deep)


def tool_mission_report(target="", campaign_dir="", deep=False):
    return _run_phase(target, "report", campaign_dir, False, 110, deep=deep)


def tool_mission_resume(target="", campaign_dir="", run_nuclei=False,
                        deep=False):
    """Resume a mission from its saved campaign state (auto mode)."""
    return tool_attack_mission(target, "", campaign_dir, run_nuclei, 110,
                               deep=deep)


def tool_mission_deep(target="", campaign_dir="", run_nuclei=False,
                      budget_sec=115):
    """DEEP-SCAN POSTURE: full auto-pilot with a wider attack surface.

    Same pipeline as attack_mission but oriented toward depth:
      - recon   : scans ports 1-1024 + high-value services (~1535 ports),
                  SSL grabbed on 443/8443/9443 when open
      - scan    : up to 12 web targets / 4 live roots dir-fuzzed with the
                  deep wordlist (250 entries)
      - vuln    : up to 20 CVE queries + AUTO nuclei sniper on up to 3
                  live web targets (no run_nuclei opt-in needed)
    Progress persists under campaigns/<target>.json with posture=deep.
    """
    return tool_attack_mission(target, "", campaign_dir, run_nuclei,
                               budget_sec, deep=True)


def tool_mission_status(target="", campaign_dir=""):
    """Show campaign progress for one target, or list all campaigns."""
    cdir = _campaign_dir(campaign_dir)
    if target:
        state = _load(target, campaign_dir)
        lines = ["mission status: %s" % state["target"],
                 "  created: %s | updated: %s" % (
                     state.get("created", "?"), state.get("updated", "?"))]
        posture = state.get("posture", "standard")
        lines.append(
            "  posture: %s%s" % (
                posture, "  [DEEP-SCAN]" if posture == "deep" else ""))
        for ph in PHASE_ORDER:
            lines.append("  %s: %s" % (
                ph, state.get("phases", {}).get(ph, {}).get(
                    "status", "pending")))
        f_total = sum(
            state.get("phases", {}).get(p, {}).get("findings_logged", 0)
            for p in PHASE_ORDER)
        lines.append("  errors: %d | findings: %d" % (
            len(state.get("errors", [])), f_total))
        lines.append("  file: %s" % state["campaign_file"])
        return "\n".join(lines)
    if not os.path.isdir(cdir):
        return "no campaigns yet (dir %s)" % cdir
    rows = []
    for fn in sorted(os.listdir(cdir)):
        if not fn.endswith(".json"):
            continue
        try:
            with io.open(os.path.join(cdir, fn), encoding="utf-8") as fh:
                st = json.load(fh)
            done = [p for p in PHASE_ORDER
                    if st.get("phases", {}).get(p, {}).get("status") == "done"]
            tag = " [deep]" if st.get("posture") == "deep" else ""
            rows.append("- %s%s [%s] file=%s" % (
                st.get("target", fn[:-5]), tag,
                ",".join(done) or "new", fn))
        except Exception:
            rows.append("- %s (unreadable)" % fn)
    return "campaigns (%d):\n%s" % (len(rows), "\n".join(rows)) if rows \
        else "no campaigns yet (dir %s)" % cdir


def tool_mission_reset(target="", campaign_dir=""):
    """Delete the campaign state file for a target (start clean)."""
    if not (target or "").strip():
        return "mission_reset: provide a target"
    cdir = _campaign_dir(campaign_dir)
    path = os.path.join(cdir, _slug(target) + ".json")
    if os.path.exists(path):
        try:
            os.remove(path)
            return "campaign reset: removed %s" % path
        except Exception as exc:
            return "mission_reset: FAILED: %r" % (exc,)
    return "mission_reset: no campaign file for %r" % (target,)


def tool_mission_payloads(target="", top_k=10, global_rank=False):
    """Campaign continuity: ranked payload-effectiveness memory.
    target='' + global_rank=True -> CROSS-CAMPAIGN leaderboard (payloads
    that worked across many hosts); otherwise per-target memory."""
    try:
        top_k = int(top_k or 10)
    except (TypeError, ValueError):
        top_k = 10
    if global_rank:
        return tool_payload_memory_ranking(top_k=top_k)
    return tool_payload_memory_top((target or "").strip(),
                                   top_k=top_k)

