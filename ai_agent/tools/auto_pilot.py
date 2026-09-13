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
from ..memory.payload_fusion import (
    PayloadMemory as FusedPayloadMemory,
)

PHASE_ORDER = ("recon", "scan", "vuln", "exploit", "report")

WEB_PORTS = frozenset({
    80, 443, 8000, 8080, 8443, 8888, 9000, 9090, 9443, 3000, 5000,
    7000, 7080, 8020, 8081, 8088, 8880,
})

# PAYLOAD FUSION AUTO-INJECT (Feature B, v10.4): the cross-campaign fused
# payload memory is injected into every NEW campaign so proven ammo fires
# on day one instead of waiting for a fresh vuln-phase CVE hit.
FUSED_SOURCE = "payload_fusion"
FUSED_INJECT_TOP_K = 12
FUSED_MATCH_TOP_K = 6

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


def _control_path(campaign_dir=""):
    """WAR-ROOM LIVE CONTROL: shared control-state file so the WebUI
    (start/pause/kill buttons) and the runner speak the same source."""
    return os.path.join(_campaign_dir(campaign_dir), ".control.json")


def _control_read(target, campaign_dir=""):
    """Return {"status": running|paused|killed, "set_at": ...} or {}."""
    try:
        with io.open(_control_path(campaign_dir), "r", encoding="utf-8") as fh:
            d = json.load(fh)
        return d.get(target, {}) or {}
    except Exception:
        return {}


def _control_set(target, action, campaign_dir=""):
    """Persist a war-room control action for one campaign target.
    Accepts UI verbs (start|pause|kill) or statuses (running|paused|
    killed); always stores the canonical status vocabulary."""
    action = {"start": "running", "pause": "paused", "kill": "killed"} \
        .get(str(action).strip().lower(), str(action).strip().lower())
    p = _control_path(campaign_dir)
    d = {}
    try:
        with io.open(p, "r", encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception:
        pass
    d[target] = {"status": action, "set_at": _now()}
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with io.open(p, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2)
    except Exception:
        pass
    return d[target]


def _control_gate(target, campaign_dir=""):
    """Block until RUNNING, then return True ; return False when KILLED.
    Missing control state = RUNNING (backwards compatible)."""
    while True:
        st = str((_control_read(target, campaign_dir) or {})
                 .get("status", "running")).strip().lower()
        if st in ("kill", "killed"):
            return False
        if st not in ("pause", "paused"):
            return True
        time.sleep(2.0)


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
# Payload Fusion auto-inject (Feature B)
# ---------------------------------------------------------------------------

_FUSION_MEMORY = None


def _fused_memory():
    """Lazy singleton over the fused payload store (monkeypatchable)."""
    global _FUSION_MEMORY
    if _FUSION_MEMORY is None:
        _FUSION_MEMORY = FusedPayloadMemory()
    return _FUSION_MEMORY


def _inject_fused_payloads(state, campaign_dir="", top_k=FUSED_INJECT_TOP_K):
    """Exact-once auto-inject: on a campaign WITHOUT a cache yet, merge the
    top fused payload rows into state['payload_cache'].  Never clobbers an
    existing cache, and leaves the state untouched when memory has no fused
    rows so a later run (after more campaigns fuse evidence) can inject."""
    try:
        if state.get("payload_cache") is not None:
            return None
        payloads = _fused_memory().fuse(min_hits=1)[:top_k]
        if not payloads:
            return None
        state["payload_cache"] = {
            "injected_at": _now(),
            "source": FUSED_SOURCE,
            "count": len(payloads),
            "payloads": payloads,
        }
        _save(state, campaign_dir)
        return state["payload_cache"]
    except Exception:
        return None


def _fused_tags(rec):
    """nuclei:poc|rce|sqli  ->  'poc,rce,sqli' (nuclei -tags style)."""
    tech = str(rec.get("technique") or "")
    if not tech.startswith("nuclei:"):
        return ""
    return ",".join(t for t in tech[len("nuclei:"):].split("|") if t)


def _match_fused(payload_cache, open_ports, top_k=FUSED_MATCH_TOP_K):
    """Rank fused memory rows against the campaign's OPEN ports:
      rank 2 - recorded numeric port is open (service/port pair proven)
      rank 1 - only the svc_key '/<port>' suffix matches the open port
    Returns shallow copies sorted by (rank desc, score desc), capped."""
    if not payload_cache:
        return []
    ports = set()
    for p in open_ports or []:
        try:
            ports.add(int(p))
        except (TypeError, ValueError):
            continue
    ranked = []
    for rec in (payload_cache.get("payloads") or []):
        rank = 0
        try:
            port = int(rec.get("port") or 0)
            if port in ports:
                rank = 2
        except (TypeError, ValueError):
            port = 0
        if not rank:
            m = re.search(r"/(\d+)$", str(rec.get("svc_key") or ""))
            if m and int(m.group(1)) in ports:
                rank = 1
        if not rank:
            continue
        row = dict(rec)
        row["_rank"] = rank
        ranked.append(row)
    ranked.sort(key=lambda r: (-r["_rank"], -float(r.get("score") or 0.0)))
    return ranked[:top_k]


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
    Feature B: fused cross-campaign ammo auto-injected at mission start is
    matched against this campaign's open ports and fired with its proven
    nuclei tags. Bounded by the mission budget; nothing is hidden."""
    started = time.time()
    host = state["target"]
    vuln = state.get("phases", {}).get("vuln", {})
    hits = vuln.get("hits", []) or []
    web_targets = list(state.get("phases", {}).get("scan", {})
                       .get("web", {}) or {})
    entry = {"status": "done", "attempts": [], "pocs": []}
    open_ports = [p.get("port")
                  for p in state.get("phases", {}).get("recon", {})
                  .get("ports", []) if p.get("port")]
    fused_matched = _match_fused(state.get("payload_cache") or {},
                                 open_ports)
    if not hits and not fused_matched:
        entry["note"] = ("no CVE hits from vuln phase and no fused ammo "
                          "matched - chain idle")
        state["phases"]["exploit"] = entry
        _save(state, ctx.campaign_dir)
        return "[exploit] idle - no CVE hits, no fused ammo matched"
    if fused_matched:
        # FEATURE B: fire the auto-injected fused ammo against ONE live web
        # target per matched record, using the proven nuclei tags from the
        # fused technique (e.g. nuclei:poc|rce|sqli). Budget-bounded.
        applied = []
        for rec in fused_matched:
            tags = _fused_tags(rec)
            fire = {"svc_key": rec.get("svc_key", "?"),
                    "port": rec.get("port"),
                    "score": rec.get("score", 0.0),
                    "hits": rec.get("hits", 0),
                    "technique": rec.get("technique", ""),
                    "cves": (rec.get("cves") or [])[:3],
                    "tags": tags,
                    "attempts": []}
            if not tags or not web_targets:
                fire["note"] = ("no nuclei tags in technique" if not tags
                                else "matched but no live web target")
                applied.append(fire)
                continue
            ctx.budget.check(20.0)   # raises _BudgetExceeded when spent
            url = web_targets[0]
            res = ""
            try:
                res = tool_nuclei_scan(url, tags=tags)
            except Exception as exc:
                res = "FAILED: %r" % (exc,)
            fire["attempts"].append(
                {"url": url, "nuclei": _trunc(res, 700)})
            applied.append(fire)
            try:
                tool_payload_memory_record(
                    host, payload="fused:%s:%s" % (rec.get("svc_key", "?"),
                                                   tags),
                    signal="fused_auto_inject", vuln_class="fused")
            except Exception:
                pass
        entry["fused_applied"] = applied
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
            ctx.budget.check(30.0)   # raises _BudgetExceeded when spent
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
    fused_n = len(entry.get("fused_applied", []))
    fused_fired = sum(len(a.get("attempts", []))
                      for a in entry.get("fused_applied", []))
    return ("[exploit] chained: %d CVE hit(s) | %d nuclei attempt(s) | "
            "%d PoC probe(s) | fused ammo: %d matched / %d fired | "
            "findings: %d" % (
                len(entry["attempts"]),
                sum(len(a.get("attempts", []))
                    for a in entry["attempts"]),
                len(entry["pocs"]), fused_n, fused_fired, findings))


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


def _html_escape(text):
    """Minimal HTML escaping for report fields."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _write_html_report(state, ctx, md_markdown=""):
    """Feature C: client-ready dark-themed self-contained HTML pentest report.

    Generated alongside the markdown report at campaign end.  Inline CSS only
    (no CDN) so the file opens offline and prints clean.  Sections mirror the
    markdown: phase chips, recon ports, scan targets, CVE matches, exploit
    attempts, fused payload intel + applied ammo, errors.
    """
    host = _html_escape(state.get("target", "?"))
    gen = _html_escape(_now())
    posture = _html_escape(state.get("posture", "standard"))
    phases = state.get("phases", {})
    chips = "".join(
        '<span class="chip %s">%s:%s</span>' % (
            "ok" if phases.get(p, {}).get("status") == "done" else
            ("err" if phases.get(p, {}).get("status") == "error" else "run"),
            p, _html_escape(phases.get(p, {}).get("status", "pending")))
        for p in PHASE_ORDER)
    recon = phases.get("recon", {})
    port_rows = "".join(
        "<tr><td>%d</td><td>%s</td></tr>" % (
            int(p.get("port") or 0),
            _html_escape(p.get("service") or "unknown"))
        for p in recon.get("ports", []))
    scan = phases.get("scan", {})
    scan_rows = "".join(
        "<tr><td>%s</td><td>%s</td></tr>" % (
            _html_escape(url), _html_escape(info.get("status", "?")))
        for url, info in (scan.get("web") or {}).items())
    vuln = phases.get("vuln", {})
    cve_rows = ""
    for h in (vuln.get("hits") or [])[:15]:
        cve_rows += "<tr><td>%s</td><td>%s</td></tr>" % (
            _html_escape(h.get("query", "?")),
            _html_escape(", ".join(h.get("cves") or [])))
    exploit = phases.get("exploit", {})
    att_rows = ""
    for att in (exploit.get("attempts") or [])[:8]:
        att_rows += "<tr><td>%s</td><td>%s</td></tr>" % (
            _html_escape(att.get("query", "?")),
            _html_escape(", ".join(att.get("cves") or [])))
    pc = state.get("payload_cache") or {}
    fused_rows = "".join(
        "<tr><td>%s</td><td>%.3f</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _html_escape(r.get("svc_key", "?")),
            float(r.get("score") or 0.0),
            r.get("hits", 0),
            len(r.get("campaigns") or []),
            _html_escape(r.get("technique") or "?"),
            _html_escape(", ".join(r.get("cves") or []) or "-"))
        for r in (pc.get("payloads") or [])[:10])
    fused_app = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _html_escape(fa.get("svc_key", "?")),
            _html_escape(fa.get("tags") or "-"),
            _html_escape((fa.get("attempts") or [{}])[0]
                         .get("nuclei", fa.get("note") or "not fired"))[:160])
        for fa in (exploit.get("fused_applied") or [])[:8])
    errs = "".join(
        "<li><b>%s/%s</b>: %s</li>" % (
            _html_escape(e.get("phase", "?")), _html_escape(e.get("step", "?")),
            _html_escape(e.get("error", "?")))
        for e in (state.get("errors") or [])[-10:])
    page = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Pentest Report — %s</title>
<style>
body{background:#0b0f1a;color:#dbe4ff;font-family:Consolas,'Segoe UI',monospace;margin:32px;}
h1{font-size:26px;color:#7df9ff;}h2{color:#ffd479;border-bottom:1px solid #2a355a;padding-bottom:4px;}
.chip{display:inline-block;margin:4px;padding:3px 10px;border-radius:12px;font-size:12px;}
.chip.ok{background:#0f3d24;color:#7dffa8;}.chip.run{background:#2a355a;color:#ffd479;}.chip.err{background:#4a1220;color:#ff8080;}
table{border-collapse:collapse;width:100%%;margin:10px 0;}th,td{border:1px solid #2a355a;padding:6px 10px;text-align:left;font-size:13px;}
th{background:#141c30;color:#7df9ff;}tr:nth-child(even){background:#10172a;}
.meta{color:#8fa3c8;font-size:13px;}code{background:#141c30;padding:1px 5px;border-radius:4px;}
@media print{body{background:#fff;color:#000;}}@media print{table{border-color:#999;}th{background:#eee;}}
</style></head><body>
<h1>ATTACK MISSION REPORT — %s</h1>
<p class="meta">Generated: %s &nbsp;|&nbsp; Posture: <b>%s</b> &nbsp;|&nbsp; Fused ammo rows: %d</p>
<div>%s</div>
<h2>Recon — open ports</h2><table><tr><th>Port</th><th>Service</th></tr>%s</table>
<h2>Scan — web targets</h2><table><tr><th>URL</th><th>Status</th></tr>%s</table>
<h2>Vulnerability matches (CVE)</h2><table><tr><th>Query</th><th>CVEs</th></tr>%s</table>
<h2>Exploitation — auto-run chain</h2><table><tr><th>Query</th><th>CVEs</th></tr>%s</table>
<h2>Fused payload intel (auto-injected)</h2>
<p class="meta">source: %s | injected_at: %s</p>
<table><tr><th>svc_key</th><th>score</th><th>hits</th><th>campaigns</th><th>technique</th><th>CVEs</th></tr>%s</table>
<h2>Fused ammo applied (matched open ports)</h2>
<table><tr><th>svc_key</th><th>tags</th><th>outcome</th></tr>%s</table>
<h2>Phase errors</h2><ul>%s</ul>
</body></html>
""" % (
        host, host, gen, posture, len(pc.get("payloads") or []), chips,
        port_rows or "<tr><td colspan=2>none</td></tr>",
        scan_rows or "<tr><td colspan=2>none</td></tr>",
        cve_rows or "<tr><td colspan=2>no CVE hits</td></tr>",
        att_rows or "<tr><td colspan=2>no exploits</td></tr>",
        _html_escape(pc.get("source") or "?"),
        _html_escape(pc.get("injected_at") or "?"),
        fused_rows or "<tr><td colspan=5>no fused rows</td></tr>",
        fused_app or "<tr><td colspan=3>no fused ammo fired</td></tr>",
        errs or "<li>none</li>")
    try:
        os.makedirs(ctx.reports_dir, exist_ok=True)
        html_path = os.path.join(ctx.reports_dir,
                                 "attack_mission_%s.html" % _slug(host))
        with io.open(html_path, "w", encoding="utf-8") as fh:
            fh.write(page)
        return html_path
    except Exception:
        return ""


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
    payload_cache = state.get("payload_cache") or {}
    fused_rows = payload_cache.get("payloads") or []
    if fused_rows:
        lines.append("")
        lines.append("## Fused payload intel (auto-injected)")
        lines.append("_source: %s | injected_at: %s | %d row(s)_" % (
            payload_cache.get("source", "?"),
            payload_cache.get("injected_at", "?"), len(fused_rows)))
        for rec in fused_rows[:8]:
            lines.append("- `%s` — score %.3f, %s hit(s) across %d "
                         "campaign(s), technique `%s`, cves: %s" % (
                             rec.get("svc_key", "?"),
                             float(rec.get("score") or 0.0),
                             rec.get("hits", 0),
                             len(rec.get("campaigns") or []),
                             rec.get("technique") or "?",
                             ", ".join((rec.get("cves") or [])[:4])
                             or "none"))
    fused_applied = exploit.get("fused_applied") or []
    if fused_applied:
        lines.append("")
        lines.append("### Fused ammo applied (matched open ports)")
        for fa in fused_applied[:6]:
            tagbit = "[%s]" % fa["tags"] if fa.get("tags") else ""
            att = ""
            if fa.get("attempts"):
                a0 = fa["attempts"][0]
                att = " — nuclei %s — %s" % (
                    a0.get("url", "?"),
                    str(a0.get("nuclei", ""))[:160].replace("\n", " | "))
            tail = att or (" — %s" % fa.get("note") if fa.get("note")
                           else " — not fired")
            lines.append("- `%s` (score %.3f, %s hit(s), %s%s)%s" % (
                fa.get("svc_key", "?"),
                float(fa.get("score") or 0.0),
                fa.get("hits", 0),
                fa.get("technique") or "technique?",
                " " + tagbit if tagbit else "",
                tail))
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
    html_path = ""
    try:
        html_path = _write_html_report(state, ctx, md)
    except Exception as exc:  # HTML is a bonus; markdown report stays valid
        state["errors"].append({"phase": "report", "step": "write_html",
                                "error": repr(exc)})
    if html_path:
        entry["html"] = html_path   # Feature C: client-ready HTML report
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
    _inject_fused_payloads(state, campaign_dir)  # silent hook (Feature B)
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
    fused = _inject_fused_payloads(state, campaign_dir)
    if fused:
        out.append("PAYLOAD FUSION: %d cross-campaign fused payload(s) "
                   "auto-injected" % (fused.get("count", 0) or 0))
    for ph in PHASE_ORDER:
        if not _control_gate(target, campaign_dir):
            out.append("WAR-ROOM: campaign KILLED by operator - "
                       "remaining phases aborted at %s" % ph)
            _mark(state, ph, "killed")
            _save(state, campaign_dir)
            break
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

