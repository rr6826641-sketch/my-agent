"""Engagement scope enforcement.

The agent records the user-declared targets (domains, IPs, CIDRs, URLs)
in scope.json and can verify hosts/URLs against that list before running
recon or exploitation. This mirrors the authorization boundaries of a
real engagement: only user-declared targets may be touched.

Authorized use only - targets must be in your engagement scope.
"""

import datetime
import ipaddress
import json
import os
import threading

SCOPE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "scope.json",
)

_lock = threading.Lock()


def _load():
    try:
        with open(SCOPE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("targets", [])
    data.setdefault("note", "")
    return data


def _save(data):
    try:
        os.makedirs(os.path.dirname(SCOPE_PATH) or ".", exist_ok=True)
        with open(SCOPE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as exc:
        return "save failed: %s" % exc
    return ""


def _normalize(target):
    t = (target or "").strip().lower().rstrip("/")
    t = t.replace("http://", "").replace("https://", "")
    return t


def tool_set_scope(targets="", note=""):
    """Set the engagement scope: comma-separated domains/IPs/CIDRs/URLs.

    Only these targets may be scanned or tested. Call this at the start
    of an engagement and check_scope before touching a new host.
    """
    targets = (targets or "").strip()
    if not targets:
        return ("set_scope: provide comma-separated targets "
                "(domains, IPs, CIDRs or URLs)")
    parsed = [_normalize(t) for t in targets.split(",") if t.strip()]
    if not parsed:
        return "set_scope: no valid targets found"
    with _lock:
        data = _load()
        data["targets"] = parsed
        data["note"] = (note or "").strip()
        data["updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        err = _save(data)
    return err or ("Scope set (%d target(s)):\n  %s"
                   % (len(parsed), "\n  ".join("- " + p for p in parsed)))


def tool_show_scope():
    """Show the current engagement scope."""
    data = _load()
    if not data.get("targets"):
        return ("(scope is empty - use set_scope to define authorized "
                "targets before scanning)")
    lines = ["Current scope (%d target(s)):" % len(data["targets"])]
    for t in data["targets"]:
        lines.append("  - " + t)
    if data.get("note"):
        lines.append("")
        lines.append("Note: " + data["note"])
    return "\n".join(lines)


def tool_check_scope(host=""):
    """Check whether a host/URL is inside the declared engagement scope.

    Returns a clear ALLOWED / BLOCKED verdict plus the matching rule.
    """
    host = (host or "").strip()
    if not host:
        return "check_scope: provide a host, IP or URL to check"
    h = _normalize(host)
    # strip port/path for IP/domain matching
    h_host = h.split("/")[0].split(":")[0]
    try:
        ip = ipaddress.ip_address(h_host)
        is_ip = True
    except ValueError:
        ip = None
        is_ip = False

    data = _load()
    targets = data.get("targets") or []
    if not targets:
        return ("BLOCKED: scope is empty - run set_scope with the "
                "authorized targets first (then re-check)")

    for rule in targets:
        r = rule.split("/")[0].split(":")[0]
        # exact IP or CIDR containment
        if is_ip:
            if "/" in rule:
                try:
                    if ip in ipaddress.ip_network(rule, strict=False):
                        return "ALLOWED: %s is inside scope CIDR %s" % (host, rule)
                except ValueError:
                    pass
            else:
                try:
                    if ip == ipaddress.ip_address(r):
                        return "ALLOWED: %s exactly matches scope entry %s" % (host, rule)
                except ValueError:
                    pass  # rule is a domain name; skip for IP checks
        # domain rules
        if r and not is_ip:
            hh = h_host
            if hh == r or hh.endswith("." + r) or r.startswith("*."):
                base = r[2:] if r.startswith("*.") else r
                if hh == base or hh.endswith("." + base):
                    return "ALLOWED: %s matches scope rule %s" % (host, rule)
    return ("BLOCKED: %s is NOT in the declared scope. Only scan targets "
            "listed by set_scope." % host)
