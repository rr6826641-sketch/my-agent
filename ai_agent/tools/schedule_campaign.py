# -*- coding: utf-8 -*-
"""
Scheduled Campaigns (bundle #6) - autonomous autopilot layer.

tools:
  schedule_campaign  - durable job store: add/remove/list/status campaigns
                       (target + schedule + action chain + notify channels)
  campaign_run_now   - execute a job's chain immediately (or ad-hoc one-shot)
  campaign_daemon    - start/stop/status the background autopilot loop

Schedule formats ("schedule" arg):
  - "daily 03:00" | "03:00"   run every day at 03:00
  - "every 30m" | "every 2h"  interval loop (min 30s)
  - "0 3 * * *"               cron-lite (minute hour dom month dow, 7-day week)

Chain ("chain" arg): JSON list of tool calls, e.g.
    [{"tool": "port_scan", "args": {"target": "10.0.0.5"}},
     {"tool": "notify_findings", "args": {"channel": "telegram"}}]
  "auto" => default chain: http_request liveness -> port_scan ->
             notify_findings (first configured notify channel).

Notify ("notify" arg): comma list telegram,discord,webhook (bundle #1 keys).

Store: scheduled_campaigns.json (gitignored; env SCHED_STORE_PATH override).
Autopilot: scheduled_campaign_runner.py (repo root) - run due jobs loop;
  can be spawned detached via campaign_daemon or added to Windows Task
  Scheduler (schtasks) for OS-level cron.
"""
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _store_path():
    return os.environ.get("SCHED_STORE_PATH") or os.path.join(_BASE_DIR, "scheduled_campaigns.json")


def _daemon_pid_path():
    return os.path.join(_BASE_DIR, ".campaign_daemon.pid")


def _daemon_log_path():
    return os.path.join(_BASE_DIR, "campaign_daemon.log")


def _load_jobs():
    try:
        with open(_store_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_jobs(jobs):
    p = _store_path()
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(jobs, f, ensure_ascii=False, indent=1)
    os.replace(tmp, p)


# --- schedule parsing ---------------------------------------------------
def _parse_schedule(spec):
    """-> {'type': 'daily'|'interval'|'cron', ...} or raise ValueError."""
    s = (spec or "").strip().lower()
    if not s:
        raise ValueError("schedule required (e.g. 'daily 03:00', 'every 2h', '0 3 * * *')")
    m = re.match(r"^daily[:\s]+(\d{1,2}):(\d{2})$", s)
    if m:
        return {"type": "daily", "hour": int(m.group(1)) % 24, "minute": int(m.group(2)) % 60}
    m = re.match(r"^(\d{1,2}):(\d{2})$", s)
    if m:
        return {"type": "daily", "hour": int(m.group(1)) % 24, "minute": int(m.group(2)) % 60}
    m = re.match(r"^every\s+(\d+(?:\.\d+)?)\s*(s|m|h)$", s)
    if m:
        secs = float(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]
        if secs < 30:
            raise ValueError("interval too short (min 30s)")
        return {"type": "interval", "seconds": int(secs)}
    parts = s.split()
    if len(parts) == 5 and all(
            p == "*" or p.isdigit()
            or (p.startswith("*/") and p[2:].isdigit()
                and 1 <= int(p[2:]) <= 59) for p in parts):
        return {"type": "cron", "minute": parts[0], "hour": parts[1],
                "dom": parts[2], "month": parts[3], "dow": parts[4]}
    raise ValueError("unrecognized schedule %r" % spec)


def _next_run(spec, now=None):
    now = now or datetime.now()
    if spec["type"] == "daily":
        nxt = now.replace(hour=spec["hour"], minute=spec["minute"],
                          second=0, microsecond=0)
        if nxt <= now:
            nxt += timedelta(days=1)
        return nxt
    if spec["type"] == "interval":
        return now + timedelta(seconds=spec["seconds"])
    def _vals(field: str, lo: int, hi: int):
        """'*' -> all, '*/N' -> stepped range (cron step syntax), else int."""
        if field == "*":
            return range(lo, hi)
        if field.startswith("*/"):
            return range(lo, hi, int(field[2:]))
        return [int(field)]

    dow = spec.get("dow", "*")
    h_vals = _vals(spec["hour"], 0, 24)
    m_vals = _vals(spec["minute"], 0, 60)
    for i in range(1, 9):
        cand = now + timedelta(days=i)
        if dow != "*" and cand.weekday() != (int(dow) % 7):
            continue
        for h in h_vals:
            for mn in m_vals:
                nxt = cand.replace(hour=h, minute=mn, second=0, microsecond=0)
                if nxt > now:
                    return nxt
    return now + timedelta(days=8)


# --- chain execution ----------------------------------------------------
def _build_registry():
    """tool name -> callable, freshly built (registry evolves over time)."""
    try:
        from ai_agent.tools import create_tools
        tools = create_tools(memory=None)
        return {t.name: t.func for t in tools}
    except Exception as e:
        return {}


def _parse_chain(chain, target, notify_channels):
    """chain arg -> list of {'tool':..., 'args': {...}}."""
    if not chain:
        host = target
        if host.startswith(("http://", "https://")):
            h = host.split("://", 1)[1].split("/", 1)[0]
            host = h.split(":", 1)[0]
        steps = [
            {"tool": "http_request", "args": {"url": target, "method": "GET"}},
            {"tool": "port_scan", "args": {"host": host}},
        ]
        if notify_channels:
            steps.append({"tool": "notify_findings",
                          "args": {"channel": notify_channels[0],
                                   "min_severity": "high", "limit": 10}})
        return steps
    if isinstance(chain, str):
        chain = chain.strip()
        if chain.lower() == "auto":
            return _parse_chain(None, target, notify_channels)
        try:
            parsed = json.loads(chain)
        except Exception as e:
            raise ValueError("chain must be JSON list of tool calls: %s" % e)
    else:
        parsed = chain
    if not isinstance(parsed, list) or not parsed:
        raise ValueError("chain must be a non-empty JSON list")
    steps = []
    for c in parsed:
        if not isinstance(c, dict) or not c.get("tool"):
            raise ValueError("each chain step needs 'tool' (+ optional 'args')")
        args = c.get("args") or {}
        if not isinstance(args, dict):
            raise ValueError("chain step 'args' must be an object")
        if "target" in args and not args.get("target"):
            args["target"] = target
        if "url" in args and not args.get("url"):
            args["url"] = target
        steps.append({"tool": c["tool"], "args": args})
    return steps


def _run_one_step(step, registry):
    """-> {'tool','ok','error','result_preview','ts'}"""
    fn = registry.get(step["tool"])
    began = datetime.now().isoformat(timespec="seconds")
    if not fn:
        return {"tool": step["tool"], "ok": False, "ts": began,
                "error": "tool %r not in registry" % step["tool"],
                "result_preview": ""}
    try:
        res = fn(**step["args"])
        if isinstance(res, (bytes, bytearray)):
            res = res.decode("utf-8", "replace")
        if not isinstance(res, str):
            res = json.dumps(res, ensure_ascii=False, default=str)
        preview = res if len(res) <= 1200 else res[:1200] + "...[truncated]"
        return {"tool": step["tool"], "ok": True, "ts": began,
                "error": "", "result_preview": preview}
    except Exception as e:
        return {"tool": step["tool"], "ok": False, "ts": began,
                "error": "%s: %s" % (type(e).__name__, e),
                "result_preview": ""}


def _notify(job, summary_lines, channels):
    """Send run summary over configured channels (bundle #1 notify tools)."""
    if not channels:
        return []
    text = "\n".join(summary_lines)[:3000]
    out = []
    for ch in channels:
        try:
            if ch == "telegram":
                from .notify import tool_notify_telegram
                out.append({"channel": ch, "ok": True,
                            "result": tool_notify_telegram(message=text)})
            elif ch == "discord":
                from .notify import tool_notify_discord
                out.append({"channel": ch, "ok": True,
                            "result": tool_notify_discord(message=text)})
            elif ch == "webhook":
                from .notify import tool_notify_webhook
                out.append({"channel": ch, "ok": True,
                            "result": tool_notify_webhook(url="", message=text)})
            else:
                out.append({"channel": ch, "ok": False, "error": "unknown channel"})
        except Exception as e:
            out.append({"channel": ch, "ok": False,
                        "error": "%s: %s" % (type(e).__name__, e)})
    return out


def _run_job(job, registry=None):
    """Execute one job object (full chain) -> result dict."""
    registry = registry or _build_registry()
    target = job.get("target", "")
    channels = job.get("notify", [])
    try:
        steps = _parse_chain(job.get("chain"), target, channels)
    except Exception as e:
        steps, plan_err = [], str(e)
    else:
        plan_err = ""
    ran_at = datetime.now().isoformat(timespec="seconds")
    step_results = []
    for s in steps:
        step_results.append(_run_one_step(s, registry))
    ok = all(sr["ok"] for sr in step_results) and not plan_err
    summary_lines = [
        "[Scheduler] job=%s target=%s status=%s at %s" % (
            job.get("name", "?"), target, "OK" if ok else "ERROR", ran_at),
    ]
    for sr in step_results:
        status = "OK" if sr["ok"] else "FAIL"
        pl = sr["result_preview"] if sr["ok"] else sr["error"]
        summary_lines.append("  %s %s -> %s" % (sr["tool"], status, pl[:200]))
    if plan_err:
        summary_lines.append("  chain-plan-error: " + plan_err)
    notify_out = _notify(job, summary_lines, channels) if channels else []
    return {"ran_at": ran_at, "status": "ok" if ok else "error",
            "chain_plan_error": plan_err,
            "steps": step_results, "summary": "\n".join(summary_lines),
            "notify": notify_out}


# --- public tools -------------------------------------------------------
def tool_schedule_campaign(action="list", name="", target="", schedule="",
                           chain="", notify="", enabled=True, job_id=""):
    """Persistent campaign job manager.

    action: list | add | remove | enable | disable | status
    add -> creates job {id, name, target, schedule, chain, notify, enabled,
                        created_at, next_run}
    """
    jobs = _load_jobs()
    action = (action or "list").strip().lower()
    if action in ("list", "status"):
        view = []
        for j in jobs:
            view.append({k: j.get(k) for k in
                         ("id", "name", "target", "schedule", "enabled",
                          "next_run", "last_run", "last_status")})
        return json.dumps({"action": action, "count": len(view), "jobs": view,
                           "store": _store_path()}, ensure_ascii=False, indent=1)

    if action == "add":
        if not name.strip():
            return json.dumps({"error": "name is required for add"},
                              ensure_ascii=False)
        if not target.strip():
            return json.dumps({"error": "target is required for add"},
                              ensure_ascii=False)
        try:
            _parse_schedule(schedule)
        except ValueError as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)
        nxt = _next_run(_parse_schedule(schedule)).isoformat(timespec="minutes")
        nid = "CAMP-%03d" % (len(jobs) + 1)
        channels = [c.strip().lower() for c in notify.split(",")
                    if c.strip().lower() in ("telegram", "discord", "webhook")]
        job = {"id": nid, "name": name.strip(), "target": target.strip(),
               "schedule": schedule.strip(), "chain": chain, "notify": channels,
               "enabled": bool(enabled),
               "created_at": datetime.now().isoformat(timespec="seconds"),
               "next_run": nxt, "last_run": None, "last_status": None}
        jobs.append(job)
        _save_jobs(jobs)
        return json.dumps({"action": "add", "ok": True, "job": job},
                          ensure_ascii=False, indent=1)

    if action in ("remove", "delete"):
        hit = [j for j in jobs if (job_id and j["id"] == job_id)
               or (name and j["name"] == name)]
        if not hit:
            return json.dumps({"error": "no job matches id=%r name=%r"
                                       % (job_id, name)}, ensure_ascii=False)
        jobs = [j for j in jobs if j not in hit]
        _save_jobs(jobs)
        return json.dumps({"action": "remove", "ok": True,
                           "removed": [j["id"] for j in hit]},
                          ensure_ascii=False, indent=1)

    if action in ("enable", "disable"):
        hit = [j for j in jobs if (job_id and j["id"] == job_id)
               or (name and j["name"] == name)]
        if not hit:
            return json.dumps({"error": "no job matches id=%r name=%r"
                                       % (job_id, name)}, ensure_ascii=False)
        for j in hit:
            j["enabled"] = (action == "enable")
        _save_jobs(jobs)
        return json.dumps({"action": action, "ok": True,
                           "ids": [j["id"] for j in hit]},
                          ensure_ascii=False, indent=1)

    return json.dumps({"error": "unknown action %r "
                                "(list|add|remove|enable|disable|status)"
                       % action}, ensure_ascii=False)


def tool_campaign_run_now(job_id="", name="", target="", schedule="",
                          chain="", notify=""):
    """Run a stored campaign job immediately; without job_id/name runs an
    ad-hoc one-shot job from the given params (not persisted).
    """
    job = None
    if job_id or name:
        jobs = _load_jobs()
        hit = [j for j in jobs if (job_id and j["id"] == job_id)
               or (name and j["name"] == name)]
        if hit:
            job = hit[0]
    if job is None:
        if not target:
            return json.dumps({"error": "job_id/name not found and target "
                                        "not given for ad-hoc run"},
                              ensure_ascii=False)
        job = {"name": name or "adhoc-" + target[:24],
               "target": target, "schedule": schedule or "every 2h",
               "chain": chain,
               "notify": [c for c in notify.split(",")
                          if c in ("telegram", "discord", "webhook")]}
        persist = False
    else:
        persist = True
    res = _run_job(job)
    if persist:
        jobs = _load_jobs()
        for j in jobs:
            if j["id"] == job["id"]:
                j["last_run"] = res["ran_at"]
                j["last_status"] = res["status"]
                try:
                    j["next_run"] = _next_run(
                        _parse_schedule(j.get("schedule", "every 2h")),
                        datetime.fromisoformat(res["ran_at"])).isoformat(
                            timespec="minutes")
                except Exception:
                    pass
        _save_jobs(jobs)
    return json.dumps({"ran_at": res["ran_at"], "status": res["status"],
                       "steps": [{k: s[k] for k in ("tool", "ok", "error")}
                                 for s in res["steps"]],
                       "summary": res["summary"][:2000],
                       "notify": res.get("notify", [])},
                      ensure_ascii=False, indent=1)


def tool_campaign_daemon(action="status", interval_sec=30):
    """Autopilot daemon control: spawn/stop/status the detached runner loop.

    start: launches 'python scheduled_campaign_runner.py --daemon
           --interval N' (poll seconds), PID saved to .campaign_daemon.pid
    stop:  terminates the daemon process
    status: running / stopped + pid + log + store
    """
    action = (action or "status").strip().lower()
    pid_path = _daemon_pid_path()
    log_path = _daemon_log_path()
    runner = os.path.join(_BASE_DIR, "scheduled_campaign_runner.py")

    def _read_pid():
        try:
            with open(pid_path, "r") as f:
                return int(f.read().strip())
        except Exception:
            return None

    def _alive(pid):
        if not pid:
            return False
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False
        except Exception:
            return False

    if action == "status":
        pid = _read_pid()
        return json.dumps({"action": "status", "running": _alive(pid),
                           "pid": pid if _alive(pid) else None,
                           "log": log_path, "store": _store_path(),
                           "interval_sec": interval_sec},
                          ensure_ascii=False, indent=1)

    if action == "start":
        if _alive(_read_pid()):
            return json.dumps({"action": "start", "ok": True,
                               "already_running": True, "pid": _read_pid()},
                              ensure_ascii=False)
        if not os.path.exists(runner):
            return json.dumps({"error": "runner script missing: %s" % runner},
                              ensure_ascii=False)
        try:
            flags = 0
            if os.name == "nt":
                flags = (getattr(subprocess, "DETACHED_PROCESS", 0x8) |
                         getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
            logf = open(log_path, "a", encoding="utf-8")
            proc = subprocess.Popen(
                [sys.executable, runner, "--daemon",
                 "--interval", str(max(30, int(interval_sec)))],
                cwd=_BASE_DIR, stdout=logf, stderr=logf, stdin=subprocess.DEVNULL,
                creationflags=flags, close_fds=True)
            with open(pid_path, "w") as f:
                f.write(str(proc.pid))
            time.sleep(1.2)
            return json.dumps({"action": "start", "ok": True,
                               "pid": proc.pid if _alive(proc.pid) else None,
                               "log": log_path}, ensure_ascii=False, indent=1)
        except Exception as e:
            return json.dumps({"action": "start", "ok": False,
                               "error": "%s: %s" % (type(e).__name__, e)},
                              ensure_ascii=False)

    if action == "stop":
        pid = _read_pid()
        if not pid or not _alive(pid):
            return json.dumps({"action": "stop", "ok": True,
                               "already_stopped": True}, ensure_ascii=False)
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
                else:
                    os.kill(pid, signal.SIGKILL if hasattr(signal, "SIGKILL")
                            else signal.SIGTERM)
            except Exception as e:
                return json.dumps({"action": "stop", "ok": False,
                                   "error": "%s: %s" % (type(e).__name__, e)},
                                  ensure_ascii=False)
        time.sleep(1.2)
        if _alive(pid):
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
            except Exception:
                pass
        time.sleep(0.5)
        try:
            os.remove(pid_path)
        except Exception:
            pass
        return json.dumps({"action": "stop", "ok": True, "pid": pid},
                          ensure_ascii=False, indent=1)

    return json.dumps({"error": "unknown action %r (status|start|stop)"
                       % action}, ensure_ascii=False)


def run_due_campaigns(now=None, run_all=False):
    """Execute all due enabled jobs. Used by the runner/daemon loop.
    Returns JSON: {'ran': [...], 'count': N, 'checked_at': ...}
    """
    jobs = _load_jobs()
    now = now or datetime.now()
    changes = False
    out = []
    for j in jobs:
        if not j.get("enabled", True):
            continue
        spec = None
        try:
            spec = _parse_schedule(j.get("schedule", ""))
        except Exception:
            continue
        due = run_all
        if not due and j.get("next_run"):
            try:
                due = datetime.fromisoformat(j["next_run"]) <= now
            except Exception:
                due = True
        if not due:
            continue
        res = _run_job(j)
        j["last_run"] = res["ran_at"]
        j["last_status"] = res["status"]
        try:
            j["next_run"] = _next_run(
                spec, datetime.fromisoformat(res["ran_at"])).isoformat(
                    timespec="minutes")
        except Exception:
            j["next_run"] = _next_run(spec).isoformat(timespec="minutes")
        out.append({"job": j["name"], "id": j["id"], "status": res["status"],
                    "ran_at": res["ran_at"],
                    "steps_ok": sum(1 for s in res["steps"] if s["ok"]),
                    "steps_total": len(res["steps"])})
        changes = True
    if changes:
        _save_jobs(jobs)
    return json.dumps({"ran": out, "count": len(out),
                       "checked_at": now.isoformat(timespec="seconds")},
                      ensure_ascii=False, indent=1)
