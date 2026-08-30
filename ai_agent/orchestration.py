"""Managed Asynchronous Sub-Agent Orchestration Protocol.

Upgrades the legacy fire-and-forget spawn machinery into a bounded,
tracked, asynchronous delegation engine.

Core guarantees:

1. BOUNDED EXECUTION STATE - every spawned child is registered in a
   per-parent OrchestrationManager as a SubAgentRecord carrying a strict
   state machine (queued / running / done / error / cancelled /
   timed_out), lifecycle timestamps, a progress ledger and a full
   transcript. No child can run or exist outside the manager's bookkeeping.

2. CAPS - spawning is bounded by explicit limits:
     max_siblings  : how many children may RUN at the same time (2)
     max_children  : how many children may be tracked non-terminal at
                     once, queued included (4)
     max_depth     : inherited from the parent's max_spawn_depth
   Excess spawn requests are either queued (bounded) or rejected with a
   clear error; the registry self-prunes terminal records.

3. SUCCESS CRITERIA + CAPABILITIES - every spawn may declare explicit
   success criteria (checked against the final output when the parent
   explicitly validates) and a capability list (cross-checked against the
   child's actual toolset so gaps are reported, not silently assumed).

4. ASYNC BY DEFAULT - spawn_agent / spawn_agents return immediately with
   an agent_id; the parent keeps running. Child output is treated as
   UNVERIFIED until the parent explicitly validates it with
   check_agent_status(validate=true), which cross-checks the recorded
   success criteria against the output.

5. MANAGEMENT TOOLS - check_agent_status, fetch_agent_transcript,
   continue_agent (resume a finished child from its persisted transcript)
   and cancel_agent operate on the same records the spawn tools created.
"""

import json
import threading
import time
import uuid

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_ERROR = "error"
STATUS_CANCELLED = "cancelled"
STATUS_TIMED_OUT = "timed_out"
TERMINAL_STATUSES = frozenset(
    [STATUS_DONE, STATUS_ERROR, STATUS_CANCELLED, STATUS_TIMED_OUT])
ACTIVE_STATUSES = frozenset([STATUS_QUEUED, STATUS_RUNNING])

DEFAULT_MAX_SIBLINGS = 2
DEFAULT_MAX_CHILDREN = 4

# Capability tag -> tools that must exist on the child to honor the claim.
CAPABILITY_TOOLS = {
    "terminal": ["run_terminal"],
    "web": ["http_request", "open_url", "web_search"],
    "recon": ["port_scan", "nmap_scan", "dns_lookup", "subdomain_enum"],
    "spawn": ["spawn_agent"],
    "memory": ["remember"],
    "code": ["read_file", "grep_files", "run_terminal"],
    "payloads": ["gen_reverse_shell"],
    "reporting": ["add_finding", "write_report"],
    "workspace": ["workspace_list"],
    "verify": ["verify_finding"],
}

TRANSCRIPT_MAX_ENTRIES = 600
TRANSCRIPT_ENTRY_LIMIT = 2000
OUTPUT_LIMIT = 50000
LEDGER_LIMIT = 200


def _now():
    return time.time()


def _clock(ts=None):
    t = time.localtime(ts if ts is not None else time.time())
    return time.strftime("%Y-%m-%d %H:%M:%S", t)


def _short(text, limit=80):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "..."


def parse_list(value, split="|||"):
    """Parse a criteria/capability value that may be a JSON array string,
    a pipe/comma separated string, or already a list."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        out = [str(v).strip() for v in value]
        return [v for v in out if v]
    text = str(value).strip()
    if not text:
        return []
    if text.lstrip().startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                out = [str(v).strip() for v in parsed]
                return [v for v in out if v]
        except ValueError:
            pass
    if split and split in text:
        out = [p.strip() for p in text.split(split)]
        return [p for p in out if p]
    if "," in text:
        out = [p.strip() for p in text.split(",")]
        return [p for p in out if p]
    return [text]


class SubAgentRecord:
    """Bounded execution state for one child sub-agent."""

    def __init__(self, agent_id, task, parent, persona=None,
                 success_criteria=None, capabilities=None, timeout=None,
                 depth=0, index=None, extra=None):
        self.agent_id = agent_id
        self.task = task
        self.parent = parent
        self.persona = persona
        self.success_criteria = list(success_criteria or [])
        self.capabilities = list(capabilities or [])
        self.capability_report = {}      # capability -> ok/partial/missing
        self.timeout = timeout
        self.depth = depth
        self.index = index               # original position for batch spawns
        self.extra = extra or {}
        self.status = STATUS_QUEUED
        self.created_at = _now()
        self.started_at = None
        self.finished_at = None
        self.phase = "queued"
        self.tool_calls = 0
        self.run_count = 0
        self.verified = False            # unverified until explicit validation
        self.validation_note = ""
        self.output = ""
        self.error = ""
        self.ledger = []                 # {ts, phase, note}
        self.transcript = []             # {ts, kind, content}
        self.child = None                # the running Agent instance
        self.thread = None
        self.cancel_event = threading.Event()

    # ------------------------------------------------------------ state
    def progress(self, phase, note=""):
        if len(self.ledger) >= LEDGER_LIMIT:
            self.ledger = self.ledger[-(LEDGER_LIMIT // 2):]
        self.ledger.append({"ts": _clock(), "phase": phase, "note": note})
        self.phase = phase

    def line(self, kind, content):
        if len(self.transcript) >= TRANSCRIPT_MAX_ENTRIES:
            del self.transcript[:100]
        text = str(content)
        if len(text) > TRANSCRIPT_ENTRY_LIMIT:
            text = text[:TRANSCRIPT_ENTRY_LIMIT] + "...[truncated]"
        self.transcript.append({"ts": _clock(), "kind": kind,
                                "content": text})

    def set_status(self, status):
        self.status = status
        if status == STATUS_RUNNING and self.started_at is None:
            self.started_at = _now()
        if status in TERMINAL_STATUSES and self.finished_at is None:
            self.finished_at = _now()

    def is_terminal(self):
        return self.status in TERMINAL_STATUSES

    def elapsed(self):
        end = self.finished_at if self.finished_at is not None else _now()
        return end - self.created_at

    # ------------------------------------------------------------ views
    def snapshot(self, include_output=True):
        out = {
            "agent_id": self.agent_id,
            "status": self.status,
            "phase": self.phase,
            "task": _short(self.task, 140),
            "persona": bool(self.persona),
            "depth": self.depth,
            "run_count": self.run_count,
            "tool_calls": self.tool_calls,
            "elapsed_s": round(self.elapsed(), 1),
            "success_criteria": self.success_criteria,
            "capabilities": self.capabilities,
            "capability_report": self.capability_report,
            "verified": self.verified,
            "output_verified": self.verified and self.status == STATUS_DONE,
            "ledger": list(self.ledger[-8:]),
        }
        if self.status == STATUS_DONE and include_output:
            excerpt = self.output
            if len(excerpt) > 1200:
                excerpt = excerpt[:1200] + "...[truncated]"
            out["output_unverified"] = (
                "UNVERIFIED - use check_agent_status(validate=true) to "
                "cross-check success criteria against this output" if not
                self.verified else "VERIFIED against success criteria")
            out["output"] = excerpt
        if self.status == STATUS_ERROR:
            out["error"] = _short(self.error, 300)
        return out

    def transcript_text(self):
        lines = []
        for entry in self.transcript:
            lines.append("[%s] %s: %s" % (entry["ts"], entry["kind"],
                                          entry["content"]))
        text = "\n".join(lines)
        if len(text) > 40000:
            text = text[:40000] + "\n...[transcript truncated]"
        return text


class OrchestrationManager:
    """Per-parent registry of bounded, asynchronous sub-agent executions."""

    def __init__(self, parent_name="agent", spawn_timeout=900,
                 max_siblings=DEFAULT_MAX_SIBLINGS,
                 max_children=DEFAULT_MAX_CHILDREN, max_depth=3,
                 make_child=None):
        self.parent_name = parent_name
        self.spawn_timeout = spawn_timeout
        self.max_siblings = max_siblings
        self.max_children = max_children
        self.max_depth = max_depth
        # make_child(task, depth) -> (child_agent, remaining_task)
        self._make_child = make_child
        self._lock = threading.RLock()
        self._records = {}
        self._order = []

    # ------------------------------------------------------------ helpers
    def _new_id(self):
        return "sa-%s" % uuid.uuid4().hex[:8]

    def _record(self, agent_id):
        with self._lock:
            return self._records.get(agent_id)

    def _running_count(self):
        with self._lock:
            return sum(1 for r in self._records.values()
                       if r.status == STATUS_RUNNING)

    def _active_count(self):
        with self._lock:
            return sum(1 for r in self._records.values()
                       if r.status in ACTIVE_STATUSES)

    def _prune(self):
        """Drop oldest terminal records once the registry grows past
        max_children * 4, so the bounded bookkeeping never leaks."""
        with self._lock:
            if len(self._records) <= self.max_children * 4:
                return
            terminal = [r for r in self._records.values() if r.is_terminal()]
            terminal.sort(key=lambda r: r.finished_at or 0)
            excess = len(self._records) - self.max_children * 4
            for r in terminal[:excess]:
                del self._records[r.agent_id]
                try:
                    self._order.remove(r.agent_id)
                except ValueError:
                    pass

    def _dispatch_next(self):
        """Start queued children while sibling capacity allows (>=1)."""
        with self._lock:
            running = self._running_count()
            if running >= self.max_siblings:
                return
            queued = [r for r in self._records.values()
                      if r.status == STATUS_QUEUED]
            queued.sort(key=lambda r: r.created_at)
            for r in queued[:self.max_siblings - running]:
                r.set_status(STATUS_RUNNING)
                r.run_count += 1
                r.cancel_event = threading.Event()
                r.progress("running", "started")
                r.thread = threading.Thread(
                    target=self._runner, args=(r,), daemon=True)
                r.thread.start()

    def _sweep(self):
        """Mark over-time running children as timed_out and request stop."""
        with self._lock:
            now = _now()
            for r in self._records.values():
                if r.status == STATUS_RUNNING and r.timeout:
                    if now - r.started_at > r.timeout:
                        r.cancel_event.set()
                        r.progress("timeout",
                                   "exceeded %ds budget" % r.timeout)
                        r.set_status(STATUS_TIMED_OUT)
                        r.error = ("timed out after %ds" % r.timeout)

    def _capability_report(self, record, child):
        tools = {t.name for t in child._tool_list} \
            if hasattr(child, "_tool_list") else set()
        for cap in record.capabilities:
            needed = CAPABILITY_TOOLS.get(cap.lower())
            if not needed:
                record.capability_report[cap] = "unknown-tag"
                continue
            missing = [t for t in needed if t not in tools]
            record.capability_report[cap] = (
                "ok" if not missing else "missing: " + ", ".join(missing))

    def _runner(self, record):
        """Background worker: run the child, capture transcript + ledger,
        then free a sibling slot for the next queued child."""
        if record.status == STATUS_CANCELLED:
            record.progress("cancelled", "cancelled before start")
            record.set_status(STATUS_CANCELLED)
            self._dispatch_next()
            return
        try:
            if self._make_child is None:
                raise RuntimeError("no child factory configured")
            record.progress("initializing", "building child agent")
            child, rest = self._make_child(record.task, record.depth)
            record.child = child
            self._capability_report(record, child)
            record.line("note", "child agent ready (%s), capabilities %s"
                        % (child.name,
                           json.dumps(record.capability_report)))
            buffer = []

            def flush():
                text = "".join(buffer).strip()
                if text:
                    record.line("assistant", text)
                del buffer[:]

            record.progress("running", "child executing")
            for ev in child.run_stream(rest or record.task,
                                       stop_event=record.cancel_event):
                kind = ev.get("type")
                if kind == "delta":
                    buffer.append(ev.get("content") or "")
                    continue
                flush()
                if kind == "tool_call":
                    record.tool_calls += 1
                    record.progress("executing",
                                    "tool: %s" % ev.get("name", "?"))
                    record.line("tool_call",
                                "%s(%s)" % (ev.get("name", "?"),
                                            ev.get("arguments", "{}")))
                elif kind == "tool_result":
                    record.line("tool_result",
                                _short(ev.get("content", ""), 600))
                elif kind == "final":
                    record.progress("finalizing", "child produced answer")
                    content = ev.get("content", "")
                    record.line("final", content)
                    if record.run_count > 1:
                        record.output = (
                            record.output
                            + "\n\n[continued run %d]\n\n" % record.run_count
                            + content)
                    else:
                        record.output = content
                elif kind == "error":
                    record.line("error", ev.get("content", ""))
                    if not record.error:
                        record.error = ev.get("content", "")
            flush()
            if record.status != STATUS_CANCELLED:
                if record.status == STATUS_TIMED_OUT:
                    pass
                elif record.error:
                    record.set_status(STATUS_ERROR)
                    record.progress("error", record.error)
                else:
                    record.set_status(STATUS_DONE)
                    record.progress("done", "completed")
        except Exception as exc:
            record.error = "%s: %s" % (type(exc).__name__, exc)
            if record.status not in (STATUS_CANCELLED, STATUS_TIMED_OUT):
                record.set_status(STATUS_ERROR)
                record.progress("error", record.error)
            record.line("error", record.error)
        finally:
            self._dispatch_next()

    # ------------------------------------------------------------ spawn
    def spawn(self, task, wait=False, success_criteria=None,
              capabilities=None, persona=None, timeout=None, depth=0,
              meta=None):
        """Spawn ONE tracked child. Returns a status string immediately
        (with agent_id) unless wait=True, which blocks and returns the
        final output (legacy synchronous behaviour)."""
        task = (task or "").strip()
        if not task:
            return "Error: spawn needs a task."
        if self.max_depth is not None and depth > self.max_depth:
            return "Error: sub-agent depth limit reached."
        with self._lock:
            if self._active_count() >= self.max_children:
                return ("Error: sub-agent cap reached (%d children tracked; "
                        "cancel or wait for one to finish)."
                        % self.max_children)
            agent_id = self._new_id()
            record = SubAgentRecord(
                agent_id, task, self.parent_name, persona=persona,
                success_criteria=parse_list(success_criteria),
                capabilities=parse_list(capabilities),
                timeout=timeout or self.spawn_timeout, depth=depth,
                extra=meta or {})
            if meta and meta.get("index") is not None:
                record.index = meta.get("index")
            record.progress("queued", "spawned by %s" % self.parent_name)
            self._records[agent_id] = record
            self._order.append(agent_id)
            self._dispatch_next()
        if wait:
            return self.sync_result(agent_id)
        return json.dumps({
            "agent_id": agent_id,
            "status": record.status,
            "depth": depth,
            "note": ("child running in background; output is UNVERIFIED "
                     "until you check_agent_status(validate=true)"),
        })

    def spawn_many(self, tasks, wait=False, success_criteria=None,
                   capabilities=None, timeout=None, depth=0, meta=None):
        """Spawn up to max_children tracked children; at most max_siblings
        run at once, the rest are queued (bounded). Excess tasks are
        rejected and reported. Returns a JSON status list (or, with
        wait=True, the combined results in task order)."""
        if isinstance(tasks, str):
            tasks = tasks.strip()
            if not tasks:
                return "Error: spawn_agents needs at least one task."
            if tasks.lstrip().startswith("["):
                try:
                    tasks = json.loads(tasks)
                except ValueError:
                    return "Error: tasks JSON is invalid."
            else:
                tasks = [t.strip() for t in tasks.split("|||") if t.strip()]
        if not isinstance(tasks, (list, tuple)) or not tasks:
            return "Error: spawn_agents needs a list of tasks."
        with self._lock:
            free = self.max_children - self._active_count()
            accepted = list(tasks)[:max(free, 0)]
            rejected = list(tasks)[free:] if free < len(tasks) else []
        spawned = []
        for i, task in enumerate(accepted):
            result = self.spawn(task, wait=False,
                                success_criteria=success_criteria,
                                capabilities=capabilities,
                                timeout=timeout, depth=depth,
                                meta={"batch": True, "index": i})
            spawned.append((i, result))
        statuses = []
        for i, result in spawned:
            try:
                parsed = json.loads(result)
                parsed["index"] = i
                statuses.append(parsed)
            except (ValueError, TypeError):
                statuses.append({"index": i, "error": result})
        for i in range(len(accepted), len(accepted) + len(rejected)):
            statuses.append({"index": i,
                             "error": ("rejected: child cap (%d) reached"
                                       % self.max_children)})
        if wait:
            return self.sync_results(
                [s.get("agent_id") for s in statuses if s.get("agent_id")],
                timeout=timeout)
        return json.dumps({
            "spawned": len(accepted),
            "queued_or_running": statuses,
            "rejected": len(rejected),
            "note": ("children run in background (max %d siblings at once, "
                     "%d tracked); outputs are UNVERIFIED until you "
                     "check_agent_status(validate=true)"
                     % (self.max_siblings, self.max_children)),
        }, indent=1)

    # ------------------------------------------------------------ sync
    def sync_result(self, agent_id, timeout=None):
        """Block until the child finishes; returns the raw output (legacy
        spawn_agent behaviour)."""
        record = self._record(agent_id)
        if record is None:
            return "Error: unknown sub-agent %s" % agent_id
        deadline = time.time() + (timeout or record.timeout or 60)
        while not record.is_terminal():
            self._sweep()
            if record.is_terminal():
                break
            if time.time() > deadline:
                record.cancel_event.set()
                record.set_status(STATUS_TIMED_OUT)
                record.progress("timeout", "sync wait deadline exceeded")
                break
            time.sleep(0.1)
        if record.status == STATUS_DONE:
            return record.output
        if record.status == STATUS_ERROR:
            return "Sub-agent error: %s" % record.error
        if record.status == STATUS_TIMED_OUT:
            return ("Error: sub-agent timed out after %ds."
                    % (timeout or record.timeout))
        if record.status == STATUS_CANCELLED:
            return "Sub-agent cancelled."
        return "(no output)"

    def sync_results(self, agent_ids, timeout=None):
        """Block until every listed child finishes; returns combined
        results in the order given (legacy spawn_agents behaviour)."""
        lines = []
        deadline = time.time() + (timeout or self.spawn_timeout or 600)
        for agent_id in agent_ids:
            record = self._record(agent_id)
            if record is None:
                continue
            while not record.is_terminal():
                self._sweep()
                if record.is_terminal():
                    break
                if time.time() > deadline:
                    record.cancel_event.set()
                    record.set_status(STATUS_TIMED_OUT)
                    break
                time.sleep(0.1)
        for agent_id in agent_ids:
            record = self._record(agent_id)
            if record is None:
                continue
            lines.append("--- Sub-agent %s: %s ---"
                         % (record.index + 1 if record.index is not None
                            else "?", _short(record.task, 80)))
            if record.status == STATUS_DONE:
                lines.append(record.output)
            elif record.status == STATUS_ERROR:
                lines.append("ERROR: %s" % record.error)
            else:
                lines.append("(%s)" % record.status)
        return "\n\n".join(lines)

    # ------------------------------------------------------------ mgmt
    def check_status(self, agent_id="", validate=False):
        """Status of one child (or a table of all children). With
        validate=true, done outputs are cross-checked against their
        success criteria and marked verified / unverified."""
        self._sweep()
        with self._lock:
            ids = [agent_id] if agent_id else list(self._order)
        if not ids:
            return "No sub-agents spawned yet by %s." % self.parent_name
        if agent_id and agent_id not in self._records:
            return "Error: unknown sub-agent %s." % agent_id
        if agent_id:
            return self._status_detail(self._record(agent_id), validate)
        lines = ["Sub-agents of %s (%d tracked, cap %d children / "
                 "%d siblings):"
                 % (self.parent_name, len(self._records),
                    self.max_children, self.max_siblings)]
        lines.append("%-11s %-9s %-6s %-9s %s" % (
            "agent_id", "status", "phase", "elapsed", "task"))
        for aid in ids:
            r = self._record(aid)
            if r is None:
                continue
            lines.append("%-11s %-9s %-6s %-8ss %s" % (
                r.agent_id, r.status, r.phase,
                round(r.elapsed(), 1), _short(r.task, 60)))
        lines.append("Tip: check_agent_status(<agent_id>, validate=true) "
                     "cross-checks success criteria and marks output "
                     "verified/unverified.")
        return "\n".join(lines)

    def _status_detail(self, record, validate=False):
        if record is None:
            return "Error: unknown sub-agent."
        if validate and record.status == STATUS_DONE:
            missing = []
            for criterion in record.success_criteria:
                needle = criterion.lower()
                if needle and needle not in record.output.lower():
                    missing.append(criterion)
            if not record.success_criteria:
                record.verified = True
                record.validation_note = ("no success criteria declared; "
                                          "treated as satisfied")
            elif missing:
                record.verified = False
                record.validation_note = (
                    "criteria NOT met: " + "; ".join(missing))
            else:
                record.verified = True
                record.validation_note = (
                    "all %d success criteria met" % len(record.success_criteria))
        snap = record.snapshot()
        block = ["=== Sub-agent %s ===" % record.agent_id]
        block.append("status:   %s" % snap["status"])
        block.append("phase:    %s" % snap["phase"])
        block.append("elapsed:  %ss" % snap["elapsed_s"])
        block.append("task:     %s" % snap["task"])
        block.append("criteria: %s"
                     % (snap["success_criteria"] or "(none)"))
        block.append("caps:     %s" % (snap["capabilities"] or "(none)"))
        block.append("capability_report: %s"
                     % json.dumps(snap["capability_report"]))
        block.append("verified: %s%s" % (
            snap["verified"],
            (" - %s" % record.validation_note) if record.validation_note
            else ""))
        if "output" in snap:
            block.append("output:   %s" % snap["output_unverified"])
            block.append(snap["output"])
        if "error" in snap:
            block.append("error:    %s" % snap["error"])
        if record.is_terminal():
            block.append("next:     continue_agent(%s, '<follow-up>') to "
                         "resume, or cancel_agent(%s) while it runs"
                         % (record.agent_id, record.agent_id))
        return "\n".join(block)

    def fetch_transcript(self, agent_id=""):
        """Full transcript of one child (or a summary for all)."""
        self._sweep()
        if agent_id:
            record = self._record(agent_id)
            if record is None:
                return "Error: unknown sub-agent %s." % agent_id
            body = record.transcript_text()
            return ("=== Transcript: %s (%s, %d entries) ===\n%s"
                    % (agent_id, record.status,
                       len(record.transcript), body))
        with self._lock:
            ids = list(self._order)
        if not ids:
            return "No sub-agents spawned yet by %s." % self.parent_name
        lines = ["Sub-agent transcripts available for %s:" % self.parent_name]
        for aid in ids:
            r = self._record(aid)
            if r is None:
                continue
            lines.append("  %s  %-9s %3d entries  %s"
                         % (r.agent_id, r.status, len(r.transcript),
                            _short(r.task, 60)))
        lines.append("fetch_agent_transcript(<agent_id>) for the full log.")
        return "\n".join(lines)

    def continue_agent(self, agent_id, follow_up):
        """Resume a finished child with a follow-up prompt. The child's
        messages and transcript persist, so the follow-up continues the
        same conversation. Returns the new status string."""
        follow_up = (follow_up or "").strip()
        if not follow_up:
            return "Error: continue_agent needs a follow-up prompt."
        record = self._record(agent_id)
        if record is None:
            return "Error: unknown sub-agent %s." % agent_id
        if record.status in ACTIVE_STATUSES:
            return ("Error: sub-agent %s is still %s; wait for it to "
                    "finish first." % (agent_id, record.status))
        with self._lock:
            record.status = STATUS_QUEUED
            record.finished_at = None
            record.verified = False
            record.validation_note = ""
            record.progress("queued", "continued with follow-up: %s"
                            % _short(follow_up, 60))
            record.line("note", "parent continued the agent: %s"
                        % _short(follow_up, 200))
            self._dispatch_next()
        return json.dumps({
            "agent_id": agent_id,
            "status": record.status,
            "note": ("child resumed in background; its transcript persists; "
                     "output re-marked UNVERIFIED until explicit validation"),
        })

    def cancel_agent(self, agent_id=""):
        """Cancel one child (or all active children). Running children get
        their cancel event set so the loop unwinds; queued children are
        cancelled immediately."""
        self._sweep()
        if agent_id:
            record = self._record(agent_id)
            if record is None:
                return "Error: unknown sub-agent %s." % agent_id
            if record.is_terminal():
                return ("Sub-agent %s is already %s."
                        % (agent_id, record.status))
            record.cancel_event.set()
            if record.status == STATUS_QUEUED:
                record.set_status(STATUS_CANCELLED)
                record.progress("cancelled", "cancelled while queued")
                record.line("note", "cancelled by parent while queued")
                self._dispatch_next()
                return ("Sub-agent %s cancelled (was queued)." % agent_id)
            record.progress("cancelling", "stop requested")
            return ("Sub-agent %s cancel requested; loop is unwinding."
                    % agent_id)
        with self._lock:
            active = [r for r in self._records.values()
                      if r.status in ACTIVE_STATUSES]
        if not active:
            return "No active sub-agents to cancel."
        for r in active:
            r.cancel_event.set()
            if r.status == STATUS_QUEUED:
                r.set_status(STATUS_CANCELLED)
                r.progress("cancelled", "cancelled while queued")
        self._dispatch_next()
        return "Cancel requested for %d active sub-agent(s): %s" % (
            len(active), ", ".join(r.agent_id for r in active))

    def registry_summary(self):
        with self._lock:
            return {
                "parent": self.parent_name,
                "tracked": len(self._records),
                "max_children": self.max_children,
                "max_siblings": self.max_siblings,
                "active": self._active_count(),
                "running": self._running_count(),
            }
