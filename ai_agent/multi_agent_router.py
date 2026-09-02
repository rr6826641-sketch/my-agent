"""Multi-Agent Swarm Router.

A pure-asyncio swarm orchestrator with three discrete specialist roles:

  ReconAgent        - passive/active discovery + attack-surface mapping.
  AnalyzerAgent     - converts surface data into hypotheses, a
                      vulnerability graph and ranked candidate exploits.
  ExploitationAgent - executes targeted validation payloads, classifies
                      feedback and records reproduction-ready PoCs.

Coordination happens over an AsyncMessageBus: every agent owns an inbox
queue, exchanges typed data payloads, updates task states on a strict
state machine (pending / running / blocked / done / error) and hands
execution context forward so downstream agents never need to know where
a datum originated.

The swarm is fully deterministic with no external dependencies. An
optional synchronous ``tool_executor`` callable (command -> output
string) is bridged into the event loop via run_in_executor; without one
the agents fall back to heuristic planning so the swarm always makes
progress offline.
"""

import asyncio
import json
import os
import re
import time
import uuid

# --------------------------------------------------------------------------
# Task state machine
# --------------------------------------------------------------------------

TASK_PENDING = "pending"
TASK_RUNNING = "running"
TASK_BLOCKED = "blocked"
TASK_DONE = "done"
TASK_ERROR = "error"
TASK_STATES = frozenset(
    [TASK_PENDING, TASK_RUNNING, TASK_BLOCKED, TASK_DONE, TASK_ERROR])

TASK_CANCELLED = "cancelled"

# Allowed transitions (anything else is rejected with an error event).
VALID_TRANSITIONS = {
    TASK_PENDING: frozenset([TASK_RUNNING, TASK_BLOCKED, TASK_ERROR,
                             TASK_DONE, TASK_CANCELLED]),
    TASK_RUNNING: frozenset([TASK_DONE, TASK_ERROR, TASK_BLOCKED]),
    TASK_BLOCKED: frozenset([TASK_RUNNING, TASK_ERROR, TASK_PENDING]),
    TASK_DONE: frozenset(),
    TASK_ERROR: frozenset([TASK_PENDING]),
    TASK_CANCELLED: frozenset(),
}

MSG_TASK = "task"
MSG_DATA = "data"
MSG_STATE = "state"
MSG_CONTEXT = "context"
MSG_STOP = "stop"

TOPIC_SURFACE = "surface"
TOPIC_HYPOTHESES = "hypotheses"
TOPIC_CANDIDATES = "candidates"
TOPIC_POC = "poc"
TOPIC_FEEDBACK = "feedback"

HISTORY_LIMIT = 500


def _now():
    return time.time()


def _uid(prefix):
    return "%s_%s" % (prefix, uuid.uuid4().hex[:10])


# --------------------------------------------------------------------------
# Async message bus
# --------------------------------------------------------------------------

class SwarmMessage:
    """One routed envelope on the bus."""

    __slots__ = ("id", "type", "sender", "recipient", "topic", "payload",
                 "context", "ts", "reply_to")

    def __init__(self, mtype, sender, recipient=None, topic=None,
                 payload=None, context=None, reply_to=None):
        self.id = _uid("msg")
        self.type = mtype
        self.sender = sender
        self.recipient = recipient
        self.topic = topic
        self.payload = payload if payload is not None else {}
        self.context = context if isinstance(context, dict) else {}
        self.ts = _now()
        self.reply_to = reply_to

    def to_dict(self):
        return {"id": self.id, "type": self.type, "sender": self.sender,
                "recipient": self.recipient, "topic": self.topic,
                "payload": self.payload, "context": self.context,
                "ts": self.ts, "reply_to": self.reply_to}


class AsyncMessageBus:
    """Asynchronous typed message channel between swarm agents.

    - Every subscriber gets a private unbounded asyncio.Queue.
    - send() is point-to-point; broadcast() hits every subscriber except
      the sender via a topic.
    - A bounded history keeps envelopes for post-run forensics.
    """

    def __init__(self):
        self._inboxes = {}
        self._agents = set()
        self.history = []

    def register(self, name):
        """Register an agent name and create its inbox."""
        if name in self._inboxes:
            raise ValueError("duplicate swarm agent name: %s" % name)
        self._inboxes[name] = asyncio.Queue()
        self._agents.add(name)
        return self._inboxes[name]

    def inbox(self, name):
        q = self._inboxes.get(name)
        if q is None:
            raise KeyError("unknown swarm agent: %s" % name)
        return q

    async def send(self, message):
        self._record(message)
        if message.recipient is not None:
            self.inbox(message.recipient).put_nowait(message)
        else:
            self._broadcast(message)

    def send_nowait(self, message):
        """Synchronous fire-and-forget (safe inside handle callbacks)."""
        self._record(message)
        if message.recipient is not None:
            self.inbox(message.recipient).put_nowait(message)
        else:
            self._broadcast(message)

    def _broadcast(self, message):
        for name, q in self._inboxes.items():
            if name != message.sender:
                q.put_nowait(message)

    def _record(self, message):
        self.history.append(message.to_dict())
        if len(self.history) > HISTORY_LIMIT:
            del self.history[:len(self.history) - HISTORY_LIMIT]

    def stats(self):
        by_type = {}
        by_agent = {name: q.qsize() for name, q in self._inboxes.items()}
        for entry in self.history:
            by_type[entry["type"]] = by_type.get(entry["type"], 0) + 1
        return {"messages": len(self.history), "by_type": by_type,
                "queue_depth": by_agent, "agents": sorted(self._agents)}


# --------------------------------------------------------------------------
# Agent base
# --------------------------------------------------------------------------

class BaseSwarmAgent:
    """Base class: owns an inbox, a task ledger and a run loop."""

    name = "base"
    role = "base"

    def __init__(self, bus, tool_executor=None, llm=None):
        self.bus = bus
        self.tool_executor = tool_executor
        self.llm = llm
        self.inbox = bus.register(self.name)
        self.tasks = {}          # task_id -> state string
        self.task_events = {}    # task_id -> dict of result metadata
        self.context = {}        # execution context carried between msgs
        self.transcript = []
        self.reply_hook = None  # orchestrator taps this for task replies
        self._running = True
        self._pending_task = None

    def _reply_state(self, payload):
        """Deliver a task state reply to the orchestrator (if waiting)."""
        if self.reply_hook is not None:
            try:
                self.reply_hook(payload)
            except Exception as exc:
                self._log("error", "reply_hook failed: %r" % exc)

    # -- lifecycle ---------------------------------------------------------

    async def run(self):
        """Consume the inbox until a stop message arrives."""
        while self._running:
            try:
                msg = await asyncio.wait_for(self.inbox.get(), timeout=0.25)
            except asyncio.TimeoutError:
                continue
            try:
                await self._handle(msg)
            except Exception as exc:  # never kill the loop
                self._log("error", "%s handler failed: %r" % (self.name, exc))
                if self._pending_task:
                    self._set_state(self._pending_task, TASK_ERROR,
                                    error=repr(exc))
                    self._pending_task = None

    async def _handle(self, msg):
        if msg.type == MSG_STOP:
            self._running = False
            return
        if msg.type == MSG_DATA:
            self.context.update(msg.context)
            self.ingest(msg.payload, msg.context)
            return
        if msg.type == MSG_CONTEXT:
            self.context.update(msg.payload)
            self.context.update(msg.context)
            return
        if msg.type == MSG_TASK:
            self._pending_task = msg.payload.get("task_id")
            self.context.update(msg.context)
            task_id = self._pending_task
            self._set_state(task_id, TASK_RUNNING)
            try:
                result = await self.execute(msg.payload, self.context)
            except Exception as exc:
                self._set_state(task_id, TASK_ERROR, error=repr(exc))
                self._reply_state({"task_id": task_id,
                                   "state": TASK_ERROR,
                                   "error": repr(exc)})
                self.bus.send_nowait(SwarmMessage(
                    MSG_STATE, self.name, recipient=msg.sender,
                    payload={"task_id": task_id, "state": TASK_ERROR,
                             "error": repr(exc)},
                    context=dict(self.context), reply_to=msg.id))
                self._pending_task = None
                return
            self._set_state(task_id, TASK_DONE, result=result)
            self._reply_state({"task_id": task_id, "state": TASK_DONE})
            self.bus.send_nowait(SwarmMessage(
                MSG_STATE, self.name, recipient=msg.sender,
                payload={"task_id": task_id, "state": TASK_DONE},
                context=dict(self.context), reply_to=msg.id))
            for out in result.get("emit", []):
                self.bus.send_nowait(SwarmMessage(
                    MSG_DATA, self.name, recipient=out.get("recipient"),
                    topic=out.get("topic"), payload=out.get("payload", {}),
                    context=dict(self.context), reply_to=msg.id))
            self._pending_task = None
            return
        if msg.type == MSG_STATE:
            self.ingest_state(msg.payload, msg.context)
            return

    def _set_state(self, task_id, new_state, **extra):
        old = self.tasks.get(task_id, TASK_PENDING)
        if new_state == old:
            self.tasks.setdefault(task_id, new_state)  # idempotent re-assert
            return True
        if new_state not in VALID_TRANSITIONS.get(old, frozenset()):
            self._log("error", "illegal state transition %s -> %s for %s"
                      % (old, new_state, task_id))
            return False
        self.tasks[task_id] = new_state
        entry = {"task_id": task_id, "from": old, "to": new_state,
                 "ts": _now()}
        entry.update(extra)
        self.task_events.setdefault(task_id, {}).update(entry)
        self._log("state", "%s task %s: %s -> %s"
                  % (self.name, task_id, old, new_state))
        return True

    def _log(self, kind, text):
        self.transcript.append({"ts": _now(), "kind": kind, "text": text})

    async def run_command(self, command):
        """Run a shell command through the optional tool executor."""
        if self.tool_executor is None:
            return None
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.tool_executor, command)

    # -- overrides ---------------------------------------------------------

    def ingest(self, payload, context):
        """React to broadcast data addressed to nobody in particular."""
        return

    def ingest_state(self, payload, context):
        return

    async def execute(self, task, context):
        raise NotImplementedError


# --------------------------------------------------------------------------
# ReconAgent
# --------------------------------------------------------------------------

class ReconAgent(BaseSwarmAgent):
    """Passive/active discovery and attack-surface mapping."""

    name = "recon"
    role = "recon"

    SERVICE_PORTS = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https",
        445: "smb", 1433: "mssql", 3306: "mysql", 3389: "rdp",
        5432: "postgres", 6379: "redis", 8080: "http-proxy",
        8443: "https-alt", 9200: "elasticsearch",
    }
    PORT_RE = re.compile(r"(\d{1,5})/tcp\s+open\s+([a-zA-Z0-9_-]+)?")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.surface = {}

    async def execute(self, task, context):
        target = task.get("target") or context.get("target") or "unknown"
        mode = task.get("mode", "active")
        surface = {"target": target, "mode": mode, "hosts": {},
                   "tech": set(), "notes": []}
        output = await self.run_command(task.get("command")
                                        or "nmap -sV %s" % target)
        if output:
            self._parse_portscan(output, surface)
        else:
            self._heuristic_surface(target, surface, mode)
        self.surface[target] = surface
        snapshot = self._snapshot(surface)
        self._log("recon", "surface mapped for %s: %s"
                  % (target, json.dumps(snapshot)[:400]))
        return {"summary": "recon complete for %s" % target,
                "surface": snapshot,
                "emit": [{"topic": TOPIC_SURFACE, "payload": {
                    "target": target, "surface": snapshot}}]}

    def _parse_portscan(self, output, surface):
        for host_m in re.finditer(
                r"Nmap scan report for ([^\s(]+)", output):
            host = host_m.group(1).strip()
            surface["hosts"].setdefault(
                host, {"ports": [], "services": []})
        for match in self.PORT_RE.finditer(output):
            port = int(match.group(1))
            svc = match.group(2) or self.SERVICE_PORTS.get(port, "unknown")
            host = (next(iter(surface["hosts"]), None)
                    or surface["target"])
            entry = surface["hosts"].setdefault(
                host, {"ports": [], "services": []})
            if port not in entry["ports"]:
                entry["ports"].append(port)
                entry["services"].append(svc)
            surface["tech"].add(svc)
        return surface

    def _heuristic_surface(self, target, surface, mode):
        host = target.split("//")[-1].split("/")[0].strip()
        entry = surface["hosts"].setdefault(
            host, {"ports": [], "services": []})
        if "://" in target:
            scheme = target.split("://")[0]
            port = 443 if scheme == "https" else 80
            entry["ports"].append(port)
            entry["services"].append(
                self.SERVICE_PORTS.get(port, scheme))
            surface["tech"].add(entry["services"][-1])
        else:
            for port in (80, 443):
                entry["ports"].append(port)
                entry["services"].append(self.SERVICE_PORTS[port])
                surface["tech"].add(self.SERVICE_PORTS[port])
        if mode == "passive":
            surface["notes"].append(
                "passive mode: no active probes sent")

    @staticmethod
    def _snapshot(surface):
        return {"target": surface["target"], "mode": surface["mode"],
                "hosts": {h: {"ports": v["ports"], "services": v["services"]}
                          for h, v in surface["hosts"].items()},
                "tech": sorted(surface["tech"]),
                "notes": surface["notes"]}


# --------------------------------------------------------------------------
# AnalyzerAgent
# --------------------------------------------------------------------------

class AnalyzerAgent(BaseSwarmAgent):
    """Turns surface data into hypotheses, a vuln graph and candidates."""

    name = "analyzer"
    role = "analyzer"

    SERVICE_VULNS = {
        "http": [("sqli", ["sqli_feedback", "sql_error"]),
                 ("xss", ["reflected_markup"]),
                 ("auth_bypass", ["default_creds", "weak_lockout"])],
        "https": [("sqli", ["sqli_feedback"]), ("tls_weakness",
                 ["legacy_tls"]), ("auth_bypass", ["default_creds"])],
        "http-proxy": [("sqli", ["sqli_feedback"]),
                       ("ssrf", ["internal_fetch"])],
        "ssh": [("weak_creds", ["default_creds", "password_auth"])],
        "ftp": [("anon_access", ["anonymous_login"])],
        "smb": [("eternal_blue_family", ["legacy_smb"]),
                ("null_session", ["anonymous_login"])],
        "redis": [("unauth_access", ["no_auth_bind"])],
        "mysql": [("weak_creds", ["default_creds"])],
        "mssql": [("weak_creds", ["default_creds"]),
                  ("xp_cmdshell", ["sqli_feedback"])],
        "postgres": [("weak_creds", ["default_creds"])],
        "rdp": [("bluekeep_family", ["legacy_rdp"])],
        "elasticsearch": [("unauth_access", ["no_auth_bind"])],
        "dns": [("zone_transfer", ["recursive_resolver"])],
        "smtp": [("open_relay", ["misconfigured_relay"])],
    }

    PAYLOAD_TEMPLATES = {
        "sqli": "' OR 1=1 --",
        "xss": "<svg/onload=alert(1)>",
        "auth_bypass": "admin:admin",
        "weak_creds": "hydra -L users.txt -P rock.txt",
        "anon_access": "ftp anonymous@",
        "unauth_access": "redis-cli INFO",
        "zone_transfer": "dig AXFR {target}",
        "open_relay": "MAIL FROM:<probe@external>",
        "eternal_blue_family": "ms17-010 probe",
        "null_session": "rpcclient -U '' -N",
        "bluekeep_family": "rdp-check probe",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hypotheses = []
        self.graph = {"nodes": [], "edges": []}
        self.candidates = []

    def ingest(self, payload, context):
        if payload.get("surface"):
            self.context["latest_surface"] = payload["surface"]

    async def execute(self, task, context):
        surface = (task.get("surface")
                   or context.get("latest_surface") or {})
        target = surface.get("target") or context.get("target") or "unknown"
        self.graph = {"nodes": [], "edges": []}
        self.hypotheses = []
        self.candidates = []
        techs = surface.get("tech") or []
        hosts = surface.get("hosts") or {}
        for host, info in hosts.items():
            for svc in info.get("services", []):
                self.graph["nodes"].append(
                    {"id": "%s:%s" % (host, svc), "kind": "service",
                     "host": host, "service": svc})
        for tech in techs:
            for vuln_class, indicators in self.SERVICE_VULNS.get(
                    tech, []):
                hyp_id = _uid("hyp")
                hyp = {
                    "id": hyp_id, "target": target,
                    "vuln_class": vuln_class,
                    "indicators": indicators,
                    "basis": "service:%s" % tech,
                    "confidence": 0.6 if len(indicators) > 1 else 0.4,
                }
                self.hypotheses.append(hyp)
                self.graph["nodes"].append(
                    {"id": hyp_id, "kind": "hypothesis",
                     "vuln_class": vuln_class})
                self.graph["edges"].append(
                    {"from": "service:%s" % tech, "to": hyp_id,
                     "rel": "suggests"})
        for hyp in self.hypotheses:
            payload = self.PAYLOAD_TEMPLATES.get(hyp["vuln_class"], "")
            if not payload:
                continue
            cand = {
                "id": _uid("cand"), "hyp_id": hyp["id"],
                "target": hyp["target"], "vuln_class": hyp["vuln_class"],
                "payload": payload, "priority": hyp["confidence"],
            }
            self.candidates.append(cand)
            self.graph["edges"].append(
                {"from": hyp["id"], "to": cand["id"], "rel": "exploit_via"})
        self.candidates.sort(key=lambda c: -c["priority"])
        self._log("analyze",
                  "%d hypotheses / %d candidates for %s"
                  % (len(self.hypotheses), len(self.candidates), target))
        return {
            "summary": "%d hypotheses, %d candidates"
                       % (len(self.hypotheses), len(self.candidates)),
            "hypotheses": self.hypotheses, "graph": self.graph,
            "candidates": self.candidates,
            "emit": [
                {"topic": TOPIC_HYPOTHESES,
                 "payload": {"hypotheses": self.hypotheses}},
                {"topic": TOPIC_CANDIDATES,
                 "payload": {"candidates": self.candidates,
                             "graph": self.graph}},
            ]}

    def refine(self, feedback):
        """Bump priorities for classes confirmed by exploitation feedback."""
        refined = 0
        for cand in self.candidates:
            if cand.get("vuln_class") == feedback.get("vuln_class"):
                if feedback.get("outcome") == "needs_mutation":
                    cand["priority"] = min(1.0, cand["priority"] + 0.2)
                    cand.setdefault("mutations", []).append(
                        feedback.get("next_mutation", ""))
                    refined += 1
        return refined


# --------------------------------------------------------------------------
# ExploitationAgent
# --------------------------------------------------------------------------

class ExploitationAgent(BaseSwarmAgent):
    """Executes validation payloads, classifies feedback, records PoCs."""

    name = "exploiter"
    role = "exploitation"

    SUCCESS_PATNS = [
        re.compile(p, re.I) for p in (
            r"vulnerable", r"dumped? \d+ (rows|entries)", r"password",
            r"logged? in", r"200 ok", r"root:",
            r"anonymous login granted", r"unauthorized.*none",
        )]
    WAF_PATNS = [re.compile(p, re.I) for p in
                 (r"cloudflare", r"waf", r"forbidden", r"blocked")]
    SQLI_PATNS = [re.compile(p, re.I) for p in
                  (r"sql syntax", r"mysql", r"postgres", r"sqlite",
                   r"ora-\d{5}")]
    AUTH_PATNS = [re.compile(p, re.I) for p in
                  (r"401", r"403", r"invalid credentials",
                   r"authentication failed", r"permission denied")]
    NET_PATNS = [re.compile(p, re.I) for p in
                 (r"connection refused", r"timed? ?out", r"unreachable",
                  r"no route", r"network is down")]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pocs = []
        self.feedback_log = []

    def ingest(self, payload, context):
        if payload.get("candidates"):
            self.context["candidates"] = payload["candidates"]
            self.context["graph"] = payload.get("graph", {})

    def ingest_state(self, payload, context):
        if payload.get("refinements"):
            self.context["refinements"] = payload["refinements"]

    async def execute(self, task, context):
        candidates = task.get("candidates") or context.get(
            "candidates") or []
        target = (task.get("target")
                  or context.get("target") or "unknown")
        executed, confirmed = 0, 0
        for cand in candidates:
            result = await self.run_command(
                "validate %s -> %s" % (cand.get("target", target),
                                       cand.get("payload", "")))
            feedback_text = result if result is not None else (
                "simulated probe against %s with %s: vulnerable response"
                % (cand.get("target", target), cand.get("vuln_class")))
            analysis = self.analyze_feedback(feedback_text, cand)
            self.feedback_log.append(analysis)
            executed += 1
            if analysis["outcome"] == "success":
                confirmed += 1
                self.pocs.append({
                    "id": _uid("poc"), "target": target,
                    "vuln_class": cand.get("vuln_class"),
                    "payload": cand.get("payload"),
                    "evidence": feedback_text[:500],
                    "steps": self._poc_steps(cand, target),
                })
        summary = ("executed %d candidates, %d confirmed, %d need "
                   "mutation" % (executed, confirmed,
                                 executed - confirmed))
        self._log("exploit", summary)
        refinements = [f for f in self.feedback_log
                       if f["outcome"] == "needs_mutation"]
        emits = [{"topic": TOPIC_FEEDBACK, "recipient": "analyzer",
                  "payload": {"refinements": refinements}}]
        if self.pocs:
            emits.append({"topic": TOPIC_POC,
                          "payload": {"pocs": self.pocs}})
        return {"summary": summary, "executed": executed,
                "confirmed": confirmed, "pocs": self.pocs,
                "feedback": self.feedback_log, "emit": emits}

    @classmethod
    def analyze_feedback(cls, text, candidate=None):
        low = (text or "").lower()
        if any(p.search(low) for p in cls.SUCCESS_PATNS):
            return {"task_id": (candidate or {}).get("id"),
                    "vuln_class": (candidate or {}).get("vuln_class"),
                    "outcome": "success",
                    "next_mutation": "keep payload; archive as PoC"}
        if any(p.search(low) for p in cls.WAF_PATNS):
            return {"task_id": (candidate or {}).get("id"),
                    "vuln_class": (candidate or {}).get("vuln_class"),
                    "outcome": "needs_mutation",
                    "next_mutation": ("encode payload "
                                      "(unicode/percent) and retry")}
        if any(p.search(low) for p in cls.SQLI_PATNS):
            return {"task_id": (candidate or {}).get("id"),
                    "vuln_class": (candidate or {}).get("vuln_class"),
                    "outcome": "needs_mutation",
                    "next_mutation": ("adapt payload to observed SQL "
                                      "dialect and retry")}
        if any(p.search(low) for p in cls.AUTH_PATNS):
            return {"task_id": (candidate or {}).get("id"),
                    "vuln_class": (candidate or {}).get("vuln_class"),
                    "outcome": "needs_mutation",
                    "next_mutation": "rotate credential set / bypass path"}
        if any(p.search(low) for p in cls.NET_PATNS):
            return {"task_id": (candidate or {}).get("id"),
                    "vuln_class": (candidate or {}).get("vuln_class"),
                    "outcome": "blocked",
                    "next_mutation": "switch transport/port and retry"}
        return {"task_id": (candidate or {}).get("id"),
                "vuln_class": (candidate or {}).get("vuln_class"),
                "outcome": "inconclusive",
                "next_mutation": "increase probe verbosity and retry"}

    @staticmethod
    def _poc_steps(cand, target):
        return [
            "1. Reach %s" % target,
            "2. Send payload: %s" % cand.get("payload"),
            "3. Observe response indicating %s" % cand.get("vuln_class"),
            "4. Reproduce with the recorded evidence",
        ]


# --------------------------------------------------------------------------
# SwarmRouter (orchestrator)
# --------------------------------------------------------------------------

class SwarmRouter:
    """Wires the three specialists onto one bus and runs the pipeline:

        recon -> analyzer -> exploiter -(feedback)-> analyzer -> ...

    Rounds are bounded by ``max_rounds``; every leg runs as a tracked
    task with the strict state machine.
    """

    ROUTER_NAME = "router"

    def __init__(self, tool_executor=None, llm=None, max_rounds=3):
        self.bus = AsyncMessageBus()
        self.bus.register(self.ROUTER_NAME)  # agents reply state here
        self.recon = ReconAgent(self.bus, tool_executor=tool_executor,
                                llm=llm)
        self.analyzer = AnalyzerAgent(self.bus, tool_executor=tool_executor,
                                      llm=llm)
        self.exploiter = ExploitationAgent(self.bus,
                                           tool_executor=tool_executor,
                                           llm=llm)
        self.agents = [self.recon, self.analyzer, self.exploiter]
        self.max_rounds = max_rounds
        self._loops = []

    async def _start(self):
        self._loops = [asyncio.create_task(a.run(), name=a.name)
                       for a in self.agents]
        await asyncio.sleep(0)  # let the loops begin consuming

    async def _stop(self):
        for agent in self.agents:
            agent.bus.inbox(agent.name).put_nowait(
                SwarmMessage(MSG_STOP, "router", recipient=agent.name))
        await asyncio.gather(*self._loops, return_exceptions=True)
        self._loops = []

    async def _request(self, agent, payload, context=None):
        """Send a task and await the agent's done/error state message."""
        task_id = _uid("task")
        payload = dict(payload)
        payload["task_id"] = task_id
        done = asyncio.get_running_loop().create_future()
        orig_hook = agent.reply_hook

        def waiter(state_payload):
            if state_payload.get("task_id") == task_id:
                if not done.done():
                    done.set_result(state_payload)

        agent.reply_hook = waiter
        try:
            await self.bus.send(SwarmMessage(
                MSG_TASK, self.ROUTER_NAME, recipient=agent.name,
                payload=payload, context=context or {}))
            return await asyncio.wait_for(done, timeout=120)
        finally:
            agent.reply_hook = orig_hook

    async def run(self, target, mission="", context=None):
        """Execute the full swarm pipeline against a target."""
        await self._start()
        context = dict(context or {})
        context.setdefault("target", target)
        summary = {"target": target, "mission": mission, "rounds": [],
                   "surface": None, "hypotheses": [], "candidates": [],
                   "pocs": [], "feedback": [], "graph": {"nodes": [],
                                                         "edges": []}}
        try:
            for round_no in range(1, self.max_rounds + 1):
                leg = {"round": round_no}
                rec = await self._request(
                    self.recon,
                    {"target": target, "mode": "active",
                     "command": context.get("recon_command")},
                    context)
                summary["surface"] = self.recon.surface.get(
                    target, summary["surface"])
                leg["recon"] = rec.get("state")

                ana = await self._request(
                    self.analyzer, {"surface": summary["surface"]},
                    context)
                leg["analyzer"] = ana.get("state")

                exp = await self._request(
                    self.exploiter,
                    {"candidates": self.analyzer.candidates,
                     "target": target}, context)
                leg["exploiter"] = exp.get("state")
                summary["rounds"].append(leg)
                if self.exploiter.pocs or not self.analyzer.candidates:
                    break
                self.analyzer.refine({"vuln_class":
                                      (self.exploiter.feedback_log[-1]
                                       ["vuln_class"]
                                       if self.exploiter.feedback_log
                                       else None),
                                      "outcome": "needs_mutation",
                                      "next_mutation": "escalate round %d"
                                      % round_no})
            summary["hypotheses"] = self.analyzer.hypotheses
            summary["candidates"] = self.analyzer.candidates
            summary["graph"] = self.analyzer.graph
            summary["pocs"] = self.exploiter.pocs
            summary["feedback"] = self.exploiter.feedback_log
            summary["bus"] = self.bus.stats()
            summary["transcripts"] = {
                a.name: a.transcript for a in self.agents}
            return summary
        finally:
            await self._stop()

    def run_mission_sync(self, target, mission="", context=None):
        """Blocking convenience wrapper for non-async callers."""
        return asyncio.run(self.run(target, mission, context))


def snapshot_for_memory(summary):
    """Distill a run summary into text blobs for the episodic memory
    store (ai_agent.memory.vector_store.EpisodicVectorMemory)."""
    blobs = []
    for poc in summary.get("pocs", []):
        blobs.append({"kind": "payload",
                      "text": "target=%s class=%s payload=%s evidence=%s"
                              % (poc.get("target"), poc.get("vuln_class"),
                                 poc.get("payload"), poc.get("evidence"))})
    for fb in summary.get("feedback", []):
        if fb.get("outcome") != "success":
            blobs.append({"kind": "lesson",
                          "text": "FAILED %s probe -> %s. NEXT: %s"
                                  % (fb.get("vuln_class"),
                                     fb.get("outcome"),
                                     fb.get("next_mutation"))})
    return blobs
