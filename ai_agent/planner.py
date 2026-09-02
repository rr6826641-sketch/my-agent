"""Goal-Oriented Action Planning (GOAP) engine for red-team operations.

Breaks a high-level engagement target down into a structured
Goal-Action-State tree (Target -> Initial Access -> Privilege Escalation
-> Persistence -> Objective) and plans the concrete action path with an
A* forward search over preconditions/effects.

Key behaviours:
  * GOAP graph construction - a complex instruction is decomposed into
    kill-chain stages before any tool runs; each stage lists its primary
    branch plus alternative branches (Path B, Path C, ...).
  * Blocked-state detection - tool results are scanned for WAF triggers,
    closed/filtered ports, failed authentication and hard errors.
  * Automatic back-tracking - when the active branch is blocked the
    planner selects the next viable alternative branch at the deepest
    stage whose goal is still unmet, and NEVER terminates the operation
    (bounded by a pivot cap only).
"""

import heapq
import logging
import re
import time
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Hard cap on back-track (branch switch) events per plan.
_MAX_PIVOTS = 12


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

class GOAPAction:
    """One planning action: preconditions -> effects, with a cost."""

    def __init__(self, name: str, stage: str, label: str,
                 preconditions: Iterable[str],
                 add_effects: Iterable[str],
                 cost: float = 1.0,
                 tools: str = "",
                 detail: str = "") -> None:
        self.name = name
        self.stage = stage
        self.label = label
        self.preconditions: FrozenSet[str] = frozenset(
            p for p in (preconditions or ()) if p)
        self.add_effects: FrozenSet[str] = frozenset(
            e for e in (add_effects or ()) if e)
        self.cost = max(0.1, float(cost))
        self.tools = tools
        self.detail = detail

    def satisfied_by(self, facts: FrozenSet[str]) -> bool:
        return self.preconditions.issubset(facts)

    def apply(self, facts: FrozenSet[str]) -> FrozenSet[str]:
        return (facts | self.add_effects)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "stage": self.stage, "label": self.label,
            "preconditions": sorted(self.preconditions),
            "effects": sorted(self.add_effects), "cost": self.cost,
            "tools": self.tools, "detail": self.detail,
        }


# Kill-chain stage keys, in execution order. Each stage's goal is a single
# world fact; the stage is complete once that fact holds in the world state.
# (stage key, human label, goal world-fact). Each stage is complete once
# its goal fact holds in the world state.
STAGE_GOALS: Tuple[Tuple[str, str, str], ...] = (
    ("recon", "Reconnaissance", "surface_mapped"),
    ("initial_access", "Initial Access", "foothold"),
    ("priv_esc", "Privilege Escalation", "elevated"),
    ("persistence", "Persistence", "durable"),
    ("objective", "Objective / Impact", "objective_complete"),
)


def _domain_actions() -> List[GOAPAction]:
    """The red-team action library. Alternatives that achieve the same
    stage goal share their add_effects - the A* planner treats them as
    interchangeable branches and the back-tracker walks them Path A/B/C."""
    return [
        # ---- stage: recon -> surface_mapped ------------------------------
        GOAPAction(
            "recon_passive", "recon", "Passive recon (OSINT/DNS/WHOIS)",
            (), {"surface_mapped"}, cost=1.0,
            tools="subdomain_enum, dns_lookup, whois, ssl_info, httpx_probe",
            detail="zero-touch enumeration; safest first branch"),
        GOAPAction(
            "recon_active", "recon", "Active scan (ports/services/paths)",
            (), {"surface_mapped"}, cost=1.5,
            tools="port_scan, nmap_scan, tech_detect, check_headers, "
                  "dir_fuzz, extract_links",
            detail="direct probing; use when passive data is insufficient"),
        # ---- stage: initial_access -> foothold ---------------------------
        GOAPAction(
            "access_cve", "initial_access", "Exploit known CVE/service",
            {"surface_mapped"}, {"foothold"}, cost=2.0,
            tools="cve_lookup, nuclei_scan, sqli_test, cmd_inject_test",
            detail="match exposed version to a public exploit"),
        GOAPAction(
            "access_injection", "initial_access",
            "Web injection chain (SQLi/SSTI/XXE -> code exec)",
            {"surface_mapped"}, {"foothold"}, cost=2.5,
            tools="sqli_test, ssti_test, xxe_test, path_traversal_test",
            detail="injection primitives observed during analysis"),
        GOAPAction(
            "access_creds", "initial_access",
            "Credential attack (brute/spray/reuse/default)",
            {"surface_mapped"}, {"foothold"}, cost=3.0,
            tools="run_terminal (hydra/medusa), jwt_attack",
            detail="use when services expose auth and no CVE fits"),
        GOAPAction(
            "access_misconfig", "initial_access",
            "Misconfiguration abuse (exposed admin, default paths, "
            "permissive CORS/upload)",
            {"surface_mapped"}, {"foothold"}, cost=2.2,
            tools="dir_fuzz, cors_check, graphql_check, check_headers",
            detail="path B when direct exploitation is blocked/WAF'd"),
        # ---- stage: priv_esc -> elevated ---------------------------------
        GOAPAction(
            "pe_kernel", "priv_esc", "Kernel/service exploit on host",
            {"foothold"}, {"elevated"}, cost=3.0,
            tools="run_terminal, cve_lookup",
            detail="local exploit matching kernel/OS version"),
        GOAPAction(
            "pe_sudo", "priv_esc",
            "Sudo/suid/cron misconfiguration abuse",
            {"foothold"}, {"elevated"}, cost=2.5,
            tools="run_terminal (linpeas/winPEAS, sudo -l)",
            detail="enumerate local privesc vectors first"),
        GOAPAction(
            "pe_creds", "priv_esc",
            "Credential harvesting & reuse (configs, history, keys)",
            {"foothold"}, {"elevated"}, cost=2.8,
            tools="run_python, run_terminal",
            detail="loot secrets from the foothold and reuse"),
        # ---- stage: persistence -> durable -------------------------------
        GOAPAction(
            "persist_webshell", "persistence", "Web shell on writable root",
            {"elevated"}, {"durable"}, cost=2.0,
            tools="run_terminal, write_file",
            detail="when a web root is writable"),
        GOAPAction(
            "persist_service", "persistence",
            "Backdoor service / scheduled task / cron",
            {"elevated"}, {"durable"}, cost=2.2,
            tools="run_terminal",
            detail="system-level persistence mechanism"),
        GOAPAction(
            "persist_key", "persistence",
            "Authorized key / additional account",
            {"elevated"}, {"durable"}, cost=1.8,
            tools="run_terminal",
            detail="ssh authorized_keys or a new privileged account"),
        # ---- stage: objective --------------------------------------------
        GOAPAction(
            "objective_prove", "objective",
            "Execute objective & capture proof-of-impact",
            {"durable"}, {"objective_complete"}, cost=1.0,
            tools="add_finding, verify_finding, run_python",
            detail="safe PoC + evidence chain"),
        GOAPAction(
            "objective_report", "objective",
            "Write validated engagement report + remediation",
            {"objective_complete"}, {}, cost=1.0,
            tools="write_report",
            detail="final deliverable"),
    ]


# ---------------------------------------------------------------------------
# Blocked-state detection
# ---------------------------------------------------------------------------

_BLOCKED_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("waf",
     r"\bwaf\b|cloudflare|incapsula|akamai|blocked by|rate.?limit|"
     r"\b403\b|forbidden|captcha|challenge page"),
    ("closed_port",
     r"connection refused|\bclosed\b|filtered|no route|unreachable|"
     r"timed? ?out|timeout|100% packet loss|could not connect|"
     r"\bRST\b|no service"),
    ("auth_fail",
     r"authenticat\w* fail|invalid credential|access denied|"
     r"permission denied|login incorrect|unauthorized|\b401\b|"
     r"\b403\b|bad request.*token|login failed"),
    ("hard_error",
     r"traceback|\bfatal\b|segmentation fault|exception (?:in|while)|"
     r"command not found|no such file or directory"),
)

_RE_BLOCKED = [(cat, re.compile(pat, re.I)) for cat, pat in _BLOCKED_PATTERNS]

# Result prefixes that mean the tool itself failed outright.
_ERROR_PREFIXES = ("[LLM error]", "[error]", "[tool error]")


def classify_result(result: str) -> Optional[Tuple[str, str]]:
    """Return (category, matched-snippet) when a tool result looks blocked,
    else None. First matching category wins (WAF > closed port > auth >
    hard error)."""
    text = (result or "")[:4000]
    if not text:
        return None
    stripped = text.lstrip()
    if any(stripped.startswith(p) for p in _ERROR_PREFIXES):
        return ("hard_error", stripped[:120])
    for cat, rx in _RE_BLOCKED:
        m = rx.search(text)
        if m:
            start = max(0, m.start() - 40)
            snippet = " ".join(text[start:m.end() + 60].split())
            return (cat, snippet[:160])
    return None


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

class GOAPPlanner:
    """Dynamic goal planner: builds a Goal-Action-State tree for a target,
    plans with A*, observes tool results, and back-tracks to alternative
    branches when a path is blocked."""

    def __init__(self, max_pivots: int = _MAX_PIVOTS) -> None:
        self.actions: List[GOAPAction] = _domain_actions()
        self.active = False
        self.objective = ""
        self.target = ""
        self.facts: FrozenSet[str] = frozenset()
        self.goal = "objective_complete"
        self.plan: List[GOAPAction] = []          # current primary path
        self.step_index = 0                        # next plan step to run
        self.completed_steps: List[str] = []
        self.blocked: List[Dict[str, Any]] = []    # blocked branch records
        self.pivots: List[Dict[str, Any]] = []     # back-track events
        self.max_pivots = max_pivots
        self.plan_built = False

    # ------------------------------------------------------- planning (A*)

    def _heuristic(self, facts: FrozenSet[str]) -> float:
        """Cheap estimate: count of unsatisfied stage goals still between
        the current facts and the objective."""
        h = 0.0
        for _key, _label, goal_fact in STAGE_GOALS:
            if goal_fact not in facts:
                h += 0.5
        if self.goal not in facts:
            h += 0.5
        return h

    def plan_graph(self, objective: str, target: str = "",
                   start_facts: Optional[Iterable[str]] = None
                   ) -> Optional[List[GOAPAction]]:
        """Build the Goal-Action-State tree and return the best action path
        (list of GOAPAction) from the start facts to the goal, or None."""
        self.objective = (objective or "").strip()[:180]
        self.target = (target or "").strip()[:120]
        self.facts = frozenset(start_facts or ())
        # Game-Master World-State fusion: seed the planner with facts
        # from the central world model so completed stages (mapped
        # surface, known footholds, elevations) are never re-planned.
        try:
            from .world_model import get_manager
            self.facts = self.facts | frozenset(
                get_manager().planning_facts())
        except Exception:
            pass
        start = self.facts
        # A* over world states (states are frozensets of facts).
        open_set: List[Tuple[float, float, int, FrozenSet[str],
                             Tuple[GOAPAction, ...]]] = []
        counter = 0
        heapq.heappush(open_set, (self._heuristic(start), 0.0, counter,
                                   start, ()))
        explored: List[FrozenSet[str]] = []
        while open_set and len(explored) < 4000:
            _f, g, _c, facts, path = heapq.heappop(open_set)
            if self.goal in facts:
                self.plan = list(path)
                self.plan_built = True
                self.active = True
                self.step_index = 0
                return self.plan
            if facts in explored:
                continue
            explored.append(facts)
            for act in self.actions:
                if not act.satisfied_by(facts):
                    continue
                nxt = act.apply(facts)
                if nxt in explored:
                    continue
                counter += 1
                heapq.heappush(open_set, (
                    g + act.cost + self._heuristic(nxt), g + act.cost,
                    counter, nxt, path + (act,)))
        logger.info("GOAP: no plan found for objective=%r", self.objective)
        return None

    # ------------------------------------------------------- observations

    def observe(self, tool: str, args: str, result: str
                ) -> Optional[Dict[str, Any]]:
        """Feed one tool result into the planner.

        Returns an event dict when the planner reacts:
          {"event": "step_done"}     - plan step completed
          {"event": "blocked", ...}  - blocked state detected
          {"event": "pivot", ...}    - back-tracked to an alternative branch
        or None when nothing changed."""
        if not self.active or not self.plan:
            return None
        hit = classify_result(result)
        if hit is None:
            # Mark the current step done and advance through satisfied
            # preconditions of upcoming steps.
            done = self.plan[self.step_index] if (
                self.step_index < len(self.plan)) else None
            if done is not None:
                self.completed_steps.append(done.name)
                self.facts = done.apply(self.facts)
                self.step_index += 1
            if self.step_index >= len(self.plan):
                self.active = False
            return {"event": "step_done", "step": done.name if done else "",
                    "index": self.step_index,
                    "remaining": max(0, len(self.plan) - self.step_index)}
        return self._handle_blocked(tool, hit)

    def _handle_blocked(self, tool: str,
                        hit: Tuple[str, str]) -> Dict[str, Any]:
        category, snippet = hit
        rec = {"tool": tool, "category": category, "evidence": snippet,
               "at": time.time()}
        self.blocked.append(rec)
        if len(self.blocked) > 40:
            del self.blocked[:-40]
        blocked_step = (self.plan[self.step_index].name
                        if self.step_index < len(self.plan) else "?")
        pivot = self._backtrack(category)
        event = {"event": "blocked", "category": category,
                 "evidence": snippet, "step": blocked_step,
                 "pivot": pivot, "pivots_used": len(self.pivots)}
        if pivot:
            event["event"] = "pivot"
            event["next_action"] = pivot["next_action"]
            event["reason"] = pivot["reason"]
        return event

    def _backtrack(self, category: str) -> Optional[Dict[str, Any]]:
        """Select the next viable branch. Never terminates the operation:
        walks forward through remaining plan alternatives, then re-plans
        from the current world facts with the blocked branch's effects
        excluded. Bounded only by max_pivots."""
        if len(self.pivots) >= self.max_pivots:
            return None
        if self.goal in self.facts:
            self.active = False
            return None
        # Re-plan from current facts: exclude the branch that just got
        # blocked plus every branch already tried in earlier pivots. Other
        # (untried) actions - including future-stage ones - stay eligible.
        tried = {r.get("step") for r in self.pivots}
        current = {self.plan[self.step_index].name
                   if self.step_index < len(self.plan) else ""}
        alt = self._plan_excluding(current | tried)
        if not alt:
            return None
        self.plan = alt
        self.step_index = 0
        nxt = alt[0]
        self.pivots.append({"step": nxt.name, "category": category,
                            "at": time.time()})
        return {"next_action": nxt.name, "next_label": nxt.label,
                "next_tools": nxt.tools, "detail": nxt.detail,
                "reason": ("branch blocked (%s); back-tracked to "
                           "alternative path" % category)}

    def _plan_excluding(self, exclude: Iterable[str]
                        ) -> Optional[List[GOAPAction]]:
        """A* re-plan from current facts, skipping excluded action names."""
        exclude = set(exclude or ())
        open_set: List[Tuple[float, float, int, FrozenSet[str],
                             Tuple[GOAPAction, ...]]] = []
        counter = 0
        heapq.heappush(open_set, (self._heuristic(self.facts), 0.0, counter,
                                  self.facts, ()))
        explored: List[FrozenSet[str]] = []
        while open_set and len(explored) < 2000:
            _f, g, _c, facts, path = heapq.heappop(open_set)
            if self.goal in facts:
                return list(path)
            if facts in explored:
                continue
            explored.append(facts)
            for act in self.actions:
                if act.name in exclude or not act.satisfied_by(facts):
                    continue
                nxt = act.apply(facts)
                if nxt in explored:
                    continue
                counter += 1
                heapq.heappush(open_set, (
                    g + act.cost + self._heuristic(nxt), g + act.cost,
                    counter, nxt, path + (act,)))
        return None

    # ------------------------------------------------------- rendering

    def branches_for(self, stage: str) -> List[GOAPAction]:
        """All actions achieving the stage goal, cheapest first (the branch
        list: Path A / B / C ...)."""
        acts = [a for a in self.actions if a.stage == stage]
        return sorted(acts, key=lambda a: a.cost)

    def render_plan_block(self) -> str:
        """The [GOAP PLAN] block injected before tool execution begins."""
        lines = ["[GOAP PLAN] objective=%s target=%s"
                 % (self.objective or "-", self.target or "-")]
        for idx, (key, label, goal_fact) in enumerate(STAGE_GOALS):
            branches = self.branches_for(key)
            names = ["Path %s: %s (%s)" % (
                chr(65 + i), a.label, a.tools) for i, a in enumerate(branches)]
            done = goal_fact in self.facts
            status = ("completed" if done else
                      "ACTIVE" if any(a.stage == key for a in
                                      self.plan[self.step_index:])
                      else "pending")
            lines.append("  %d. %s [%s] goal=%s" % (
                idx + 1, label, status, goal_fact))
            for n in names:
                lines.append("       %s" % n)
        lines.append(
            "A blocked branch (WAF, closed port, failed auth, hard error) "
            "triggers automatic back-tracking to the next alternative "
            "branch - the operation continues, it never aborts.")
        return "\n".join(lines)

    def render_pivot_block(self, event: Dict[str, Any]) -> str:
        """The [GOAP PIVOT] block injected after a back-track."""
        p = event.get("pivot") or {}
        return ("[GOAP PIVOT] blocked=%s (%s) at step=%s -> switching to "
                "%s (%s) using %s. Operation continues on Path B." % (
                    event.get("category", "?"),
                    (event.get("evidence") or "")[:120],
                    event.get("step", "?"),
                    p.get("next_action", "?"), p.get("next_label", ""),
                    p.get("next_tools", "")))

    def snapshot(self) -> Dict[str, Any]:
        return {
            "active": self.active, "objective": self.objective,
            "target": self.target, "facts": sorted(self.facts),
            "plan": [a.name for a in self.plan],
            "step_index": self.step_index,
            "completed": list(self.completed_steps),
            "pivots": len(self.pivots), "blocked": len(self.blocked),
            "plan_built": self.plan_built,
        }



