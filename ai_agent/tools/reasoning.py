"""HackerAI Reasoning Engine - the agent's 'brain'.

Senior-engineer thinking exposed as tools so the agent plans, reasons and
self-reviews before acting:

  tool_plan_task(task, context="")  -> ordered plan with per-step verification
  tool_reason(question, premises="")-> step-by-step reasoning chain + confidence
  tool_reflect(answer, evidence="") -> self-review checklist (gaps, errors, fixes)
"""

from __future__ import annotations

_KEYWORDS = {
    "recon": ["recon", "scan", "enumerate", "osint", "subdomain", "footprint", "fingerprint"],
    "exploit": ["exploit", "pwn", "bypass", "rce", "inject", "payload", "attack"],
    "debug": ["debug", "error", "crash", "traceback", "broken", "not working", "hang"],
    "research": ["research", "search", "cve", "citation", "source", "compare", "investigate"],
    "report": ["report", "summary", "writeup", "document", "review"],
    "code": ["implement", "write", "refactor", "build", "feature", "function", "fix"],
}

_TEMPLATES = {
    "recon": [
        "Scope + target inventory define karo (domain, IPs, repo, dirs)",
        "Passive recon: OSINT, tech stack, subdomains, exposed endpoints",
        "Active enumeration: ports/services, hidden paths, params",
        "Prioritize attack surface (severity-wise) + evidence record karo",
        "Har finding ke saath source cite karo",
    ],
    "exploit": [
        "Entry point aur parameters identify karo",
        "Auth/session context samjho (roles, tokens, CSRF)",
        "Payload variants test karo (encoder, casing, context)",
        "Impact verify karo proof ke saath (screenshot/response)",
        "Reproduction steps + remediation document karo",
    ],
    "debug": [
        "Error message poori padho, symptom vs cause alag karo",
        "Minimal reproduction banao (smallest input/steps)",
        "Bisect karo: config, dependency, code path",
        "Failure state inspect karo (logs, stack, data)",
        "Root cause fix karo + regression test chalao",
    ],
    "research": [
        "Intent clear karo: keywords, jargon, non-EN glosses",
        "1-3 query variants generate karo (generate_queries)",
        "Fetch + dedupe karo, empty-URL sources drop karo",
        "Har fact extract karke citation banao (build_citation)",
        "Conflicting sources cross-check karo, unverified mark karo",
    ],
    "report": [
        "Sirf verified findings likho, severity ke sath",
        "Har finding: evidence + impact + exploit chain",
        "Remediation + confidence level har item pe",
        "Open questions / needs-validation alag section",
    ],
    "code": [
        "Requirement split karo: input -> behavior -> output",
        "Minimal implementation design (existing patterns follow karo)",
        "Code likho + edge cases (empty, unicode, errors)",
        "Test: happy path + negative + regression",
        "Commit with clear message",
    ],
}

_ADVICE = {
    "recon": "Never assume: har finding evidence ke sath verify karo; bina URL/source ke claim na karo.",
    "exploit": "Har step ke baad impact confirm karo; working PoC = proof.",
    "debug": "Symptom nahi, ROOT CAUSE fix karo.",
    "research": "Citation mandatory: Source: Title - URL (snippet).",
    "report": "Severity: Critical > High > Medium > Low; sirf demonstrated impact.",
    "code": "Pehle reproduce, phir fix; regression test zaroori.",
}

_REASON_STEPS = [
    "Facts (jo verified hain, source ke sath)",
    "Assumptions (mark karo: unverified)",
    "Relevant knowledge (fundamentals, CVEs, prior findings)",
    "Deduction (step-by-step: A -> B -> C)",
    "Counter-check (what breaks this conclusion?)",
    "Conclusion + confidence (high/med/low) + open questions",
]


def _detect_kind(task: str) -> str:
    t = task.lower()
    best, best_hits = "code", 0
    for kind, kws in _KEYWORDS.items():
        hits = sum(1 for k in kws if k in t)
        if hits > best_hits:
            best, best_hits = kind, hits
    return best


def tool_plan_task(task: str, context: str = "") -> dict:
    """Break any goal into ordered, verifiable execution steps."""
    task = (task or "").strip()
    if not task:
        return {"error": "task is required", "steps": []}
    kind = _detect_kind(task)
    steps = []
    for i, action in enumerate(_TEMPLATES[kind], 1):
        steps.append({"step": i, "action": action,
                      "verify": "output + evidence check", "done": False})
    return {"task": task, "kind": kind, "steps": steps,
            "advice": _ADVICE[kind], "context": (context or "")[:200]}


def tool_reason(question: str, premises: str = "") -> dict:
    """Structured reasoning chain for any question/analysis."""
    q = (question or "").strip()
    if not q:
        return {"error": "question is required"}
    prems = [p.strip() for p in (premises or "").splitlines() if p.strip()][:8]
    return {
        "question": q,
        "method": "deductive (facts -> conclusion) + abductive (best explanation)",
        "premises": prems or ["(koi verified premise nahi diya - pehle verify karo)"],
        "chain": _REASON_STEPS,
        "rule": "Bina evidence ke conclusion never 'confirmed' bolo - 'unverified' likho.",
    }


def tool_reflect(answer: str, evidence: str = "") -> dict:
    """Self-review an answer before delivering: catch gaps and errors."""
    a = (answer or "").strip()
    if not a:
        return {"error": "answer is required"}
    return {
        "answer_summary": a[:300],
        "review_checklist": [
            "Har claim ke paas evidence/citation hai?",
            "Koi assumption bina verify ke nahi chhupi?",
            "Root cause covered hai ya sirf symptom?",
            "Severity/confidence honest hai?",
            "Koi simpler/better approach miss hua?",
        ],
        "verdicts": {
            "verified": None,
            "needs_evidence": [],
            "corrections": [],
            "follow_up": ["Missing evidence collect karo", "Affected scope verify karo"],
        },
        "rule": "Self-review ke baad hi final answer do; gaps ko openly batao.",
    }
