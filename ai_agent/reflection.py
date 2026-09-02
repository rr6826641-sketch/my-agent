"""Self-Reflection Engine for red-team tool executions.

After EVERY tool execution - and in particular after failed exploitation
attempts - the engine runs an internal reflection loop that answers:

  1. What was the EXPECTED vs. the ACTUAL stdout/stderr result?
  2. WHY did the payload/tool fail (root cause: WAF, closed port, bad
     auth, wrong syntax, host unreachable, ...)?
  3. WHAT specific mutation or parameter shift should be applied next?

Each reflection is appended to ``memory/reflection_history.json`` for
cross-session retrieval, and successful exploitation evidence is archived
into the episodic vector memory (``ai_agent/memory/vector_store.py``) so
future sessions can recall the winning technique.

The engine is fully heuristic (no LLM dependency): failure roots are
classified from stderr/stdout fingerprints and mapped to concrete,
actionable mutations (payload encoding, port/proto switch, timing shift,
credential rotation, ...).
"""

import json
import logging
import os
import re
import threading
import time

from .memory.vector_store import EpisodicVectorMemory

logger = logging.getLogger(__name__)

_MAX_RESULT_CHARS = 6000
_MAX_HISTORY = 2000

# (regex, failure_root, why, mutation) - ordered by specificity.
_FAILURE_SIGNATURES = [
    (r"403|blocked|forbidden|waf|cloudflare|sucuri|imperva|akamai|"
     r"mod_?security", "waf_block",
     "Request was rejected by a WAF / edge filter (403 or explicit "
     "block).",
     "Re-encode the payload (double-URL, unicode-escape, case-tamper, "
     "chunked transfer) and retry from a different header/User-Agent; "
     "consider a parameter-pollution variant."),
    (r"429|rate.?limit|too many requests|throttl", "rate_limit",
     "Rate limiter / throttling kicked in.",
     "Add delays (throttle 1 req/2-5s), rotate source IP/proxy, and "
     "reduce scan concurrency before retrying."),
    (r"401|unauthorized|authentication failed|access denied|"
     r"login failed|invalid credentials", "auth_failure",
     "Authentication failed - credentials or session token are invalid "
     "or missing.",
     "Re-check credentials/session cookie, try default or previously "
     "leaked creds for this target, or obtain a fresh token before "
     "re-running."),
    (r"404|not found", "not_found",
     "Endpoint/path does not exist (404).",
     "Re-fuzz the path with a bigger wordlist or different extensions; "
     "verify the base URL and virtual-host routing."),
    (r"connection refused|econnrefused|couldn'?t connect|no route to "
     r"host|host unreachable|network unreachable|econnreset|timed? ?out|"
     r"timeout", "network_unreachable",
     "Network-level failure - port closed, host down, or firewalled.",
     "Switch protocol/port (http<->https, alt ports), re-ping the host, "
     "or pivot through a different vantage point; mark the port closed "
     "and let GOAP pick an alternative branch."),
    (r"500|internal server error", "server_error",
     "Target returned a 500 - payload likely broke server-side parsing.",
     "The vector REACHED the sink but malformed it: simplify the "
     "payload, remove destructive branches, and try a less invasive "
     "variant to confirm injection before escalating."),
    (r"sql(ite|server)? (syntax )?error|mysql|postgresql|syntax error|"
     r"unterminated|odbc|sqlstate", "sqli_feedback",
     "Raw SQL error leaked - injection point confirmed but payload "
     "syntax wrong for the backend.",
     "Adapt the payload to the backend dialect (e.g. quote handling, "
     "comment style -- vs #, version-specific functions) and re-run; "
     "escalate to UNION/error-based extraction."),
    (r"permission denied|access is denied|eacces|operation not permitted",
     "permission_denied",
     "Insufficient privileges on the target context.",
     "Escalate first: enumerate sudo/SUID/token privileges, then retry "
     "the original action from the elevated context."),
    (r"command not found|not recognized|no such file or directory",
     "bad_command",
     "Local/tool-side error - bad syntax, missing binary or wrong path.",
     "Fix the command syntax or install/locate the missing binary; "
     "quote arguments properly and re-run."),
]

_SUCCESS_SIGNATURES = [
    r"vulnerable",
    r"success(fully)?",
    r"exploit (succeeded|worked)",
    r"root@|uid=0|www-data\b",
    r"password(_to)?(\s+is)?\s*[:=]",
    r"\bopen\b.{0,20}\bport\b",
    r"shell.{0,30}(spawned|obtained|session)",
    r"logged in|login successful",
    r"dumped|admin hash|password hash",
]

_SUCCESS_RE = [re.compile(p, re.IGNORECASE) for p in _SUCCESS_SIGNATURES]

_EXPECTED_HINTS = [
    (r"nmap|port.?scan", "List of open ports with service versions."),
    (r"sqlmap|sql.?inject",
     "Confirmation of injectable parameter and dumped data (or at least "
     "injectable=True)."),
    (r"hydra|brute.?force|password.?spray",
     "A valid credential pair (login:password) discovered."),
    (r"nikto|dirb|gobuster|ferox|fuzz",
     "Discovered endpoints/dirs beyond the 404 baseline."),
    (r"shell|reverse|bind",
     "Interactive command execution on the target."),
    (r"privesc|sudo|suid|winpeas|linpeas",
     "A privilege-escalation vector or elevated shell."),
    (r"curl|wget|http|request",
     "HTTP response with expected status/body proving the injection or "
     "access."),
    (r"scan|enumerat",
     "Enumerated surface: hosts, shares, users or services."),
]


def _infer_expected(tool: str, args: str) -> str:
    blob = (tool + " " + str(args or "")).lower()
    for pat, expected in _EXPECTED_HINTS:
        if re.search(pat, blob):
            return expected
    return ("Tool completes and returns evidence relevant to the current "
            "GOAP stage (open ports, valid creds, injected output, ...).")


def _excerpt(text: str, limit: int = 400) -> str:
    text = (text or "").strip().replace("\n", " ")
    text = re.sub(r"\s{2,}", " ", text)
    return text[:limit]


def _success_kind(tool: str) -> str:
    t = (tool or "").lower()
    if any(k in t for k in ("sqli", "xss", "inject", "exploit", "fuzz")):
        return EpisodicVectorMemory.KIND_PAYLOAD
    if any(k in t for k in ("waf", "bypass", "encode", "evasion")):
        return EpisodicVectorMemory.KIND_BYPASS
    return EpisodicVectorMemory.KIND_METHODOLOGY


class ReflectionEngine:
    """Runs the post-execution reflection loop and persists lessons."""

    def __init__(self, history_path: str = None,
                 episodic: EpisodicVectorMemory = None) -> None:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        mem_dir = os.path.join(base, "memory")
        os.makedirs(mem_dir, exist_ok=True)
        self.history_path = history_path or os.path.join(
            mem_dir, "reflection_history.json")
        self.episodic = episodic or EpisodicVectorMemory(
            persist_dir=mem_dir)
        self._lock = threading.RLock()

    def reflect(self, tool: str, args: str, result: str,
                expected: str = None, target: str = "") -> dict:
        """Evaluate one tool execution and return the reflection record.

        The record answers the three canonical questions (expected vs
        actual, root cause, next mutation) and is persisted to
        ``reflection_history.json``. Successful exploitation evidence is
        additionally archived into the episodic vector store.
        """
        result = (result or "")[:_MAX_RESULT_CHARS]
        outcome, _ = self._classify(result)
        rec = {
            "ts": time.time(),
            "ts_human": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tool": tool,
            "args": _excerpt(str(args or ""), 300),
            "target": target,
            "expected": expected or _infer_expected(tool, args),
            "actual": _excerpt(result, 400),
            "outcome": outcome,           # success | failure | neutral
            "failure_root": "",
            "why_failed": "",
            "next_mutation": "",
            "tags": [],
        }
        if outcome == "failure":
            sig = self._signature_for(result)
            if sig:
                rec["failure_root"] = sig[1]
                rec["why_failed"] = sig[2]
                rec["next_mutation"] = sig[3]
            else:
                rec["failure_root"] = "unclassified_failure"
                rec["why_failed"] = (
                    "Tool reported an error without a known fingerprint; "
                    "inspect stderr above.")
                rec["next_mutation"] = (
                    "Re-read the error output, adjust the most suspicious "
                    "argument (payload, path or credentials), and retry a "
                    "minimal variant first.")
            rec["tags"] = [t for t in (rec["failure_root"], tool) if t]
            # Feed the lesson to the episodic layer (dormant knowledge
            # for future sessions).
            try:
                self.episodic.archive_lesson(
                    "FAILED %s %s -> %s: %s NEXT: %s" % (
                        tool, rec["args"], rec["failure_root"],
                        rec["why_failed"], rec["next_mutation"]),
                    tags=rec["tags"], target=target, outcome="failure")
            except Exception as exc:
                logger.warning("episodic lesson archive failed: %s", exc)
        elif outcome == "success":
            rec["next_mutation"] = (
                "Keep this technique; archive the working payload and "
                "escalate to the next kill-chain stage.")
            try:
                self.episodic.archive(
                    _success_kind(tool), result,
                    tags=[tool, "success"], target=target,
                    outcome="success")
            except Exception as exc:
                logger.warning("episodic success archive failed: %s", exc)
        else:  # neutral
            rec["next_mutation"] = (
                "No explicit failure; continue the current plan but "
                "verify the output actually advanced the stage goal.")
        self._append(rec)
        return rec

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _classify(result: str) -> tuple:
        blob = (result or "").strip()
        if blob == "" or "[cancelled by user]" in result:
            return "neutral", None
        for rx in _SUCCESS_RE:
            if rx.search(result):
                return "success", None
        hard_fail = any(s in blob.lower() for s in (
            "error", "failed", "refused", "denied", "timeout",
            "unreachable", "blocked", "exception", "traceback", "403",
            "401", "404", "429", "500", "not found"))
        if hard_fail:
            return "failure", None
        return "neutral", None

    @staticmethod
    def _signature_for(result: str):
        for rx, root, why, mutation in _FAILURE_SIGNATURES:
            if re.search(rx, result or "", re.IGNORECASE):
                return (rx, root, why, mutation)
        return None

    def _append(self, rec: dict) -> None:
        with self._lock:
            try:
                history = []
                try:
                    with open(self.history_path, "r",
                              encoding="utf-8") as fh:
                        data = json.load(fh)
                    history = data.get("reflections", []) \
                        if isinstance(data, dict) else data
                    if not isinstance(history, list):
                        history = []
                except FileNotFoundError:
                    pass
                except Exception as exc:
                    logger.warning("reflection history load failed: %s",
                                   exc)
                history.append(rec)
                if len(history) > _MAX_HISTORY:
                    history = history[-_MAX_HISTORY:]
                tmp = self.history_path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump({"reflections": history}, fh,
                              ensure_ascii=False, indent=1)
                os.replace(tmp, self.history_path)
            except Exception as exc:
                logger.warning("reflection history save failed: %s", exc)

    # -- cross-session retrieval ---------------------------------------------

    def lessons_for(self, tool: str = "", args: str = "",
                    target: str = "", limit: int = 5) -> list:
        """Relevant past lessons (failed attempts) for the given context."""
        query = " ".join(x for x in (tool, args, target) if x).strip()
        if not query:
            return []
        try:
            hits = self.episodic.query(
                query, top_k=limit * 2,
                kind=EpisodicVectorMemory.KIND_LESSON)
        except Exception:
            return []
        return hits[:limit]

    def render_lesson_block(self, tool: str = "", args: str = "",
                            target: str = "") -> str:
        """[LESSONS] system block for the LLM, or '' when none apply."""
        lessons = self.lessons_for(tool=tool, args=args, target=target)
        if not lessons:
            return ""
        lines = ["[LESSONS] Relevant failed attempts from past sessions "
                 "- do NOT repeat them blindly:"]
        for h in lessons:
            lines.append("- %s" % (h.get("text") or "")[:240]
                         .replace("\n", " "))
        return "\n".join(lines)

    def render_reflection_block(self, rec: dict) -> str:
        """Format a fresh reflection as an instruction block for the loop."""
        if not rec or rec.get("outcome") != "failure":
            return ""
        return ("[REFLECTION] tool=%s\n"
                "  expected: %s\n"
                "  actual  : %s\n"
                "  why it failed (%s): %s\n"
                "  next mutation: %s" % (
                    rec.get("tool", ""),
                    rec.get("expected", ""),
                    rec.get("actual", "") or "(empty output)",
                    rec.get("failure_root", "unknown"),
                    rec.get("why_failed", ""),
                    rec.get("next_mutation", "")))

    def stats(self) -> dict:
        try:
            with open(self.history_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            history = data.get("reflections", []) \
                if isinstance(data, dict) else data
        except Exception:
            history = []
        out = {"total": len(history), "success": 0, "failure": 0,
               "neutral": 0}
        roots = {}
        for r in history:
            o = r.get("outcome")
            if o in out:
                out[o] += 1
            root = r.get("failure_root")
            if root:
                roots[root] = roots.get(root, 0) + 1
        out["failure_roots"] = roots
        out["episodic_backend"] = getattr(self.episodic, "backend", "?")
        return out
