"""Live Sandbox Feedback Loop Engine.

Real-time monitoring + self-healing execution for the agent's terminal
sandboxes. Two cooperating components:

1. TerminalStreamAnalyzer - watches live terminal/PTY stdout+stderr
   streams (both the persistent PTY sessions and plain one-shot
   subprocess output) and INSTANTLY classifies what it sees:

   - interactive prompts  (password:, y/n, sudo, mysql>, ...)
   - syntax errors        (python traceback / node / bash syntax ...)
   - access denied        (permission denied, 401/403, sudo, WAF ...)
   - execution timeouts   ([command timed out], watchdog expiry ...)

2. DynamicCommandCorrector - when the analyzer flags a failure
   signature, the command is auto-corrected BEFORE re-issue:

   - ReflectionEngine.reflect() roots the failure (WAF / auth /
     syntax / network) and produces the next-mutation advice
   - deterministic fixers repair flag syntax, quoting, timeouts and
     inject bypass wrappers (sudo, /dev/tcp checks, shell fallbacks)
   - the corrected command is re-issued through the live feedback
     executor; each round is tracked, lessons persist via the
     reflection history and episodic memory archive

Design constraints honored from the platform style: bounded rounds
(default 3, hard cap 6), bounded output capture, no silent retries
every correction is logged into the reflection record so the audit
trail shows exactly what was mutated and why.

Example::

    loop = LiveFeedbackLoop()
    result = loop.run("nmap -sV --top-portsx 100 10.0.0.1", timeout=30)
    # result["corrections"] -> [{"round": 1, "signature": "syntax_error",
    #                           "fixed_command": "nmap -sV --top-ports 100 ..."}]
"""

import json
import os
import re
import threading
import time

from ..reflection import ReflectionEngine

# --------------------------------------------------------------------------
# Stream signature database
# --------------------------------------------------------------------------

SIG_PROMPT = "interactive_prompt"
SIG_SYNTAX = "syntax_error"
SIG_DENIED = "access_denied"
SIG_TIMEOUT = "execution_timeout"

# Interactive prompts the sandbox should auto-answer or escalate on.
_PROMPT_PATTERNS = (
    (re.compile(r"(?:\bpassword\s*(?:for\s*\S+)?\s*:\s*$)", re.I), "password"),
    (re.compile(r"(?:\bpassphrase\s*(?:for\s*\S+)?\s*:\s*$)", re.I), "passphrase"),
    (re.compile(r"(?:\byou\s+are\s+about\s+to\s+run|sudo\b)", re.I), "sudo_confirm"),
    (re.compile(r"(?:\(y/n\)|\[y/n\]|\(yes/no\)|continue\?\s*$)", re.I), "yes_no"),
    (re.compile(r"(?:are\s+you\s+sure)", re.I), "confirm"),
    (re.compile(r"(?:overwrite\s+.*\s*\?\s*$|\?\\s*$)"), "overwrite"),
    (re.compile(r"(?:mysql>|mariadb\[\d+\]>$|psql=*>$)", re.I), "db_shell"),
    (re.compile(r"(?:\bcould\s+not\s+open\s+a\s+connection|host\s+key\s+verification\s+failed)", re.I), "ssh_prompt"),
)

# Syntax / interpreter errors.
_SYNTAX_PATTERNS = (
    (re.compile(r"SyntaxError:.*(?:line\s+\d+|invalid|unexpected)", re.I), "python_syntax"),
    (re.compile(r"IndentationError:.*", re.I), "python_indent"),
    (re.compile(r"bash:\s*syntax\s+error", re.I), "bash_syntax"),
    (re.compile(r"syntax\s+error\s+near\s+unexpected\s+token", re.I), "bash_unexpected"),
    (re.compile(r"(?:command|option|argument)\s+not\s+(?:found|recognized|supported)", re.I), "unknown_flag"),
    (re.compile(r"unrecognized\s+option", re.I), "unknown_flag"),
    (re.compile(r"invalid\s+(?:option|argument|flag)", re.I), "invalid_flag"),
    (re.compile(r"(?:node|npm|powershell|go|rust|gcc|javac).*error", re.I), "compiler"),
    (re.compile(r"Traceback\s+\(most\s+recent\s+call\s+last\)", re.I), "python_traceback"),
    (re.compile(r"(?:NoMethodError|NameError|ReferenceError|TypeError):", re.I), "runtime_name"),
)

# Access denied / permission responses.
_DENIED_PATTERNS = (
    (re.compile(r"(?:permission\s+denied|access\s+is\s+denied|operation\s+not\s+permitted)", re.I), "fs_permission"),
    (re.compile(r"(?:401|403)\s+(?:unauthorized|forbidden)", re.I), "http_auth"),
    (re.compile(r"(?:http/[\d.]+\s+40[13]\b)", re.I), "http_auth_code"),
    (re.compile(r"(?:waf|cloudflare|akamai|sucuri)\b.*(?:blocked|denied|captcha)", re.I), "waf_block"),
    (re.compile(r"(?:sudo:.*password|user\s+is\s+not\s+in\s+the\s+sudoers|sorry,\s+try\s+again)", re.I), "sudo_denied"),
    (re.compile(r"(?:authentication\s+failed|login\s+incorrect|invalid\s+credentials|bad\s+password)", re.I), "cred_reject"),
    (re.compile(r"(?:connection\s+refused|ncat:\s+connection\s+refused)", re.I), "conn_refused"),
    (re.compile(r"(?:quota\s+exceeded|rate\s+limit|429\s+too\s+many)", re.I), "rate_limit"),
)

# Execution timeout / hang fingerprints.
_TIMEOUT_PATTERNS = (
    (re.compile(r"\[command\s+timed\s+out\s+after\s+\d+s\]", re.I), "tool_timeout"),
    (re.compile(r"(?:watchdog|deadline)\s+(?:expired|timeout|timed\s+out)", re.I), "watchdog"),
    (re.compile(r"(?:operation\s+timed\s+out|timed\s+out\s+waiting)", re.I), "op_timeout"),
    (re.compile(r"timeout\s+exceeded", re.I), "generic_timeout"),
)


class StreamSignature:
    """One detected anomaly in a live stream sample."""

    __slots__ = ("kind", "family", "excerpt", "offset", "ts")

    def __init__(self, kind, family, excerpt, offset=0):
        self.kind = kind            # prompt | syntax_error | access_denied | execution_timeout
        self.family = family        # e.g. password / python_syntax / fs_permission
        self.excerpt = (excerpt or "")[:300]
        self.offset = int(offset or 0)
        self.ts = time.time()

    def to_dict(self):
        return {"kind": self.kind, "family": self.family,
                "excerpt": self.excerpt, "offset": self.offset,
                "ts": round(self.ts, 3)}

    def __repr__(self):
        return "<StreamSignature %s/%s>" % (self.kind, self.family)


class TerminalStreamAnalyzer:
    """Real-time stdout/stderr anomaly detector for terminal streams.

    Works on both live PTY buffers (polled chunks) and one-shot
    subprocess output (final capture). Detection is pattern-table
    driven so new fingerprints can be added without touching code
    paths; latency is one analysis pass (~sub-millisecond for the
    bounded sample sizes used by the sandbox).
    """

    MAX_SAMPLE = 20000  # chars analyzed per pass; protects the loop

    def __init__(self, extra_patterns=None):
        self._prompt = list(_PROMPT_PATTERNS)
        self._syntax = list(_SYNTAX_PATTERNS)
        self._denied = list(_DENIED_PATTERNS)
        self._timeout = list(_TIMEOUT_PATTERNS)
        if extra_patterns:
            for kind, rx in extra_patterns:
                rx = re.compile(rx) if isinstance(rx, str) else rx
                {"prompt": self._prompt, "syntax": self._syntax,
                 "denied": self._denied, "timeout": self._timeout
                 }[kind].append((rx, "custom"))

    # -- detection -----------------------------------------------------------

    def analyze(self, text, stream="stdout"):
        """Scan a stream chunk; return list[StreamSignature] in
        priority order: timeout > denied > syntax > prompt."""
        if not text:
            return []
        sample = text[-self.MAX_SAMPLE:]
        found = []
        for table, kind in ((self._timeout, SIG_TIMEOUT),
                            (self._denied, SIG_DENIED),
                            (self._syntax, SIG_SYNTAX),
                            (self._prompt, SIG_PROMPT)):
            for rx, family in table:
                m = rx.search(sample)
                if m:
                    start = max(0, m.start() - 60)
                    found.append(StreamSignature(
                        kind, family, sample[start:m.end() + 60].strip(),
                        offset=m.start()))
        # Prompt family: only the FIRST prompt wins (avoid duplicates
        # when a banner contains several markers).
        if kind == SIG_PROMPT and sum(1 for s in found
                                      if s.kind == SIG_PROMPT) > 1:
            first = next(s for s in found if s.kind == SIG_PROMPT)
            found = [s for s in found if s.kind != SIG_PROMPT] + [first]
        return found

    def analyze_session(self, pty_read_fn, session_id, timeout=2.0,
                        include_stderr=True):
        """Poll a live PTY session once via its read function and
        analyze whatever NEW output arrived. Returns (text, sigs)."""
        try:
            text = pty_read_fn(session_id, timeout=timeout,
                               include_stderr=include_stderr) or ""
        except Exception as exc:
            return "", [StreamSignature(SIG_SYNTAX, "read_error",
                                        "pty read failed: %r" % exc)]
        return text, self.analyze(text, stream="pty")

    def classify_exit(self, exit_code, output=""):
        """Post-run classification combining exit code + captured
        output. Used by the correction loop after a command dies."""
        sigs = self.analyze(output)
        if exit_code not in (0, None):
            if not any(s.kind in (SIG_DENIED, SIG_TIMEOUT, SIG_SYNTAX)
                       for s in sigs):
                sigs.append(StreamSignature(
                    SIG_SYNTAX, "nonzero_exit",
                    "exit code %s; tail: %s" % (exit_code,
                                                output[-160:].strip())))
        return sigs


# --------------------------------------------------------------------------
# Dynamic command correction
# --------------------------------------------------------------------------

_FLAG_FIXES = (
    # nmap classic typos / unsupported combos
    (re.compile(r"--top-portsx\b", re.I), "--top-ports"),
    (re.compile(r"(?<!-)-T-?\s*0(\s|$)"), "-T0 "),        # '-T- 0' style
    (re.compile(r"-Pn-(n|s)\b"), "-Pn"),
    (re.compile(r"\b--script=(\S+)\s+--script=\S+"), r"--script=\1"),
    # curl / httpie flag typos
    (re.compile(r"\b--user-agent\b"), "-A"),
    (re.compile(r"\b-kK\b"), "-k"),
    (re.compile(r"\b--insecure(-insecure)+\b"), "--insecure"),
    # gobuster / dirb style
    (re.compile(r"\b-wordlist\b"), "-w"),
    (re.compile(r"\b-url\b"), "-u"),
    # sqlmap
    (re.compile(r"\b--batch=yes\b"), "--batch"),
)

_BYPASS_WRAPPERS = (
    # fs_permission -> try elevated wrapper when not already sudo'd
    (re.compile(r"\bsudo\b"), None),
    ("fs_permission", "sudo {cmd}"),
    ("conn_refused", None),
)

_SHELL_FIXES = (
    # quoting damage that breaks subprocess on Windows/msys
    (re.compile(r"'([^']*)'\""), r"'\1'"),
    (re.compile(r"\s{2,}"), " "),
)

_YES_NO_ANSWERS = {"yes_no": "y", "confirm": "y", "overwrite": "y",
                   "sudo_confirm": ""}


class DynamicCommandCorrector:
    """Turns a failed command + failure signature into a corrected
    command (or interactive answer) before re-issue.

    Corrections run in two layers:
      1. deterministic fixers (flag repair, quoting, timeout bump,
         bypass wrapper injection) - always applied when matched;
      2. Reflection Engine advice - ``ReflectionEngine.reflect()``
         roots the failure and its ``next_mutation`` advice is
         recorded with the round so the audit trail shows WHY the
         mutation was chosen.
    """

    def __init__(self, reflection=None, platform="win"):
        self.reflection = reflection or ReflectionEngine()
        self.platform = platform  # 'win' | 'nix' - affects wrappers

    def correct(self, command, signature, target="", round_no=1):
        """Return dict(corrected, mutation, reflection, interactive_answer).

        ``corrected`` is None when the failure is not auto-correctable.
        """
        # The analyzer has ALREADY classified this as a failure
        # signature, so hand the reflection engine a failure-flagged
        # excerpt - guaranteeing it roots the failure instead of
        # classifying it neutral when the raw excerpt lacks a
        # hard-fail keyword.
        sig_kind, family = signature.kind, signature.family
        flagged = ("error: %s" % signature.excerpt
                   if sig_kind != SIG_PROMPT else signature.excerpt)
        reflection = self.reflection.reflect(
            "sandbox_exec", command, flagged,
            target=target)

        out = {"corrected": None, "mutation": "", "reflection": reflection,
               "interactive_answer": None, "signature": sig_kind,
               "family": family, "round": round_no}

        if sig_kind == SIG_PROMPT:
            answer = _YES_NO_ANSWERS.get(family)
            if family in ("password", "passphrase") or answer is None:
                out["mutation"] = (
                    "interactive prompt detected (%s); send credentials "
                    "manually or use a non-interactive equivalent flag "
                    "(-oBatchMode=yes for ssh, --batch for sqlmap)"
                    % family)
                return out
            out["interactive_answer"] = answer
            out["mutation"] = "auto-answer prompt family %s" % family
            return out

        if sig_kind == SIG_TIMEOUT:
            bumped = self._bump_timeout(command)
            out["corrected"] = bumped
            out["mutation"] = "timeout: extended budget / reduced scope"
            return out

        if sig_kind == SIG_DENIED:
            fixed = self._denied_fix(command, signature, target)
            out["corrected"] = fixed
            out["mutation"] = (
                "denied(%s): bypass wrapper / auth mutation applied"
                % family)
            return out

        # syntax_error + fallback
        fixed = self._syntax_fix(command)
        if fixed != command:
            out["corrected"] = fixed
            out["mutation"] = "syntax: repaired flags/quoting deterministically"
        else:
            out["corrected"] = self._fallback_mutate(command, family)
            out["mutation"] = ("syntax(%s): heuristic variant issued per "
                               "reflection advice" % family)
        return out

    # -- deterministic fixers -------------------------------------------------

    def _syntax_fix(self, command):
        fixed = command
        for rx, repl in _FLAG_FIXES:
            fixed = rx.sub(repl, fixed)
        for rx, repl in _SHELL_FIXES:
            fixed = rx.sub(repl, fixed)
        return fixed.strip()

    def _bump_timeout(self, command):
        # Reduce aggressive timing templates and duplicated verbose
        # flags that commonly cause sandbox watchdog trips.
        fixed = re.sub(r"-T[45]\b", "-T3", command)
        fixed = re.sub(r"(\s-v+)(\s-\1)+", r"\1", fixed)
        return fixed.strip()

    def _denied_fix(self, command, signature, target):
        family = signature.family
        if family == "fs_permission":
            if not re.search(r"\bsudo\b", command) and self.platform != "win":
                return "sudo %s" % command
            return command
        if family in ("http_auth", "http_auth_code", "cred_reject"):
            # Suggest header/auth mutation; the deterministic layer
            # adds common bypass headers when absent.
            if "user-agent" not in command.lower():
                return command + " -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)'"
            return command
        if family == "waf_block":
            if "--random-agent" not in command:
                return command + " --random-agent"
            return command
        if family == "rate_limit":
            # Add polite delay flag for known tools.
            if command.strip().lower().startswith(("nmap",)):
                return re.sub(r"-T\d\b", "-T2", command)
            if command.strip().lower().startswith(("sqlmap",)) and "--delay" not in command:
                return command + " --delay=2"
            return command
        return command

    def _fallback_mutate(self, command, family):
        # Last-resort minimal variant per reflection doctrine: strip
        # suspicious tail flags and retry the core command.
        parts = command.split()
        if len(parts) > 2:
            return " ".join(parts[:-1])
        return command


# --------------------------------------------------------------------------
# Live feedback loop (monitor -> correct -> re-issue)
# --------------------------------------------------------------------------

class LiveFeedbackLoop:
    """The full engine: run a command in the sandbox, watch its live
    streams, auto-correct on failure signatures and re-issue until the
    round budget or a success is reached.

    ``executor`` is the sandbox command runner (defaults to the
    agent's tool_run_terminal); ``pty_read_fn`` enables live PTY
    monitoring via the persistent-session bridge.
    """

    MAX_ROUNDS_CAP = 6

    def __init__(self, executor=None, pty_read_fn=None,
                 reflection=None, platform=None, max_rounds=3,
                 command_timeout=45):
        if executor is None:
            from ..tools.terminal import tool_run_terminal
            executor = lambda cmd, timeout=45: tool_run_terminal(
                cmd, timeout=timeout, max_output=12000)  # noqa: E731
        if pty_read_fn is None:
            try:
                from ..tools.pty_terminal import pty_read_output
                pty_read_fn = pty_read_output
            except Exception:
                pty_read_fn = None
        if platform is None:
            platform = "win" if os.name == "nt" else "nix"
        self.executor = executor
        self.pty_read_fn = pty_read_fn
        self.analyzer = TerminalStreamAnalyzer()
        self.corrector = DynamicCommandCorrector(
            reflection=reflection, platform=platform)
        self.max_rounds = max(1, min(int(max_rounds), self.MAX_ROUNDS_CAP))
        self.command_timeout = command_timeout
        self.history = []
        self._lock = threading.RLock()

    # -- public API ------------------------------------------------------------

    def run(self, command, target="", session_id=None):
        """Execute with live feedback; returns a summary dict::

            {"command": <original>, "final_command": <last issued>,
             "success": bool, "rounds": [<round records>],
             "corrections": [<correction records>],
             "output_tail": <last captured output tail>}
        """
        command = (command or "").strip()
        if not command:
            return {"command": command, "success": False,
                    "error": "empty command"}
        rounds, corrections = [], []
        current = command
        success = False
        output_tail = ""
        with self._lock:
            for round_no in range(1, self.max_rounds + 1):
                rec = self._execute_round(current, session_id=session_id)
                rec["round"] = round_no
                rec["command"] = current
                rounds.append(rec)
                output_tail = rec["tail"]
                if rec["success"]:
                    success = True
                    break
                # Live stream signature check first (prompts, mid-run
                # failures), then post-run classification.
                sigs = rec["stream_sigs"] or rec["exit_sigs"]
                if not sigs:
                    # Unknown failure shape: one heuristic retry with a
                    # trimmed variant, then stop.
                    if round_no < self.max_rounds:
                        corrected = self.corrector._fallback_mutate(
                            current, "unclassified")
                        corrections.append({
                            "round": round_no, "signature": "unclassified",
                            "fixed_command": corrected, "mutation":
                            "heuristic trim (no signature matched)"})
                        current = corrected
                        continue
                    break
                primary = sigs[0]
                fix = self.corrector.correct(current, primary,
                                             target=target,
                                             round_no=round_no)
                if fix["interactive_answer"] is not None and session_id:
                    self._answer_prompt(session_id, fix["interactive_answer"])
                    corrections.append({
                        "round": round_no,
                        "signature": primary.kind,
                        "interactive_answer": fix["interactive_answer"],
                        "mutation": fix["mutation"]})
                    continue  # same command, prompt answered - re-run
                if fix["corrected"] is None or fix["corrected"] == current:
                    corrections.append({
                        "round": round_no, "signature": primary.kind,
                        "fixed_command": None,
                        "mutation": fix["mutation"],
                        "reflection": {k: fix["reflection"].get(k)
                                       for k in ("failure_root", "why_failed",
                                                 "next_mutation")}})
                    break  # not auto-correctable - stop cleanly
                corrections.append({
                    "round": round_no, "signature": primary.kind,
                    "family": primary.family,
                    "fixed_command": fix["corrected"],
                    "mutation": fix["mutation"],
                    "reflection": {k: fix["reflection"].get(k)
                                   for k in ("failure_root", "why_failed",
                                             "next_mutation")}})
                current = fix["corrected"]
            return {"command": command, "final_command": current,
                    "success": success, "rounds": rounds,
                    "corrections": corrections,
                    "output_tail": output_tail[-1500:]}

    # -- internals ---------------------------------------------------------------

    def _execute_round(self, command, session_id=None):
        """Issue one command execution, optionally monitoring a live
        PTY session for streaming signatures during the run."""
        rec = {"command": command, "success": False, "output": "",
               "tail": "", "stream_sigs": [], "exit_sigs": [],
               "exit_code": None, "ts": time.time()}
        if session_id and self.pty_read_fn:
            # Live monitoring: poll the PTY while the command's owner
            # process drives it. Signature checks happen per poll.
            deadline = time.time() + self.command_timeout
            buf = ""
            while time.time() < deadline:
                text, sigs = self.analyzer.analyze_session(
                    self.pty_read_fn, session_id, timeout=2.0)
                buf += text
                rec["stream_sigs"] = sigs
                if sigs:
                    break
            rec["output"] = buf
            rec["tail"] = buf[-1200:]
            # No session result contract here: caller decides success by
            # absence of failure signatures + prompt resolution.
            rec["success"] = not sigs
            return rec
        result = self.executor(command, timeout=self.command_timeout)
        m = re.search(r"\[exit code (\d+)\]", result or "")
        rec["exit_code"] = int(m.group(1)) if m else None
        rec["output"] = result or ""
        rec["tail"] = (result or "")[-1200:]
        rec["exit_sigs"] = self.analyzer.classify_exit(
            rec["exit_code"], result or "")
        rec["success"] = (rec["exit_code"] == 0
                          and not rec["exit_sigs"])
        return rec

    def _answer_prompt(self, session_id, answer):
        """Push an auto-answer into the live PTY session."""
        try:
            from ..tools.pty_terminal import pty_send_input
            pty_send_input(session_id, answer, press_enter=True)
        except Exception:
            pass

    def summary(self):
        """Compact JSON-able summary of the last run for the agent log."""
        if not self.history:
            return {"runs": 0}
        return {"runs": len(self.history)}


def run_with_feedback(command, target="", max_rounds=3, executor=None,
                      pty_read_fn=None):
    """Module-level convenience: one-shot Live Sandbox Feedback Loop."""
    loop = LiveFeedbackLoop(max_rounds=max_rounds, executor=executor,
                            pty_read_fn=pty_read_fn)
    return loop.run(command, target=target)
