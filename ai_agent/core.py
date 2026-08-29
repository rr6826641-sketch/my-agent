"""The Agent: an LLM wrapped in a think -> act -> observe loop."""

import json
import os
import re
import threading
import time

from .llm import LLMError, RunCancelled
from .tools import create_tools, execute_tool

SYSTEM_PROMPT = """You are {name}, an elite AI penetration testing assistant
for authorized cybersecurity professionals.

You have tools you can call. Work like this:
1. Think about what the user needs.
2. Decide which tool call(s) will get the information or do the action.
3. Call the tool(s), read the result, then continue.
4. When you have enough to fully answer, reply with your final answer
   (a normal message, no tool calls).

# PENTEST FRAMEWORK (expert methodology - follow this order)
Run every security assessment as a staged operation through these five
phases. Treat each phase's output as the input to the next; do NOT skip
phases or jump straight to exploitation.

1. RECONNAISSANCE - scope and attack-surface mapping: set_scope first if
   not done, then subdomain_enum, dns_lookup, whois, ssl_info, httpx_probe.
   Goal: know the target's identity, IPs, subdomains and exposed services.

2. ENUMERATION - active service discovery: port_scan / nmap_scan for open
   ports and service versions; for each web port (80, 443, 8080, 8000,
   8443, 3000) run http_request, check_headers, tech_detect; then dir_fuzz
   / gobuster_dir / ffuf_fuzz for hidden paths. Goal: build a full map of
   services, versions, headers, endpoints and parameters.

3. VULNERABILITY IDENTIFICATION - match what you enumerated against known
   weaknesses: cve_lookup on each identified software+version, nuclei_scan
   / nikto_scan templates, and targeted manual web tests (sqli_test,
   xss_test, cmd_inject_test, path_traversal_test, ssrf_test, xxe_test,
   ssti_test, graphql_check, ...). Goal: produce a candidate list with
   severity, CWE and evidence.

4. SAFE VERIFICATION - confirm each candidate without destructive impact:
   reproduce the issue, verify it is real (not a false positive), check
   scope, and log confirmed/probable findings with add_finding. Avoid
   irreversible or destructive commands unless the user explicitly asked
   for that exact action. Goal: verified findings with reproduction steps.

5. STRUCTURED REPORTING - summarize what was found, how to reproduce it,
   and how to fix it. Prioritize by severity (Critical > High > Medium >
   Low > Info), use the findings log and write_report, and end with a short
   high-signal summary. Goal: an actionable report.

# TOOL CHAINING AUTOMATION RULES
Chain tools automatically based on what the previous tool returned. Do not
stop after one tool call when the output still has unexamined attack
surface. Follow these conditional chains:

- IF a network/port scan (port_scan, nmap_scan) reveals open WEB ports
  (80, 443, 8080, 8000, 8443, 3000, 8888):
    THEN queue directory fuzzing (dir_fuzz or gobuster_dir / ffuf_fuzz)
    AND tech stack detection (tech_detect) + check_headers on each web
    port. Continue with extract_links / robots_txt for more surface.

- IF web enumeration (http_request, tech_detect, check_headers, dir_fuzz)
  discovers a specific software/CMS version (e.g. WordPress 6.1, nginx
  1.18, PHP 8.1) or fingerprint headers (server, x-powered-by, generator):
    THEN trigger cve_lookup on that software+version, AND run
    nuclei_scan (or nikto_scan if nuclei unavailable) with templates
    matching that technology.

- IF exposed endpoints, dynamic parameters (id=, page=, q=), API routes
  (/api/, /graphql, /admin), or file upload points are found:
    THEN outline and run appropriate validation checks - map each param
    to its likely injection class (SQLi -> sqli_test/sqlmap_check,
    reflected -> xss_test, file path -> path_traversal_test, URL fetch ->
    ssrf_test, XML -> xxe_test, JSON -> graphql_check, JWT -> jwt_attack,
    templates -> ssti_test) and run the matching probes.

- IF a scan returns no results: reconsider - wrong target? wrong port?
  WAF/firewall? Try an alternative approach (different wordlist, -Pn,
  UDP, larger port range) before reporting nothing found.

# EXECUTION CONTROL
- Maintain structured reasoning before each tool execution phase: state
  the current phase, what the previous tool output implies, and which
  tool(s) you will run next and why. Reason about tool results before
  proceeding.
- Do NOT end the operation prematurely after a single tool call. Keep
  executing until the current phase's surface is covered and the chain
  rules above are satisfied, then move to the next phase.
- Plan multi-stage operations before starting: for assessments with 3+
  steps, use manage_tasks to lay out the phases and track progress.
- When in doubt about what a result means, run one more targeted probe
  rather than guessing.

Rules:
- Always reply in the same language the user writes in.
- Prefer several small tool calls over one giant one.
- For terminal commands, choose safe read-only commands unless the user
  explicitly asked for an action (install, scan, create, delete, ...).
- If a tool returns an error, try a reasonable alternative once before
  giving up.
- Do not invent facts; base answers on tool results.
- Be concise but complete. For technical work, include the key output.

Formatting rules (very important):
- Always format every reply in clean Markdown so it renders nicely in the UI.
- Use ## and ### headings to structure longer answers; a short paragraph needs no heading.
- Use bullet lists (-) and numbered lists (1. 2. 3.) for anything listed.
- Use Markdown tables when comparing data, tool output columns, or options.
- Wrap commands, code, logs and raw tool output in fenced code blocks (```).
- Put a blank line between paragraphs, headings and lists - never cram text together.
- Use **bold** only for key terms and *italics* sparingly.
{memory_block}
{knowledge_block}"""

# ---------------------------------------------------------------------------
# Verification sub-agent (Automated Verification Architecture)
# ---------------------------------------------------------------------------
# When the main agent's final answer contains security findings (open ports,
# subdomains, CVEs, vulnerability keywords), an independent child sub-agent is
# spawned that re-checks each claim with the real tools and rejects false
# positives BEFORE the final report is delivered. See _verify_findings.
VALIDATOR_PROMPT = """You are an independent security verification sub-agent (VALIDATION SUB-AGENT).

The main agent reported these security findings:

{findings}

Your ONLY job: re-verify each finding yourself using the available tools.
- Do NOT trust the main agent's report. Independently re-check the claims
  (e.g. port_scan for open ports, subdomain_enum / dns_lookup for subdomains,
  cve_lookup for CVE references, http_request / url_status for web claims).
- If the evidence confirms a claim, mark it VERIFIED.
- If the evidence contradicts a claim, mark it FALSE_POSITIVE.
- If you cannot gather enough evidence, mark it UNVERIFIED.
- Do NOT expand scope or attack anything new. Only re-check the listed findings.
- Be concise and evidence-based. Do not write a report; just verify.

Finish with a per-finding list, then the overall verdict. Format EXACTLY:
FINDING VERDICTS:
- VERIFIED: <finding text>
- FALSE_POSITIVE: <finding text>
- UNVERIFIED: <finding text>
...
VERDICT: VERIFIED|FALSE_POSITIVE|UNVERIFIED
REASON: <one short line>
"""

# Finding-extraction regexes used to decide when verification should trigger.
# Open ports appear in many phrasings, so several patterns are combined:
#   - "port 80 is open" / "ports 22, 443 are open" (keyword trails)
#   - "80/tcp open"                                    (slash notation)
#   - "open ports: 80, 443" / "Open ports on HOST:"   (keyword leads)
#   - "  80     http" table rows from port_scan       (bare table lines)
#   - "host:80"                                        (host:port notation)
_RE_PORT_OPEN_TRAIL = re.compile(
    r"\bports?\b[^\n]{0,60}\b(?:open|listening|reachable)\b", re.I)
_RE_PORT_SLASH_OPEN = re.compile(
    r"\b(\d{1,5})/(?:tcp|udp)\s+(?:open|listening|filtered)\b", re.I)
_RE_PORT_OPEN_LEAD = re.compile(
    r"\b(?:open|listening)\s+ports?\b[^\n]{0,120}", re.I)
_RE_PORT_TABLE_ROW = re.compile(
    r"(?m)^[ \t]*(?:[-*+]|\||\d+\.)?[ \t]*(\d{1,5})\s*(?:/tcp|/udp)?\s*"
    r"(?:open|listening|filtered)\b", re.I)
_RE_PORT_TABLE_ROW_BARE = re.compile(
    r"(?m)^(?:[ \t]*(?:[-*+]|\|)[ \t]*|[ \t]{2,})(\d{1,5})[ \t]+\|?[ \t]*"
    r"(?:tcp|udp[ \t]+)?[a-z][a-z0-9_\-]*\b", re.I)
_RE_HOST_PORT = re.compile(
    r"\b(\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9.-]*\.[a-z]{2,24}):(\d{1,5})\b",
    re.I)
# "on <host>" / "of <host>" / "at <host>" right after a port phrase, so
# "port 80 open on 192.0.2.1" keeps its target host for re-verification.
_RE_HOST_PHRASE = re.compile(
    r"\b(?:on|of|at|from)\s+"
    r"((?:\d{1,3}(?:\.\d{1,3}){3})|"
    r"(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,24}))\b", re.I)
# Subdomains only count as findings when the text actually reports discovery
# (dns_lookup / subdomain_enum output, "found subdomain X", ...). A casual
# domain mention like "see github.com" is not a finding, so this whole-text
# gate keeps the validator from re-checking unrelated domains.
_RE_SUB_CTX = re.compile(
    r"\b(sub\s*domain\w*|enumerat\w*|discover\w*|found|resolved|resolve|"
    r"dns|hostname|certificate|attack\s+surface|related\s+domain|records?|"
    r"a\s+records?|domain)\b", re.I)
_RE_SUBDOMAIN = re.compile(
    r"\b(?<![\w.])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|co|info|biz|me|xyz|tech|cloud|app|[a-z]{2})\b",
    re.I)
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_RE_VULN = re.compile(
    r"\b(SQL injection|XSS|SSRF|CSRF|RCE|command injection|path traversal|"
    r"directory traversal|open redirect|deserialization|vulnerab\w+|"
    r"expos(?:ed|ing)\s+(?:service|services|endpoint|endpoints|port|ports|"
    r"interface|interfaces|admin|panel|dashboard|api|console|database|db|files?))\b",
    re.I)


def _valid_port(num, exclude_years=True):
    """True when num is a plausible TCP/UDP port (years filtered out so prose
    like 'in 2026' is never mistaken for a port)."""
    try:
        n = int(num)
    except (TypeError, ValueError):
        return False
    if not (1 <= n <= 65535):
        return False
    if exclude_years and 1900 <= n <= 2100:
        return False
    return True


def _ports_from_text(seg):
    """Extract plausible port numbers from a phrase, stripping IPs, scan
    counters (e.g. 'scanned 35') and parenthesised metadata first."""
    seg = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", " ", seg or "")
    seg = re.sub(r"\([^)\n]*\d+[^)\n]*\)", " ", seg)
    seg = re.sub(r"\bscanned\s+\d+\b", " ", seg, flags=re.I)
    out = []
    for pm in re.finditer(r"\b(\d{1,5})\b", seg):
        if _valid_port(pm.group(1), exclude_years=True):
            out.append(int(pm.group(1)))
    return out

# Verdict parsing for the validator child's output.
_RE_PER_FINDING_VERDICT = re.compile(
    r"^\s*[-*]\s*(VERIFIED|FALSE_POSITIVE|UNVERIFIED)\s*[:|]\s*(.+?)\s*$",
    re.M | re.I)
_RE_OVERALL_VERDICT = re.compile(
    r"\bVERDICT\s*[:|]\s*(VERIFIED|FALSE_POSITIVE|UNVERIFIED)\b", re.I)
_RE_REASON = re.compile(r"\bREASON\s*[:|]\s*(.+)$", re.I | re.M)

# ---------------------------------------------------------------------------
# Cross-chat knowledge base: target detection for auto-injection
# ---------------------------------------------------------------------------
# When a user message names a target domain/IP, past findings from the
# SQLite global_knowledge store are injected into the system prompt, so a
# brand-new chat about the same target starts with the relevant context
# already discovered in earlier chats (see Agent._system_prompt).
_RE_KB_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_KB_TARGET = re.compile(
    r"(?<![a-zA-Z0-9.])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:"
    r"com|net|org|io|dev|co|info|biz|me|xyz|tech|cloud|app|ai|gov|edu|mil|"
    r"int|uk|us|in|de|fr|jp|cn|ru|br|au|ca|nl|se|no|fi|dk|pl|ch|at|be|es|"
    r"it|pt|mx|ar|za|ng|kr|sg|my|id|hk|tw|th|vn|ph|nz|il|tr|sa|ae|eg|"
    r"[a-z]{2})(?::\d{1,5})?(?![a-zA-Z0-9.])", re.I)


def _detect_kb_target(text):
    """Best-guess target domain/IP mentioned in a user message (else None)."""
    text = text or ""
    m = _RE_KB_IP.search(text)
    if m:
        return m.group(0)
    m = _RE_KB_TARGET.search(text)
    if m:
        # strip scheme leftovers, port and path (e.g. example.com:8080/x)
        return re.sub(r"[:/].*$", "", m.group(0)).lower()
    return None


# ---------------------------------------------------------------------------
# RPG Game Master mode
# ---------------------------------------------------------------------------
# Placeholders: {name} {story_log} {world_state} {lore_block} {memory_block}
GAME_MASTER_PROMPT = """You are {name}, the all-powerful Game Master of an interactive text-adventure RPG. You narrate the world, control every NPC and creature, adjudicate the rules, and keep the story coherent. You are an evocative writer: paint scenes with all five senses, give every NPC a distinct voice and manner of speaking, and weave the player's choices into a coherent evolving campaign. Keep track of who the player is, where they are, and what they know. One player is at the keyboard; write to them in second person, present tense.

# Your duties
- Narrate vividly in second person present tense (\"You step into the lantern-lit inn...\"). Keep it rich but tight: 2-4 short paragraphs per turn covering the consequences of the player's last action, the current scene, and hooks to pull them forward.
- Give every NPC a distinct voice. When a character speaks, quote their exact words in blockquote format:
  > **The innkeeper:** "Welcome, traveler - you look like you've walked a long road tonight."
  Keep each NPC's voice consistent turn after turn.
- Manage dramatic tension: every turn should raise a question, deepen a mystery, or push the player toward a decision with real stakes. Pacing matters - let the scene breathe after big moments.
- Stay consistent with the World State and the Lorebook below. Whenever something changes (moving, taking items, gaining gold, meeting NPCs, finishing quests) update the world with the gm_world_update tool BEFORE writing your reply.
- Keep every NPC in character. When an NPC must speak or act on their own, bring them to life with the spawn_agent tool (see Tools below) and quote their words in the narrative.
- Adjudicate fairly. If the player attempts something risky or contested, call for a roll: say \"Roll d20\" and ask them to reply with a number, then resolve using their stats. Respect their choices; failure should create drama, not dead ends.
- The player can win or lose. Death is possible but should be a meaningful story beat. Clear endings are fine. Always leave room for the next turn.
- NEVER break character. NEVER mention that you are an AI, a language model, an \"agent\" or a game system.

# Recent Story (the last few turns of the campaign - continue from here, don't repeat)
{story_log}

# World State (current truth - always accurate)
{world_state}

# Lorebook (recorded facts - do not contradict them)
{lore_block}

# Choices
End EVERY turn with exactly 3 distinct, meaningful choices for the player's next action. Format them EXACTLY like this as the final lines of your reply:
[CHOICES]
1. <choice text>
2. <choice text>
3. <choice text>
Each choice must be a plausible next action in the current scene, and all three must lead to genuinely different outcomes. Make each choice concrete and directly actionable (a physical action, a question to an NPC, a place to investigate), keep each under a dozen words, and vary the flavour: at least one bold or risky option, one observant or investigative option, and one social or conversational option when the scene allows. Never leave the player without these three choices.

# Tools
- gm_world_update: update location / stats / inventory / flags / quests / npcs / counters after anything changes. Call it, then write your reply.
- gm_lore_add: record important facts (names, places, rumors, item properties, faction politics) so the campaign never forgets them.
- gm_lore_search: recall relevant lore before answering a question that touches on history, people, places or items.
- spawn_agent: bring ONE NPC to life. Task format (put the persona in the [PERSONA] block):
  [PERSONA]Full description: appearance, voice, personality, motives, secrets, speaking style, knowledge.\nThe adventurer asks: <their question or action>. Reply as this character in 2-4 sentences, in first person, with their spoken words.
  Use the returned reply as that character's exact words/actions in the narrative. Include the relevant lore facts about the character, faction or place inside their [PERSONA] block so the reply stays consistent with the Lorebook.
- spawn_agents: run several NPC reactions in PARALLEL (same [PERSONA] format per task, up to 8).
- remember / recall / vector_search: long-term campaign notes and lore retrieval.
- All other tools (run_terminal, web_search, ...): only if the story genuinely needs them (e.g. rendering a treasure map). Never use terminal/network/scanning tools for game content unless it is the actual point of the scene.

# Turn structure (repeat every turn)
1. Resolve the player's action; update the world with gm_world_update if anything changed.
2. Narrate the consequences vividly, in second person, present tense.
3. React as the NPCs would; advance the plot. When NPCs speak, quote them as > **Name:** "Their exact words."
4. End with exactly 3 choices in the [CHOICES] block.
{memory_block}"""

# Placeholder: {persona} {world_context} {memory_block}
NPC_PROMPT = """You are roleplaying as the following character. Stay in character for your ENTIRE reply.

{PERSONA}

# Scene context (what is happening around you right now)
{world_context}

Rules:
- Reply only as this character: their spoken words, actions and inner thoughts.
- NEVER mention that you are an AI, an agent, a language model or that this is a game.
- Use the character's voice, dialect, catchphrases and knowledge. Do not invent facts that contradict the persona description.
- Keep it short (2-6 sentences) unless the scene demands more.
- Your reply is inserted into the Game Master's narrative verbatim, so end your sentences - no stage directions about the format.
{memory_block}"""

# Marker used by the GM to close a turn with choices, plus the regex that
# strips the leading "1." numbering from each parsed choice line.
CHOICES_MARKER = "[CHOICES]"
_PERSONA_RE = re.compile(
    r"\[PERSONA\](.*?)\[/PERSONA\]", re.IGNORECASE | re.DOTALL)
_CHOICE_LINE_RE = re.compile(r"^\s*\d+[.)]\s*")


def parse_choices(text):
    """Split a GM reply into (narrative, choices).

    Everything before the [CHOICES] marker is the narrative; the numbered
    lines after it (up to 3) become the choice list. A reply without the
    marker yields (text, []).
    """
    text = (text or "").strip()
    if not text:
        return "", []
    marker = text.find(CHOICES_MARKER)
    if marker == -1:
        return text, []
    narrative = text[:marker].strip()
    block = text[marker + len(CHOICES_MARKER):]
    choices = []
    for line in block.splitlines():
        line = line.strip()
        if not line:
            continue
        clean = _CHOICE_LINE_RE.sub("", line).strip()
        if clean:
            choices.append(clean)
        if len(choices) >= 3:
            break
    return narrative, choices


def apply_choice_input(user_input, choices):
    """Map a bare '1' / '2' / '3' (with optional '.' or ')') to the matching
    choice text. Any other input is returned unchanged."""
    s = (user_input or "").strip()
    m = re.match(r"^([1-3])[.)]?\s*$", s)
    if m and choices:
        idx = int(m.group(1)) - 1
        if 0 <= idx < len(choices):
            return choices[idx]
    return user_input


def extract_persona(task):
    """Pull a [PERSONA]...[/PERSONA] block out of a spawn task.

    Returns (persona, remaining_task). If no persona block is present,
    returns (None, task) so normal sub-agent calls behave as before.
    """
    task = task or ""
    m = _PERSONA_RE.search(task)
    if not m:
        return None, task
    persona = m.group(1).strip()
    rest = (task[:m.start()] + " " + task[m.end():]).strip()
    return persona, rest


# Optional external system prompt override (project root).
SYSTEM_PROMPT_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "system_prompt.txt",
)



class Agent:
    def __init__(self, llm, memory=None, name="HackerAI",
                 max_iterations=60, max_messages=400,
                 confirm_terminal=False, spawn_fn=None,
                 spawn_depth=0, max_spawn_depth=3, allow_subagents=True,
                 spawn_timeout=900, game_master=False, world_state=None,
                 lorebook=None, npc_persona=None, auto_verify=True,
                 knowledge=None):
        self.llm = llm
        self.memory = memory
        self.name = name
        self.max_iterations = max_iterations
        self.max_messages = max_messages
        self.confirm_terminal = confirm_terminal
        self.spawn_depth = spawn_depth
        self.max_spawn_depth = max_spawn_depth
        self.allow_subagents = allow_subagents
        self.spawn_timeout = spawn_timeout
        self.game_master = game_master
        self.world_state = world_state
        self.lorebook = lorebook
        self.npc_persona = npc_persona
        self.auto_verify = auto_verify
        self.knowledge = knowledge
        self._kb_target = None
        self.messages = []
        self._tool_list = create_tools(
            memory, knowledge=knowledge,
            confirm_terminal=confirm_terminal,
            spawn_fn=(lambda task: self._spawn_impl(task, self.spawn_depth + 1))
            if allow_subagents else None,
            allow_spawn=allow_subagents,
            spawn_parallel_fn=(lambda tasks, timeout=spawn_timeout:
                               self._spawn_parallel_impl(tasks, timeout))
            if allow_subagents else None,
            rpg_ctx=({"world": world_state, "lorebook": lorebook}
                     if game_master else None),
        )
        self._tools_by_name = {t.name: t for t in self._tool_list}

    # ------------------------------------------------------------ prompt

    def _system_prompt(self):
        if self.npc_persona:
            return self._npc_prompt()
        if self.game_master:
            return self._gm_prompt()
        memory_block = ""
        if self.memory is not None:
            snap = self.memory.snapshot(limit=1500)
            if snap:
                memory_block = (
                    "\n\nSaved memory you should use when relevant:\n" + snap
                )
        # Cross-chat knowledge: if the chat names a target domain/IP, inject
        # what past chats already found about it (SQLite global_knowledge).
        knowledge_block = ""
        if self.knowledge is not None:
            target = self._kb_target
            if target is None and self.messages:
                first = self.messages[0].get("content") if isinstance(
                    self.messages[0], dict) else None
                target = _detect_kb_target(first)
                self._kb_target = target
            if target:
                try:
                    kb = self.knowledge.get_target_summary(target)
                except Exception:
                    kb = ""
                if kb:
                    knowledge_block = kb
        template = SYSTEM_PROMPT
        try:
            if os.path.exists(SYSTEM_PROMPT_FILE):
                with open(SYSTEM_PROMPT_FILE, "r", encoding="utf-8") as f:
                    template = f.read()
        except Exception:
            pass  # fall back to the built-in prompt on any error
        prompt = template.format(name=self.name, memory_block=memory_block,
                                 knowledge_block=knowledge_block)
        if knowledge_block and "{knowledge_block}" not in template:
            prompt = "%s\n\n%s" % (prompt, knowledge_block)
        return prompt

    def _npc_prompt(self):
        memory_block = ""
        if self.memory is not None:
            snap = self.memory.snapshot(limit=800)
            if snap:
                memory_block = "\n\nUseful memory for this character:\n" + snap
        world_context = ""
        if self.world_state is not None:
            try:
                world_context = self.world_state.to_context()
                story = self.world_state.story_log(limit=3, max_chars=1200)
                if story:
                    world_context += "\n\nRecent scene:\n" + story
            except Exception:
                world_context = ""
        return NPC_PROMPT.format(
            PERSONA=self.npc_persona,
            world_context=world_context or "(no scene context)",
            memory_block=memory_block)

    def _gm_prompt(self):
        world_state = ""
        if self.world_state is not None:
            try:
                world_state = self.world_state.to_context()
            except Exception:
                world_state = "(no world state available)"
        lore_block = ""
        if self.lorebook is not None:
            try:
                lore = self.lorebook.to_context(limit=4000)
            except Exception:
                lore = ""
            lore_block = lore or "(lorebook empty - record new facts as they appear)"
        memory_block = ""
        if self.memory is not None:
            try:
                snap = self.memory.snapshot(limit=1200)
            except Exception:
                snap = ""
            if snap:
                memory_block = "\n\nLong-term campaign memory:\n" + snap
        story_log = ""
        if self.world_state is not None:
            try:
                story_log = self.world_state.story_log()
            except Exception:
                story_log = ""
        return GAME_MASTER_PROMPT.format(
            name=self.name, story_log=story_log or "(no turns yet - the story starts now)",
            world_state=world_state,
            lore_block=lore_block, memory_block=memory_block)

    # ------------------------------------------------------------ loop

    def run(self, user_input):
        """Run one user query and return the final answer string."""
        parts = []
        for event in self.run_stream(user_input):
            if event.get("type") == "final":
                parts.append(event.get("content", ""))
        return "\n".join(p for p in parts if p) or "(empty reply)"

    def run_stream(self, user_input, stop_event=None, model=None):
        """Same agent loop but yields events for live UI updates.

        Event types:
          start      -> user input accepted
          llm        -> assistant content (may precede tool calls)
          tool_call  -> {name, arguments} about to execute
          tool_result-> {name, content}
          final      -> the final answer (sent once per terminal reply)
          error      -> LLM/tool error

        Verification sub-agent events (only when the final answer contains
        security findings and auto_verify is enabled):
          validation_start           -> re-verification began (N findings)
          validation_tool_call       -> validator child tool call
          validation_tool_result     -> validator child tool result
          validation                 -> {status, finding, reason} per finding
          validation_done            -> {summary, verified, rejected, unverified}

        stop_event: optional threading.Event. When set (Stop button), the
        loop aborts by raising RunCancelled so the caller can stop cleanly.
        model: optional per-run LLM model override (Smart Auto-Router).
        """
        user_input = (user_input or "").strip()
        if not user_input:
            yield {"type": "error", "content": "(empty input)"}
            return
        self.messages.append({"role": "user", "content": user_input})
        self._maybe_trim()
        yield {"type": "start", "content": user_input}
        final = ""
        tool_schemas = [t.schema() for t in self._tool_list]

        for _ in range(self.max_iterations):
            if stop_event is not None and stop_event.is_set():
                raise RunCancelled("run cancelled by user")
            prompt = ([{"role": "system", "content": self._system_prompt()}]
                      + list(self.messages))
            reply = None
            try:
                for ev in self.llm.chat_stream(prompt, tools=tool_schemas,
                                               cancel_event=stop_event,
                                               model=model):
                    if ev["type"] == "delta":
                        yield {"type": "delta", "content": ev.get("content", "")}
                    elif ev["type"] == "message":
                        reply = ev["message"]
            except LLMError as exc:
                yield {"type": "error", "content": "[LLM error] %s" % exc}
                return
            if reply is None:
                yield {"type": "error", "content": "[LLM error] no reply received"}
                return

            content = reply.get("content") or ""
            tool_calls = reply.get("tool_calls") or []

            if not tool_calls:
                self.messages.append({"role": "assistant", "content": content})
                yield {"type": "llm", "content": content}
                if self.auto_verify:
                    summary = ""
                    try:
                        for vev in self._verify_findings(
                                content, stop_event=stop_event, model=model):
                            yield vev
                            if vev.get("type") == "validation_done":
                                summary = vev.get("summary", "")
                    except RunCancelled:
                        raise
                    except Exception as exc:
                        yield {"type": "validation_done",
                               "summary": ("[VALIDATION SUB-AGENT] verification "
                                           "error: %s" % exc)}
                    if summary:
                        content = "%s\n\n---\n\n%s" % (content, summary)
                yield {"type": "final", "content": content or "(empty reply)"}
                return

            if content:
                yield {"type": "llm", "content": content}
            self.messages.append({
                "role": "assistant",
                "content": content,
                "tool_calls": tool_calls,
            })
            for call in tool_calls:
                if stop_event is not None and stop_event.is_set():
                    raise RunCancelled("run cancelled by user")
                try:
                    name = call["function"]["name"]
                    args = call["function"].get("arguments") or "{}"
                except Exception:
                    name, args = "?", "{}"
                yield {"type": "tool_call", "name": name,
                       "arguments": args}
                if self._check_tool_confirm(call):
                    result = execute_tool(self._tools_by_name, call,
                                          cancel_event=stop_event)
                else:
                    result = "[cancelled by user]"
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": call.get("id", "call_0"),
                    "content": result,
                })
                yield {"type": "tool_result", "name": name,
                       "content": result}
            self._maybe_trim()

        yield {"type": "final",
               "content": final or "[stopped: max iterations reached]"}

    def _check_tool_confirm(self, call):
        if not self.confirm_terminal:
            return True
        try:
            name = call["function"]["name"]
        except Exception:
            return True
        if name != "run_terminal":
            return True
        try:
            import sys
            if not sys.stdin.isatty():
                return True
        except Exception:
            return True
        try:
            args = json.loads(call["function"].get("arguments") or "{}")
            cmd = str(args.get("command", ""))[:200]
        except Exception:
            cmd = "(unparseable)"
        try:
            ans = input("Run command? [y/N] %s\n> " % cmd).strip().lower()
        except Exception:
            return True
        return ans in ("y", "yes", "run")

    # ------------------------------------------------------------ memory mgmt

    def _maybe_trim(self):
        if len(self.messages) <= self.max_messages:
            return
        keep = self.messages[-self.max_messages:]
        while keep and keep[0].get("role") == "tool":
            keep.pop(0)
        dropped = self.messages[: len(self.messages) - len(keep)]
        if dropped:
            summary = ""
            try:
                r = self.llm.chat([
                    {"role": "system",
                     "content": "Summarize this conversation in under 150 "
                                "words. Keep key facts, decisions, commands "
                                "run, and results."},
                ] + dropped)
                summary = (r.get("content") or "").strip()
            except Exception:
                summary = ""
            if summary:
                keep.insert(0, {
                    "role": "system",
                    "content": "Earlier conversation summary: " + summary,
                })
        self.messages = keep

    # ------------------------------------------------------------ verification sub-agent

    def _extract_findings(self, text):
        """Pull candidate security findings (open ports, subdomains, CVEs,
        vulnerability keywords) out of a final answer. Deduped, capped at 10."""
        text = (text or "")[:6000]
        out = []
        seen = set()

        def add(ftype, value):
            value = " ".join((value or "").split())
            if not value or len(value) > 140:
                return
            key = (ftype, value.lower())
            if key in seen:
                return
            seen.add(key)
            out.append({"type": ftype, "value": value})

        def add_port(port, host=None):
            if not _valid_port(port):
                return
            if host:
                add("open_port", "port %s open on %s" % (port, host))
            else:
                add("open_port", "port %s open" % port)

        # host:port notation is the most specific -> includes the host.
        for m in _RE_HOST_PORT.finditer(text):
            add_port(m.group(2), m.group(1))

        # keyword-trailing phrasings: "port 80 is open", "ports 22, 443 open".
        # The host in "port 80 open on HOST" is kept for re-verification.
        for m in _RE_PORT_OPEN_TRAIL.finditer(text):
            hm = _RE_HOST_PHRASE.search(
                text[m.start():m.end() + 80])
            host = hm.group(1) if hm else None
            for p in _ports_from_text(m.group(0)):
                add_port(p, host)

        # keyword-leading phrasings: "open ports: 80, 443",
        # "Open ports on 1.2.3.4 (scanned 35):" (numbers only, no IP/counter).
        for m in _RE_PORT_OPEN_LEAD.finditer(text):
            hm = _RE_HOST_PHRASE.search(
                text[m.start():m.end() + 40])
            host = hm.group(1) if hm else None
            for p in _ports_from_text(m.group(0)):
                add_port(p, host)

        # slash notation: "80/tcp open" (nmap style).
        for m in _RE_PORT_SLASH_OPEN.finditer(text):
            add_port(m.group(1))

        # explicit table rows carrying an open/listening keyword.
        for m in _RE_PORT_TABLE_ROW.finditer(text):
            add_port(m.group(1))

        # bare table rows from port_scan ("  80     http") only fire when the
        # text is clearly a scan report, so prose can't inject false ports.
        if re.search(r"\b(?:ports?|scan|nmap|masscan|open|listening|banner)\b",
                     text, re.I):
            for m in _RE_PORT_TABLE_ROW_BARE.finditer(text):
                add_port(m.group(1))

        # Subdomains need discovery context (see _RE_SUB_CTX).
        if _RE_SUB_CTX.search(text):
            for m in _RE_SUBDOMAIN.finditer(text):
                add("subdomain", m.group(0).lower())
        for m in _RE_CVE.finditer(text):
            add("cve", m.group(0).upper())
        for m in _RE_VULN.finditer(text):
            add("vuln", m.group(0).lower())
        return out[:10]

    def _parse_validator_output(self, text):
        """Parse the validator child's reply into verdict dicts.
        Prefers per-finding 'FINDING VERDICTS:' lines; falls back to the
        overall VERDICT line."""
        text = (text or "")[:4000]
        verdicts = []
        for m in _RE_PER_FINDING_VERDICT.finditer(text):
            status = m.group(1).strip().upper()
            status = {"VERIFIED": "verified",
                      "FALSE_POSITIVE": "rejected",
                      "UNVERIFIED": "unverified"}.get(status, "unverified")
            verdicts.append({"status": status,
                             "finding": m.group(2).strip()[:160]})
        if not verdicts:
            om = _RE_OVERALL_VERDICT.search(text)
            if om:
                status = om.group(1).strip().upper()
                status = {"VERIFIED": "verified",
                          "FALSE_POSITIVE": "rejected",
                          "UNVERIFIED": "unverified"}.get(status, "unverified")
                reason = ""
                rm = _RE_REASON.search(text)
                if rm:
                    reason = rm.group(1).strip()[:160]
                verdicts = [{"status": status, "finding": "(overall)",
                             "reason": reason}]
        return verdicts

    def _verify_findings(self, text, stop_event=None, model=None):
        """Spawn an independent child sub-agent that re-checks the security
        findings in `text` with real tools and rejects false positives.
        Runs inline (blocking the final answer) with a time budget.

        Yields UI events: validation_start -> validation_tool_call /
        validation_tool_result -> validation (per finding) -> validation_done.
        """
        findings = self._extract_findings(text)
        if not findings:
            return
        yield {"type": "validation_start", "count": len(findings),
               "content": "[VALIDATION SUB-AGENT] Re-verifying %d finding(s)..."
                           % len(findings)}
        child = Agent(
            llm=self.llm, memory=None,
            name=self.name + "-validator",
            max_iterations=min(self.max_iterations, 10),
            max_messages=200, confirm_terminal=False,
            spawn_depth=self.spawn_depth + 1,
            max_spawn_depth=self.max_spawn_depth,
            allow_subagents=False, auto_verify=False,
            spawn_timeout=self.spawn_timeout,
            game_master=False, world_state=None, lorebook=None,
        )
        lines = ["- [%s] %s" % (f["type"], f["value"]) for f in findings]
        task = VALIDATOR_PROMPT.format(findings="\n".join(lines))
        deadline = time.time() + min(max(self.spawn_timeout, 30), 180)
        child_out, child_err = "", ""
        try:
            for ev in child.run_stream(task, stop_event=stop_event,
                                       model=model):
                if time.time() > deadline:
                    break
                t = ev.get("type")
                if t == "tool_call":
                    yield {"type": "validation_tool_call",
                           "name": ev.get("name", "?"),
                           "arguments": ev.get("arguments", "{}")}
                elif t == "tool_result":
                    yield {"type": "validation_tool_result",
                           "name": ev.get("name", "?"),
                           "content": (ev.get("content") or "")[:1500]}
                elif t == "final":
                    child_out = ev.get("content", "") or ""
                elif t == "error":
                    child_err = ev.get("content", "") or ""
        except RunCancelled:
            raise
        except Exception as exc:
            child_err = "%s: %s" % (type(exc).__name__, exc)

        verdicts = self._parse_validator_output(child_out)
        overall_status, overall_reason = None, ""
        if verdicts:
            for vd in verdicts:
                if vd.get("finding") == "(overall)":
                    overall_status = vd["status"]
                    overall_reason = vd.get("reason", "")
                    break
            if overall_status is None:
                overall_status = verdicts[0]["status"]
                overall_reason = verdicts[0].get("reason", "")
        if overall_status is None:
            if child_err:
                overall_status, overall_reason = "unverified", \
                    "validator failed (%s)" % child_err[:140]
            else:
                overall_status, overall_reason = "unverified", "no verdict returned"

        def match_verdict(value):
            v = value.lower()
            for vd in verdicts:
                f = (vd.get("finding") or "").lower()
                if f and f != "(overall)" and (v in f or f in v):
                    return vd
            return None

        seen_findings = set()
        for f in findings:
            vd = match_verdict(f["value"])
            if vd:
                status, reason = vd["status"], vd.get("reason", "") or ""
            else:
                status, reason = overall_status, overall_reason or ""
            key = (status, f["value"].lower())
            if key in seen_findings:
                continue
            seen_findings.add(key)
            yield {"type": "validation", "status": status,
                   "finding": f["value"], "reason": reason}

        verified = sum(1 for vd in verdicts if vd["status"] == "verified")
        rejected = sum(1 for vd in verdicts if vd["status"] == "rejected")
        unverified = sum(1 for vd in verdicts if vd["status"] == "unverified")
        summary = ("[VALIDATION SUB-AGENT] %d finding(s) re-checked: "
                   "%d verified, %d false positives rejected, %d unverified."
                   % (len(findings), verified, rejected, unverified))
        yield {"type": "validation_done", "summary": summary,
               "verified": verified, "rejected": rejected,
               "unverified": unverified, "count": len(findings)}

    # ------------------------------------------------------------ sub-agents

    def _spawn_impl(self, task, depth=0):
        if not self.allow_subagents or depth >= self.max_spawn_depth:
            return "Error: sub-agent depth limit reached."
        persona, rest = extract_persona(task)
        child = Agent(
            llm=self.llm, memory=self.memory,
            name=self.name + "-child", max_iterations=self.max_iterations,
            max_messages=self.max_messages, confirm_terminal=False,
            spawn_depth=depth, max_spawn_depth=self.max_spawn_depth,
            allow_subagents=self.allow_subagents,
            npc_persona=persona,
            game_master=False, world_state=self.world_state,
            lorebook=self.lorebook, auto_verify=False,
            knowledge=self.knowledge,
        )
        box = {}
        def work():
            try:
                box["out"] = child.run(rest)
            except Exception as exc:
                box["err"] = "%s: %s" % (type(exc).__name__, exc)
        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        thread.join(timeout=self.spawn_timeout)
        if thread.is_alive():
            return "Error: sub-agent timed out after %ds." % self.spawn_timeout
        if "err" in box:
            return "Sub-agent error: %s" % box["err"]
        return box.get("out", "(no output)")

    def _spawn_parallel_impl(self, tasks, timeout=600):
        """Run multiple sub-agents concurrently; returns one combined result.

        tasks: JSON array of strings, or a string with tasks separated by
        '|||'. Each task runs in its own thread with its own agent.
        """
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
        if len(tasks) > 8:
            tasks = tasks[:8]

        boxes = [{} for _ in tasks]
        threads = []
        for i, task in enumerate(tasks):
            def work(idx, t):
                try:
                    persona, rest = extract_persona(str(t))
                    child = Agent(
                        llm=self.llm, memory=self.memory,
                        name=self.name + "-child%d" % (idx + 1),
                        max_iterations=self.max_iterations,
                        max_messages=self.max_messages,
                        confirm_terminal=False,
                        spawn_depth=self.spawn_depth + 1,
                        max_spawn_depth=self.max_spawn_depth,
                        allow_subagents=self.allow_subagents,
                        spawn_timeout=self.spawn_timeout,
                        npc_persona=persona,
                        game_master=False, world_state=self.world_state,
                        lorebook=self.lorebook, auto_verify=False,
                        knowledge=self.knowledge,
                    )
                    boxes[idx]["out"] = child.run(rest)
                except Exception as exc:
                    boxes[idx]["err"] = "%s: %s" % (type(exc).__name__, exc)
            th = threading.Thread(target=work, args=(i, str(task)), daemon=True)
            th.start()
            threads.append(th)

        for th in threads:
            th.join(timeout=timeout)

        lines = []
        for i, (task, box) in enumerate(zip(tasks, boxes), 1):
            snippet = " ".join(str(task).split())[:80]
            lines.append("--- Sub-agent %d: %s ---" % (i, snippet))
            if "err" in box:
                lines.append("ERROR: %s" % box["err"])
            elif "out" in box:
                lines.append(box["out"])
            else:
                lines.append("(timed out after %ds)" % timeout)
        return "\n\n".join(lines)

    # ------------------------------------------------------------ helpers

    def reset(self):
        self.messages = []

    def tool_names(self):
        return ", ".join(t.name for t in self._tool_list)
