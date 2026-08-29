"""The Agent: an LLM wrapped in a think -> act -> observe loop."""

import json
import os
import re
import threading

from .llm import LLMError, RunCancelled
from .tools import create_tools, execute_tool

SYSTEM_PROMPT = """You are {name}, a capable AI agent.

You have tools you can call. Work like this:
1. Think about what the user needs.
2. Decide which tool call(s) will get the information or do the action.
3. Call the tool(s), read the result, then continue.
4. When you have enough to fully answer, reply with your final answer
   (a normal message, no tool calls).

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
{memory_block}"""

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
                 lorebook=None, npc_persona=None):
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
        self.messages = []
        self._tool_list = create_tools(
            memory, confirm_terminal=confirm_terminal,
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
        template = SYSTEM_PROMPT
        try:
            if os.path.exists(SYSTEM_PROMPT_FILE):
                with open(SYSTEM_PROMPT_FILE, "r", encoding="utf-8") as f:
                    template = f.read()
        except Exception:
            pass  # fall back to the built-in prompt on any error
        return template.format(name=self.name, memory_block=memory_block)

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
            lorebook=self.lorebook,
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
                        lorebook=self.lorebook,
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
