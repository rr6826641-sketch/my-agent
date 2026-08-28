"""The Agent: an LLM wrapped in a think -> act -> observe loop."""

import json
import os
import threading

from .llm import LLMError
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
                 spawn_timeout=900):
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
        self.messages = []
        self._tool_list = create_tools(
            memory, confirm_terminal=confirm_terminal,
            spawn_fn=(lambda task: self._spawn_impl(task, self.spawn_depth + 1))
            if allow_subagents else None,
            allow_spawn=allow_subagents,
            spawn_parallel_fn=(lambda tasks, timeout=spawn_timeout:
                               self._spawn_parallel_impl(tasks, timeout))
            if allow_subagents else None,
        )
        self._tools_by_name = {t.name: t for t in self._tool_list}

    # ------------------------------------------------------------ prompt

    def _system_prompt(self):
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

    # ------------------------------------------------------------ loop

    def run(self, user_input):
        """Run one user query and return the final answer string."""
        parts = []
        for event in self.run_stream(user_input):
            if event.get("type") == "final":
                parts.append(event.get("content", ""))
        return "\n".join(p for p in parts if p) or "(empty reply)"

    def run_stream(self, user_input):
        """Same agent loop but yields events for live UI updates.

        Event types:
          start      -> user input accepted
          llm        -> assistant content (may precede tool calls)
          tool_call  -> {name, arguments} about to execute
          tool_result-> {name, content}
          final      -> the final answer (sent once per terminal reply)
          error      -> LLM/tool error
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
            prompt = ([{"role": "system", "content": self._system_prompt()}]
                      + list(self.messages))
            reply = None
            try:
                for ev in self.llm.chat_stream(prompt, tools=tool_schemas):
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
                try:
                    name = call["function"]["name"]
                    args = call["function"].get("arguments") or "{}"
                except Exception:
                    name, args = "?", "{}"
                yield {"type": "tool_call", "name": name,
                       "arguments": args}
                if self._check_tool_confirm(call):
                    result = execute_tool(self._tools_by_name, call)
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
        child = Agent(
            llm=self.llm, memory=self.memory,
            name=self.name + "-child", max_iterations=self.max_iterations,
            max_messages=self.max_messages, confirm_terminal=False,
            spawn_depth=depth, max_spawn_depth=self.max_spawn_depth,
            allow_subagents=self.allow_subagents,
        )
        box = {}
        def work():
            try:
                box["out"] = child.run(task)
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
                    )
                    boxes[idx]["out"] = child.run(t)
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
