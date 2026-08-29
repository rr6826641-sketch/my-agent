"""LLM clients. OpenAIClient works with any OpenAI-compatible API
(OpenAI, OpenRouter, Groq, Together, Ollama, LM Studio, vLLM, ...).
MockClient simulates an LLM for offline testing of the agent loop.
"""

import json
import os
import re
import threading

import requests


class LLMError(Exception):
    pass


class RunCancelled(Exception):
    """Raised when the user clicks Stop to cancel a running generation."""
    pass


class OpenAIClient:
    """OpenAI-compatible chat completions client (function calling).

    Automatic failover: if the primary model errors (429, empty/invalid
    response body, network failure), the next model in fallback_models is
    tried in order until one answers.
    """

    FALLBACK_MODELS = [
        "minimax/minimax-m3:free",
        "liquid/lfm-2.5-2.6b:free",
        "dots-studio/dots-3-note-preview:free",
    ]

    def __init__(self, api_key="", base_url="https://api.openai.com/v1",
                 model="gpt-4o-mini", timeout=120, fallback_models=None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.model = model or "gpt-4o-mini"
        self.timeout = timeout
        self.fallback_models = list(fallback_models or self.FALLBACK_MODELS)

    def chat(self, messages, tools=None, temperature=0.2):
        models = [self.model] + list(self.fallback_models)
        last_error = None
        for index, model in enumerate(models):
            try:
                return self._chat_once(model, messages, tools, temperature)
            except LLMError as exc:
                last_error = exc
                if index + 1 < len(models):
                    continue
                raise
        raise last_error

    def _chat_once(self, model, messages, tools, temperature):
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        url = self.base_url + "/chat/completions"
        try:
            resp = requests.post(url, headers=headers, json=payload,
                                 timeout=self.timeout)
        except requests.exceptions.RequestException as exc:
            raise LLMError("API request failed: %s" % exc)
        # SSE/JSON bodies are always UTF-8; stop requests from guessing
        # ISO-8859-1 when the upstream omits the charset (mojibake source)
        resp.encoding = "utf-8"
        if resp.status_code != 200:
            raise LLMError("API %s: %s" % (resp.status_code, resp.text[:500]))
        if not resp.text or not resp.text.strip():
            raise LLMError("API 200: empty response body from model '%s'" % model)
        try:
            data = resp.json()
        except ValueError as exc:
            raise LLMError("API 200: invalid JSON from model '%s': %s"
                           % (model, exc))
        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError):
            raise LLMError("Unexpected API response: %s" % str(data)[:500])


    def chat_stream(self, messages, tools=None, temperature=0.2,
                    cancel_event=None):
        """Stream a completion: yields delta events, then a message event.

        Models are tried in order (primary + fallback_models) until one
        actually produces content. A model that errors out before the first
        token (429, empty/whitespace body, invalid JSON, connection failure)
        is skipped and the next candidate is tried.

        cancel_event: optional threading.Event. When set, the current call is
        aborted by raising RunCancelled.
        """
        models = [self.model] + list(self.fallback_models)
        last_error = None
        for index, model in enumerate(models):
            if cancel_event is not None and cancel_event.is_set():
                raise RunCancelled("generation cancelled by user")
            try:
                produced = False
                for ev in self._stream_once(model, messages, tools, temperature,
                                            cancel_event=cancel_event):
                    if ev["type"] == "delta":
                        produced = True
                    yield ev
                if produced:
                    return
                last_error = LLMError("model '%s' returned no content" % model)
            except LLMError as exc:
                last_error = exc
            if index + 1 < len(models):
                continue
            break
        raise last_error
    def _stream_once(self, model, messages, tools, temperature,
                     cancel_event=None):
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "stream": True,
        }
        if tools:
            payload["tools"] = tools
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        url = self.base_url + "/chat/completions"
        try:
            resp = requests.post(url, headers=headers, json=payload,
                                 timeout=self.timeout, stream=True)
        except requests.exceptions.RequestException as exc:
            raise LLMError("API request failed: %s" % exc)
        # SSE/JSON bodies are always UTF-8; stop requests from guessing
        # ISO-8859-1 when the upstream omits the charset (mojibake source)
        resp.encoding = "utf-8"
        if resp.status_code != 200:
            body = ""
            try:
                body = resp.text[:500]
            except Exception:
                pass
            resp.close()
            raise LLMError("API %s: %s" % (resp.status_code, body))

        stop_watch = threading.Event()
        if cancel_event is not None:

            def _watch():
                # Close the HTTP connection once the run is cancelled so the
                # blocked iter_lines() loop unblocks promptly.
                while not stop_watch.is_set():
                    if cancel_event.is_set():
                        try:
                            resp.close()
                        except Exception:
                            pass
                        return
                    stop_watch.wait(0.2)

            threading.Thread(target=_watch, daemon=True).start()

        content_parts = []
        tool_slots = {}
        try:
            for raw in resp.iter_lines(decode_unicode=True):
                if cancel_event is not None and cancel_event.is_set():
                    raise RunCancelled("generation cancelled by user")
                if not raw:
                    continue
                line = raw.strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                except ValueError:
                    continue
                try:
                    choice = chunk["choices"][0]
                except (KeyError, IndexError, TypeError):
                    continue
                delta = choice.get("delta") or {}
                if delta.get("content"):
                    content_parts.append(delta["content"])
                    yield {"type": "delta", "content": delta["content"]}
                for tc in delta.get("tool_calls") or []:
                    try:
                        idx = int(tc.get("index", 0))
                    except (TypeError, ValueError):
                        idx = 0
                    slot = tool_slots.get(idx)
                    if slot is None:
                        slot = tool_slots[idx] = {
                            "id": tc.get("id") or "call_%d" % idx,
                            "name": "",
                            "args": "",
                        }
                    fn = tc.get("function") or {}
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    if fn.get("name"):
                        slot["name"] += fn["name"]
                    if fn.get("arguments"):
                        slot["args"] += fn["arguments"]
        except RunCancelled:
            raise
        except requests.exceptions.RequestException:
            pass
        finally:
            stop_watch.set()
            resp.close()

        if cancel_event is not None and cancel_event.is_set():
            raise RunCancelled("generation cancelled by user")

        tool_calls = []
        for idx in sorted(tool_slots):
            slot = tool_slots[idx]
            args = slot["args"] or "{}"
            try:
                json.loads(args)
            except ValueError:
                pass
            tool_calls.append({
                "id": slot["id"],
                "type": "function",
                "function": {"name": slot["name"], "arguments": args},
            })
        message = {
            "role": "assistant",
            "content": "".join(content_parts),
            "tool_calls": tool_calls or None,
        }
        yield {"type": "message", "message": message}


class MockClient:
    """Rule-based fake LLM used to test the agent without an API key.

    Understands a tiny command language in the user message:
      run <command>          -> calls run_terminal
      list files <path>      -> calls list_files
      read <path>            -> calls read_file
      remember key:value     -> calls remember
      recall                 -> calls recall
      search <query>         -> calls web_search
      fetch <url>            -> calls open_url
      spawn <task>           -> calls spawn_agent
      spawns <json tasks>    -> calls spawn_agents (parallel)
      plan <cmd>             -> run_terminal, then final answer
      system info            -> calls system_info
      list tools             -> calls list_tools
      dns <host>             -> calls dns_lookup
      port scan <host>       -> calls port_scan
      password <len>         -> calls generate_password
      hash <text>            -> calls hash_text
      anything else          -> plain final answer
    """

    def __init__(self, model="mock-1"):
        self.model = model

    def chat(self, messages, tools=None, temperature=0.2):
        tools = tools or []
        names = {t["function"]["name"] for t in tools}
        last_user = next((m for m in reversed(messages)
                          if m.get("role") == "user"), {})
        last_tool = next((m for m in reversed(messages)
                          if m.get("role") == "tool"), None)
        text = (last_user.get("content") or "").strip()
        lower = text.lower()

        def call(name, args):
            return {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": "call_mock_1",
                    "type": "function",
                    "function": {"name": name, "arguments": args},
                }],
            }

        if last_tool is not None:
            content = last_tool.get("content", "")
            excerpt = content[:300].replace("\n", " ")
            return {"role": "assistant",
                    "content": "Tool result received. %s" % excerpt}

        if lower.startswith("run ") and "run_terminal" in names:
            return call("run_terminal", '{"command": "%s"}' % text[4:].replace('"', '\\"'))
        if lower.startswith("list files") and "list_files" in names:
            path = text[10:].strip() or "."
            return call("list_files", '{"path": "%s"}' % path)
        if lower.startswith("read ") and "read_file" in names:
            return call("read_file", '{"path": "%s"}' % text[5:].strip())
        if lower.startswith("remember") and "remember" in names:
            rest = text[8:].strip()
            key, _, val = rest.partition(":")
            return call("remember", '{"key": "%s", "text": "%s"}'
                        % (key.strip(), val.strip().replace('"', '\\"')))
        if lower.startswith("recall") and "recall" in names:
            return call("recall", "{}")
        if lower.startswith("search ") and "web_search" in names:
            return call("web_search", '{"query": "%s"}' % text[7:].replace('"', '\\"'))
        if lower.startswith("fetch ") and "open_url" in names:
            return call("open_url", '{"url": "%s"}' % text[6:].strip())
        if lower.startswith("spawn ") and "spawn_agent" in names:
            return call("spawn_agent", '{"task": "%s"}' % text[6:].replace('"', '\\"'))
        if lower.startswith("spawns ") and "spawn_agents" in names:
            return call("spawn_agents", '{"tasks": "%s"}' % text[7:].replace('"', '\\"'))
        if lower.startswith("plan ") and "run_terminal" in names:
            cmd = text[5:].strip()
            step1 = call("run_terminal", '{"command": "%s"}' % cmd.replace('"', '\\"'))
            return step1
        if lower.startswith("system info") and "system_info" in names:
            return call("system_info", "{}")
        if lower.startswith("list tools") and "list_tools" in names:
            return call("list_tools", "{}")
        if lower.startswith("dns ") and "dns_lookup" in names:
            return call("dns_lookup", '{"hostname": "%s"}' % text[4:].strip())
        if lower.startswith("port scan ") and "port_scan" in names:
            return call("port_scan", '{"host": "%s"}' % text[10:].strip())
        if lower.startswith("password ") and "generate_password" in names:
            return call("generate_password", '{"length": %s}' % (text[9:].strip() or 16))
        if lower.startswith("hash ") and "hash_text" in names:
            return call("hash_text", '{"text": "%s"}' % text[5:].replace('"', '\\"'))

        answer = ("Mock LLM reply: understood your message. "
                  "(Run with a real API key to unlock full reasoning.)")
        return {"role": "assistant", "content": answer}
    def chat_stream(self, messages, tools=None, temperature=0.2,
                    cancel_event=None):
        """Mock streaming: simulate the delta -> message event sequence."""
        if cancel_event is not None and cancel_event.is_set():
            raise RunCancelled("generation cancelled by user")
        message = self.chat(messages, tools=tools, temperature=temperature)
        content = message.get("content") or ""
        words = content.split(" ")
        for i in range(0, len(words), 3):
            if cancel_event is not None and cancel_event.is_set():
                raise RunCancelled("generation cancelled by user")
            chunk = " ".join(words[i:i + 3])
            yield {"type": "delta", "content": chunk + " "}
        if cancel_event is not None and cancel_event.is_set():
            raise RunCancelled("generation cancelled by user")
        yield {"type": "message", "message": message}
