"""LLM clients. OpenAIClient works with any OpenAI-compatible API
(OpenAI, OpenRouter, Groq, Together, Ollama, LM Studio, vLLM, ...).
MockClient simulates an LLM for offline testing of the agent loop.
"""

import os
import re

import requests


class LLMError(Exception):
    pass


class OpenAIClient:
    """OpenAI-compatible chat completions client (function calling)."""

    def __init__(self, api_key="", base_url="https://api.openai.com/v1",
                 model="gpt-4o-mini", timeout=120):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.model = model or "gpt-4o-mini"
        self.timeout = timeout

    def chat(self, messages, tools=None, temperature=0.2):
        payload = {
            "model": self.model,
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
        if resp.status_code != 200:
            raise LLMError("API %s: %s" % (resp.status_code, resp.text[:500]))
        data = resp.json()
        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError):
            raise LLMError("Unexpected API response: %s" % str(data)[:500])


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
