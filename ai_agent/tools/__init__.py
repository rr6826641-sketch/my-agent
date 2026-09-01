"""Tool registry: assembles all built-in tools with JSON schemas.

Add your own tools by writing a function in any module here and one
Tool(...) entry below. The LLM discovers them automatically.
"""

import os

from .base import Tool, execute_tool, truncate
from .system import (
    tool_system_info, tool_current_time, tool_process_list,
    tool_disk_usage, tool_ip_info,
)
from .files import (
    tool_search_files, tool_grep_files, tool_file_info, tool_hash_file,
    tool_json_format, tool_csv_preview, tool_create_archive,
    tool_extract_archive, tool_diff_text, tool_pdf_info, tool_image_info,
)
from .web import (
    tool_http_request, tool_check_headers, tool_robots_txt,
    tool_extract_links, tool_tech_detect, tool_url_status,
)
from .network import (
    tool_dns_lookup, tool_reverse_dns, tool_port_scan, tool_whois_rdap,
    tool_geoip_lookup, tool_ssl_info, tool_ping_host,
)
from .recon import (
    tool_subdomain_enum, tool_dir_fuzz, tool_cve_lookup, tool_wordlist_gen,
)
from .code import (
    tool_run_python, tool_regex_test, tool_generate_password,
    tool_encode_decode, tool_hash_text, tool_uuid_gen,
)
from .terminal import (
    tool_run_terminal, tool_read_file, tool_write_file, tool_list_files,
    tool_start_session, tool_send_input, tool_view_session_output,
    tool_wait_for_pattern, tool_kill_session, tool_list_sessions,
)
from .pty_terminal import (
    pty_start_session, pty_send_input, pty_read_output, pty_kill_session,
    pty_status,
)
from .memory import (
    tool_memory_save, tool_memory_get, tool_memory_list, tool_memory_delete,
)
from .websearch import (
    tool_web_search, tool_open_url,
)
from .web_search import search_web
from .web_fetch import fetch_url
from .reasoning import tool_plan_task, tool_reason, tool_reflect
from .search import (
    tool_generate_queries, tool_web_search_v2, tool_research,
    tool_build_citation,
)
from .skills import (
    tool_search_skills, tool_load_skill,
)
from .hypothesis_engine import (
    tool_generate_security_hypotheses,
    tool_chain_to_verification_plan,
)
from .cloud_sec import (
    aws_s3_enum,
    cloud_misconfig_scan,
    docker_security_audit,
)
from .browser import (
    tool_browse_page,
    tool_click_element,
    tool_fill_form,
    tool_take_screenshot,
    tool_capture_network_traffic,
    browser_open_url,
    browser_click_element,
    browser_fill_form,
    browser_take_screenshot,
    browser_capture_network,
    browser_close_browser,
    tool_close_browser,
)
from .pentest import (
    tool_nmap_scan, tool_sqlmap_check, tool_nikto_scan,
    tool_nuclei_scan, tool_ffuf_fuzz, tool_gobuster_dir,
    tool_subfinder_enum, tool_httpx_probe, tool_curl_request,
    tool_jwt_decode,
)
from .tasks import tool_manage_tasks

from .extra import (
    tool_http_methods, tool_cors_check, tool_waf_detect,
    tool_redirect_chain, tool_dns_axfr, tool_extract_iocs,
    tool_http_cookies, tool_local_listeners, tool_sqlite_query,
    tool_password_strength, tool_mac_vendor, tool_subnet_calc,
)

from .payloads import (
    tool_gen_reverse_shell, tool_gen_bind_shell, tool_gen_webshell,
    tool_gen_listener, tool_gen_obfuscate, tool_gen_wordlist,
)
from .reporting import (
    tool_add_finding, tool_list_findings, tool_update_finding,
    tool_delete_finding, tool_write_report,
    tool_verify_finding, tool_verify_all_findings,
    correlate_findings, calc_cvss_score, generate_markdown_report,
)
from .attack_chains import (
    build_attack_chains, render_chain_graph, visualize_attack_chains,
    visualize_merged_chains, populate_cve_table,
)
from .webtests import (
    tool_sqli_test, tool_xss_test, tool_cmd_inject_test,
    tool_path_traversal_test, tool_ssrf_test, tool_open_redirect_test,
)
from .capabilities import (
    tool_xxe_test, tool_header_inject_test, tool_nosql_inject_test,
    tool_ssti_test, tool_jwt_attack, tool_graphql_check,
    tool_deserialization_check, tool_smuggling_detect, tool_oauth_check,
    tool_cloud_meta_test, tool_lockfile_scan, tool_ad_svc_probe,
)
from .active_directory import (
    smb_enum,
    smb_share_enum,
    ldap_search_anonymous,
    kerberos_ticket_check,
    subnet_sweep,
)
from .scope import (
    tool_set_scope, tool_show_scope, tool_check_scope,
)
from .custom import (
    tool_sha1_quick, tool_strings_extract, tool_html_to_text,
    tool_dedupe_lines, tool_count_lines,
)
from .workspace import (
    tool_workspace_scan, tool_workspace_symbols, tool_workspace_deps,
    tool_workspace_query, tool_workspace_export,
)

from .base import Tool as _Tool  # noqa: F401


def _str_prop(desc, default=None, enum=None):
    p = {"type": "string", "description": desc}
    if default is not None:
        p["default"] = default
    if enum:
        p["enum"] = enum
    return p


def _as_bool(value, default=False):
    """Coerce LLM-supplied strings ('true'/'false'/'1'/'0') to bool."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def create_tools(memory, knowledge=None, institutional=None,
                 confirm_terminal=True, spawn_fn=None, allow_spawn=True,
                 spawn_parallel_fn=None, rpg_ctx=None, workspace_index=None,
                 orchestrator=None, spawn_default_wait=False):
    """Build the full tool list for an Agent.

    rpg_ctx: optional dict with 'world' (GameState) and 'lorebook'
    (Lorebook) for Game-Master agents. When present, the gm_* tools are
    registered.
    institutional: optional InstitutionalMemory - enables the notes_* tools
    implementing the cross-conversation institutional memory doctrine.
    orchestrator: optional OrchestrationManager enforcing the Managed
    Asynchronous Sub-Agent Orchestration Protocol - bounded child state
    (max 2 siblings / 4 children), success criteria, capabilities and
    progress ledgers. When present, spawn_agent/spawn_agents become ASYNC
    (return agent_id JSON immediately) and the four management tools
    (check_agent_status, fetch_agent_transcript, continue_agent,
    cancel_agent) are registered; the legacy spawn_fn / spawn_parallel_fn
    callbacks remain as the synchronous fallback when orchestrator is None.
    spawn_default_wait: default for the wait flag (True keeps legacy
    blocking behaviour, e.g. for Game-Master NPC reactions).
    """
    world = (rpg_ctx or {}).get("world")
    lorebook = (rpg_ctx or {}).get("lorebook")

    def tool_spawn_agent(task="", success_criteria=None, capabilities=None,
                         wait=None):
        if not allow_spawn:
            return "Error: sub-agents are disabled."
        if orchestrator is not None:
            return orchestrator.spawn(
                task, wait=_as_bool(wait, spawn_default_wait),
                success_criteria=success_criteria,
                capabilities=capabilities,
                timeout=spawn_default_wait and 600 or None)
        if spawn_fn is None:
            return "Error: sub-agents are disabled."
        return spawn_fn(task)

    def tool_spawn_agents(tasks, success_criteria=None, capabilities=None,
                          wait=None):
        if not allow_spawn:
            return "Error: sub-agents are disabled."
        if orchestrator is not None:
            return orchestrator.spawn_many(
                tasks, wait=_as_bool(wait, spawn_default_wait),
                success_criteria=success_criteria,
                capabilities=capabilities,
                timeout=spawn_default_wait and 600 or None)
        if spawn_parallel_fn is None:
            return "Error: parallel sub-agents are disabled."
        return spawn_parallel_fn(tasks or "")

    def tool_check_agent_status(agent_id="", validate=False):
        if orchestrator is None:
            return "Error: sub-agent orchestration is disabled."
        return orchestrator.check_status(agent_id or "",
                                         validate=_as_bool(validate))

    def tool_fetch_agent_transcript(agent_id=""):
        if orchestrator is None:
            return "Error: sub-agent orchestration is disabled."
        return orchestrator.fetch_transcript(agent_id or "")

    def tool_continue_agent(agent_id="", follow_up=""):
        if orchestrator is None:
            return "Error: sub-agent orchestration is disabled."
        return orchestrator.continue_agent(agent_id or "", follow_up or "")

    def tool_cancel_agent(agent_id=""):
        if orchestrator is None:
            return "Error: sub-agent orchestration is disabled."
        return orchestrator.cancel_agent(agent_id or "")

    def tool_list_tools():
        names = "\n".join("  %-22s %s" % (t.name, t.description)
                          for t in _REGISTRY)
        return "Available tools (%d):\n%s" % (len(_REGISTRY), names)

    def _remember(key, text):
        if not key.strip() or not text.strip():
            return "Error: both key and text are required."
        memory.add(key.strip(), text.strip())
        return "Saved to memory: %s" % key.strip()

    def _recall(query=""):
        return memory.recall(query or None)

    def _vector_search(query="", top_k=5):
        return memory.vector_search(query or "", int(top_k or 5))

    def _rag_index(folder=""):
        return memory.index_documents(folder or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))), "docs"))

    def _knowledge_save(target_domain, finding_type, content, tags=""):
        if knowledge is None:
            return "Error: cross-chat knowledge base is not enabled."
        try:
            row = knowledge.save_finding(
                target_domain, finding_type or "note", content,
                [t.strip() for t in (tags or "").split(",") if t.strip()])
        except (TypeError, ValueError) as exc:
            return "Error: %s" % exc
        return "Saved to knowledge base (id %s, target %s, type %s)." % (
            row["id"], row["target_domain"], row["finding_type"])

    def _knowledge_search(target_domain="", query="", top_k=5):
        if knowledge is None:
            return "Error: cross-chat knowledge base is not enabled."
        hits = knowledge.search_findings(
            target_domain=target_domain.strip() or None,
            query=query.strip() or None,
            top_k=int(top_k or 5))
        if not hits:
            return "(no matching knowledge)"
        lines = []
        for h in hits:
            lines.append("- [%s] %s%s" % (
                h["finding_type"],
                " ".join(h["content"].split()),
                " (tags: %s)" % ", ".join(h["tags"]) if h["tags"] else ""))
        return "\n".join(lines)

    def _notes_add(category, title, content, target="", tags=""):
        if institutional is None:
            return "Error: institutional memory is not enabled."
        try:
            row = institutional.add_note(
                category or "findings", title, content,
                target=target, tags=[t.strip() for t in (tags or "").split(",")
                                     if t.strip()])
        except (TypeError, ValueError) as exc:
            return "Error: %s" % exc
        return ("Logged institutional note (id %s, category %s, target %s)."
                " Future chats about this target will see it automatically."
                % (row["id"], row["category"], row["target"] or "global"))

    def _notes_search(query="", category="", target="", top_k=5):
        if institutional is None:
            return "Error: institutional memory is not enabled."
        hits = institutional.search_notes(
            query.strip() or None,
            category=category.strip() or None,
            target=target.strip() or None,
            top_k=int(top_k or 5))
        if not hits:
            return "(no matching institutional notes)"
        lines = []
        for n in hits:
            lines.append("- [%s] %s: %s%s" % (
                n["category"], n["title"],
                " ".join(n["content"].split()),
                " (target: %s)" % n["target"] if n["target"] else ""))
        return "\n".join(lines)

    def _notes_list(category="", target="", limit=50):
        if institutional is None:
            return "Error: institutional memory is not enabled."
        notes = institutional.list_notes(
            category=category.strip() or None,
            target=target.strip() or None,
            limit=int(limit or 50))
        if not notes:
            return "(no institutional notes)"
        lines = []
        for n in notes:
            lines.append("- [#%s][%s] %s: %s%s" % (
                n["id"], n["category"], n["title"],
                " ".join(n["content"].split()),
                " (target: %s)" % n["target"] if n["target"] else ""))
        return "\n".join(lines)

    def _notes_delete(note_id):
        if institutional is None:
            return "Error: institutional memory is not enabled."
        ok = institutional.delete_note(note_id)
        return "Deleted note %s." % note_id if ok else \
            "Note %s not found." % note_id

    def _gm_world_update(patch=""):
        if world is None:
            return "Error: no world state in this context."
        try:
            data = json.loads(patch or "{}")
        except ValueError:
            return "Error: patch must be valid JSON."
        return world.apply_patch(data)

    def _gm_lore_add(category, title, content, tags=""):
        if lorebook is None:
            return "Error: no lorebook in this context."
        tag_list = [t.strip() for t in (tags or "").split(",") if t.strip()]
        entry = lorebook.add(category or "general", title or "untitled",
                             content or "", tag_list)
        return "Lore saved (id %s): %s" % (entry["id"], title)

    def _gm_lore_search(query="", top_k=5):
        if lorebook is None:
            return "Error: no lorebook in this context."
        hits = lorebook.search(query or "", top_k=int(top_k or 5))
        if not hits:
            return "(no matching lore entries)"
        lines = []
        for h in hits:
            lines.append("- [%s] %s\n  %s" % (
                h.get("category", ""), h.get("title", ""),
                h.get("content", "")))
        return "\n".join(lines)

    REGISTRY = [
        # ---- core ----
        Tool("run_terminal",
             "Execute a shell command on the user's machine and return its "
             "output. Use for system info, scripts, installs, scans.",
             {"type": "object",
              "properties": {"command": _str_prop("command to run", None),
                             "timeout": {"type": "integer", "default": 60,
                                         "description": "seconds"}},
              "required": ["command"]},
             lambda command="", timeout=60: tool_run_terminal(command, timeout),
             confirm=confirm_terminal),
        Tool("read_file", "Read a text file from disk.",
             {"type": "object",
              "properties": {"path": _str_prop("file path")},
              "required": ["path"]},
             lambda path="": tool_read_file(path)),
        Tool("write_file", "Write text content to a file (creates/overwrites).",
             {"type": "object",
              "properties": {"path": _str_prop("file path"),
                             "content": _str_prop("full content")},
              "required": ["path", "content"]},
             lambda path="", content="": tool_write_file(path, content)),
        Tool("list_files", "List files and directories under a path.",
             {"type": "object",
              "properties": {"path": _str_prop("directory", ".")},
              "required": []},
             lambda path=".": tool_list_files(path or ".")),

        # ---- persistent interactive sessions ----
        Tool("start_session",
             "Start a long-running interactive shell/process (e.g. a dev "
             "server, REPL, scanner, or listener) and return a session_id. "
             "The session keeps running in the background across tool calls "
             "so you can send input, read output, and wait for patterns "
             "later.",
             {"type": "object",
              "properties": {"command": _str_prop(
                  "command line to start (e.g. 'nmap -p- host')"),
                  "cwd": _str_prop("working directory", None),
                  "name": _str_prop("friendly label"),
                  "env": _str_prop("extra env vars as KEY=VALUE;...", None),
                  "shell": {"type": "boolean", "default": True,
                             "description": "run via shell"},
                  "pty": {"type": "boolean", "default": False,
                           "description": "run on a real pseudo-terminal "
                                          "(ConPTY/pty) so TUIs, colors, "
                                          "and isatty()-aware programs work"}},
              "required": ["command"]},
             lambda command="", cwd=None, name=None, env=None, shell=True,
                    pty=False:
                 tool_start_session(command, cwd=cwd or None, name=name or None,
                                    env=env or None, shell=bool(shell),
                                    pty=bool(pty))),
        Tool("send_input",
             "Send text or a control signal (ctrl_c, ctrl_break, ctrl_d, "
             "ctrl_z, esc, enter; POSIX also accepts sigint, sigterm, "
             "sigkill, sighup) into a running interactive session's stdin. "
             "Control signals do not kill the background process.",
             {"type": "object",
              "properties": {"session_id": _str_prop(
                  "session id from start_session"),
                  "input": _str_prop("text to type", ""),
                  "signal": _str_prop(
                      "control signal name: ctrl_c, ctrl_break, ctrl_d, "
                      "ctrl_z, esc, enter; POSIX also accepts sigint, "
                      "sigterm, sigkill, sighup, sigquit, sigusr1, sigusr2",
                      None, enum=["ctrl_c", "ctrl_break", "ctrl_d", "ctrl_z",
                                  "esc", "enter", "sigint", "sigterm",
                                  "sigkill", "sighup", "sigquit", "sigusr1",
                                  "sigusr2"]),  # enum aligned with terminal.py
                  "press_enter": {"type": "boolean", "default": True}},
              "required": ["session_id"]},
             lambda session_id="", input="", signal=None, press_enter=True:
                 tool_send_input(session_id, input=input, signal=signal,
                                 press_enter=bool(press_enter))),
        Tool("view_session_output",
             "Read accumulated output of a running session (never blocks; "
             "use wait_for_pattern to wait for something).",
             {"type": "object",
              "properties": {"session_id": _str_prop(
                  "session id from start_session"),
                  "tail": {"type": "integer", "default": 4000,
                            "description": "max chars per stream"},
                  "clear": {"type": "boolean", "default": False,
                             "description": "clear buffers after read"},
                  "include_stderr": {"type": "boolean", "default": True}},
              "required": ["session_id"]},
             lambda session_id="", tail=4000, clear=False,
                    include_stderr=True:
                 tool_view_session_output(
                     session_id, tail=int(tail or 4000), clear=bool(clear),
                     include_stderr=bool(include_stderr))),
        Tool("wait_for_pattern",
             "Poll a running session until a regex pattern appears in its "
             "combined output (or a timeout elapses). Use this after "
             "sending input to wait for the program's next prompt.",
             {"type": "object",
              "properties": {"session_id": _str_prop(
                  "session id from start_session"),
                  "pattern": _str_prop("regex to search for"),
                  "timeout": {"type": "integer", "default": 60,
                               "description": "seconds (max 100)"},
                  "fresh_only": {"type": "boolean", "default": False,
                                  "description": "only match output produced "
                                                 "after this call starts"}},
              "required": ["session_id", "pattern"]},
             lambda session_id="", pattern="", timeout=60, fresh_only=False:
                 tool_wait_for_pattern(session_id, pattern, timeout=timeout,
                                       fresh_only=bool(fresh_only))),
        Tool("kill_session",
             "Terminate a session's process tree and remove it from the "
             "session ledger.",
             {"type": "object",
              "properties": {"session_id": _str_prop(
                  "session id from start_session")},
              "required": ["session_id"]},
             lambda session_id="": tool_kill_session(session_id)),
        Tool("list_sessions",
             "List all interactive sessions: id, pid, status, age, and "
             "output sizes. Pass active_only=true for just running ones.",
             {"type": "object",
              "properties": {"active_only": {"type": "boolean",
                                              "default": False}},
              "required": []},
             lambda active_only=False:
                 tool_list_sessions(active_only=bool(active_only))),

        # ---- persistent PTY sessions (real pseudo-terminal) ----
        Tool("pty_start_session",
             "Start a long-running interactive process on a REAL "
             "pseudo-terminal (ConPTY on Windows, pty on POSIX) and return "
             "a unique session_id. The PTY stays alive in the background "
             "across tool calls. Use for TUI programs, REPLs, ssh, mysql "
             "clis, top/htop, or anything that needs isatty()/colors. "
             "Read output with pty_read_output, type with pty_send_input, "
             "tear down with pty_kill_session, inspect with pty_status.",
             {"type": "object",
              "properties": {"command": _str_prop(
                  "command line to start (e.g. 'python -i' or 'ssh user@host')"),
                  "cwd": _str_prop("working directory", None),
                  "name": _str_prop("friendly label"),
                  "env": _str_prop("extra env vars as KEY=VALUE;...", None),
                  "shell": {"type": "boolean", "default": True,
                             "description": "run via shell"}},
              "required": ["command"]},
             lambda command="", cwd=None, name=None, env=None, shell=True:
                 pty_start_session(command, cwd=cwd or None, name=name or None,
                                   env=env or None, shell=bool(shell))),
        Tool("pty_send_input",
             "Send raw interactive input to a PTY session's stdin: typed "
             "text, passwords, answers to prompts, or control characters. "
             "Raw bytes pass through literally (press_enter defaults to "
             "false, so '\\x03' reaches the program as a real Ctrl+C). "
             "Named signals also work: '!signal:ctrl_c', '!signal:enter', "
             "'!signal:esc', '!signal:ctrl_d'. Sending Ctrl+C does NOT "
             "kill the background session.",
             {"type": "object",
              "properties": {"session_id": _str_prop(
                  "session id from pty_start_session"),
                  "input_data": _str_prop(
                      "raw input to type, e.g. 'print(1+1)' or '\\x03' for "
                      "Ctrl+C; or '!signal:ctrl_c'"),
                  "press_enter": {"type": "boolean", "default": False,
                                   "description": "append newline after the "
                                                  "input (enable for typed "
                                                  "commands that need Enter)"}},
              "required": ["session_id", "input_data"]},
             lambda session_id="", input_data="", press_enter=False:
                 pty_send_input(session_id, input_data=input_data,
                                press_enter=bool(press_enter))),
        Tool("pty_read_output",
             "Fetch accumulated stdout/stderr of a PTY session without "
             "blocking or terminating it. Waits up to `timeout` seconds "
             "for NEW output (returns early as soon as any arrives), then "
             "returns the buffer tail. Safe to call repeatedly to stream "
             "a running process's output across tool calls.",
             {"type": "object",
              "properties": {"session_id": _str_prop(
                  "session id from pty_start_session"),
                  "timeout": {"type": "number", "default": 2.0,
                               "description": "max seconds to wait for new "
                                              "output (0 = snapshot only)"},
                  "tail": {"type": "integer", "default": 4000,
                            "description": "max chars per stream"},
                  "clear": {"type": "boolean", "default": False,
                             "description": "clear buffers after read"},
                  "include_stderr": {"type": "boolean", "default": True}},
              "required": ["session_id"]},
             lambda session_id="", timeout=2.0, tail=4000, clear=False,
                    include_stderr=True:
                 pty_read_output(session_id, timeout=timeout, tail=int(tail),
                                 clear=bool(clear),
                                 include_stderr=bool(include_stderr))),
        Tool("pty_kill_session",
             "Terminate a PTY session's whole process tree and clean up "
             "its process handles and ledger entry.",
             {"type": "object",
              "properties": {"session_id": _str_prop(
                  "session id from pty_start_session")},
              "required": ["session_id"]},
             lambda session_id="": pty_kill_session(session_id)),
        Tool("pty_status",
             "Dump the PTY session ledger: session id, pid, status "
             "(running/exited/killed), uptime and output byte counts. "
             "Pass active_only=true for just running sessions.",
             {"type": "object",
              "properties": {"active_only": {"type": "boolean",
                                               "default": False}},
              "required": []},
             lambda active_only=False: pty_status(active_only=bool(active_only))),
        Tool("web_search",
             "Search the web (DuckDuckGo) and return top results with links "
             "and snippets.",
             {"type": "object",
              "properties": {"query": _str_prop("search query"),
                             "max_results": {"type": "integer", "default": 6}},
              "required": ["query"]},
             lambda query="", max_results=6: tool_web_search(query, int(max_results or 6))),
        Tool("fetch_url",
             "Fetch a web page and extract its main readable text as clean "
             "plain text (scripts, CSS, navigation and ad junk removed, "
             "response cleanly truncated to max_length chars). Returns a "
             "structured dict: title, text, http_status, truncated flag, or "
             "a status/error message on 404/403/timeouts/SSL/DNS failures. "
             "Use after search_web/research to read a specific result page. "
             "For raw HTTP inspection (headers, status probes) use "
             "http_request instead.",
             {"type": "object",
              "properties": {"url": _str_prop("URL to fetch (https://...)"),
                             "max_length": {"type": "integer", "default": 4000,
                                             "description": "max characters of "
                                             "extracted text to return (200-50000)"}},
              "required": ["url"]},
             lambda url="", max_length=4000: fetch_url(url, int(max_length or 4000))),
        Tool("search_web",
             "Dedicated DuckDuckGo web search that returns structured JSON: "
             "a list of hits, each with title, url, and snippet. Uses the "
             "duckduckgo_search library with an automatic API-key-free "
             "fallback scraper. Use for quick factual lookups, current "
             "events, library/docs lookups, and CVE or exploit references. "
             "Prefer `research` when you need multi-variant citation-ready "
             "sources, and `open_url` afterwards to read a specific page.",
             {"type": "object",
              "properties": {"query": _str_prop("search query"),
                             "max_results": {"type": "integer", "default": 5,
                                             "description": "results to return (1-20)"}},
              "required": ["query"]},
             lambda query="", max_results=5: search_web(query, int(max_results or 5))),
        Tool("research",
             "Advanced research loop: expand an intent into 1-3 targeted query "
             "variants (technical jargon/acronym + non-English where applicable), "
             "run them, and return citation-ready structured sources "
             "(title, url, snippet). Use this for CVE lookups, tool parameters, "
             "and external technical facts.",
             {"type": "object",
              "properties": {"intent": _str_prop("research intent, e.g. 'CVE-2024-1234 details'"),
                             "lang": _str_prop("optional language hint, e.g. 'ur' for Urdu", ""),
                             "max_results": {"type": "integer", "default": 6}},
              "required": ["intent"]},
             lambda intent="", lang="", max_results=6:
                 tool_research(intent, lang, int(max_results or 6))),
        Tool("generate_queries",
             "Expand a research intent into 1-3 targeted query variants.",
             {"type": "object",
              "properties": {"intent": _str_prop("research intent"),
                             "lang": _str_prop("optional language hint", "")},
              "required": ["intent"]},
             lambda intent="", lang="": tool_generate_queries(intent, lang)),
        Tool("build_citation",
             "Build a strict markdown citation line from a validated source "
             "(title, URL, snippet). Call for every external fact used in a final response.",
             {"type": "object",
              "properties": {"title": _str_prop("source title"),
                             "url": _str_prop("source URL"),
                             "snippet": _str_prop("optional snippet context", "")},
              "required": ["url"]},
             lambda title="", url="", snippet="":
                 tool_build_citation(title, url, snippet)),
        Tool("open_url", "Fetch and read the text content of a webpage.",
             {"type": "object",
              "properties": {"url": _str_prop("page URL")},
              "required": ["url"]},
             lambda url="": tool_open_url(url)),
        Tool("memory_save",
             "Persist a fact/note/preference to long-term memory (survives "
             "agent restarts). Overwrites an existing key.",
             {"type": "object",
              "properties": {"key": _str_prop("short unique key, e.g. 'target_scope'"),
                             "value": _str_prop("the fact/note to remember")},
              "required": ["key", "value"]},
             lambda key="", value="": tool_memory_save(key, value)),
        Tool("memory_get",
             "Read a saved memory by exact key or key prefix.",
             {"type": "object",
              "properties": {"key": _str_prop("memory key or prefix")},
              "required": ["key"]},
             lambda key="": tool_memory_get(key)),
        Tool("memory_list",
             "List all long-term memories, optionally filtered by a text query.",
             {"type": "object",
              "properties": {"query": _str_prop("optional filter text", "")},
              "required": []},
             lambda query=None: tool_memory_list(query)),
        Tool("memory_delete",
             "Delete one long-term memory by key.",
             {"type": "object",
              "properties": {"key": _str_prop("memory key to delete")},
              "required": ["key"]},
             lambda key="": tool_memory_delete(key)),
        Tool("plan_task", "Break any complex task into an ordered, verifiable execution plan (HackerAI brain).",
             {"type": "object",
              "properties": {"task": _str_prop("the task/goal to plan"),
                             "context": _str_prop("optional context (findings, target, constraints)", "")},
              "required": ["task"]},
             lambda task="", context="": tool_plan_task(task, context)),
        Tool("reason", "Structured step-by-step reasoning chain (facts -> deduction -> conclusion -> confidence) for any analysis.",
             {"type": "object",
              "properties": {"question": _str_prop("question or analysis to reason about"),
                             "premises": _str_prop("verified premises/facts, one per line", "")},
              "required": ["question"]},
             lambda question="", premises="": tool_reason(question, premises)),
        Tool("reflect", "Self-review an answer before delivering: evidence check, gaps, corrections (HackerAI brain).",
             {"type": "object",
              "properties": {"answer": _str_prop("draft answer to review"),
                             "evidence": _str_prop("evidence/citations gathered", "")},
              "required": ["answer"]},
             lambda answer="", evidence="": tool_reflect(answer, evidence)),
        Tool("search_skills", "Search the on-demand pentest skill library. "
             "Returns ranked matching skills (id, title, tags, preview). "
             "Empty query lists all skills.",
             {"type": "object",
              "properties": {"query": _str_prop("free-text search query", ""),
                             "limit": _str_prop("max results (1-10, default 5)", 5)},
              "required": []},
             lambda query="", limit=5: tool_search_skills(query, int(limit or 5))),
        
Tool("browse_page", "Open a URL in headless Chromium; returns final URL, title, HTTP status, body preview and JS console/page errors (DOM XSS + SPA checks).",
     {"type": "object", "properties": {"uri": _str_prop("page URL to open (http/https/file)"), "wait_ms": {"type": "integer", "default": 2500}, "capture_js_errors": {"type": "boolean", "default": True}, "user_agent": _str_prop("optional custom User-Agent header for evasion/fingerprint checks", "")}, "required": ["uri"]},
     lambda uri="", wait_ms=2500, capture_js_errors=True, user_agent="": tool_browse_page(uri, int(wait_ms), bool(capture_js_errors), user_agent)),
Tool("click_element", "Click a CSS selector in the live browser page (SPA navigation, client-side auth bypass).",
     {"type": "object", "properties": {"selector": _str_prop("CSS selector to click"), "wait_ms": {"type": "integer", "default": 1200}}, "required": ["selector"]},
     lambda selector="", wait_ms=1200: tool_click_element(selector, int(wait_ms))),
Tool("fill_form", "Fill form fields in the live page.",
     {"type": "object", "properties": {"fields": _str_prop("JSON object mapping CSS selector to value"), "submit_selector": _str_prop("optional CSS selector to click after filling", "")}, "required": ["fields"]},
     lambda fields="{}", submit_selector="": tool_fill_form(fields, submit_selector)),
Tool("take_screenshot", "Save a PNG screenshot of the current page.",
     {"type": "object", "properties": {"path": _str_prop("absolute output path (default: temp dir)", ""), "full_page": {"type": "boolean", "default": False}}, "required": []},
     lambda path="", full_page=False: tool_take_screenshot(path, bool(full_page))),
Tool("capture_network_traffic", "Record page network requests/responses (CSRF tokens, API calls).",
     {"type": "object", "properties": {"uri": _str_prop("optional URL to navigate to", ""), "wait_ms": {"type": "integer", "default": 3000}, "filter_substring": _str_prop("optional URL substring filter", ""), "max_entries": {"type": "integer", "default": 250}}, "required": []},
     lambda uri="", wait_ms=3000, filter_substring="", max_entries=250: tool_capture_network_traffic(uri, int(wait_ms), filter_substring, int(max_entries))),
Tool("close_browser", "Close the headless browser and free memory.",
     {"type": "object", "properties": {}, "required": []},
     lambda: tool_close_browser()),
Tool("browser_open_url", "Open a URL in headless Chromium; returns final URL, title, HTTP status, body preview and JS console/page errors (DOM XSS + SPA checks). Supports custom User-Agent.",
     {"type": "object", "properties": {"uri": _str_prop("page URL to open (http/https/file)"), "wait_ms": {"type": "integer", "default": 2500}, "capture_js_errors": {"type": "boolean", "default": True}, "user_agent": _str_prop("optional custom User-Agent for evasion/fingerprint checks", "")}, "required": ["uri"]},
     lambda uri="", wait_ms=2500, capture_js_errors=True, user_agent="": browser_open_url(uri, int(wait_ms), bool(capture_js_errors), user_agent)),
Tool("browser_click_element", "Click a CSS selector in the live browser page (SPA navigation, client-side auth bypass).",
     {"type": "object", "properties": {"selector": _str_prop("CSS selector to click"), "wait_ms": {"type": "integer", "default": 1200}}, "required": ["selector"]},
     lambda selector="", wait_ms=1200: browser_click_element(selector, int(wait_ms))),
Tool("browser_fill_form", "Fill form fields in the live browser page (DOM XSS payload delivery, client-side auth form checks).",
     {"type": "object", "properties": {"fields": _str_prop("JSON object mapping CSS selector to value"), "submit_selector": _str_prop("optional CSS selector to click after filling", "")}, "required": ["fields"]},
     lambda fields="{}", submit_selector="": browser_fill_form(fields, submit_selector)),
Tool("browser_take_screenshot", "Save a PNG screenshot of the current browser page (visual evidence capture).",
     {"type": "object", "properties": {"path": _str_prop("absolute output path (default: temp dir)", ""), "full_page": {"type": "boolean", "default": False}}, "required": []},
     lambda path="", full_page=False: browser_take_screenshot(path, bool(full_page))),
Tool("browser_capture_network", "Record page network requests/responses in headless Chromium (CSRF tokens, API calls, auth redirects).",
     {"type": "object", "properties": {"uri": _str_prop("optional URL to navigate to", ""), "wait_ms": {"type": "integer", "default": 3000}, "filter_substring": _str_prop("optional URL substring filter", ""), "max_entries": {"type": "integer", "default": 250}}, "required": []},
     lambda uri="", wait_ms=3000, filter_substring="", max_entries=250: browser_capture_network(uri, int(wait_ms), filter_substring, int(max_entries))),
Tool("browser_close_browser", "Close the headless browser and free memory.",
     {"type": "object", "properties": {}, "required": []},
     lambda: browser_close_browser()),
Tool("aws_s3_enum", "Enumerate anonymous (public) access on an AWS S3 bucket: checks public read, object listing and optional anonymous write probe (misconfigured bucket policies).",
     {"type": "object", "properties": {"bucket_name": _str_prop("S3 bucket name to audit"), "probe_write": {"type": "boolean", "default": False}}, "required": ["bucket_name"]},
     lambda bucket_name="", probe_write=False: aws_s3_enum(bucket_name, bool(probe_write))),
Tool("cloud_misconfig_scan", "Scan a target domain for subdomain takeover fingerprints (AWS S3, GitHub Pages, Azure, GCP, Heroku, Fastly, CloudFront) and anonymously exposed cloud endpoints (.env, storage buckets).",
     {"type": "object", "properties": {"target_domain": _str_prop("target domain to scan (e.g. example.com)"), "max_subdomains": {"type": "integer", "default": 15}}, "required": ["target_domain"]},
     lambda target_domain="", max_subdomains=15: cloud_misconfig_scan(target_domain, int(max_subdomains))),
Tool("docker_security_audit", "Audit local/remote Docker daemon security: exposed unix/TCP sockets (2375/2376), privileged containers, published ports and daemon reachability.",
     {"type": "object", "properties": {"docker_host": _str_prop("optional remote host to probe for exposed Docker TCP API", ""), "timeout": {"type": "number", "default": 3.0}}, "required": []},
     lambda docker_host="", timeout=3.0: docker_security_audit(docker_host, float(timeout))),
Tool("load_skill", "Load a full methodology guide for one skill into "
             "context. Call search_skills first to find skill ids.",
             {"type": "object",
              "properties": {"skill_id": _str_prop("skill id, e.g. 'recon_methodology'")},
              "required": ["skill_id"]},
             lambda skill_id="": tool_load_skill(skill_id)),
        Tool("generate_security_hypotheses", "Hypothesis-driven vulnerability "
             "discovery: reason over enumerated attack surface (endpoints, "
             "routes, code snippets, services) and derive structured, "
             "logic-flaw hypotheses - state flaws, race conditions, "
             "authz bypasses, multi-step business-logic errors - each with "
             "reasoning, a proposed test strategy and a confidence score. "
             "NOT pattern scanning; feed recon/enumeration output from "
             "earlier steps. Every hypothesis is UNTESTED until validated.",
             {"type": "object",
              "properties": {"target_scope": _str_prop(
                  "engagement target (domain/URL/app name) the hypotheses "
                  "belong to"),
                             "attack_surface_json": _str_prop(
                  "JSON list of enumerated endpoints/routes/code snippets/" 
                  "services, e.g. [{\"route\": \"/api/orders/123\", "
                  "\"method\": \"GET\", \"code\": \"order = db.get(id)\"}] - "
                  "denser input yields higher-confidence hypotheses"),
                             "max_hypotheses": {"type": "integer",
                                 "description": "cap on returned hypotheses "
                                 "(1-15, default 8)", "default": 8}},
              "required": ["target_scope", "attack_surface_json"]},
             lambda target_scope="", attack_surface_json="", max_hypotheses=8:
                 tool_generate_security_hypotheses(
                     target_scope or "", attack_surface_json or "",
                     int(max_hypotheses or 8))),
        Tool("chain_to_verification_plan", "Map security hypotheses (from "
             "generate_security_hypotheses) into executable verification "
             "plans: each plan carries a ready-to-spawn verification_task "
             "for spawn_agent plus observable success_criteria that "
             "check_agent_status(validate=true) cross-checks. Chain order: "
             "recon -> generate_security_hypotheses -> "
             "chain_to_verification_plan -> spawn_agent(plan_json) -> "
             "check_agent_status(validate=true). Plans are ranked by "
             "confidence.",
             {"type": "object",
              "properties": {"hypotheses_json": _str_prop(
                  "JSON hypotheses from generate_security_hypotheses (list, "
                  "single object, or its full result dict)")},
              "required": ["hypotheses_json"]},
             lambda hypotheses_json="": tool_chain_to_verification_plan(
                 hypotheses_json or "")),
        Tool("remember", "Save a fact/note to persistent memory.",
             {"type": "object",
              "properties": {"key": _str_prop("short key, e.g. 'target_ip'"),
                             "text": _str_prop("the fact to remember")},
              "required": ["key", "text"]},
             lambda key="", text="": _remember(key, text)),
        Tool("recall", "List saved memory notes, optionally filtered.",
             {"type": "object",
              "properties": {"query": _str_prop("optional keyword filter", "")},
              "required": []},
             lambda query="": _recall(query)),
        Tool("vector_search",
             "RAG semantic search over saved notes + indexed documents. "
             "Returns the most relevant notes/chunks with similarity scores "
             "for a natural-language query. Use before answering when the "
             "question depends on saved knowledge.",
             {"type": "object",
              "properties": {"query": _str_prop("natural-language query"),
                             "top_k": {"type": "integer", "default": 5}},
              "required": ["query"]},
             lambda query="", top_k=5: _vector_search(query, top_k)),
        Tool("rag_index",
             "Index documents (txt/md/csv/json/log) from a folder into "
             "memory for vector_search. Default folder: ./docs in the "
             "project root.",
             {"type": "object",
              "properties": {"folder": _str_prop("folder path (optional)", "")},
              "required": []},
             lambda folder="": _rag_index(folder)),
        Tool("knowledge_save",
             "Persist a security finding/note to the cross-chat knowledge "
             "base for a target domain or IP, so future chats about the same "
             "target get it auto-injected into their system prompt.",
             {"type": "object",
              "properties": {
                  "target_domain": _str_prop(
                      "target domain or IP, e.g. example.com or 1.2.3.4"),
                  "finding_type": _str_prop(
                      "e.g. open_port, subdomain, cve, vulnerability, note",
                      "note"),
                  "content": _str_prop("the finding/note detail"),
                  "tags": _str_prop("comma-separated tags (optional)", "")},
              "required": ["target_domain", "content"]},
             lambda target_domain="", finding_type="note", content="",
                    tags="": _knowledge_save(target_domain, finding_type,
                                               content, tags)),
        Tool("knowledge_search",
             "Search the cross-chat knowledge base for past findings, "
             "optionally filtered to one target domain and ranked by "
             "relevance to a query.",
             {"type": "object",
              "properties": {
                  "target_domain": _str_prop(
                      "target domain/IP filter (optional)", ""),
                  "query": _str_prop(
                      "natural-language relevance query (optional)", ""),
                  "top_k": {"type": "integer", "default": 5}},
              "required": []},
             lambda target_domain="", query="", top_k=5:
                 _knowledge_search(target_domain, query, top_k)),

        # ---- cross-conversation institutional memory (notes_*) ----
        Tool("notes_add",
             "Log an institutional note to the GLOBAL cross-chat memory "
             "(SQLite, shared by every chat session). Categories: "
             "findings | methodology | active_plans | target_context. "
             "ABSOLUTE RULE: immediately after discovering a key finding, "
             "credential, token, endpoint, open port, subdomain, CVE or "
             "confirmed technique, call this in the SAME turn - do not wait "
             "for the final report. Future chats about the same target get "
             "these notes auto-injected.",
             {"type": "object",
              "properties": {
                  "category": _str_prop(
                      "findings | methodology | active_plans | target_context",
                      "findings"),
                  "title": _str_prop("short title"),
                  "content": _str_prop("the note detail (1-5 sentences)"),
                  "target": _str_prop(
                      "target domain/IP this note belongs to (optional)", ""),
                  "tags": _str_prop("comma-separated tags (optional)", "")},
              "required": ["title", "content"]},
             lambda category="findings", title="", content="", target="",
                    tags="": _notes_add(category, title, content, target,
                                         tags)),
        Tool("notes_search",
             "Consult the cross-chat institutional memory (mandatory before "
             "planning or answering): semantic search over historical notes "
             "about the current target - prior findings, credentials, "
             "endpoints, methodology and active plans. Optionally filter by "
             "category and/or target.",
             {"type": "object",
              "properties": {
                  "query": _str_prop(
                      "natural-language query (target name, endpoint, "
                      "technique)"),
                  "category": _str_prop(
                      "filter: findings | methodology | active_plans | "
                      "target_context", ""),
                  "target": _str_prop(
                      "filter to one target domain/IP (optional)", ""),
                  "top_k": {"type": "integer", "default": 5}},
              "required": ["query"]},
             lambda query="", category="", target="", top_k=5:
                 _notes_search(query, category, target, top_k)),
        Tool("notes_list",
             "List recent institutional notes, optionally filtered by "
             "category and/or target.",
             {"type": "object",
              "properties": {
                  "category": _str_prop(
                      "findings | methodology | active_plans | target_context",
                      ""),
                  "target": _str_prop(
                      "filter to one target domain/IP (optional)", ""),
                  "limit": {"type": "integer", "default": 50}},
              "required": []},
             lambda category="", target="", limit=50:
                 _notes_list(category, target, limit)),
        Tool("notes_delete",
             "Delete an institutional note by its id (e.g. after it is "
             "proven a false positive or a plan is closed).",
             {"type": "object",
              "properties": {"note_id": _str_prop("numeric note id")},
              "required": ["note_id"]},
             lambda note_id="": _notes_delete(note_id)),
        Tool("spawn_agent",
             "Spawn ONE tracked sub-agent that independently works on a task. "
             "Async by default: returns an agent_id JSON status immediately "
             "and the child runs in the background (max 2 siblings at once, "
             "4 children tracked). The child's output is UNVERIFIED until "
             "check_agent_status(agent_id, validate=true). Pass wait=true "
             "for legacy synchronous behaviour (blocks, returns the reply).",
             {"type": "object",
              "properties": {
                  "task": _str_prop("the task for the sub-agent"),
                  "success_criteria": _str_prop(
                      "what counts as done (optional; used by validation)", ""),
                  "capabilities": _str_prop(
                      "comma-separated capability bundle, e.g. 'terminal,web_research' (optional)", ""),
                  "wait": {"type": "boolean",
                            "default": False,
                            "description": "false=async (default), true=block until done"}},
              "required": ["task"]},
             lambda task="", success_criteria=None, capabilities=None, wait=None:
                 tool_spawn_agent(task or "", success_criteria,
                                  capabilities, wait)),
        Tool("spawn_agents",
             "Spawn MULTIPLE tracked sub-agents. Pass a JSON array of tasks "
             "or tasks separated by '|||'. Async by default: returns agent_id "
             "JSON statuses immediately. At most 2 run at once and 4 are "
             "tracked - excess tasks are REJECTED and reported. Outputs stay "
             "UNVERIFIED until check_agent_status(agent_id, validate=true). "
             "Pass wait=true for legacy synchronous behaviour.",
             {"type": "object",
              "properties": {
                  "tasks": _str_prop("JSON array of task strings, or 'task1 ||| task2 ||| task3'"),
                  "success_criteria": _str_prop(
                      "what counts as done (optional)", ""),
                  "capabilities": _str_prop(
                      "comma-separated capability bundle (optional)", ""),
                  "wait": {"type": "boolean",
                            "default": False,
                            "description": "false=async (default), true=block until done"}},
              "required": ["tasks"]},
             lambda tasks="", success_criteria=None, capabilities=None, wait=None:
                 tool_spawn_agents(tasks or "", success_criteria,
                                   capabilities, wait)),
        Tool("check_agent_status",
             "Check the status of one tracked sub-agent (or a table of all "
             "children when agent_id is empty). Pass validate=true to "
             "cross-check a finished child's output against its success "
             "criteria and mark it VERIFIED or UNVERIFIED. Sub-agent output "
             "must be validated this way before it is trusted.",
             {"type": "object",
              "properties": {
                  "agent_id": _str_prop("child agent id (empty = all children)", ""),
                  "validate": {"type": "boolean",
                                "default": False,
                                "description": "cross-check finished output against success criteria"}},
              "required": []},
             lambda agent_id="", validate=False:
                 tool_check_agent_status(agent_id or "", validate)),
        Tool("fetch_agent_transcript",
             "Fetch the full persisted transcript of one tracked sub-agent "
             "(or a summary table of all children when agent_id is empty). "
             "Use to audit exactly what a background child said and did.",
             {"type": "object",
              "properties": {"agent_id": _str_prop(
                  "child agent id (empty = all children)", "")},
              "required": []},
             lambda agent_id="": tool_fetch_agent_transcript(agent_id or "")),
        Tool("continue_agent",
             "Resume a FINISHED tracked sub-agent from its persisted "
             "transcript with a follow-up prompt; the same conversation "
             "continues. The new output is re-marked UNVERIFIED until "
             "validated again.",
             {"type": "object",
              "properties": {
                  "agent_id": _str_prop("child agent id to resume"),
                  "follow_up": _str_prop("follow-up prompt continuing the task")},
              "required": ["agent_id", "follow_up"]},
             lambda agent_id="", follow_up="":
                 tool_continue_agent(agent_id or "", follow_up or "")),
        Tool("cancel_agent",
             "Cancel one tracked sub-agent (or ALL active children when "
             "agent_id is empty). The child stops at its next checkpoint "
             "and its slot frees up for new spawns.",
             {"type": "object",
              "properties": {"agent_id": _str_prop(
                  "child agent id (empty = cancel all active)", "")},
              "required": []},
             lambda agent_id="": tool_cancel_agent(agent_id or "")),
        Tool("list_tools", "List every available tool with a short description.",
             {"type": "object", "properties": {}, "required": []},
             lambda: tool_list_tools()),
        Tool("manage_tasks",
             "Manage your task/todo list for multi-step assessments: add, "
             "list, update (pending/in_progress/completed/cancelled), delete, clear.",
             {"type": "object",
              "properties": {
                  "action": _str_prop("add | list | update | delete | clear", "list"),
                  "task_id": _str_prop("short task id, required for update/delete", ""),
                  "content": _str_prop("task description (required for add)", ""),
                  "status": _str_prop("pending | in_progress | completed | cancelled", ""),
              },
              "required": []},
             lambda action="list", task_id="", content="", status="":
                 tool_manage_tasks(action or "list", task_id or "",
                                   content or "", status or "")),

        # ---- system ----
        Tool("system_info", "OS, CPU, memory, hostname, cwd, user info.",
             {"type": "object", "properties": {}, "required": []},
             lambda: tool_system_info()),
        Tool("current_time", "Current local and UTC time with timezone.",
             {"type": "object", "properties": {}, "required": []},
             lambda: tool_current_time()),
        Tool("process_list", "List running processes, optionally filtered.",
             {"type": "object",
              "properties": {"name_filter": _str_prop("filter by name, or 'all'", "all")},
              "required": []},
             lambda name_filter="all": tool_process_list(name_filter)),
        Tool("disk_usage", "Disk space usage for a path or all drives ('all').",
             {"type": "object",
              "properties": {"path": _str_prop("path or 'all' for drives", ".")},
              "required": []},
             lambda path=".": tool_disk_usage(path or ".")),
        Tool("ip_info", "Show this machine's local IP addresses.",
             {"type": "object", "properties": {}, "required": []},
             lambda: tool_ip_info()),

        # ---- files & data ----
        Tool("search_files", "Find files by name glob under a path.",
             {"type": "object",
              "properties": {"pattern": _str_prop("glob, e.g. '*.log'", "*"),
                             "path": _str_prop("start directory", ".")},
              "required": []},
             lambda pattern="*", path=".": tool_search_files(pattern or "*", path or ".")),
        Tool("grep_files", "Search text inside files for a regex pattern.",
             {"type": "object",
              "properties": {"pattern": _str_prop("regex to find"),
                             "path": _str_prop("start directory", "."),
                             "file_pattern": _str_prop("file glob filter", "*")},
              "required": ["pattern"]},
             lambda pattern="", path=".", file_pattern="*":
                 tool_grep_files(pattern, path or ".", file_pattern or "*")),
        Tool("file_info", "Metadata of a file/dir: size, dates, type, magic bytes.",
             {"type": "object",
              "properties": {"path": _str_prop("file path")},
              "required": ["path"]},
             lambda path="": tool_file_info(path)),
        Tool("hash_file", "MD5/SHA1/SHA256/SHA512 hashes of a file.",
             {"type": "object",
              "properties": {"path": _str_prop("file path")},
              "required": ["path"]},
             lambda path="": tool_hash_file(path)),
        Tool("json_format", "Validate and pretty-print JSON (text or file).",
             {"type": "object",
              "properties": {"text": _str_prop("JSON string"),
                             "path": _str_prop("or a JSON file path")},
              "required": []},
             lambda text="", path="": tool_json_format(text or None, path or None)),
        Tool("csv_preview", "Preview a CSV file: rows, columns, head.",
             {"type": "object",
              "properties": {"path": _str_prop("CSV file path")},
              "required": ["path"]},
             lambda path="": tool_csv_preview(path)),
        Tool("create_archive", "Zip a file or directory.",
             {"type": "object",
              "properties": {"target_path": _str_prop("output zip path"),
                             "source_path": _str_prop("file or dir to zip")},
              "required": ["target_path", "source_path"]},
             lambda target_path="", source_path="":
                 tool_create_archive(target_path, source_path)),
        Tool("extract_archive", "Extract zip/tar/tar.gz into a folder.",
             {"type": "object",
              "properties": {"archive_path": _str_prop("archive file"),
                             "dest_dir": _str_prop("destination dir (optional)")},
              "required": ["archive_path"]},
             lambda archive_path="", dest_dir="":
                 tool_extract_archive(archive_path, dest_dir or None)),
        Tool("diff_text", "Show differences between two texts or files.",
             {"type": "object",
              "properties": {"text_a": _str_prop("first text"),
                             "text_b": _str_prop("second text"),
                             "path_a": _str_prop("or first file"),
                             "path_b": _str_prop("or second file")},
              "required": []},
             lambda text_a="", text_b="", path_a="", path_b="":
                 tool_diff_text(text_a or None, text_b or None,
                                path_a or None, path_b or None)),
        Tool("pdf_info", "PDF metadata: pages, title, creator, producer.",
             {"type": "object",
              "properties": {"path": _str_prop("PDF file path")},
              "required": ["path"]},
             lambda path="": tool_pdf_info(path)),
        Tool("image_info", "Image format and dimensions (PNG/JPEG/GIF/BMP/WEBP).",
             {"type": "object",
              "properties": {"path": _str_prop("image file path")},
              "required": ["path"]},
             lambda path="": tool_image_info(path)),

        # ---- web & http ----
        Tool("http_request", "Send a raw HTTP request (any method) and get "
             "status, headers, body.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "method": _str_prop("GET/POST/PUT/DELETE/HEAD/OPTIONS", "GET"),
                             "headers": _str_prop("extra headers, one per line 'Name: value'"),
                             "data": _str_prop("request body for POST/PUT")},
              "required": ["url"]},
             lambda url="", method="GET", headers="", data="":
                 tool_http_request(url, method or "GET", _parse_headers(headers),
                                   data or None)),
        Tool("check_headers", "Audit a URL's security headers (HSTS, CSP, "
             "X-Frame-Options, cookies...).",
             {"type": "object",
              "properties": {"url": _str_prop("target URL")},
              "required": ["url"]},
             lambda url="": tool_check_headers(url)),
        Tool("robots_txt", "Fetch a site's robots.txt.",
             {"type": "object",
              "properties": {"url": _str_prop("site base URL")},
              "required": ["url"]},
             lambda url="": tool_robots_txt(url)),
        Tool("extract_links", "Extract internal/external links from a page.",
             {"type": "object",
              "properties": {"url": _str_prop("page URL")},
              "required": ["url"]},
             lambda url="": tool_extract_links(url)),
        Tool("tech_detect", "Detect web technologies (server, CMS, framework).",
             {"type": "object",
              "properties": {"url": _str_prop("target URL")},
              "required": ["url"]},
             lambda url="": tool_tech_detect(url)),
        Tool("url_status", "Check HTTP status of comma-separated URLs.",
             {"type": "object",
              "properties": {"urls": _str_prop("comma-separated URLs")},
              "required": ["urls"]},
             lambda urls="": tool_url_status(urls)),

        # ---- network ----
        Tool("dns_lookup", "DNS records: A, AAAA, CNAME, MX, NS, TXT.",
             {"type": "object",
              "properties": {"hostname": _str_prop("domain/host"),
                             "record_type": _str_prop("A/AAAA/CNAME/MX/NS/TXT", "A")},
              "required": ["hostname"]},
             lambda hostname="", record_type="A":
                 tool_dns_lookup(hostname, record_type or "A")),
        Tool("reverse_dns", "PTR lookup for an IP address.",
             {"type": "object",
              "properties": {"ip": _str_prop("IP address")},
              "required": ["ip"]},
             lambda ip="": tool_reverse_dns(ip)),
        Tool("port_scan", "TCP connect scan with banner grabbing "
             "(pure Python, no nmap needed).",
             {"type": "object",
              "properties": {"host": _str_prop("target host/IP"),
                             "ports": _str_prop("ports, e.g. '80,443' or '1-1024'",
                                                "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,2375,3000,3306,3389,5432,5900,6379,8000,8080,8443,8888,9000,9090,9200,11211,27017"),
                             "timeout": {"type": "number", "default": 1.5}},
              "required": ["host"]},
             lambda host="", ports="", timeout=1.5:
                 tool_port_scan(host, ports or DEFAULT_PORTS, timeout)),
        Tool("whois", "WHOIS-style registration info via RDAP.",
             {"type": "object",
              "properties": {"domain_or_ip": _str_prop("domain or IP")},
              "required": ["domain_or_ip"]},
             lambda domain_or_ip="": tool_whois_rdap(domain_or_ip)),
        Tool("geoip", "IP geolocation: country, city, ISP, ASN.",
             {"type": "object",
              "properties": {"ip": _str_prop("IP address")},
              "required": ["ip"]},
             lambda ip="": tool_geoip_lookup(ip)),
        Tool("ssl_info", "TLS certificate details: issuer, expiry, SANs, cipher.",
             {"type": "object",
              "properties": {"host": _str_prop("hostname"),
                             "port": {"type": "integer", "default": 443}},
              "required": ["host"]},
             lambda host="", port=443: tool_ssl_info(host, port or 443)),
        Tool("ping_host", "ICMP ping a host (system ping).",
             {"type": "object",
              "properties": {"host": _str_prop("host/IP"),
                             "count": {"type": "integer", "default": 3}},
              "required": ["host"]},
             lambda host="", count=3: tool_ping_host(host, int(count or 3))),

        # ---- recon ----
        Tool("subdomain_enum", "Enumerate subdomains via Certificate "
             "Transparency (crt.sh).",
             {"type": "object",
              "properties": {"domain": _str_prop("root domain, e.g. example.com")},
              "required": ["domain"]},
             lambda domain="": tool_subdomain_enum(domain)),
        Tool("dir_fuzz", "Brute-force common paths on a web server. Optionally "
             "pass your own comma-separated wordlist or a wordlist file path.",
             {"type": "object",
              "properties": {"base_url": _str_prop("e.g. https://example.com"),
                             "wordlist": _str_prop("comma-separated paths (optional)"),
                             "wordlist_path": _str_prop("path to a wordlist file (optional)"),
                             "max_results": {"type": "integer", "default": 40}},
              "required": ["base_url"]},
             lambda base_url="", wordlist="", wordlist_path="", max_results=40:
                 tool_dir_fuzz(base_url, wordlist or None, wordlist_path or None,
                               int(max_results or 40))),
        Tool("cve_lookup", "Search known CVEs by product/keyword/version.",
             {"type": "object",
              "properties": {"query": _str_prop("e.g. 'nginx 1.18' or 'wordpress'")},
              "required": ["query"]},
             lambda query="": tool_cve_lookup(query)),
        Tool("wordlist_gen", "Generate a wordlist from keywords + numbers + "
             "years + special chars.",
             {"type": "object",
              "properties": {"keywords": _str_prop("comma-separated base words"),
                             "numbers": _str_prop("range like '0-9'", "0-9"),
                             "years": _str_prop("range like '2015-2026'", "2015-2026"),
                             "specials": _str_prop("chars to append", "!@#")},
              "required": ["keywords"]},
             lambda keywords="", numbers="0-9", years="2015-2026", specials="!@#":
                 tool_wordlist_gen(keywords, numbers, years, specials)),

        # ---- code & utilities ----
        Tool("run_python", "Execute Python code in a subprocess; returns "
             "stdout/stderr.",
             {"type": "object",
              "properties": {"code": _str_prop("Python source code"),
                             "timeout": {"type": "integer", "default": 30}},
              "required": ["code"]},
             lambda code="", timeout=30: tool_run_python(code, timeout)),
        Tool("regex_test", "Test a regex against sample text and show matches "
             "with capture groups.",
             {"type": "object",
              "properties": {"pattern": _str_prop("regex pattern"),
                             "text": _str_prop("sample text"),
                             "flags": _str_prop("i/m/s flags, e.g. 'i'")},
              "required": ["pattern", "text"]},
             lambda pattern="", text="", flags="":
                 tool_regex_test(pattern, text, flags or "")),
        Tool("generate_password", "Generate strong random passwords.",
             {"type": "object",
              "properties": {"length": {"type": "integer", "default": 16},
                             "count": {"type": "integer", "default": 3}},
              "required": []},
             lambda length=16, count=3:
                 tool_generate_password(length=int(length or 16), count=int(count or 3))),
        Tool("encode_decode", "Encode/decode text: base64, hex, url, base32, rot13.",
             {"type": "object",
              "properties": {"action": _str_prop("encode or decode", "encode",
                                                 ["encode", "decode"]),
                             "encoding": _str_prop("base64/hex/url/base32/rot13", "base64"),
                             "data": _str_prop("input text")},
              "required": ["data"]},
             lambda action="encode", encoding="base64", data="":
                 tool_encode_decode(action or "encode", encoding or "base64", data)),
        Tool("hash_text", "Hash a string: md5, sha1, sha256, sha512.",
             {"type": "object",
              "properties": {"text": _str_prop("input text"),
                             "algorithms": _str_prop("comma-separated", "sha256")},
              "required": ["text"]},
             lambda text="", algorithms="sha256":
                 tool_hash_text(text, algorithms or "sha256")),
        Tool("uuid_gen", "Generate one or more UUID v4.",
             {"type": "object",
              "properties": {"count": {"type": "integer", "default": 1}},
              "required": []},
             lambda count=1: tool_uuid_gen(int(count or 1))),

        # ---- custom utilities ----
        Tool("sha1_quick", "Quick SHA1 hash of a file (streaming).",
             {"type": "object",
              "properties": {"path": _str_prop("file path")},
              "required": ["path"]},
             lambda path="": tool_sha1_quick(path)),
        Tool("strings_extract", "Extract printable strings from a binary/file "
             "(recon, malware, config dumps).",
             {"type": "object",
              "properties": {"path": _str_prop("file path"),
                             "min_len": {"type": "integer", "default": 4},
                             "limit": {"type": "integer", "default": 200}},
              "required": ["path"]},
             lambda path="", min_len=4, limit=200:
                 tool_strings_extract(path, int(min_len or 4), int(limit or 200))),
        Tool("html_to_text", "Convert HTML (URL or raw source) into readable "
             "text - useful to read page content without tags.",
             {"type": "object",
              "properties": {"source": _str_prop("URL or raw HTML string"),
                             "max_chars": {"type": "integer", "default": 4000}},
              "required": ["source"]},
             lambda source="", max_chars=4000:
                 tool_html_to_text(source or "", int(max_chars or 4000))),
        Tool("dedupe_lines", "Remove duplicate lines from a file (wordlist/scope "
             "cleanup); optionally write the cleaned file.",
             {"type": "object",
              "properties": {"path": _str_prop("input file"),
                             "output_path": _str_prop("output file (optional)", "")},
              "required": ["path"]},
             lambda path="", output_path="":
                 tool_dedupe_lines(path, output_path or "")),
        Tool("count_lines", "Count lines in a file, optionally matching a regex.",
             {"type": "object",
              "properties": {"path": _str_prop("file path"),
                             "pattern": _str_prop("regex (optional)", "")},
              "required": ["path"]},
             lambda path="", pattern="":
                 tool_count_lines(path, pattern or "")),

        # ---- pentest arsenal (external binary wrappers) ----
        Tool("nmap_scan", "Run nmap against a host with service detection "
             "(requires nmap installed; fallback: port_scan).",
             {"type": "object",
              "properties": {"host": _str_prop("target host/IP"),
                             "ports": _str_prop("e.g. '80,443' or '1-1024' (optional)"),
                             "args": _str_prop("extra nmap flags", "-sV -T4")},
              "required": ["host"]},
             lambda host="", ports="", args="":
                 tool_nmap_scan(host, ports or "", args or "-sV -T4")),
        Tool("sqlmap_check", "Automated SQL injection testing with sqlmap "
             "(non-interactive --batch).",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "data": _str_prop("POST body (optional)"),
                             "level": {"type": "integer", "default": 1},
                             "risk": {"type": "integer", "default": 1}},
              "required": ["url"]},
             lambda url="", data="", level=1, risk=1:
                 tool_sqlmap_check(url, data or "", int(level or 1), int(risk or 1))),
        Tool("nikto_scan", "Run a nikto web server vulnerability scan.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL")},
              "required": ["url"]},
             lambda url="": tool_nikto_scan(url)),
        Tool("nuclei_scan", "Run nuclei template-based vulnerability scanning.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "templates": _str_prop("template name/path (optional)"),
                             "severity": _str_prop("comma list", "low,medium,high,critical")},
              "required": ["url"]},
             lambda url="", templates="", severity="":
                 tool_nuclei_scan(url, templates or "", severity or "low,medium,high,critical")),
        Tool("ffuf_fuzz", "Fast web fuzzing with ffuf (dir or vhost mode).",
             {"type": "object",
              "properties": {"base_url": _str_prop("target base URL"),
                             "wordlist_path": _str_prop("path to wordlist file"),
                             "mode": _str_prop("dir or vhost", "dir", ["dir", "vhost"])},
              "required": ["base_url", "wordlist_path"]},
             lambda base_url="", wordlist_path="", mode="dir":
                 tool_ffuf_fuzz(base_url, wordlist_path or "", mode or "dir")),
        Tool("gobuster_dir", "Directory/file brute force with gobuster.",
             {"type": "object",
              "properties": {"base_url": _str_prop("target base URL"),
                             "wordlist_path": _str_prop("path to wordlist file"),
                             "extensions": _str_prop("e.g. 'php,txt,zip' (optional)")},
              "required": ["base_url", "wordlist_path"]},
             lambda base_url="", wordlist_path="", extensions="":
                 tool_gobuster_dir(base_url, wordlist_path or "", extensions or "")),
        Tool("subfinder_enum", "Passive subdomain enumeration with subfinder "
             "(ProjectDiscovery).",
             {"type": "object",
              "properties": {"domain": _str_prop("root domain")},
              "required": ["domain"]},
             lambda domain="": tool_subfinder_enum(domain)),
        Tool("httpx_probe", "Probe URLs with httpx: status, title, tech stack.",
             {"type": "object",
              "properties": {"urls": _str_prop("comma-separated URLs")},
              "required": ["urls"]},
             lambda urls="": tool_httpx_probe(urls)),
        Tool("curl_request", "Raw HTTP request via curl (ships with Windows "
             "10+/macOS/Linux) - full control over headers/method/body.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "method": _str_prop("GET/POST/PUT/DELETE/HEAD/OPTIONS", "GET"),
                             "headers": _str_prop("one per line 'Name: value'"),
                             "data": _str_prop("request body")},
              "required": ["url"]},
             lambda url="", method="GET", headers="", data="":
                 tool_curl_request(url, method or "GET", headers or "", data or "")),
        Tool("jwt_decode", "Decode a JWT header and payload (no signature "
             "verification) - useful for token tampering analysis.",
             {"type": "object",
              "properties": {"token": _str_prop("JWT token")},
              "required": ["token"]},
             lambda token="": tool_jwt_decode(token)),
        # ---- extra security & utilities ----
        Tool("http_methods", "Probe which HTTP methods a server allows "
             "(OPTIONS, PUT, DELETE, TRACE...) and flag TRACE/XST risk.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL")},
              "required": ["url"]},
             lambda url="": tool_http_methods(url)),
        Tool("cors_check", "Test CORS misconfiguration: sends attacker "
             "origins and checks Access-Control-Allow-Origin reflection.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL")},
              "required": ["url"]},
             lambda url="": tool_cors_check(url)),
        Tool("waf_detect", "Detect a WAF: fingerprint headers and send "
             "attack payloads to look for blocking/anomalies.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL")},
              "required": ["url"]},
             lambda url="": tool_waf_detect(url)),
        Tool("redirect_chain", "Follow and display the full redirect chain "
             "of a URL with each hop status and Location.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "max_hops": {"type": "integer", "default": 10}},
              "required": ["url"]},
             lambda url="", max_hops=10: tool_redirect_chain(url, int(max_hops or 10))),
        Tool("dns_axfr", "Attempt a DNS zone transfer (AXFR) for a domain; "
             "success = serious misconfiguration (full record dump).",
             {"type": "object",
              "properties": {"domain": _str_prop("domain to test"),
                             "nameserver": _str_prop("optional NS to query")},
              "required": ["domain"]},
             lambda domain="", nameserver="": tool_dns_axfr(domain, nameserver or "")),
        Tool("extract_iocs", "Extract IOCs from text: URLs, emails, IPs, "
             "domains, hashes (MD5/SHA1/SHA256/SHA512).",
             {"type": "object",
              "properties": {"text": _str_prop("text to scan")},
              "required": ["text"]},
             lambda text="": tool_extract_iocs(text)),
        Tool("http_cookies", "Audit cookies set by a URL: names, flags "
             "(HttpOnly, Secure, SameSite), expiry, and weaknesses.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL")},
              "required": ["url"]},
             lambda url="": tool_http_cookies(url)),
        Tool("local_listeners", "List locally listening TCP/UDP ports with "
             "the owning process name (Windows/Linux).",
             {"type": "object", "properties": {}, "required": []},
             lambda: tool_local_listeners()),
        Tool("sqlite_query", "Run read-only SQL against a SQLite database "
             "file; '.tables' and '.schema' helpers supported.",
             {"type": "object",
              "properties": {"db_path": _str_prop("path to .db/.sqlite file"),
                             "query": _str_prop("SQL or .tables/.schema", ".tables")},
              "required": ["db_path"]},
             lambda db_path="", query=".tables": tool_sqlite_query(db_path, query or ".tables")),
        Tool("password_strength", "Analyze a password: length, charset, "
             "entropy, strength score (0-4), common-password check.",
             {"type": "object",
              "properties": {"password": _str_prop("password to analyze")},
              "required": ["password"]},
             lambda password="": tool_password_strength(password)),
        Tool("mac_vendor", "Look up the NIC vendor (OUI) for a MAC address "
             "via macvendors.com with offline fallback.",
             {"type": "object",
              "properties": {"mac_address": _str_prop("MAC address, e.g. 00:0c:29:ab:cd:ef")},
              "required": ["mac_address"]},
             lambda mac_address="": tool_mac_vendor(mac_address)),
        Tool("subnet_calc", "CIDR subnet calculator: network, mask, "
             "broadcast, usable hosts, first/last address.",
             {"type": "object",
              "properties": {"cidr": _str_prop("e.g. 192.168.1.0/24")},
              "required": ["cidr"]},
             lambda cidr="": tool_subnet_calc(cidr)),

        # ---- exploit & payload generation ----
        Tool("gen_reverse_shell", "Generate a ready-to-run reverse shell "
             "payload (bash/nc/python/powershell/php/perl/ruby/socat/msfvenom) "
             "with the matching listener command.",
             {"type": "object",
              "properties": {"os_type": _str_prop("linux | windows", "linux"),
                             "lhost": _str_prop("listener IP", "127.0.0.1"),
                             "lport": {"type": "integer", "default": 4444},
                             "method": _str_prop("auto | bash | nc | python | powershell | php | perl | ruby | socat | msfvenom", "auto"),
                             "encode": {"type": "boolean", "default": False}},
              "required": []},
             lambda os_type="linux", lhost="127.0.0.1", lport=4444, method="auto", encode=False:
                 tool_gen_reverse_shell(os_type or "linux", lhost or "127.0.0.1",
                                        lport, method or "auto", bool(encode))),
        Tool("gen_bind_shell", "Generate a bind shell payload for the target.",
             {"type": "object",
              "properties": {"os_type": _str_prop("linux | windows", "linux"),
                             "port": {"type": "integer", "default": 4444},
                             "method": _str_prop("auto | nc | python | powershell | socat", "auto")},
              "required": []},
             lambda os_type="linux", port=4444, method="auto":
                 tool_gen_bind_shell(os_type or "linux", port, method or "auto")),
        Tool("gen_webshell", "Generate a minimal web shell (php/asp/aspx/jsp) "
             "gated by a password parameter.",
             {"type": "object",
              "properties": {"platform": _str_prop("php | asp | aspx | jsp", "php"),
                             "password": _str_prop("gate password", "s3cr3t")},
              "required": []},
             lambda platform="php", password="s3cr3t":
                 tool_gen_webshell(platform or "php", password or "s3cr3t")),
        Tool("gen_listener", "Generate listener commands to catch a shell.",
             {"type": "object",
              "properties": {"lhost": _str_prop("bind address", "0.0.0.0"),
                             "lport": {"type": "integer", "default": 4444},
                             "upgrade": {"type": "boolean", "default": False}},
              "required": []},
             lambda lhost="0.0.0.0", lport=4444, upgrade=False:
                 tool_gen_listener(lhost or "0.0.0.0", lport, bool(upgrade))),
        Tool("gen_obfuscate", "Obfuscate a command for evasion testing: "
             "base64, single/double quote, unicode (windows).",
             {"type": "object",
              "properties": {"payload": _str_prop("command to obfuscate"),
                             "technique": _str_prop("b64 | single_quote | double_quote | unicode", "b64"),
                             "os_type": _str_prop("linux | windows", "linux")},
              "required": ["payload"]},
             lambda payload="", technique="b64", os_type="linux":
                 tool_gen_obfuscate(payload, technique or "b64", os_type or "linux")),
        Tool("gen_wordlist", "Generate a candidate wordlist from base words "
             "with leetspeak + suffixes (password/credential testing).",
             {"type": "object",
              "properties": {"base_words": _str_prop("comma or newline separated"),
                             "l33t": {"type": "boolean", "default": True},
                             "suffixes": _str_prop("comma-separated suffixes", "!,@,#,$,123,1234,2024,2025")},
              "required": ["base_words"]},
             lambda base_words="", l33t=True, suffixes="":
                 tool_gen_wordlist(base_words or "", bool(l33t), suffixes or "")),

        # ---- manual web attack detectors ----
        Tool("sqli_test", "Manual boolean-based SQL injection detection on a "
             "parameter (no sqlmap needed). Follow up with sqlmap_check.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "param": _str_prop("parameter to test"),
                             "method": _str_prop("GET | POST", "GET"),
                             "data": _str_prop("POST body (optional)")},
              "required": ["url", "param"]},
             lambda url="", param="", method="GET", data="":
                 tool_sqli_test(url, param, method or "GET", data or "")),
        Tool("xss_test", "Manual reflected XSS detection on a parameter.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "param": _str_prop("parameter to test"),
                             "method": _str_prop("GET | POST", "GET"),
                             "data": _str_prop("POST body (optional)")},
              "required": ["url", "param"]},
             lambda url="", param="", method="GET", data="":
                 tool_xss_test(url, param, method or "GET", data or "")),
        Tool("cmd_inject_test", "Manual command injection detection on a "
             "parameter (non-destructive echo probes).",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "param": _str_prop("parameter to test"),
                             "method": _str_prop("GET | POST", "GET"),
                             "data": _str_prop("POST body (optional)")},
              "required": ["url", "param"]},
             lambda url="", param="", method="GET", data="":
                 tool_cmd_inject_test(url, param, method or "GET", data or "")),
        Tool("path_traversal_test", "Manual path traversal / LFI detection on "
             "a parameter (passwd / win.ini / proc signatures).",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "param": _str_prop("parameter to test"),
                             "method": _str_prop("GET | POST", "GET"),
                             "data": _str_prop("POST body (optional)")},
              "required": ["url", "param"]},
             lambda url="", param="", method="GET", data="":
                 tool_path_traversal_test(url, param, method or "GET", data or "")),
        Tool("ssrf_test", "SSRF detection via an external callback URL you "
             "control (listener / webhook.site / interactsh).",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "param": _str_prop("parameter to test"),
                             "callback_url": _str_prop("your callback URL")},
              "required": ["url", "param", "callback_url"]},
             lambda url="", param="", callback_url="":
                 tool_ssrf_test(url, param, callback_url or "")),
        Tool("open_redirect_test", "Manual open redirect detection on a parameter.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "param": _str_prop("parameter to test")},
              "required": ["url", "param"]},
             lambda url="", param="": tool_open_redirect_test(url, param)),

        # ---- advanced capability detectors (XXE / NoSQLi / SSTI / JWT / GQL / etc.) ----
        Tool("xxe_test", "XXE detection: inject external entity payloads (XML + "
             "JSON variants), look for file-read / SSRF / error reflection.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "param": _str_prop("parameter holding XML/JSON"),
                             "data": _str_prop("full request body (optional)"),
                             "method": _str_prop("POST | GET", "POST"),
                             "content_type": _str_prop("content-type override", "")},
              "required": ["url"]},
             lambda url="", param="", data="", method="POST", content_type="":
                 tool_xxe_test(url or "", param or "", data or "", method or "POST", content_type or "")),
        Tool("header_inject_test", "CRLF / header injection detection on a parameter "
             "(response splitting, cache poisoning surface).",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "param": _str_prop("parameter to test"),
                             "method": _str_prop("GET | POST", "GET"),
                             "data": _str_prop("POST body (optional)")},
              "required": ["url", "param"]},
             lambda url="", param="", method="GET", data="":
                 tool_header_inject_test(url or "", param or "", method or "GET", data or "")),
        Tool("nosql_inject_test", "NoSQL injection (MongoDB $ne/$gt/$or operator "
             "auth-bypass) on a login endpoint.",
             {"type": "object",
              "properties": {"url": _str_prop("login endpoint URL"),
                             "user_param": _str_prop("username field name", "username"),
                             "pass_param": _str_prop("password field name", "password"),
                             "method": _str_prop("POST | GET", "POST")},
              "required": ["url"]},
             lambda url="", user_param="username", pass_param="password", method="POST":
                 tool_nosql_inject_test(url or "", user_param or "username", pass_param or "password", method or "POST")),
        Tool("ssti_test", "Server-Side Template Injection detection on a parameter "
             "({{7*7}} math probes across common engines).",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "param": _str_prop("parameter to test"),
                             "method": _str_prop("GET | POST", "GET"),
                             "data": _str_prop("POST body (optional)")},
              "required": ["url", "param"]},
             lambda url="", param="", method="GET", data="":
                 tool_ssti_test(url or "", param or "", method or "GET", data or "")),
        Tool("jwt_attack", "JWT attack lab: decode, verify signature, try alg=none / "
             "key-confusion / weak-HS256 brute-force on a token.",
             {"type": "object",
              "properties": {"token": _str_prop("the JWT to analyze"),
                             "public_key": _str_prop("public key (RS256->HS256 confusion)", ""),
                             "wordlist": _str_prop("common secrets wordlist (optional)", "")},
              "required": ["token"]},
             lambda token="", public_key="", wordlist="":
                 tool_jwt_attack(token or "", public_key or "", wordlist or "")),
        Tool("graphql_check", "GraphQL endpoint check: introspection query, schema "
             "dump, field enumeration, depth/alias abuse probes.",
             {"type": "object",
              "properties": {"url": _str_prop("GraphQL endpoint URL"),
                             "auth_header": _str_prop("optional 'Authorization: ...' value", "")},
              "required": ["url"]},
             lambda url="", auth_header="":
                 tool_graphql_check(url or "", auth_header or "")),
        Tool("deserialization_check", "Deserialization detection: probe common gadget "
             "signatures (Java/PHP/Python/JSON) in serialized payloads, flag "
             "error/behavioral signals.",
             {"type": "object",
              "properties": {"request_text": _str_prop("raw serialized payload / request"),
                             "url": _str_prop("target URL (optional)", ""),
                             "param": _str_prop("parameter holding the payload", ""),
                             "method": _str_prop("POST | GET", "POST")},
              "required": []},
             lambda request_text="", url="", param="", method="POST":
                 tool_deserialization_check(request_text or "", url or "", param or "", method or "POST")),
        Tool("smuggling_detect", "HTTP request smuggling detection: send CL+TE / "
             "TE+CL probe pairs and look for desynced response evidence.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "method": _str_prop("POST | GET", "POST")},
              "required": ["url"]},
             lambda url="", method="POST":
                 tool_smuggling_detect(url or "", method or "POST")),
        Tool("oauth_check", "OAuth flow audit: analyze authorization URL for "
             "redirect_uri validation, state usage, response-type flaws.",
             {"type": "object",
              "properties": {"auth_url": _str_prop("authorization endpoint URL"),
                             "redirect_uri": _str_prop("client redirect_uri", ""),
                             "client_id": _str_prop("client_id", ""),
                             "state": _str_prop("expected state value", "")},
              "required": ["auth_url"]},
             lambda auth_url="", redirect_uri="", client_id="", state="":
                 tool_oauth_check(auth_url or "", redirect_uri or "", client_id or "", state or "")),
        Tool("cloud_meta_test", "Cloud metadata SSRF probe: test a URL-fetching param "
             "against 169.254.169.254 / 100.100.100.200 with IMDSv1/v2 payloads, "
             "look for cloud credentials reflection.",
             {"type": "object",
              "properties": {"url": _str_prop("SSRF-capable endpoint URL"),
                             "param": _str_prop("URL parameter to test"),
                             "method": _str_prop("GET | POST", "GET"),
                             "data": _str_prop("POST body (optional)")},
              "required": ["url", "param"]},
             lambda url="", param="", method="GET", data="":
                 tool_cloud_meta_test(url or "", param or "", method or "GET", data or "")),
        Tool("lockfile_scan", "Dependency CVE scan: parse package lockfiles "
             "(package-lock.json, yarn.lock, requirements.txt, Pipfile.lock, "
             "poetry.lock, go.sum, Cargo.lock, composer.lock) and query the "
             "OSV API for known CVEs.",
             {"type": "object",
              "properties": {"path": _str_prop("path to lockfile"),
                             "max_packages": {"type": "integer", "default": 200}},
              "required": ["path"]},
             lambda path="", max_packages=200:
                 tool_lockfile_scan(path or "", int(max_packages or 200))),
        Tool("ad_svc_probe", "Active Directory presence probe: TCP-connect to AD "
             "service ports (Kerberos/LDAP/SMB/GC/RDP) and score how likely "
             "the host is a domain controller.",
             {"type": "object",
              "properties": {"host": _str_prop("IP or hostname"),
                             "ports": _str_prop("comma-separated custom ports", ""),
                             "timeout": {"type": "integer", "default": 3}},
              "required": ["host"]},
             lambda host="", ports="", timeout=3:
                 tool_ad_svc_probe(host or "", ports or "", int(timeout or 3))),
        Tool("smb_enum", "Active Directory / SMB enumeration: probe an SMB "
             "server (default port 445) for reachability, negotiated SMB1/SMB2 "
             "protocol dialects, signing requirements, null-session anonymous "
             "access (SMB1 session setup + tree connect), accessible anonymous "
             "shares (IPC$, NETLOGON, SYSVOL, ADMIN$, C$), plus adjacent "
             "NetBIOS (139) and MSRPC (135) presence.",
             {"type": "object",
              "properties": {"target_ip": _str_prop("IP address or hostname to probe"),
                             "port": {"type": "integer", "default": 445,
                                      "description": "SMB TCP port"}},
              "required": ["target_ip"]},
             lambda target_ip="", port=445:
                 smb_enum(target_ip or "", int(port or 445))),
        Tool("smb_share_enum", "Deep anonymous SMB share enumeration: establish "
             "an NTLMSSP null session over SMB2 (SMB1 fallback), then "
             "TREE_CONNECT brute-force ~70 common share names (IPC$, ADMIN$, "
             "C$, NETLOGON, SYSVOL, Backup, HR, Finance, Deploy, ...). Returns "
             "accessible shares with types, per-share NTSTATUS errors and "
             "findings (critical if ADMIN$/C$ open). Pass 'shares' to test a "
             "custom list.",
             {"type": "object",
              "properties": {"target_ip": _str_prop("IP address or hostname"),
                             "port": {"type": "integer", "default": 445,
                                      "description": "SMB TCP port"},
                             "shares": _str_prop("optional comma/space-separated custom share list", "")},
              "required": ["target_ip"]},
             lambda target_ip="", port=445, shares="":
                 smb_share_enum(target_ip or "", int(port or 445), shares or "")),
        Tool("ldap_search_anonymous", "Anonymous LDAP enumeration on port 389: "
             "perform an anonymous bind, then query the root DSE (or a supplied "
             "base DN) for naming contexts, default/root domain naming contexts, "
             "supported LDAP versions and SASL mechanisms, server DNS host, and "
             "any exposed directory entries. Returns structured JSON; never raises.",
             {"type": "object",
              "properties": {"target_ip": _str_prop("IP address or hostname"),
                             "base_dn": _str_prop("base DN to search (empty = root DSE)", "")},
              "required": ["target_ip"]},
             lambda target_ip="", base_dn="":
                 ldap_search_anonymous(target_ip or "", base_dn or "")),
        Tool("kerberos_ticket_check", "Kerberos KDC probing on port 88: send raw "
             "AS-REQ packets for given usernames against the supplied domain/realm "
             "and classify KDC responses (AS-REP vs KRB-ERROR codes) to detect "
             "AS-REP roastable accounts (pre-auth disabled, hashcat mode 18200) "
             "and enumerate valid usernames via PREAUTH_REQUIRED responses.",
             {"type": "object",
              "properties": {"target_ip": _str_prop("IP address of the KDC / DC"),
                             "domain": _str_prop("AD domain/realm (e.g. corp.local)"),
                             "usernames": _str_prop("comma-separated usernames to probe", "Administrator")},
              "required": ["target_ip", "domain"]},
             lambda target_ip="", domain="", usernames="Administrator":
                 kerberos_ticket_check(target_ip or "", domain or "", usernames or "Administrator")),
        Tool("subnet_sweep", "Rapid parallel internal network host discovery: sweep "
             "an IPv4 CIDR block for hosts with common enterprise service ports "
             "(default 80, 445, 3389, 22) using non-blocking concurrent TCP "
             "connects. Returns per-host open ports for pivot mapping.",
             {"type": "object",
              "properties": {"subnet_cidr": _str_prop("IPv4 CIDR e.g. 10.10.10.0/24"),
                             "ports": _str_prop("comma-separated ports", "80,445,3389,22"),
                             "max_hosts": {"type": "integer", "default": 8192,
                                           "description": "cap on addresses swept"}, 
                             "workers": {"type": "integer", "default": 200,
                                         "description": "concurrent connections"}, 
                             "timeout": {"type": "number", "default": 1.5,
                                         "description": "connect timeout seconds"}},
              "required": ["subnet_cidr"]},
             lambda subnet_cidr="", ports="", max_hosts=8192, workers=200, timeout=1.5:
                 subnet_sweep(subnet_cidr or "", ports or "",
                             max_hosts, workers, timeout)),


        # ---- findings & reporting ----
        Tool("add_finding", "Log a vulnerability finding for the engagement "
             "(asset, title, severity, CWE, evidence, impact, remediation).",
             {"type": "object",
              "properties": {"asset": _str_prop("affected URL/host/endpoint"),
                             "title": _str_prop("short finding title"),
                             "severity": _str_prop("critical | high | medium | low | info", "medium"),
                             "cwe": _str_prop("e.g. CWE-89", ""),
                             "description": _str_prop("what and where", ""),
                             "evidence": _str_prop("proof: payload + response excerpt", ""),
                             "impact": _str_prop("demonstrated blast radius", ""),
                             "remediation": _str_prop("fix guidance", ""),
                             "confidence": _str_prop("low | medium | high | confirmed", "medium"),
                             "status": _str_prop("open | confirmed | needs-validation | hypothesis | false-positive | fixed", "open"),
                             "verification": _str_prop("verified | unverified | false-positive - verification state of the claim (sets matching status)", ""),
                             "verification_reason": _str_prop("why the claim was verified/filtered", "")},
              "required": ["asset", "title"]},
             lambda asset="", title="", severity="medium", cwe="", description="", evidence="", impact="", remediation="", confidence="medium", status="open", verification="", verification_reason="":
                 tool_add_finding(asset, title, severity or "medium", cwe or "", description or "", evidence or "", impact or "", remediation or "", confidence or "medium", status or "open", verification or "", verification_reason or "")),
        Tool("list_findings", "List all logged findings, optionally filtered "
             "by severity/status.",
             {"type": "object",
              "properties": {"severity": _str_prop("comma list e.g. high,critical", ""),
                             "status": _str_prop("comma list e.g. open,confirmed", ""),
                             "sort_by": _str_prop("severity | asset | ts", "severity")},
              "required": []},
             lambda severity="", status="", sort_by="severity":
                 tool_list_findings(severity or "", status or "", sort_by or "severity")),
        Tool("update_finding", "Update a logged finding by id (severity, status, remediation...).",
             {"type": "object",
              "properties": {"finding_id": _str_prop("e.g. F-1A2B3C4D"),
                             "severity": _str_prop("critical | high | medium | low | info", ""),
                             "status": _str_prop("open | confirmed | false-positive | fixed | ...", ""),
                             "title": _str_prop("new title", ""),
                             "remediation": _str_prop("new remediation", ""),
                             "confidence": _str_prop("low | medium | high | confirmed", ""),
                             "verification": _str_prop("verified | unverified | false-positive", ""),
                             "verification_reason": _str_prop("why the claim was verified/filtered", "")},
              "required": ["finding_id"]},
             lambda finding_id="", severity="", status="", title="", remediation="", confidence="", verification="", verification_reason="":
                 tool_update_finding(finding_id or "", severity or "", status or "", title or "", remediation or "", confidence or "", verification or "", verification_reason or "")),
        Tool("delete_finding", "Delete a finding by id.",
             {"type": "object",
              "properties": {"finding_id": _str_prop("e.g. F-1A2B3C4D")},
              "required": ["finding_id"]},
             lambda finding_id="": tool_delete_finding(finding_id or "")),
        Tool("verify_finding", "Re-verify one logged finding with lightweight "
             "benign checks (TCP port probe, DNS resolution, CVE database "
             "lookup, single HTTP GET + header validation) and update its "
             "verification state + status automatically.",
             {"type": "object",
              "properties": {"finding_id": _str_prop("e.g. F-1A2B3C4D"),
                             "method": _str_prop("verification method label", "auto")},
              "required": ["finding_id"]},
             lambda finding_id="", method="auto":
                 tool_verify_finding(finding_id or "", method or "auto")),
        Tool("verify_findings", "Re-verify all (unverified) logged findings with "
             "lightweight benign checks; confirmed ones become verified true "
             "positives, contradicted ones are filtered as false positives "
             "with an explanation.",
             {"type": "object",
              "properties": {"only_unverified": {"type": "boolean",
                                                     "default": True}},
              "required": []},
             lambda only_unverified=True:
                 tool_verify_all_findings(bool(only_unverified))),
        Tool("write_report", "Generate a complete Markdown penetration test "
             "report from the logged findings (exec summary, severity table, "
             "detailed findings, remediation).",
             {"type": "object",
              "properties": {"target": _str_prop("assessed asset / engagement name"),
                             "author": _str_prop("report author", "HackerAI Agent"),
                             "output_path": _str_prop("optional file path"),
                             "include_open_only": {"type": "boolean", "default": False},
                             "include_remediation": {"type": "boolean", "default": True}},
              "required": ["target"]},
             lambda target="", author="HackerAI Agent", output_path="", include_open_only=False, include_remediation=True:
                 tool_write_report(target or "", author or "HackerAI Agent", output_path or "", bool(include_open_only), bool(include_remediation))),
        Tool("correlate_findings", "Correlate & deduplicate raw vulnerability scan "
             "results from multiple scanners (Nmap, Nuclei, Nikto, HTTP probes "
             "or any mix - field names are auto-normalized). Merges duplicate "
             "findings, tracks which scanners corroborate each one, upgrades "
             "severity if any source rates higher, and maps every unique "
             "finding to a unified CVSS v3.1 risk vector. Returns structured "
             "JSON with per-severity counts and a risk matrix.",
             {"type": "object",
              "properties": {"findings_list": _str_prop("JSON array of finding objects (raw scanner output accepted)")},
              "required": ["findings_list"]},
             lambda findings_list="":
                 correlate_findings(findings_list or "")),
        Tool("build_attack_chains", "Attack-Chain Graph Correlator: reconstruct "
             "linked attack paths from raw findings instead of flat lists. "
             "Example: Null SMB Session -> Unencrypted Share Read -> Hardcoded "
             "Credential -> Local Admin PrivEsc -> Domain Controller Compromise. "
             "Each chain carries chain_id, entry_point, intermediate_pivots, "
             "final_impact, composite_risk_score (series-system risk compounding "
             "across hops) and a remediation_choke_point (the single highest-impact "
             "hop whose fix collapses every path through it). Raw scanner JSON is "
             "accepted and auto-deduplicated first.",
             {"type": "object",
              "properties": {"findings_list": _str_prop("JSON array of finding objects (raw scanner output accepted)")},
              "required": ["findings_list"]},
             lambda findings_list="":
                 build_attack_chains(findings_list or "")),
        Tool("visualize_attack_chains", "Build attack chains from findings and "
             "return a graph visualization of the attack paths (chain table + "
             "per-chain graph blocks) ready to embed in reports. fmt selects "
             "the graph format: ascii (default), mermaid or graphviz. "
             "per_asset=true keeps each chain scoped to its own asset.",
             {"type": "object",
              "properties": {"findings_list": _str_prop("JSON array of finding objects (raw scanner output accepted)"),
                             "fmt": _str_prop("graph format: ascii | mermaid | graphviz"),
                             "per_asset": {"type": "boolean", "description": "scope each chain to its entry asset"}},
              "required": ["findings_list"]},
             lambda findings_list="", fmt="ascii", per_asset=False:
                 visualize_attack_chains(findings_list or "", fmt=fmt,
                                         per_asset=per_asset)),
        Tool("visualize_merged_chains", "Build attack chains from findings, merge "
             "chains that share pivot hops into convergence clusters (multiple "
             "entry points funnelling through common stepping stones) and return "
             "a merged-branch graph block. fmt: mermaid (default), ascii or "
             "graphviz.",
             {"type": "object",
              "properties": {"findings_list": _str_prop("JSON array of finding objects (raw scanner output accepted)"),
                             "fmt": _str_prop("graph format: mermaid | ascii | graphviz"),
                             "per_asset": {"type": "boolean", "description": "scope each chain to its entry asset"}},
              "required": ["findings_list"]},
             lambda findings_list="", fmt="mermaid", per_asset=False:
                 visualize_merged_chains(findings_list or "", fmt=fmt,
                                         per_asset=per_asset)),
        Tool("populate_cve_table", "Fetch real CVSS v3.1 base scores from the NVD "
             "API for the given CVE ids and persist chain-hop entries to "
             "cve_nodes.json, so future attack-chain builds use CVE-specific, "
             "CVSS-weighted hops without re-fetching. Accepts a comma-separated "
             "string or JSON list of CVE ids.",
             {"type": "object",
              "properties": {"cve_ids": _str_prop("CVE ids, e.g. 'CVE-2021-44228, CVE-2015-1631'")},
              "required": ["cve_ids"]},
             lambda cve_ids="": populate_cve_table(cve_ids or "")),
        Tool("calc_cvss_score", "Calculate a CVSS v3.1 score (base + temporal "
             "+ environmental), per-metric ratings and severity level "
             "(Critical/High/Medium/Low/None) from a vector string such as "
             "'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' (temporal E/RL/RC "
             "and environmental CR/IR/AR/MAV/MAC/MPR/MUI/MS/MC/MI/MA metrics "
             "may be appended) or a metrics object. Implements the official "
             "FIRST CVSS v3.1 formula including scope-changed impact.",
             {"type": "object",
              "properties": {"vector_string_or_metrics": _str_prop("CVSS vector string or JSON object with metrics AV/AC/PR/UI/S/C/I/A")},
              "required": ["vector_string_or_metrics"]},
             lambda vector_string_or_metrics="":
                 calc_cvss_score(vector_string_or_metrics or "")),
        Tool("generate_markdown_report", "Generate a standalone professional "
             "Markdown penetration test report from a supplied findings payload: "
             "executive summary, risk matrix with CVSS score bands, findings "
             "summary table, detailed findings with proof-of-concept evidence "
             "and remediation strategies, plus remediation priorities. Findings "
             "are auto-correlated and deduplicated first and the reconstructed "
             "attack-chain graph (linked attack paths with composite risk scores "
             "and a graph visualization) is embedded as its own report section. "
             "chain_fmt selects the chain graph format: ascii (default), mermaid "
             "or graphviz; per_asset=true scopes each chain to its own asset. "
             "The report is saved to the reports/ directory and returned "
             "as Markdown.",
             {"type": "object",
              "properties": {"target_name": _str_prop("assessed target / engagement name"),
                             "executive_summary": _str_prop("summary paragraph (auto-generated if empty)", ""),
                             "findings_json": _str_prop("JSON array of finding objects (raw or correlated)"),
                             "report_title": _str_prop("custom cover title (default 'Penetration Test Report')", ""),
                             "author": _str_prop("report author", "HackerAI Agent"),
                             "organization": _str_prop("client / organization name for the cover", ""),
                             "logo_url": _str_prop("markdown image URL for the logo header", ""),
                             "classification": _str_prop("data classification label", "Confidential"),
                             "chain_fmt": _str_prop("chain graph format: ascii | mermaid | graphviz", "ascii"),
                             "per_asset": {"type": "boolean", "description": "scope each attack chain to its entry asset"}},
              "required": ["target_name", "findings_json"]},
             lambda target_name="", executive_summary="", findings_json="", report_title="", author="HackerAI Agent", organization="", logo_url="", classification="Confidential", chain_fmt="ascii", per_asset=False:
                 generate_markdown_report(target_name or "", executive_summary or "", findings_json or "", report_title or "", author or "HackerAI Agent", organization or "", logo_url or "", classification or "Confidential", chain_fmt=chain_fmt, per_asset=per_asset)),

        # ---- scope enforcement ----
        Tool("set_scope", "Set the engagement scope: comma-separated domains, "
             "IPs, CIDRs, URLs. Only these targets may be tested.",
             {"type": "object",
              "properties": {"targets": _str_prop("comma-separated targets"),
                             "note": _str_prop("optional engagement note", "")},
              "required": ["targets"]},
             lambda targets="", note="": tool_set_scope(targets or "", note or "")),
        Tool("show_scope", "Show the current engagement scope.",
             {"type": "object", "properties": {}, "required": []},
             lambda: tool_show_scope()),
        Tool("check_scope", "Verify a host/URL is inside the declared engagement "
             "scope before scanning it. Returns ALLOWED or BLOCKED.",
             {"type": "object",
              "properties": {"host": _str_prop("host, IP or URL to check")},
              "required": ["host"]},
             lambda host="": tool_check_scope(host or "")),

        # ---- workspace mapping & cross-references ----
        Tool("workspace_scan", "Index a project/workspace directory: file tree "
             "with per-file stats (language, size, lines) plus a cached symbol "
             "and import index used by the other workspace_* tools. Re-scans "
             "only changed files (mtime cache).",
             {"type": "object",
              "properties": {"root": _str_prop("workspace directory to index", "."),
                             "depth": {"type": "integer",
                                       "description": "limit scan depth (optional)"}},
              "required": []},
             lambda root=".", depth=None:
                 tool_workspace_scan(root or ".", depth=depth,
                                     index=workspace_index)),
        Tool("workspace_symbols", "List function/class signatures indexed for "
             "the workspace (optionally filtered by file glob).",
             {"type": "object",
              "properties": {"root": _str_prop("workspace directory", "."),
                             "file_pattern": _str_prop(
                                 "file glob filter, e.g. 'core.py' or '*.py'", "*")},
              "required": []},
             lambda root=".", file_pattern="*":
                 tool_workspace_symbols(root or ".", file_pattern or "*",
                                        index=workspace_index)),
        Tool("workspace_deps", "Show the dependency (import) graph for one "
             "file: internal imports resolved to files, external packages, "
             "and the reverse list of files that import it. Without a file, "
             "prints all internal import edges.",
             {"type": "object",
              "properties": {"root": _str_prop("workspace directory", "."),
                             "file": _str_prop(
                                 "relative file path to inspect (empty = whole graph)", "")},
              "required": []},
             lambda root=".", file="":
                 tool_workspace_deps(root or ".", file or "",
                                     index=workspace_index)),
        Tool("workspace_query", "Cross-reference lookup across the whole "
             "workspace: where a function/class is defined and referenced, or "
             "which files import a module. Free-form text searches code lines.",
             {"type": "object",
              "properties": {"query": _str_prop(
                  "symbol name, module path, or text to find"),
                             "root": _str_prop("workspace directory", ".")},
              "required": ["query"]},
             lambda query="", root=".":
                 tool_workspace_query(query or "", root or ".",
                                      index=workspace_index)),
        Tool("workspace_export", "Export the current workspace index as JSON "
             "(files, symbols, imports) for caching or persistence.",
             {"type": "object",
              "properties": {"root": _str_prop("workspace directory", ".")},
              "required": []},
             lambda root=".":
                 tool_workspace_export(root or ".", index=workspace_index)),
    ]

    if rpg_ctx:
        REGISTRY += [
            Tool("gm_world_update",
                 "Game-Master world-state update. Apply changes to the game "
                 "world: location, stats (hp/gold/xp), inventory, flags, "
                 "quests, npcs, counters. Call BEFORE narrating when anything "
                 "changed. Returns the full updated world state.",
                 {"type": "object",
                  "properties": {"patch": _str_prop(
                      "JSON object with optional keys: location (string name), "
                      "location_desc (string), stats (object), inventory "
                      "(object of add/remove lists), flags (object of true/false "
                      "or strings), quests (object), npcs (object), counters "
                      "(object). Nested keys use dotted paths like "
                      "'counters.gold'.")},
                  "required": ["patch"]},
             lambda patch="": _gm_world_update(patch)),
            Tool("gm_lore_add",
                 "Game-Master lorebook write. Record an important world fact "
                 "(place, person, item, rumor, history, faction) so the "
                 "campaign never forgets it.",
                 {"type": "object",
                  "properties": {"category": _str_prop(
                      "people | places | items | factions | history | rules | general"),
                      "title": _str_prop("short title"),
                      "content": _str_prop("the fact, 1-3 sentences"),
                      "tags": _str_prop("comma-separated tags", "")},
                  "required": ["category", "title", "content"]},
             lambda category="", title="", content="", tags="":
                 _gm_lore_add(category, title, content, tags)),
            Tool("gm_lore_search",
                 "Game-Master lorebook recall. Semantic search over recorded "
                 "lore. Use when a question touches history, people, places "
                 "or items.",
                 {"type": "object",
                  "properties": {"query": _str_prop("what to look up"),
                                  "top_k": {"type": "integer", "default": 5}},
                  "required": ["query"]},
             lambda query="", top_k=5: _gm_lore_search(query, top_k)),
        ]

    REGISTRY.append(Tool("current_time",
        "Current date and time - local + UTC ISO-8601, unix epoch, weekday,"
        "date. Use for log correlation, artifact timestamps, TLS cert"
        "validity checks and deadline awareness. Zero arguments.",
        {"type": "object", "properties": {}, "required": []},
        lambda: tool_current_time()))
    global _REGISTRY
    _REGISTRY = REGISTRY
    return REGISTRY


DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,2375,3000,3306,3389,5432,5900,6379,8000,8080,8443,8888,9000,9090,9200,11211,27017"


def tool_current_time():
    """Current local/UTC time: ISO-8601, unix epoch, weekday, date.
    Always knows what 'today' is - for log correlation, artifact
    timestamps, TLS cert validity and deadline checks."""
    import datetime
    import time as _time
    now = datetime.datetime.now()
    return {"local": now.strftime("%Y-%m-%d %H:%M:%S"),
            "utc": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S") + "Z",
            "epoch": int(_time.time()),
            "weekday": now.strftime("%A"),
            "date": now.strftime("%Y-%m-%d")}
_REGISTRY = []


def _parse_headers(headers_text):
    """Parse 'Name: value' lines into a dict."""
    if not headers_text or not isinstance(headers_text, str):
        return None
    out = {}
    for line in headers_text.splitlines():
        line = line.strip()
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out or None


__all__ = ["Tool", "execute_tool", "create_tools", "truncate"]
