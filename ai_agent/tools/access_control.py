# -*- coding: utf-8 -*-
"""Access-Control enforcement layer (real, backend-side).

Phase-1 of the interaction-bar access/scope/mode upgrade: previously the
web UI only *instructed* the model ("[CONTROL] access=Read-Only ...") and
relied on prompt compliance.  This module turns those labels into an
enforced gate that runs in the agent core *before* any tool executes.

Modes
-----
full     -> unrestricted (operator-owned default; nothing is filtered)
labonly  -> active security testing allowed, but host/OS-destructive and
            persistence-changing operations are rejected (no rm -rf,
            format, account tampering, service disable, firewall flush,
            Remove-Item, Format-Volume, ... even when issued through
            run_terminal / run_python / pty_* free-form executors).
readonly -> fail-closed. Only informational / passive-read / pure-compute
            tools are allowed. No terminal, no python, no file writes, no
            session control, no active attack payloads.

Full mode is the default everywhere, so nothing here reduces capability
unless the operator explicitly selects Read-Only or Lab-Only in the UI
(or sets "access_mode" in config.json).

Phase-2 (documented, not yet wired): Step-By-Step human-in-the-loop
confirmation endpoint on the web layer.
"""
from __future__ import annotations

import re

# canonical mode codes (kept in sync with webui interaction-bar labels)
FULL = "full"
LABONLY = "labonly"
READONLY = "readonly"

MODE_ALIASES = {
    "full": FULL, "full access": FULL,
    "labonly": LABONLY, "lab-only": LABONLY, "lab only": LABONLY,
    "readonly": READONLY, "read-only": READONLY, "read only": READONLY,
}


def normalize_mode(mode) -> str:
    if mode is None:
        return FULL
    return MODE_ALIASES.get(str(mode).strip().lower(), FULL)


_EXEC_TOOLS = {
    "run_terminal", "run_python", "pty_start_session", "pty_send_input",
    "start_session", "send_input", "browser_fill_form", "browser_click_element",
}
_PAYLOAD_KEYS = (
    "command", "code", "script", "input", "keys", "keys_to_send",
    "commands", "content",
)

_DESTRUCTIVE = re.compile(
    r"\b(?:"
    r"rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+|[a-zA-Z]*\s+)?/|rmdir\s+/[sq]|"
    r"del\s+/[fqs]|erase\s+/[fqs]|rd\s+/[sq]|format\s+\w:?|"
    r"shutdown|reboot|restart-computer|stop-computer|mkfs\b|fdisk\b|"
    r"diskpart\b|dd\s+(?:if|of)=|wipe\b|vssadmin\b|bcdedit\b|"
    r"chkdsk\s+[a-zA-Z]:\s*/f|reg\s+(?:delete|add)|sc\s+delete\b|"
    r"taskkill\s*/f|pkill\s*-9|killall\s*-9|kill\s+-9\s+0|"
    r"systemctl\s+(?:stop|disable|mask|start|enable|restart|halt|poweroff)\b|"
    r"service\s+\S+\s+(?:stop|restart|start|enable|disable)\b|"
    r"useradd\b|userdel\b|adduser\b|deluser\b|passwd\b|"
    r"net\s+user\s+\S+\s*/\s*add|net\s+localgroup\s+\S+\s*/\s*add|"
    r"chmod\s+-[a-zA-Z]*[rwx]*[0-7]{3}|chown\s+|mount\b|umount\b|"
    r"iptables\b|ufw\b|firewall-cmd\b|takeown\b|icacls\s+\S+\s*/grant|"
    r"attrib\s+-r\s+/s|wmic\s+\S+\s+delete\b|"
    r"remove-item\b|remove-itemproperty\b|clear-item\b|format-volume\b|"
    r"initialize-disk\b|new-partition\b|set-itemproperty\b|"
    r"stop-service\b|set-service\b|restart-service\b|disable-service\b|"
    r"enable-service\b|install-package\b|uninstall-package\b|"
    r"set-executionpolicy\b|disable-item\b|remove-module\b"
    r")\b",
    re.IGNORECASE,
)

READONLY_ALLOW = {
    "current_time", "list_tools", "uuid_gen", "encode_decode", "hash_text",
    "regex_test", "subnet_calc", "json_format", "diff_text", "dedupe_lines",
    "csv_preview", "calc_cvss_score", "build_citation", "generate_password",
    "password_strength", "html_to_text", "strings_extract", "count_lines",
    "wordlist_gen", "generate_queries", "reason", "reflect", "research",
    "load_skill", "search_skills", "gen_wordlist", "gen_poc", "gen_webshell",
    "gen_reverse_shell", "gen_bind_shell", "gen_obfuscate", "gen_listener",
    "payload_memory_top", "hunt_cve_variants", "cve_lookup",
    "dns_lookup", "reverse_dns", "whois", "geoip", "ip_info", "mac_vendor",
    "ssl_info", "subdomain_enum", "subfinder_enum", "port_scan", "nmap_scan",
    "ping_host", "tech_detect", "url_status", "check_headers", "http_cookies",
    "http_methods", "robots_txt", "httpx_probe", "nikto_scan", "nuclei_scan",
    "waf_detect", "dir_fuzz", "gobuster_dir", "ffuf_fuzz", "subnet_sweep",
    "ssl_probe", "extract_links", "http_request", "curl_request", "fetch_url",
    "open_url", "web_search", "search_web", "browse_page", "extract_iocs",
    "list_files", "read_file", "grep_files", "search_files", "file_info",
    "hash_file", "process_list", "system_info", "disk_usage", "workspace_scan",
    "workspace_query", "workspace_symbols", "workspace_deps", "workspace_query",
    "pdf_info", "image_info", "sha1_quick",
    "memory_list", "memory_get", "vector_search", "knowledge_search",
    "list_findings", "show_scope", "check_scope", "list_sessions",
    "notes_list", "notes_search", "local_listeners", "view_session_output",
    "jwt_decode", "sqlite_query", "rag_index", "smb_share_enum",
    "ldap_search_anonymous", "payload_memory_reset",
}

READONLY_DENY_HINTS = (
    "delete", "remove", "write", "upload", "kill", "shutdown", "install",
    "uninstall", "upgrade", "update_finding", "reset", "reload",
)


def _args_text(args) -> str:
    if not isinstance(args, dict):
        return str(args or "")
    texts = []
    for key, val in args.items():
        if key in _PAYLOAD_KEYS or isinstance(val, str):
            texts.append(str(val))
    return "\n".join(texts)


def _payload_destructive(args) -> bool:
    return bool(_DESTRUCTIVE.search(_args_text(args)))


def _bare_tool_destructive(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in READONLY_DENY_HINTS)


def gate_tool(mode, name, args=None):
    """Enforce access control for one tool call.

    Returns (allowed, reason). When allowed is False the caller MUST NOT
    run the tool and must feed `reason` back to the model as the result.
    Full mode always allows (operator-owned unrestricted default).
    """
    mode = normalize_mode(mode)
    name = (name or "").lower()

    if mode == FULL:
        return True, None

    if mode == READONLY:
        if name in READONLY_ALLOW:
            return True, None
        if name in _EXEC_TOOLS:
            return False, ("[ACCESS DENIED] Read-Only mode blocks %s: "
                           "no terminal/python/session execution. Use the "
                           "passive read tools (list_files, read_file, "
                           "grep_files, web_search, fetch_url ...)." % name)
        if _bare_tool_destructive(name):
            return False, ("[ACCESS DENIED] Read-Only mode blocks %r: "
                           "tool can create/delete/modify state." % name)
        return False, ("[ACCESS DENIED] Read-Only mode blocks %s: not on the "
                       "read-only allowlist. Re-run with Full/Lab-Only access "
                       "or pick a passive read-only tool." % name)

    if name in _EXEC_TOOLS:
        if _payload_destructive(args):
            return False, ("[ACCESS DENIED] Lab-Only mode rejects destructive "
                           "host operation requested through %s. Full Access "
                           "is required for this operation." % name)
    return True, None
