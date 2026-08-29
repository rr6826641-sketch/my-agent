"""Structured artifact storage for automated scan/generation outputs.

Files are stored as artifacts/{chat_id}/{tool}_{timestamp}_{suffix}.{ext}
so every chat keeps its own history of nmap/nuclei/curl/recon outputs and
generated files. The web UI exposes them as downloadable badges through
/api/download/<artifact_id> and a per-chat markdown report.

Artifact ids ARE the file names. Download lookups only accept a strict
[A-Za-z0-9._-] id and glob it inside artifacts/<chat_id>/ so path
traversal (../, absolute paths, encoded separators) is impossible.
"""

import datetime
import json
import os
import re
import uuid

ARTIFACT_MAX_BYTES = 1_000_000  # per-artifact safety cap (1 MB)
ARTIFACT_TRUNCATE_NOTE = (
    "\n\n[artifact truncated by the agent: exceeds %d bytes]" %
    ARTIFACT_MAX_BYTES)

# Tool results worth persisting as artifacts (scan/recon/generation).
AUTO_CAPTURE_TOOLS = frozenset({
    "port_scan", "subdomain_enum", "dir_fuzz", "dns_lookup", "reverse_dns",
    "whois", "geoip", "ssl_info", "ping_host", "url_status", "check_headers",
    "robots_txt", "extract_links", "tech_detect", "cve_lookup",
    "http_request", "wordlist_gen", "run_python", "write_file",
})

# run_terminal is captured only when the command looks like a scan / network
# tool (nmap, nuclei, curl, ...) so harmless commands stay out of artifacts.
_SCAN_CMD_RE = re.compile(
    r"\b(nmap|nuclei|nikto|gobuster|ffuf|wfuzz|dirb|dirsearch|feroxbuster|"
    r"masscan|rustscan|sqlmap|whatweb|wpscan|hydra|medusa|john|hashcat|"
    r"aircrack-ng|tcpdump|tshark|traceroute|sslscan|testssl|amass|"
    r"sublist3r|subfinder|httpx|dnsx|naabu|katana|theharvester|waybackurls|"
    r"gau|hakrawler|jwt_tool|whois|dig|nslookup|curl|wget|python3?|"
    r"node|go run)\b", re.I)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_CHAT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_TOOL_NAME_RE = re.compile(r"[^a-z0-9_-]")


def _safe_chat_id(chat_id):
    c = (chat_id or "").strip()
    return c if _CHAT_ID_RE.match(c) else "chat"


def _safe_tool(tool):
    t = _TOOL_NAME_RE.sub("", (tool or "tool").strip().lower())
    return (t or "tool")[:60]


def _ext_for(content):
    s = (content or "").strip()
    if s[:1] in ("{", "["):
        try:
            json.loads(s)
            return "json"
        except (TypeError, ValueError):
            pass
    return "txt"


def _fmt_size(n):
    if n >= 1 << 20:
        return "%.1f MB" % (n / (1 << 20))
    if n >= 1 << 10:
        return "%.1f KB" % (n / (1 << 10))
    return "%d B" % n


class ArtifactManager:
    """Thread-safe store of per-chat scan outputs (artifacts/<chat_id>/)."""

    def __init__(self, root):
        self.root = os.path.abspath(root)

    def _chat_dir(self, chat_id):
        d = os.path.join(self.root, _safe_chat_id(chat_id))
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
        return d

    def worth_capturing(self, tool, args="{}"):
        """True when a tool result should be persisted as an artifact."""
        if tool in AUTO_CAPTURE_TOOLS:
            return True
        if tool == "run_terminal":
            try:
                if isinstance(args, str):
                    args = json.loads(args or "{}")
                elif not isinstance(args, dict):
                    args = {}
                cmd = str(args.get("command") or "")
            except (TypeError, ValueError):
                return False
            return bool(_SCAN_CMD_RE.search(cmd))
        return False

    def save(self, chat_id, tool, content, args=None, extra=None):
        """Persist one tool output and return artifact metadata (or None)."""
        chat_id = _safe_chat_id(chat_id)
        tool = _safe_tool(tool)
        content = (content or "").strip()
        if not content:
            return None
        ext = _ext_for(content)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = "%s_%s_%s.%s" % (tool, stamp, uuid.uuid4().hex[:6], ext)
        directory = self._chat_dir(chat_id)
        path = os.path.join(directory, filename)
        if len(content) > ARTIFACT_MAX_BYTES:
            content = content[:ARTIFACT_MAX_BYTES] + ARTIFACT_TRUNCATE_NOTE
        try:
            if ext == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(json.loads(content), f, ensure_ascii=False,
                              indent=2)
            else:
                with open(path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(content)
        except (OSError, ValueError, TypeError):
            return None
        size = os.path.getsize(path)
        return {
            "id": filename,
            "chat_id": chat_id,
            "tool": tool,
            "filename": filename,
            "size": size,
            "size_h": _fmt_size(size),
            "ext": ext,
            "created_at": datetime.datetime.now().isoformat(
                timespec="seconds"),
            "url": "/api/download/" + filename,
        }

    def list_chat(self, chat_id):
        """All artifacts for one chat, newest first."""
        directory = self._chat_dir(chat_id)
        rows = []
        try:
            names = os.listdir(directory)
        except OSError:
            return rows
        for name in names:
            if not _ID_RE.match(name):
                continue
            path = os.path.join(directory, name)
            try:
                size = os.path.getsize(path)
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            tool, _, _rest = name.partition("_")
            rows.append({
                "id": name,
                "chat_id": chat_id,
                "tool": tool,
                "filename": name,
                "size": size,
                "size_h": _fmt_size(size),
                "ext": os.path.splitext(name)[1].lstrip(".") or "txt",
                "created_at": datetime.datetime.fromtimestamp(
                    mtime).isoformat(timespec="seconds"),
                "url": "/api/download/" + name,
            })
        rows.sort(key=lambda r: r["created_at"], reverse=True)
        return rows

    def resolve(self, artifact_id):
        """Absolute path for an artifact id across chats (None if unsafe
        or missing). Only a strict filename id is accepted, so traversal
        is impossible."""
        if not _ID_RE.match(artifact_id or ""):
            return None
        try:
            entries = os.listdir(self.root)
        except OSError:
            return None
        for entry in entries:
            candidate = os.path.join(self.root, entry, artifact_id)
            if os.path.isfile(candidate):
                return candidate
        return None

    def delete_chat(self, chat_id):
        """Remove one chat's artifact directory; returns files deleted."""
        directory = self._chat_dir(chat_id)
        if not os.path.isdir(directory):
            return 0
        n = 0
        try:
            for name in os.listdir(directory):
                path = os.path.join(directory, name)
                if os.path.isfile(path):
                    os.remove(path)
                    n += 1
            os.rmdir(directory)
        except OSError:
            pass
        return n

    def report(self, chat_id, final_text="", title=""):
        """Markdown report for one chat: turn summary + artifact index."""
        chat_id = _safe_chat_id(chat_id)
        rows = self.list_chat(chat_id)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        title = (title or "").strip() or "Security Assessment Report"
        lines = [
            "# %s" % title,
            "",
            "**Target chat:** `%s`  " % chat_id,
            "**Generated:** %s  " % now,
            "**Artifacts:** %d" % len(rows),
            "",
        ]
        if (final_text or "").strip():
            lines += ["## Turn Summary", "", (final_text or "").strip(), ""]
        if rows:
            lines += ["## Artifacts", ""]
            for r in rows:
                lines.append(
                    "- **%s** — `%s` (%s)  " % (
                        r["tool"], r["filename"], r["size_h"]))
            lines += ["", "## Downloads", ""]
            for r in rows:
                lines.append("- [%s](/api/download/%s)" % (
                    r["filename"], r["id"]))
        else:
            lines += ["_No artifacts saved for this chat._"]
        return "\n".join(lines) + "\n"
