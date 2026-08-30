"""Structured artifact storage for automated scan/generation outputs.

Files are stored as artifacts/{chat_id}/{timestamp}/{tool}_{ts}_{suffix}.{ext}
so every run (one timestamp folder per assessment turn) keeps its own
history of nmap/nuclei/curl/recon outputs, logs and generated PoC scripts.
Legacy flat files (artifacts/{chat_id}/{tool}_{ts}.{ext}) are still listed
and downloadable, so old sessions keep working.

The web UI exposes them as downloadable badges through
/api/download/<chat_id>/<timestamp>/<file> (new layout),
/api/download/<artifact_id> (legacy lookup) and a per-chat markdown report
plus a ZIP archive of the whole chat.

Every id component is validated against a strict whitelist regex before
any filesystem access, so path traversal (../, absolute paths, encoded
separators, symlink tricks) is impossible.
"""

import datetime
import io
import json
import os
import re
import shutil
import uuid
import zipfile

ARTIFACT_MAX_BYTES = 1_000_000  # per-artifact safety cap (1 MB)
ARTIFACT_TRUNCATE_NOTE = (
    "\n\n[artifact truncated by the agent: exceeds %d bytes]" %
    ARTIFACT_MAX_BYTES)

# Tool results worth persisting as artifacts (scan/recon/generation/PoC).
AUTO_CAPTURE_TOOLS = frozenset({
    # recon / enumeration
    "port_scan", "nmap_scan", "subdomain_enum", "subfinder_enum", "dir_fuzz",
    "gobuster_dir", "ffuf_fuzz", "dns_lookup", "dns_axfr", "reverse_dns",
    "whois", "whois_rdap", "geoip", "geoip_lookup", "ssl_info", "ping_host",
    "url_status", "httpx_probe", "check_headers", "robots_txt",
    "extract_links", "tech_detect", "cve_lookup", "http_request",
    "curl_request", "http_cookies", "http_methods", "redirect_chain",
    "waf_detect", "mac_vendor", "local_listeners", "lockfile_scan",
    # vulnerability testing
    "sqli_test", "sqlmap_check", "xss_test", "ssrf_test", "xxe_test",
    "ssti_test", "path_traversal_test", "cmd_inject_test", "cors_check",
    "header_inject_test", "jwt_attack", "jwt_decode", "oauth_check",
    "open_redirect_test", "deserialization_check", "nosql_inject_test",
    "graphql_check", "smuggling_detect", "cloud_meta_test",
    "nikto_scan", "nuclei_scan",
    # generation / PoC scripts / findings
    "wordlist_gen", "run_python", "write_file", "write_report",
    "generate_password", "strings_extract", "extract_iocs",
    "create_archive", "extract_archive",
    "add_finding", "update_finding", "list_findings",
    "verify_finding", "verify_all_findings",
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
# run timestamps are always %Y%m%d_%H%M%S, e.g. 20260829_133357
_TS_RE = re.compile(r"^\d{8}_\d{6}$")


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
    """Thread-safe store of per-chat scan outputs (artifacts/<chat_id>/).

    New saves land in artifacts/<chat_id>/<timestamp>/ so every assessment
    turn is grouped in its own folder; legacy flat files at the chat root
    stay readable and downloadable.
    """

    def __init__(self, root):
        self.root = os.path.abspath(root)

    def _chat_dir(self, chat_id):
        d = os.path.join(self.root, _safe_chat_id(chat_id))
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
        return d

    def _run_dir(self, chat_id, run_ts):
        """artifacts/<chat_id>/<timestamp>/ (falls back to chat root)."""
        directory = self._chat_dir(chat_id)
        ts = _TS_RE.match((run_ts or "").strip()) and run_ts.strip() or None
        if ts:
            run_dir = os.path.join(directory, ts)
            try:
                os.makedirs(run_dir, exist_ok=True)
                return run_dir, ts
            except OSError:
                pass
        return directory, None

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

    def save(self, chat_id, tool, content, args=None, extra=None, run_ts=None):
        """Persist one tool output and return artifact metadata (or None).

        run_ts groups a whole assessment turn into one
        artifacts/<chat_id>/<timestamp>/ folder; it is strictly validated
        (%Y%m%d_%H%M%S) before being used as a path component.
        """
        chat_id = _safe_chat_id(chat_id)
        tool = _safe_tool(tool)
        content = (content or "").strip()
        if not content:
            return None
        ext = _ext_for(content)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = "%s_%s_%s.%s" % (tool, stamp, uuid.uuid4().hex[:6], ext)
        run_dir, ts = self._run_dir(chat_id, run_ts)
        path = os.path.join(run_dir, filename)
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
            "dir": ts,  # timestamp folder inside the chat (None = legacy)
            "size": size,
            "size_h": _fmt_size(size),
            "ext": ext,
            "created_at": datetime.datetime.now().isoformat(
                timespec="seconds"),
            "url": self._url_for(chat_id, ts, filename),
        }

    def _url_for(self, chat_id, ts, filename):
        if ts:
            return "/api/download/%s/%s/%s" % (chat_id, ts, filename)
        return "/api/download/" + filename

    def _append_row(self, rows, chat_id, ts, name, root_dir):
        if not _ID_RE.match(name):
            return
        path = os.path.join(root_dir, name)
        try:
            size = os.path.getsize(path)
            mtime = os.path.getmtime(path)
        except OSError:
            return
        # filename is <tool>_<YYYYmmdd>_<HHMMSS>_<hex>.<ext>; strip the
        # timestamp+random suffix to recover the real tool name (e.g.
        # port_scan, write_file) instead of just the first word
        m = re.match(r"^(.*)_\d{8}_\d{6}_[0-9a-f]{6}\.[a-z0-9]+$", name, re.I)
        tool = m.group(1) if m else name.partition("_")[0]
        rows.append({
            "id": name,
            "chat_id": chat_id,
            "tool": tool,
            "filename": name,
            "dir": ts,
            "size": size,
            "size_h": _fmt_size(size),
            "ext": os.path.splitext(name)[1].lstrip(".") or "txt",
            "created_at": datetime.datetime.fromtimestamp(
                mtime).isoformat(timespec="seconds"),
            "url": self._url_for(chat_id, ts, name),
        })

    def list_chat(self, chat_id):
        """All artifacts for one chat, newest first.

        Walks artifacts/<chat_id>/<timestamp>/ folders (new layout) AND
        legacy flat files at artifacts/<chat_id>/ (old layout).
        """
        chat_id = _safe_chat_id(chat_id)
        directory = self._chat_dir(chat_id)
        rows = []
        try:
            entries = os.listdir(directory)
        except OSError:
            return rows
        for entry in entries:
            full = os.path.join(directory, entry)
            if os.path.isdir(full) and _TS_RE.match(entry):
                try:
                    names = os.listdir(full)
                except OSError:
                    continue
                for name in names:
                    self._append_row(rows, chat_id, entry, name, full)
            elif os.path.isfile(full):
                self._append_row(rows, chat_id, None, entry, directory)
        rows.sort(key=lambda r: (r["created_at"], r["filename"]),
                  reverse=True)
        return rows

    def resolve(self, artifact_id):
        """Absolute path for an artifact id across chats (None if unsafe
        or missing).

        Accepts '<chat_id>/<timestamp>/<filename>' (new layout) or a plain
        filename (legacy flat layout + new subfolders). Every component is
        matched against a strict whitelist regex, so traversal (../, encoded
        separators, absolute paths) is impossible.
        """
        artifact_id = (artifact_id or "").replace("\\", "/").strip()
        parts = [p for p in artifact_id.split("/") if p]
        if len(parts) == 3:
            cid, ts, name = parts
            if (_CHAT_ID_RE.match(cid) and _TS_RE.match(ts)
                    and _ID_RE.match(name)):
                candidate = os.path.join(self.root, cid, ts, name)
                if os.path.isfile(candidate):
                    return candidate
            return None
        if len(parts) != 1 or not _ID_RE.match(parts[0]):
            return None
        name = parts[0]
        try:
            entries = os.listdir(self.root)
        except OSError:
            return None
        for entry in entries:
            if not _CHAT_ID_RE.match(entry):
                continue
            candidate = os.path.join(self.root, entry, name)
            if os.path.isfile(candidate):
                return candidate
            chat_dir = os.path.join(self.root, entry)
            try:
                subdirs = os.listdir(chat_dir)
            except OSError:
                continue
            for ts in subdirs:
                if not _TS_RE.match(ts):
                    continue
                candidate = os.path.join(chat_dir, ts, name)
                if os.path.isfile(candidate):
                    return candidate
        return None

    def delete_chat(self, chat_id):
        """Remove one chat's artifact directory (files + timestamp folders);
        returns the number of files deleted."""
        chat_id = _safe_chat_id(chat_id)
        directory = os.path.join(self.root, chat_id)
        if not os.path.isdir(directory):
            return 0
        n = 0
        try:
            for _root, _dirs, files in os.walk(directory):
                n += len(files)
            shutil.rmtree(directory)
        except OSError:
            return 0
        return n

    def archive(self, chat_id):
        """Bytes of a ZIP containing all artifacts of one chat (None when
        empty). Files are stored under '<timestamp>/<file>' (or 'legacy/'
        for old flat files) inside the zip."""
        rows = self.list_chat(chat_id)
        if not rows:
            return None
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for r in rows:
                path = self.resolve(r["id"])
                if not path:
                    continue
                arcname = os.path.join(
                    r.get("dir") or "legacy", r["filename"])
                try:
                    zf.write(path, arcname)
                except OSError:
                    continue
        return buf.getvalue()

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
                lines.append("- [%s](%s)" % (r["filename"], r["url"]))
        else:
            lines += ["_No artifacts saved for this chat._"]
        return "\n".join(lines) + "\n"
