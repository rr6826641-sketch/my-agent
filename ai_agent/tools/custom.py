"""Custom / user-added tools.

Har function yahan ek simple utility hai jo registry mein ek Tool(...)
entry ke through expose hoti hai. Naya tool add karne ke liye:

1. Yahan function likho (path/args python defaults ke saath).
2. ai_agent/tools/__init__.py ke imports mein naam add karo.
3. REGISTRY list mein Tool(...) entry add karo.

LLM khud naya tool discover kar lega (list_tools / tool schemas).
"""

import hashlib
import os
import re
import urllib.request


def tool_sha1_quick(path=""):
    """Quick SHA1 hash of a file (streaming, memory-friendly)."""
    if not path or not os.path.isfile(path):
        return "Error: file not found: %s" % path
    h = hashlib.sha1()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception as exc:
        return "Error reading %s: %s" % (path, exc)
    return "sha1(%s) = %s (%d bytes)" % (path, h.hexdigest(),
                                         os.path.getsize(path))


def tool_strings_extract(path="", min_len=4, limit=200):
    """Extract printable strings from a file (binaries, dumps, malware)."""
    if not path or not os.path.isfile(path):
        return "Error: file not found: %s" % path
    min_len = max(1, int(min_len or 4))
    limit = int(limit or 200)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as exc:
        return "Error reading %s: %s" % (path, exc)
    if len(data) > 50 * 1024 * 1024:
        data = data[:50 * 1024 * 1024]  # cap at 50 MB
    strings = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    out = []
    for s in strings:
        line = s.decode("ascii", "ignore").strip()
        if line:
            out.append(line)
        if len(out) >= limit:
            break
    if not out:
        return "(no printable strings of length >= %d found)" % min_len
    return "%d strings (showing %d):\n%s" % (
        len(strings), len(out), "\n".join(out))


def tool_html_to_text(source="", max_chars=4000):
    """Convert HTML to readable text. Pass a URL or raw HTML as source."""
    if not source:
        return "Error: provide a URL or raw HTML string."
    html = source
    stripped = source.strip()
    if stripped.startswith("http://") or stripped.startswith("https://"):
        try:
            req = urllib.request.Request(
                source, headers={"User-Agent": "Mozilla/5.0 (agent)"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                html = resp.read().decode("utf-8", "ignore")
        except Exception as exc:
            return "Error fetching %s: %s" % (source, exc)
    text = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;?", " ", text)
    text = re.sub(r"&amp;?", "&", text)
    text = re.sub(r"&lt;?", "<", text)
    text = re.sub(r"&gt;?", ">", text)
    text = re.sub(r"&quot;?", '"', text)
    text = re.sub(r"&#39;?", "'", text)
    text = re.sub(r"[ \t]+", " ", text)
    lines = [ln.strip() for ln in text.splitlines()]
    text = "\n".join(ln for ln in lines if ln)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n...[truncated]"
    return text or "(no readable text extracted)"


def tool_dedupe_lines(path="", output_path=""):
    """Remove duplicate lines from a file (wordlist/scope cleanup).

    output_path optional; default writes nothing and returns the count.
    """
    if not path or not os.path.isfile(path):
        return "Error: file not found: %s" % path
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as exc:
        return "Error reading %s: %s" % (path, exc)
    seen = set()
    unique = []
    for ln in lines:
        s = ln.rstrip("\r\n")
        if s and s not in seen:
            seen.add(s)
            unique.append(s)
    out_txt = "\n".join(unique)
    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(out_txt + ("\n" if out_txt else ""))
            return ("%d -> %d unique lines written to %s"
                    % (len(lines), len(unique), output_path))
        except Exception as exc:
            return "Error writing %s: %s" % (output_path, exc)
    return "%d -> %d unique lines\n%s" % (
        len(lines), len(unique),
        "\n".join(unique[:50]) + ("\n..." if len(unique) > 50 else ""))


def tool_count_lines(path="", pattern=""):
    """Count lines in a file, optionally matching a regex pattern."""
    if not path or not os.path.isfile(path):
        return "Error: file not found: %s" % path
    rx = None
    if pattern:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            return "Error: bad regex %r: %s" % (pattern, exc)
    total = matched = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                total += 1
                if rx is not None and rx.search(ln):
                    matched += 1
    except Exception as exc:
        return "Error reading %s: %s" % (path, exc)
    if rx is not None:
        return "%s: %d total lines, %d match %r" % (path, total, matched,
                                                    pattern)
    return "%s: %d lines" % (path, total)
