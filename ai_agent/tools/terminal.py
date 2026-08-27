"""Terminal & local file tools."""

import os
import subprocess


def tool_run_terminal(command, timeout=60, max_output=20000):
    if not command or not command.strip():
        return "Error: empty command"
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        parts = [proc.stdout or ""]
        if (proc.stderr or "").strip():
            parts.append("[stderr]\n" + proc.stderr)
        out = "\n".join(parts).strip() or "(no output)"
        return "[exit code %s]\n%s" % (proc.returncode, out[:max_output])
    except subprocess.TimeoutExpired:
        return "[command timed out after %ss]" % timeout
    except Exception as exc:
        return "run_terminal error: %s" % exc


def tool_read_file(path, max_chars=60000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_chars)
        if len(content) >= max_chars:
            content += "\n...[truncated]"
        return content
    except Exception as exc:
        return "read_file error: %s" % exc


def tool_write_file(path, content):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return "wrote %s (%d chars)" % (path, len(content))
    except Exception as exc:
        return "write_file error: %s" % exc


def tool_list_files(path="."):
    try:
        entries = sorted(os.listdir(path))
        if not entries:
            return "(empty directory)"
        lines = []
        for name in entries:
            full = os.path.join(path, name)
            if os.path.isdir(full):
                lines.append("[dir]  " + name)
            else:
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = 0
                lines.append("[file] %s (%d bytes)" % (name, size))
        return "\n".join(lines)
    except Exception as exc:
        return "list_files error: %s" % exc
