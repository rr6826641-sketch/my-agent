"""Terminal & local file tools."""

import locale
import os
import subprocess


def _oem_codepage():
    """OEM code page (what cmd.exe writes to pipes), e.g. 437/850/936."""
    try:
        import ctypes
        cp = ctypes.windll.kernel32.GetOEMCP()
        if cp and cp != 65001:
            return "cp%d" % cp
    except Exception:
        pass
    return None


def _ansi_codepage():
    """ANSI code page (locale), e.g. 1252."""
    try:
        import ctypes
        cp = ctypes.windll.kernel32.GetACP()
        if cp and cp != 65001:
            return "cp%d" % cp
    except Exception:
        pass
    return None


def _decode_output(data):
    """Decode raw command bytes: UTF-8 first (PowerShell, chcp 65001,
    UTF-8-emitting tools), then the OEM code page (cmd.exe's default),
    then ANSI. subprocess text=True on Windows only knows the locale
    (cp1252) page, which turns UTF-8 '•'/'—'/'→' into 'â€¢'/'â€“'/'â†’'
    mojibake and OEM box-drawing chars into 'ÄÄÄ' garbage."""
    if not data:
        return ""
    candidates = ["utf-8", _oem_codepage(), _ansi_codepage(),
                  locale.getpreferredencoding(False), "cp437", "cp850", "cp1252"]
    seen = set()
    for enc in candidates:
        if not enc or enc in seen:
            continue
        seen.add(enc)
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("cp1252", errors="replace")


def tool_run_terminal(command, timeout=60, max_output=20000):
    if not command or not command.strip():
        return "Error: empty command"
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True,
            timeout=timeout,
        )
        stdout = _decode_output(proc.stdout)
        stderr = _decode_output(proc.stderr)
        parts = [stdout]
        if stderr.strip():
            parts.append("[stderr]\n" + stderr)
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
