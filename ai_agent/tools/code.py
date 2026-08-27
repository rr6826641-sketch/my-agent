"""Code & utility tools: run python, regex, passwords, encoding, hashing."""

import base64
import hashlib
import os
import re
import secrets
import string
import subprocess
import sys
import tempfile
import uuid


def tool_run_python(code, timeout=30):
    """Execute Python code in a subprocess and return stdout/stderr."""
    if not code or not code.strip():
        return "run_python: empty code"
    fd, path = tempfile.mkstemp(suffix=".py", prefix="agent_code_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        try:
            proc = subprocess.run([sys.executable, "-u", path],
                                  capture_output=True, text=True, timeout=timeout,
                                  errors="replace",
                                  cwd=os.getcwd())
        except subprocess.TimeoutExpired:
            return "[run_python timed out after %ds]" % timeout
        parts = []
        if (proc.stdout or "").strip():
            parts.append(proc.stdout.strip())
        if (proc.stderr or "").strip():
            parts.append("[stderr]\n" + proc.stderr.strip())
        out = "\n".join(parts).strip()
        if not out:
            out = "(no output, exit code %d)" % proc.returncode
        return "[exit code %d]\n%s" % (proc.returncode, out[:6000])
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def tool_regex_test(pattern, text, flags="", show_groups=True):
    """Test a regex against sample text; returns matches and captures."""
    try:
        fl = 0
        if "i" in flags:
            fl |= re.IGNORECASE
        if "m" in flags:
            fl |= re.MULTILINE
        if "s" in flags:
            fl |= re.DOTALL
        rx = re.compile(pattern, fl)
    except re.error as exc:
        return "regex_test: invalid regex: %s" % exc
    if not text:
        return "regex_test: provide sample text"
    matches = list(rx.finditer(text))
    if not matches:
        return "(no matches)"
    lines = ["%d match(es):" % len(matches)]
    for m in matches[:20]:
        lines.append("  %d-%d: %r" % (m.start(), m.end(), m.group(0)[:200]))
        if show_groups and m.groups():
            for i, g in enumerate(m.groups(), 1):
                lines.append("    group%d: %r" % (i, g[:200]))
    if len(matches) > 20:
        lines.append("  ... %d more" % (len(matches) - 20))
    return "\n".join(lines)


def tool_generate_password(length=16, count=3, use_upper=True, use_lower=True,
                           use_digits=True, use_symbols=True):
    """Generate strong random passwords."""
    length = max(4, min(int(length), 64))
    count = max(1, min(int(count), 20))
    charset = ""
    if use_upper:
        charset += string.ascii_uppercase
    if use_lower:
        charset += string.ascii_lowercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*()-_=+[]{};:,.<>?"
    if not charset:
        charset = string.ascii_letters + string.digits
    import math
    entropy_bits = length * math.log2(len(charset))
    out = []
    for _ in range(count):
        pwd = "".join(secrets.choice(charset) for _ in range(length))
        out.append("%s  (entropy ~%.1f bits)" % (pwd, entropy_bits))
    return "\n".join(out)


def tool_encode_decode(action, encoding, data):
    """Encode or decode text using base64/hex/url."""
    action = (action or "encode").lower()
    enc = (encoding or "base64").lower()
    if action not in ("encode", "decode"):
        return "encode_decode: action must be 'encode' or 'decode'"
    try:
        if enc == "base64":
            if action == "encode":
                return base64.b64encode(data.encode("utf-8")).decode("ascii")
            return base64.b64decode(data).decode("utf-8", errors="replace")
        if enc in ("hex", "hexadecimal"):
            if action == "encode":
                return data.encode("utf-8").hex()
            return bytes.fromhex(data).decode("utf-8", errors="replace")
        if enc == "url":
            from urllib.parse import quote, unquote
            if action == "encode":
                return quote(data, safe="")
            return unquote(data)
        if enc == "base32":
            if action == "encode":
                return base64.b32encode(data.encode("utf-8")).decode("ascii")
            return base64.b32decode(data).decode("utf-8", errors="replace")
        if enc == "rot13":
            if action == "encode":
                return data.translate(str.maketrans(
                    string.ascii_letters,
                    string.ascii_lowercase[13:] + string.ascii_lowercase[:13]
                    + string.ascii_uppercase[13:] + string.ascii_uppercase[:13]))
            return data.translate(str.maketrans(
                string.ascii_letters,
                string.ascii_lowercase[13:] + string.ascii_lowercase[:13]
                + string.ascii_uppercase[13:] + string.ascii_uppercase[:13]))
        return "encode_decode: unsupported encoding '%s' (use base64/hex/url/base32/rot13)" % enc
    except Exception as exc:
        return "encode_decode error: %s" % exc


def tool_hash_text(text, algorithms="sha256"):
    """Hash a string with md5/sha1/sha256/sha512 (comma-separated)."""
    algos = [a.strip().lower() for a in algorithms.split(",") if a.strip()]
    if not algos:
        algos = ["sha256"]
    lines = []
    for a in algos:
        try:
            h = hashlib.new(a)
            h.update(text.encode("utf-8"))
            lines.append("%s: %s" % (a, h.hexdigest()))
        except ValueError:
            lines.append("unsupported algorithm: %s" % a)
    return "\n".join(lines)


def tool_uuid_gen(count=1):
    count = max(1, min(int(count), 50))
    return "\n".join(str(uuid.uuid4()) for _ in range(count))
