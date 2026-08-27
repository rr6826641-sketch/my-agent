"""System & environment tools (pure stdlib, Windows/Linux compatible)."""

import datetime
import os
import platform
import socket
import subprocess


def tool_system_info():
    lines = [
        "hostname: %s" % socket.gethostname(),
        "platform: %s" % platform.platform(),
        "system: %s" % platform.system(),
        "release: %s" % platform.release(),
        "version: %s" % platform.version(),
        "machine: %s" % platform.machine(),
        "processor: %s" % platform.processor(),
        "python: %s" % platform.python_version(),
        "cpu cores: %s" % os.cpu_count(),
        "cwd: %s" % os.getcwd(),
        "user: %s" % (os.environ.get("USERNAME") or os.environ.get("USER") or "?"),
        "os: %s" % os.environ.get("OS", "?"),
    ]
    if os.name == "nt":
        try:
            out = subprocess.run(
                ["wmic", "os", "get", "TotalVisibleMemorySize,FreePhysicalMemory",
                 "/value"],
                capture_output=True, text=True, timeout=15,
                errors="replace").stdout
            for line in out.splitlines():
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    if k in ("TotalVisibleMemorySize", "FreePhysicalMemory"):
                        try:
                            lines.append("%s: %.1f GB" % (k, int(v) / 1024 / 1024))
                        except ValueError:
                            pass
        except Exception:
            pass
    return "\n".join(lines)


def tool_current_time():
    now = datetime.datetime.now()
    utc = datetime.datetime.now(datetime.timezone.utc)
    return ("local: %s\nutc:   %s\ntz:    %s"
            % (now.strftime("%Y-%m-%d %H:%M:%S"),
               utc.strftime("%Y-%m-%d %H:%M:%S"),
               datetime.datetime.now().astimezone().tzname()))


def tool_process_list(name_filter="", limit=40):
    if os.name == "nt":
        cmd = ["tasklist", "/FO", "CSV", "/NH"]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                 errors="replace").stdout
        except Exception as exc:
            return "process_list error: %s" % exc
        rows = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith('"'):
                continue
            parts = [p.strip().strip('"') for p in line.split('","')]
            if len(parts) >= 5:
                rows.append((parts[0], parts[1], parts[4]))
        if name_filter and name_filter.lower() != "all":
            rows = [r for r in rows if name_filter.lower() in r[0].lower()]
        if not rows:
            return "(no processes matched)"
        out_lines = ["%-28s %8s  %s" % ("name", "pid", "mem")] + \
                    ["%-28s %8s  %s" % (r[0], r[1], r[2]) for r in rows[:limit]]
        if len(rows) > limit:
            out_lines.append("... %d more (limit %d)" % (len(rows) - limit, limit))
        return "\n".join(out_lines)
    # Linux/macOS fallback
    try:
        out = subprocess.run(["ps", "-eo", "pid,comm"],
                             capture_output=True, text=True, timeout=15).stdout
    except Exception as exc:
        return "process_list error: %s" % exc
    rows = [line.strip() for line in out.splitlines()[1:] if line.strip()]
    if name_filter and name_filter.lower() != "all":
        rows = [r for r in rows if name_filter.lower() in r.lower()]
    return "\n".join(rows[:limit]) or "(no processes matched)"


def tool_disk_usage(path=None):
    import shutil
    path = path or os.getcwd()
    if os.name == "nt" and path.lower() in ("drives", "all"):
        lines = []
        import string
        for letter in string.ascii_uppercase:
            root = letter + ":\\"
            if os.path.exists(root):
                try:
                    t, u, f = shutil.disk_usage(root)
                    lines.append("%s total %.1f GB, used %.1f GB, free %.1f GB"
                                 % (root, t / 2 ** 30, u / 2 ** 30, f / 2 ** 30))
                except Exception:
                    pass
        return "\n".join(lines) or "(no drives found)"
    try:
        t, u, f = shutil.disk_usage(path)
        return ("path: %s\ntotal: %.1f GB\nused:  %.1f GB\nfree:  %.1f GB\n"
                "usage: %.0f%%"
                % (path, t / 2 ** 30, u / 2 ** 30, f / 2 ** 30, u / t * 100))
    except Exception as exc:
        return "disk_usage error: %s" % exc


def tool_ip_info():
    lines = []
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in lines:
                lines.append("ipv4: %s" % ip)
        for info in socket.getaddrinfo(host, None, socket.AF_INET6):
            ip = info[4][0]
            if "%" not in ip and ip not in lines:
                lines.append("ipv6: %s" % ip)
    except Exception:
        pass
    # adapter detail + default gateway (Windows ipconfig)
    if os.name == "nt":
        try:
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=20, errors="replace").stdout
            addrs, gw = [], []
            for line in out.splitlines():
                s = line.strip()
                low = s.lower()
                if "ipv4 address" in low and ":" in s:
                    addrs.append(s.split(":", 1)[1].strip())
                elif "default gateway" in low and ":" in s:
                    g = s.split(":", 1)[1].strip()
                    if g:
                        gw.append(g)
            for a in addrs:
                if a not in lines:
                    lines.append("adapter ipv4: %s" % a)
            for g in gw:
                lines.append("gateway: %s" % g)
        except Exception:
            pass
    return "\n".join(lines) or "(could not detect IP info)"
