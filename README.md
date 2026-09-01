# 🤖 AI Agent — Aapka Apna "Perfect" AI Agent Framework

Ye ek complete AI agent hai jo **sochta hai, tools use karta hai, aur kaam karta hai** — bilkul HackerAI jaise. Aap ise apni machine par chala sakte ho, kisi bhi OpenAI-compatible LLM ke saath jod sakte ho, aur apne khud ke tools add kar sakte ho.

**Total 100 built-in tools** — terminal, files, web, network, recon, code, memory + RAG (vector search), sub-agents (parallel bhi), payload generation, manual web attack detectors, findings/reporting, scope enforcement, custom file utilities, aur complete pentest arsenal wrappers (nmap, sqlmap, nikto, nuclei, ffuf, gobuster, subfinder, httpx, curl, JWT).

**Web UI included** — dark hacker-theme dashboard (chat + streaming tool calls, tools catalog, memory manager, settings, system info). Chalao: double-click `start_ui.bat` → browser mein http://127.0.0.1:8080

---

## ✨ Features

| Capability | Kaise |
|---|---|
| 🧠 LLM Reasoning | Kisi bhi OpenAI-compatible model ke saath kaam karta hai (OpenAI, OpenRouter, Groq, Ollama, LM Studio, vLLM...) |
| 🔁 Agent Loop | Think → Act → Observe — tool call karta hai, result dekhta hai, phir aage badhta hai |
| 💻 Terminal Access | Commands chala sakta hai, output parh kar jawab deta hai |
| 📁 File Tools | Files padhna, likhna, search, grep, hash, archive, diff, PDF/image info |
| 🌐 Web Tools | Web search (bina API key), page fetch, headers audit, tech detect, link extract |
| 🧠 Persistent Memory + RAG | Facts yaad rakhta hai `memory.json` mein + `rag_index`/`vector_search` se documents ka TF-IDF vector search (pure Python) |
| 👥 Sub-Agents | Kaam ke liye child agents spawn karta hai — **ab parallel bhi** (`spawn_agents`, max 8 ek saath) |
| 💣 Payload Gen | Reverse/bind shells, web shells, listeners, obfuscation, wordlists — turant ready-to-use |
| 🔍 Manual Web Tests | SQLi / XSS / CMDi / path traversal / SSRF / open redirect — bina bhari tool ke quick probes |
| 📋 Findings & Reports | Har vulnerability structured log karo, end par professional Markdown pentest report banao |
| 🎯 Scope Guard | `set_scope` se authorized targets fix karo — `check_scope` har host scan se pehle verify karta hai |
| 🌍 Network Tools | DNS, port scan, whois, geoip, SSL certs, ping — sab pure Python (nmap/dig ki zaroorat nahi) |
| 🎯 Recon Tools | Subdomain enum, dir fuzz, CVE lookup, wordlist gen |
| 🛡️ Security | Interactive mode mein terminal commands se pehle confirmation maangta hai |
| 🗣️ Language-Aware | Jis language mein user likhe, usi mein jawab deta hai |
| 🖥️ Web UI | Chat dashboard — streaming tool calls live dekho, tools/memory/settings manage karo |
| 🛠️ Pentest Arsenal | nmap, sqlmap, nikto, nuclei, ffuf, gobuster, subfinder, httpx, curl, JWT decode — install hain toh use karta hai, nahi toh install hint deta hai |

---

## 🚀 Quick Start (Windows)

```bash
# 1. Project folder mein jao
cd E:\HackerAI\my-agent

# 2. Dependency install karo (sirf requests)
py -3 -m pip install -r requirements.txt

# 3. Bina API key test karo (mock mode)
py -3 agent.py --mock --auto

# 4. Real LLM ke saath chalao
py -3 agent.py --api-key sk-XXXX --model gpt-4o
```

> Agar `python`/`py` command kaam na karti ho toh ye full path use karo (is laptop par):
> ```bash
> "C:\Users\GLOBAL IT STORE\AppData\Local\Python\bin\python.exe" agent.py --mock --auto
> ```

### Web UI (recommended)

```bash
# Launcher se (double-click):
start_ui.bat

# Ya manually:
py -3 webui.py --port 8080
# Browser: http://127.0.0.1:8080
```

Web UI features:
- **Chat** — SSE streaming, har tool call live dikhta hai (start → tool_call → tool_result → final)
- **Tools** — saare 100 tools ki catalog + parameters
- **Memory** — persistent memory add/delete karo
- **Settings** — base URL/model/mock mode config.json mein save hote hain; **API key sirf `.env` mein** (config.json kabhi nahi — secret isolation)
- **System** — OS, IPs, disk info

### Mock mode (test ke liye — koi API key nahi chahiye)

Mock mode mein ye command language samajh aati hai:

```bash
py -3 agent.py --mock --auto --once "run echo hello"
py -3 agent.py --mock --auto --once "list files ."
py -3 agent.py --mock --auto --once "read agent.py"
py -3 agent.py --mock --auto --once "write test.txt:hello world"
py -3 agent.py --mock --auto --once "remember project:my-project"
py -3 agent.py --mock --auto --once "recall"
py -3 agent.py --mock --auto --once "spawn list files"
py -3 agent.py --mock --auto --once "search python 3.14 release date"
py -3 agent.py --mock --auto --once "fetch https://example.com"
py -3 agent.py --mock --auto --once "system info"
py -3 agent.py --mock --auto --once "list tools"
py -3 agent.py --mock --auto --once "dns example.com"
py -3 agent.py --mock --auto --once "port scan 127.0.0.1"
py -3 agent.py --mock --auto --once "password 20"
py -3 agent.py --mock --auto --once "hash hello world"
```

---

## 🔌 Real LLM se jodo (3 tareeqe)

**Tareeqa 1 — Command line flags:**
```bash
py -3 agent.py --api-key sk-xxx --base-url https://api.openai.com/v1 --model gpt-4o
```

**Tareeqa 2 — `.env` file (recommended):**
```bash
copy .env.example .env
# phir .env mein apni values daalo
```

**Tareeqa 3 — `config.json` (sirf non-secret settings):**
```json
{
  "base_url": "https://api.openai.com/v1",
  "model": "gpt-4o"
}
```
> ⚠️ Security: API keys **kabhi** config.json mein nahi daalte — wahan rakha gaya `api_key` load-time par ignore kar diya jata hai. Key ka ek hi zariya hai: `.env` (ya CLI flag).

### Free/local options

| Provider | base_url | model example |
|---|---|---|
| OpenAI | `https://api.openai.com/v1` | `gpt-4o` |
| OpenRouter | `https://openrouter.ai/api/v1` | `openai/gpt-4o` |
| Groq (free) | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` |
| Ollama (local, free) | `http://localhost:11434/v1` | `llama3` |
| LM Studio (local) | `http://localhost:1234/v1` | koi bhi loaded model |

---

## 🛠️ 100 Built-in Tools

### Core
| Tool | Kya karta hai |
|---|---|
| `run_terminal` | Shell command chalao aur output lo |
| `read_file` | Text file parho |
| `write_file` | File likho (create/overwrite) |
| `list_files` | Directory list karo |
| `web_search` | DuckDuckGo se search (bina API key) |
| `open_url` | Webpage fetch karke parho |
| `remember` | Memory mein fact save karo |
| `recall` | Memory se facts nikalo |
| `spawn_agent` | Child agent spawn karo |
| `spawn_agents` | **Parallel** sub-agents (JSON array ya `|||` separated, max 8) |
| `list_tools` | Saare tools ki list |

### System
| Tool | Kya karta hai |
|---|---|
| `system_info` | OS, CPU, user, Python info |
| `current_time` | Local/UTC time |
| `process_list` | Chalti processes (filter ke saath) |
| `disk_usage` | Disk space (path ya all drives) |
| `ip_info` | IP addresses + gateway |

### Files & Data
| Tool | Kya karta hai |
|---|---|
| `search_files` | Name se files dhoondo |
| `grep_files` | Files ke andar text dhoondo (regex) |
| `file_info` | File metadata, magic bytes |
| `hash_file` | MD5/SHA1/SHA256/SHA512 |
| `json_format` | JSON validate + pretty-print |
| `csv_preview` | CSV preview |
| `create_archive` | Zip banao |
| `extract_archive` | Zip/tar extract karo |
| `diff_text` | Two texts/files ka diff |
| `pdf_info` | PDF info (bina pypdf) |
| `image_info` | Image dimensions (PNG/JPEG/GIF/WebP/BMP) |

### Web
| Tool | Kya karta hai |
|---|---|
| `http_request` | Custom HTTP request (GET/POST/HEAD...) |
| `check_headers` | Security headers audit (HSTS, CSP...) |
| `robots_txt` | robots.txt fetch karo |
| `extract_links` | Page ke links nikalo |
| `tech_detect` | Server/CMS/framework detect karo |
| `url_status` | Multiple URLs ke status codes |

### Network
| Tool | Kya karta hai |
|---|---|
| `dns_lookup` | A/AAAA/CNAME/MX/NS/TXT records |
| `reverse_dns` | PTR lookup |
| `port_scan` | TCP connect scan + banner grab (pure Python, nmap nahi chahiye) |
| `whois` | RDAP-based registration info |
| `geoip` | IP location, ISP, ASN |
| `ssl_info` | TLS certificate details (issuer, expiry, SANs) |
| `ping_host` | ICMP ping (system ping) |

### Recon
| Tool | Kya karta hai |
|---|---|
| `subdomain_enum` | Certificate Transparency (crt.sh) se subdomains |
| `dir_fuzz` | Common paths brute-force (built-in wordlist) |
| `cve_lookup` | NVD API se CVE search (CVSS scores ke saath) |
| `wordlist_gen` | Keywords se wordlist generate karo |

### Code & Utilities
| Tool | Kya karta hai |
|---|---|
| `run_python` | Python code execute karo (subprocess) |
| `regex_test` | Regex test karo (capture groups ke saath) |
| `generate_password` | Strong passwords (entropy report) |
| `encode_decode` | base64/hex/url/base32/rot13 |
| `hash_text` | String hashing (md5/sha1/sha256/sha512) |
| `uuid_gen` | UUID v4 generate karo |
| `sha1_quick` | File ka quick SHA1 hash (single line output) |
| `strings_extract` | Binary/file se printable strings nikalo |
| `html_to_text` | HTML/URL se clean readable text (tags hata kar) |
| `dedupe_lines` | File ki duplicate lines hatao |
| `count_lines` | File ki lines count karo (regex filter ke saath) |

### 🛡️ Pentest Arsenal (10 wrappers — scope complete)
| Tool | Kya karta hai | Tool install kahan se |
|---|---|---|
| `nmap_scan` | Port/service scanning (`-sV -sC` profiles) | `apt install nmap` / nmap.org |
| `sqlmap_check` | SQL injection auto-test | `pip install sqlmap` / sqlmap.org |
| `nikto_scan` | Web server vulnerability scanner | `apt install nikto` / cirt.net |
| `nuclei_scan` | Templates-based vuln scanner | github.com/projectdiscovery/nuclei |
| `ffuf_fuzz` | Web fuzzing (FUZZ keyword) | github.com/ffuf/ffuf |
| `gobuster_dir` | Directory/wordlist brute-force | github.com/OJ/gobuster |
| `subfinder_enum` | Passive subdomain enum | github.com/projectdiscovery/subfinder |
| `httpx_probe` | Bulk URL probe + title/tech detect | github.com/projectdiscovery/httpx |
| `curl_request` | Raw curl request (headers/body) | Windows mein built-in |
| `jwt_decode` | JWT decode + signature check | Pure Python (koi install nahi) |

> Wrapper auto-detect karta hai `shutil.which` se. Tool installed nahi hai toh clear install hint deta hai (binary install karne ki zaroorat nahi — bas path par hona chahiye).
>
> **Is machine par pre-installed:** nmap 7.80, sqlmap (pip runner), nuclei v3.11.1, ffuf v2.2.1, gobuster v3.8.2, subfinder v2.16.0, httpx v1.10.0 — `E:\HackerAI\pentest-tools\bin` (user PATH mein add hai).
>
> ⚠️ **Windows Defender caveat:** `nikto.pl` aur raw `sqlmap.py` ko Defender PUA detection block karta hai (admin ke bina exclusion add nahi ho sakta). Isliye sqlmap pip package ke through chalta hai (`bin/sqlmap.cmd`). Nikto ke liye admin rights se `Add-MpPreference -ExclusionPath 'E:\HackerAI\pentest-tools'` chalao — phir `nikto_scan` kaam karega.

### 💣 Payload Generation
| Tool | Kya karta hai |
|---|---|
| `gen_reverse_shell` | Linux/Windows reverse shell (bash/nc/python/powershell/php/perl/ruby/socat/msfvenom) + listener |
| `gen_bind_shell` | Bind shell payload (nc/python/socat/powershell) |
| `gen_webshell` | Password-gated web shell (php/asp/aspx/jsp) |
| `gen_listener` | Shell pakadne ke listener commands (nc/socat/metasploit + pty upgrade) |
| `gen_obfuscate` | Command obfuscation (base64/quote/unicode) — evasion testing |
| `gen_wordlist` | Base words + leetspeak + suffixes se credential wordlist |

### 🔍 Manual Web Attack Detectors
| Tool | Kya karta hai |
|---|---|
| `sqli_test` | Boolean-based SQLi detection (sqlmap se pehle quick probe) |
| `xss_test` | Reflected XSS detection |
| `cmd_inject_test` | Command injection probes (non-destructive) |
| `path_traversal_test` | LFI/traversal signatures (passwd, win.ini) |
| `ssrf_test` | External callback URL ke saath SSRF detection |
| `open_redirect_test` | Open redirect detection |

### 📋 Findings & Reporting
| Tool | Kya karta hai |
|---|---|
| `add_finding` | Vulnerability structured log karo (asset, CWE, severity, evidence, impact, remediation) |
| `list_findings` | Findings dekho (severity/status filter, sort) |
| `update_finding` | Finding update karo (status/severity/remediation) |
| `delete_finding` | Finding delete karo |
| `write_report` | Logged findings se professional Markdown pentest report (exec summary + severity table + details) |
| `correlate_findings` | Raw scanner JSON dedupe + cross-tool correlate karo (findings merge) |
| `build_attack_chains` | Findings se linked attack paths banao — entry point, pivots, final impact, composite risk score (series-system formula), remediation choke point |
| `visualize_attack_chains` | Attack chains ka ASCII/Markdown graph — report mein embed hota hai (chain table + per-chain path diagram) |

### 🎯 Scope Enforcement
| Tool | Kya karta hai |
|---|---|
| `set_scope` | Authorized targets declare karo (domains/IPs/CIDRs/URLs) |
| `show_scope` | Current scope dikhao |
| `check_scope` | Host scope mein hai ya nahi — ALLOWED/BLOCKED verdict |

### 🧠 RAG (Vector Search)
| Tool | Kya karta hai |
|---|---|
| `rag_index` | Documents/files ka index banao (pure-Python TF-IDF, koi ML dependency nahi) |
| `vector_search` | Indexed text mein cosine-similarity search — query se related chunks (top-k) |

---

## 💬 Usage

### Interactive chat
```bash
py -3 agent.py --api-key sk-xxx
```

REPL commands:
- `/help` — help
- `/tools` — available tools
- `/memory` — saved memory dekho
- `/memdel <key>` — memory delete karo
- `/clear` — conversation reset
- `exit` — bahar niklo

### Single query
```bash
py -3 agent.py --once "E:\HackerAI\my-agent\ folder mein kya hai?"
```

### Security: terminal confirmation
Default mein agent **har terminal command se pehle aapse permission maangta hai** (interactive mode mein). Fully automatic chahiye toh `--auto` use karo.

---

## 🏗️ Architecture (Ye kaise kaam karta hai)

```
Aapka message
      │
      ▼
┌─────────────────────┐
│  LLM (reasoning)    │──► Decide: jawab do ya tool call karo
└─────────────────────┘
      │ tool call (JSON)
      ▼
┌─────────────────────┐
│  Tools (100)        │──► run_terminal, read_file, web_search,
│  (think→act→observe)│    remember, spawn_agent, nmap_scan, ...
└─────────────────────┘
      │ result
      ▼
Loop repeat hota hai jab tak final answer na aa jaye
      │
      ▼
Final jawab (user ki language mein)
```

Files:
```
my-agent/
├── agent.py                    # CLI entry point (REPL + --once)
├── webui.py                    # Web UI server (Flask, SSE streaming)
├── start_ui.bat                # Launcher — double-click aur browser khulta hai
├── templates/index.html        # Web UI frontend (dark hacker theme)
├── static/style.css            # Web UI styling
├── static/app.js               # Web UI logic (SSE, tools, memory, settings)
├── ai_agent/
│   ├── core.py                 # Agent class + think→act→observe loop
│   ├── llm.py                  # OpenAI-compatible client + Mock client
│   ├── memory.py               # Persistent memory (JSON) + RAG (TF-IDF vector search)
│   ├── config.py               # keys sirf .env se; config.json non-secret settings + flags
│   └── tools/
│       ├── __init__.py         # 100-tool registry + create_tools()
│       ├── base.py             # Tool class + execute_tool()
│       ├── terminal.py         # run_terminal, file read/write, list
│       ├── system.py           # system_info, time, processes, disk, ip
│       ├── files.py            # search, grep, hash, JSON/CSV, archives
│       ├── web.py              # http_request, headers, tech detect
│       ├── websearch.py        # web_search (DDG), open_url
│       ├── network.py          # DNS, port scan, whois, geoip, ssl, ping
│       ├── recon.py            # subdomain enum, dir fuzz, CVE, wordlist
│       ├── code.py             # run_python, regex, password, encode
│       ├── payloads.py         # reverse/bind shells, webshells, listeners, obfuscation, wordlists
│       ├── webtests.py         # manual SQLi/XSS/CMDi/traversal/SSRF/redirect probes
│       ├── reporting.py        # findings log + Markdown pentest report + attack-chain graph section
│       ├── attack_chains.py    # attack-chain graph correlator (linked paths, composite risk, ASCII viz)
│       ├── scope.py            # engagement scope guard (set/show/check)
│       ├── custom.py           # custom utilities (sha1_quick, strings, html_to_text, dedupe, count)
│       └── pentest.py          # nmap/sqlmap/nikto/nuclei/ffuf/gobuster/subfinder/httpx/curl/JWT wrappers
├── test_new_tools.py           # 47 unit tests (payloads, webtests, reporting, scope, RAG, spawn)
├── findings.jsonl              # logged findings (write_report isse report banata hai)
├── scope.json                  # declared engagement scope
├── requirements.txt            # sirf requests
├── .env.example
└── README.md
```

---

## 🛠️ Apne khud ke tools add karo

Tool package ke kisi bhi module mein function likho, phir `ai_agent/tools/__init__.py` ki registry mein ek `Tool(...)` entry add karo:

```python
Tool(
    "sha1_quick",
    "Quick SHA1 hash of a file.",
    {"type": "object",
     "properties": {"path": {"type": "string"}},
     "required": ["path"]},
    lambda path="": tool_hash_quick(path),
),
```

Bas — LLM khud naya tool discover kar lega aur jab zaroorat ho use karega.

---

## 📈 Ise aur powerful kaise banayein

1. **Best model lagao** — Settings page mein API key daalo (OpenAI/Groq/OpenRouter/Ollama)
2. **Pentest binaries** — is machine par `E:\HackerAI\pentest-tools\bin` mein install hain (PATH mein); dusri machine par inhe PATH par laga do toh agent automatically use karega
3. **RAG use karo** — `rag_index` se documents index karo, phir `vector_search` se nikal lo (koi ML dependency nahi)
4. **Bigger context** — `config.json` mein `max_iterations` ab default 60 hai (pehle 15) — bade tasks ke liye
5. **Scheduled/parallel sub-agents** — `spawn_agents` se ek saath 8 tasks chalao

---

## ✅ Naya kya hai (HackerAI-style upgrade)

- **Parallel sub-agents** — `spawn_agents` (max 8 concurrent, per-agent timeout 900s, depth 3)
- **Payload generation** — reverse/bind shells, webshells, listeners, obfuscation, wordlists
- **Manual web attack probes** — SQLi/XSS/CMDi/traversal/SSRF/open redirect quick tests
- **Professional reporting** — findings tracker + Markdown pentest report generator
- **Scope enforcement** — `set_scope`/`check_scope` se authorized targets ki guarding
- **RAG vector search** — `rag_index` + `vector_search` (pure-Python TF-IDF + cosine)
- **Custom file utilities** — sha1_quick, strings_extract, html_to_text, dedupe_lines, count_lines
- **Attack-Chain Graph Correlator** — `build_attack_chains` + `visualize_attack_chains`: flat findings ki jagah linked attack paths (entry → pivots → final impact), series-system composite risk score, remediation choke point, ASCII/Markdown graph report mein embed hota hai
- **Unit test suite** — `test_new_tools.py` (47 tests) + `test_attack_chains.py` (15 tests, sab pass)
- **102 tools total** (pehle 59) — registry, config aur prompt sab upgrade ho chuke

---

## ⚠️ Note

Terminal tool aapki machine par commands chala sakta hai. Ise sirf apni authorized testing aur apne systems par use karo.
