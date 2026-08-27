"""Tool registry: assembles all built-in tools with JSON schemas.

Add your own tools by writing a function in any module here and one
Tool(...) entry below. The LLM discovers them automatically.
"""

from .base import Tool, execute_tool, truncate
from .system import (
    tool_system_info, tool_current_time, tool_process_list,
    tool_disk_usage, tool_ip_info,
)
from .files import (
    tool_search_files, tool_grep_files, tool_file_info, tool_hash_file,
    tool_json_format, tool_csv_preview, tool_create_archive,
    tool_extract_archive, tool_diff_text, tool_pdf_info, tool_image_info,
)
from .web import (
    tool_http_request, tool_check_headers, tool_robots_txt,
    tool_extract_links, tool_tech_detect, tool_url_status,
)
from .network import (
    tool_dns_lookup, tool_reverse_dns, tool_port_scan, tool_whois_rdap,
    tool_geoip_lookup, tool_ssl_info, tool_ping_host,
)
from .recon import (
    tool_subdomain_enum, tool_dir_fuzz, tool_cve_lookup, tool_wordlist_gen,
)
from .code import (
    tool_run_python, tool_regex_test, tool_generate_password,
    tool_encode_decode, tool_hash_text, tool_uuid_gen,
)
from .terminal import (
    tool_run_terminal, tool_read_file, tool_write_file, tool_list_files,
)
from .websearch import (
    tool_web_search, tool_open_url,
)
from .pentest import (
    tool_nmap_scan, tool_sqlmap_check, tool_nikto_scan,
    tool_nuclei_scan, tool_ffuf_fuzz, tool_gobuster_dir,
    tool_subfinder_enum, tool_httpx_probe, tool_curl_request,
    tool_jwt_decode,
)

from .base import Tool as _Tool  # noqa: F401


def _str_prop(desc, default=None, enum=None):
    p = {"type": "string", "description": desc}
    if default is not None:
        p["default"] = default
    if enum:
        p["enum"] = enum
    return p


def create_tools(memory, confirm_terminal=True, spawn_fn=None, allow_spawn=True):
    """Build the full tool list for an Agent."""

    def tool_spawn_agent(task):
        if not allow_spawn or spawn_fn is None:
            return "Error: sub-agents are disabled."
        return spawn_fn(task)

    def tool_list_tools():
        names = "\n".join("  %-22s %s" % (t.name, t.description)
                          for t in _REGISTRY)
        return "Available tools (%d):\n%s" % (len(_REGISTRY), names)

    def _remember(key, text):
        if not key.strip() or not text.strip():
            return "Error: both key and text are required."
        memory.add(key.strip(), text.strip())
        return "Saved to memory: %s" % key.strip()

    def _recall(query=""):
        return memory.recall(query or None)

    REGISTRY = [
        # ---- core ----
        Tool("run_terminal",
             "Execute a shell command on the user's machine and return its "
             "output. Use for system info, scripts, installs, scans.",
             {"type": "object",
              "properties": {"command": _str_prop("command to run", None),
                             "timeout": {"type": "integer", "default": 60,
                                         "description": "seconds"}},
              "required": ["command"]},
             lambda command="", timeout=60: tool_run_terminal(command, timeout),
             confirm=confirm_terminal),
        Tool("read_file", "Read a text file from disk.",
             {"type": "object",
              "properties": {"path": _str_prop("file path")},
              "required": ["path"]},
             lambda path="": tool_read_file(path)),
        Tool("write_file", "Write text content to a file (creates/overwrites).",
             {"type": "object",
              "properties": {"path": _str_prop("file path"),
                             "content": _str_prop("full content")},
              "required": ["path", "content"]},
             lambda path="", content="": tool_write_file(path, content)),
        Tool("list_files", "List files and directories under a path.",
             {"type": "object",
              "properties": {"path": _str_prop("directory", ".")},
              "required": []},
             lambda path=".": tool_list_files(path or ".")),
        Tool("web_search",
             "Search the web (DuckDuckGo) and return top results with links "
             "and snippets.",
             {"type": "object",
              "properties": {"query": _str_prop("search query"),
                             "max_results": {"type": "integer", "default": 6}},
              "required": ["query"]},
             lambda query="", max_results=6: tool_web_search(query, int(max_results or 6))),
        Tool("open_url", "Fetch and read the text content of a webpage.",
             {"type": "object",
              "properties": {"url": _str_prop("page URL")},
              "required": ["url"]},
             lambda url="": tool_open_url(url)),
        Tool("remember", "Save a fact/note to persistent memory.",
             {"type": "object",
              "properties": {"key": _str_prop("short key, e.g. 'target_ip'"),
                             "text": _str_prop("the fact to remember")},
              "required": ["key", "text"]},
             lambda key="", text="": _remember(key, text)),
        Tool("recall", "List saved memory notes, optionally filtered.",
             {"type": "object",
              "properties": {"query": _str_prop("optional keyword filter", "")},
              "required": []},
             lambda query="": _recall(query)),
        Tool("spawn_agent",
             "Create a sub-agent that independently works on a task and "
             "returns its final answer. Use for parallel/specialized work.",
             {"type": "object",
              "properties": {"task": _str_prop("the task for the sub-agent")},
              "required": ["task"]},
             lambda task="": tool_spawn_agent(task or "")),
        Tool("list_tools", "List every available tool with a short description.",
             {"type": "object", "properties": {}, "required": []},
             lambda: tool_list_tools()),

        # ---- system ----
        Tool("system_info", "OS, CPU, memory, hostname, cwd, user info.",
             {"type": "object", "properties": {}, "required": []},
             lambda: tool_system_info()),
        Tool("current_time", "Current local and UTC time with timezone.",
             {"type": "object", "properties": {}, "required": []},
             lambda: tool_current_time()),
        Tool("process_list", "List running processes, optionally filtered.",
             {"type": "object",
              "properties": {"name_filter": _str_prop("filter by name, or 'all'", "all")},
              "required": []},
             lambda name_filter="all": tool_process_list(name_filter)),
        Tool("disk_usage", "Disk space usage for a path or all drives ('all').",
             {"type": "object",
              "properties": {"path": _str_prop("path or 'all' for drives", ".")},
              "required": []},
             lambda path=".": tool_disk_usage(path or ".")),
        Tool("ip_info", "Show this machine's local IP addresses.",
             {"type": "object", "properties": {}, "required": []},
             lambda: tool_ip_info()),

        # ---- files & data ----
        Tool("search_files", "Find files by name glob under a path.",
             {"type": "object",
              "properties": {"pattern": _str_prop("glob, e.g. '*.log'", "*"),
                             "path": _str_prop("start directory", ".")},
              "required": []},
             lambda pattern="*", path=".": tool_search_files(pattern or "*", path or ".")),
        Tool("grep_files", "Search text inside files for a regex pattern.",
             {"type": "object",
              "properties": {"pattern": _str_prop("regex to find"),
                             "path": _str_prop("start directory", "."),
                             "file_pattern": _str_prop("file glob filter", "*")},
              "required": ["pattern"]},
             lambda pattern="", path=".", file_pattern="*":
                 tool_grep_files(pattern, path or ".", file_pattern or "*")),
        Tool("file_info", "Metadata of a file/dir: size, dates, type, magic bytes.",
             {"type": "object",
              "properties": {"path": _str_prop("file path")},
              "required": ["path"]},
             lambda path="": tool_file_info(path)),
        Tool("hash_file", "MD5/SHA1/SHA256/SHA512 hashes of a file.",
             {"type": "object",
              "properties": {"path": _str_prop("file path")},
              "required": ["path"]},
             lambda path="": tool_hash_file(path)),
        Tool("json_format", "Validate and pretty-print JSON (text or file).",
             {"type": "object",
              "properties": {"text": _str_prop("JSON string"),
                             "path": _str_prop("or a JSON file path")},
              "required": []},
             lambda text="", path="": tool_json_format(text or None, path or None)),
        Tool("csv_preview", "Preview a CSV file: rows, columns, head.",
             {"type": "object",
              "properties": {"path": _str_prop("CSV file path")},
              "required": ["path"]},
             lambda path="": tool_csv_preview(path)),
        Tool("create_archive", "Zip a file or directory.",
             {"type": "object",
              "properties": {"target_path": _str_prop("output zip path"),
                             "source_path": _str_prop("file or dir to zip")},
              "required": ["target_path", "source_path"]},
             lambda target_path="", source_path="":
                 tool_create_archive(target_path, source_path)),
        Tool("extract_archive", "Extract zip/tar/tar.gz into a folder.",
             {"type": "object",
              "properties": {"archive_path": _str_prop("archive file"),
                             "dest_dir": _str_prop("destination dir (optional)")},
              "required": ["archive_path"]},
             lambda archive_path="", dest_dir="":
                 tool_extract_archive(archive_path, dest_dir or None)),
        Tool("diff_text", "Show differences between two texts or files.",
             {"type": "object",
              "properties": {"text_a": _str_prop("first text"),
                             "text_b": _str_prop("second text"),
                             "path_a": _str_prop("or first file"),
                             "path_b": _str_prop("or second file")},
              "required": []},
             lambda text_a="", text_b="", path_a="", path_b="":
                 tool_diff_text(text_a or None, text_b or None,
                                path_a or None, path_b or None)),
        Tool("pdf_info", "PDF metadata: pages, title, creator, producer.",
             {"type": "object",
              "properties": {"path": _str_prop("PDF file path")},
              "required": ["path"]},
             lambda path="": tool_pdf_info(path)),
        Tool("image_info", "Image format and dimensions (PNG/JPEG/GIF/BMP/WEBP).",
             {"type": "object",
              "properties": {"path": _str_prop("image file path")},
              "required": ["path"]},
             lambda path="": tool_image_info(path)),

        # ---- web & http ----
        Tool("http_request", "Send a raw HTTP request (any method) and get "
             "status, headers, body.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "method": _str_prop("GET/POST/PUT/DELETE/HEAD/OPTIONS", "GET"),
                             "headers": _str_prop("extra headers, one per line 'Name: value'"),
                             "data": _str_prop("request body for POST/PUT")},
              "required": ["url"]},
             lambda url="", method="GET", headers="", data="":
                 tool_http_request(url, method or "GET", _parse_headers(headers),
                                   data or None)),
        Tool("check_headers", "Audit a URL's security headers (HSTS, CSP, "
             "X-Frame-Options, cookies...).",
             {"type": "object",
              "properties": {"url": _str_prop("target URL")},
              "required": ["url"]},
             lambda url="": tool_check_headers(url)),
        Tool("robots_txt", "Fetch a site's robots.txt.",
             {"type": "object",
              "properties": {"url": _str_prop("site base URL")},
              "required": ["url"]},
             lambda url="": tool_robots_txt(url)),
        Tool("extract_links", "Extract internal/external links from a page.",
             {"type": "object",
              "properties": {"url": _str_prop("page URL")},
              "required": ["url"]},
             lambda url="": tool_extract_links(url)),
        Tool("tech_detect", "Detect web technologies (server, CMS, framework).",
             {"type": "object",
              "properties": {"url": _str_prop("target URL")},
              "required": ["url"]},
             lambda url="": tool_tech_detect(url)),
        Tool("url_status", "Check HTTP status of comma-separated URLs.",
             {"type": "object",
              "properties": {"urls": _str_prop("comma-separated URLs")},
              "required": ["urls"]},
             lambda urls="": tool_url_status(urls)),

        # ---- network ----
        Tool("dns_lookup", "DNS records: A, AAAA, CNAME, MX, NS, TXT.",
             {"type": "object",
              "properties": {"hostname": _str_prop("domain/host"),
                             "record_type": _str_prop("A/AAAA/CNAME/MX/NS/TXT", "A")},
              "required": ["hostname"]},
             lambda hostname="", record_type="A":
                 tool_dns_lookup(hostname, record_type or "A")),
        Tool("reverse_dns", "PTR lookup for an IP address.",
             {"type": "object",
              "properties": {"ip": _str_prop("IP address")},
              "required": ["ip"]},
             lambda ip="": tool_reverse_dns(ip)),
        Tool("port_scan", "TCP connect scan with banner grabbing "
             "(pure Python, no nmap needed).",
             {"type": "object",
              "properties": {"host": _str_prop("target host/IP"),
                             "ports": _str_prop("ports, e.g. '80,443' or '1-1024'",
                                                "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,2375,3000,3306,3389,5432,5900,6379,8000,8080,8443,8888,9000,9090,9200,11211,27017"),
                             "timeout": {"type": "number", "default": 1.5}},
              "required": ["host"]},
             lambda host="", ports="", timeout=1.5:
                 tool_port_scan(host, ports or DEFAULT_PORTS, timeout)),
        Tool("whois", "WHOIS-style registration info via RDAP.",
             {"type": "object",
              "properties": {"domain_or_ip": _str_prop("domain or IP")},
              "required": ["domain_or_ip"]},
             lambda domain_or_ip="": tool_whois_rdap(domain_or_ip)),
        Tool("geoip", "IP geolocation: country, city, ISP, ASN.",
             {"type": "object",
              "properties": {"ip": _str_prop("IP address")},
              "required": ["ip"]},
             lambda ip="": tool_geoip_lookup(ip)),
        Tool("ssl_info", "TLS certificate details: issuer, expiry, SANs, cipher.",
             {"type": "object",
              "properties": {"host": _str_prop("hostname"),
                             "port": {"type": "integer", "default": 443}},
              "required": ["host"]},
             lambda host="", port=443: tool_ssl_info(host, port or 443)),
        Tool("ping_host", "ICMP ping a host (system ping).",
             {"type": "object",
              "properties": {"host": _str_prop("host/IP"),
                             "count": {"type": "integer", "default": 3}},
              "required": ["host"]},
             lambda host="", count=3: tool_ping_host(host, int(count or 3))),

        # ---- recon ----
        Tool("subdomain_enum", "Enumerate subdomains via Certificate "
             "Transparency (crt.sh).",
             {"type": "object",
              "properties": {"domain": _str_prop("root domain, e.g. example.com")},
              "required": ["domain"]},
             lambda domain="": tool_subdomain_enum(domain)),
        Tool("dir_fuzz", "Brute-force common paths on a web server. Optionally "
             "pass your own comma-separated wordlist.",
             {"type": "object",
              "properties": {"base_url": _str_prop("e.g. https://example.com"),
                             "wordlist": _str_prop("comma-separated paths (optional)"),
                             "max_results": {"type": "integer", "default": 40}},
              "required": ["base_url"]},
             lambda base_url="", wordlist="", max_results=40:
                 tool_dir_fuzz(base_url, wordlist or None, int(max_results or 40))),
        Tool("cve_lookup", "Search known CVEs by product/keyword/version.",
             {"type": "object",
              "properties": {"query": _str_prop("e.g. 'nginx 1.18' or 'wordpress'")},
              "required": ["query"]},
             lambda query="": tool_cve_lookup(query)),
        Tool("wordlist_gen", "Generate a wordlist from keywords + numbers + "
             "years + special chars.",
             {"type": "object",
              "properties": {"keywords": _str_prop("comma-separated base words"),
                             "numbers": _str_prop("range like '0-9'", "0-9"),
                             "years": _str_prop("range like '2015-2026'", "2015-2026"),
                             "specials": _str_prop("chars to append", "!@#")},
              "required": ["keywords"]},
             lambda keywords="", numbers="0-9", years="2015-2026", specials="!@#":
                 tool_wordlist_gen(keywords, numbers, years, specials)),

        # ---- code & utilities ----
        Tool("run_python", "Execute Python code in a subprocess; returns "
             "stdout/stderr.",
             {"type": "object",
              "properties": {"code": _str_prop("Python source code"),
                             "timeout": {"type": "integer", "default": 30}},
              "required": ["code"]},
             lambda code="", timeout=30: tool_run_python(code, timeout)),
        Tool("regex_test", "Test a regex against sample text and show matches "
             "with capture groups.",
             {"type": "object",
              "properties": {"pattern": _str_prop("regex pattern"),
                             "text": _str_prop("sample text"),
                             "flags": _str_prop("i/m/s flags, e.g. 'i'")},
              "required": ["pattern", "text"]},
             lambda pattern="", text="", flags="":
                 tool_regex_test(pattern, text, flags or "")),
        Tool("generate_password", "Generate strong random passwords.",
             {"type": "object",
              "properties": {"length": {"type": "integer", "default": 16},
                             "count": {"type": "integer", "default": 3}},
              "required": []},
             lambda length=16, count=3:
                 tool_generate_password(length=int(length or 16), count=int(count or 3))),
        Tool("encode_decode", "Encode/decode text: base64, hex, url, base32, rot13.",
             {"type": "object",
              "properties": {"action": _str_prop("encode or decode", "encode",
                                                 ["encode", "decode"]),
                             "encoding": _str_prop("base64/hex/url/base32/rot13", "base64"),
                             "data": _str_prop("input text")},
              "required": ["data"]},
             lambda action="encode", encoding="base64", data="":
                 tool_encode_decode(action or "encode", encoding or "base64", data)),
        Tool("hash_text", "Hash a string: md5, sha1, sha256, sha512.",
             {"type": "object",
              "properties": {"text": _str_prop("input text"),
                             "algorithms": _str_prop("comma-separated", "sha256")},
              "required": ["text"]},
             lambda text="", algorithms="sha256":
                 tool_hash_text(text, algorithms or "sha256")),
        Tool("uuid_gen", "Generate one or more UUID v4.",
             {"type": "object",
              "properties": {"count": {"type": "integer", "default": 1}},
              "required": []},
             lambda count=1: tool_uuid_gen(int(count or 1))),

        # ---- pentest arsenal (external binary wrappers) ----
        Tool("nmap_scan", "Run nmap against a host with service detection "
             "(requires nmap installed; fallback: port_scan).",
             {"type": "object",
              "properties": {"host": _str_prop("target host/IP"),
                             "ports": _str_prop("e.g. '80,443' or '1-1024' (optional)"),
                             "args": _str_prop("extra nmap flags", "-sV -T4")},
              "required": ["host"]},
             lambda host="", ports="", args="":
                 tool_nmap_scan(host, ports or "", args or "-sV -T4")),
        Tool("sqlmap_check", "Automated SQL injection testing with sqlmap "
             "(non-interactive --batch).",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "data": _str_prop("POST body (optional)"),
                             "level": {"type": "integer", "default": 1},
                             "risk": {"type": "integer", "default": 1}},
              "required": ["url"]},
             lambda url="", data="", level=1, risk=1:
                 tool_sqlmap_check(url, data or "", int(level or 1), int(risk or 1))),
        Tool("nikto_scan", "Run a nikto web server vulnerability scan.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL")},
              "required": ["url"]},
             lambda url="": tool_nikto_scan(url)),
        Tool("nuclei_scan", "Run nuclei template-based vulnerability scanning.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "templates": _str_prop("template name/path (optional)"),
                             "severity": _str_prop("comma list", "low,medium,high,critical")},
              "required": ["url"]},
             lambda url="", templates="", severity="":
                 tool_nuclei_scan(url, templates or "", severity or "low,medium,high,critical")),
        Tool("ffuf_fuzz", "Fast web fuzzing with ffuf (dir or vhost mode).",
             {"type": "object",
              "properties": {"base_url": _str_prop("target base URL"),
                             "wordlist_path": _str_prop("path to wordlist file"),
                             "mode": _str_prop("dir or vhost", "dir", ["dir", "vhost"])},
              "required": ["base_url", "wordlist_path"]},
             lambda base_url="", wordlist_path="", mode="dir":
                 tool_ffuf_fuzz(base_url, wordlist_path or "", mode or "dir")),
        Tool("gobuster_dir", "Directory/file brute force with gobuster.",
             {"type": "object",
              "properties": {"base_url": _str_prop("target base URL"),
                             "wordlist_path": _str_prop("path to wordlist file"),
                             "extensions": _str_prop("e.g. 'php,txt,zip' (optional)")},
              "required": ["base_url", "wordlist_path"]},
             lambda base_url="", wordlist_path="", extensions="":
                 tool_gobuster_dir(base_url, wordlist_path or "", extensions or "")),
        Tool("subfinder_enum", "Passive subdomain enumeration with subfinder "
             "(ProjectDiscovery).",
             {"type": "object",
              "properties": {"domain": _str_prop("root domain")},
              "required": ["domain"]},
             lambda domain="": tool_subfinder_enum(domain)),
        Tool("httpx_probe", "Probe URLs with httpx: status, title, tech stack.",
             {"type": "object",
              "properties": {"urls": _str_prop("comma-separated URLs")},
              "required": ["urls"]},
             lambda urls="": tool_httpx_probe(urls)),
        Tool("curl_request", "Raw HTTP request via curl (ships with Windows "
             "10+/macOS/Linux) - full control over headers/method/body.",
             {"type": "object",
              "properties": {"url": _str_prop("target URL"),
                             "method": _str_prop("GET/POST/PUT/DELETE/HEAD/OPTIONS", "GET"),
                             "headers": _str_prop("one per line 'Name: value'"),
                             "data": _str_prop("request body")},
              "required": ["url"]},
             lambda url="", method="GET", headers="", data="":
                 tool_curl_request(url, method or "GET", headers or "", data or "")),
        Tool("jwt_decode", "Decode a JWT header and payload (no signature "
             "verification) - useful for token tampering analysis.",
             {"type": "object",
              "properties": {"token": _str_prop("JWT token")},
              "required": ["token"]},
             lambda token="": tool_jwt_decode(token)),
    ]

    global _REGISTRY
    _REGISTRY = REGISTRY
    return REGISTRY


DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,2375,3000,3306,3389,5432,5900,6379,8000,8080,8443,8888,9000,9090,9200,11211,27017"

_REGISTRY = []


def _parse_headers(headers_text):
    """Parse 'Name: value' lines into a dict."""
    if not headers_text or not isinstance(headers_text, str):
        return None
    out = {}
    for line in headers_text.splitlines():
        line = line.strip()
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out or None


__all__ = ["Tool", "execute_tool", "create_tools", "truncate"]
