"""CVE Variant & Structural Sibling Hunter.

hunt_cve_variants(known_cve_details, codebase_path_or_endpoint_list)

Given a known CVE - its ID, a free-text description, or structured JSON
(id/description/cwes) - this tool extracts the *root-cause family* the
vulnerability belongs to (e.g. unchecked length parameter, unsafe
deserialization, insecure regex / ReDoS, command or SQL injection, XXE,
SSRF, SSTI, XSS, path traversal, open redirect, auth bypass, race
condition) and then scans a target surface for STRUCTURALLY SIMILAR sinks:
the same dangerous operation fed by tainted user input, at a different
location.

Two target forms are supported:

* codebase_path  - a directory; every source file is walked (ignoring
  vendored/dependency trees) and each line is matched against the
  family-specific sink patterns of the extracted root cause.
* endpoint_list  - a JSON array of endpoints (strings or objects with
  route/path/url/method/params/code), or a plain-text list of URLs; each
  route is matched against family-specific endpoint fingerprints and any
  embedded code snippets are also pattern-scanned.

Each returned candidate is ranked by a confidence score built from:
sink presence, tainted (user-reachable) data proximity, and absence of
validation/sanitization/allowlisting in the immediate context. Every
candidate carries the evidence snippet, the matched structural pattern
and a concrete verification hint so the operator can confirm the sibling
without re-reading the whole codebase.
"""

import json
import os
import re

import requests

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

_IGNORE_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".tox", ".nox", "dist", "build", ".next", ".nuxt", "target",
    "vendor", ".mypy_cache", ".pytest_cache", ".ruff_cache", "coverage",
    "htmlcov", ".idea", ".vscode", ".vs", "bower_components", "jspm_packages",
    ".cache", "tmp", "temp", ".gradle", ".sass-cache", ".parcel-cache",
    ".terraform", ".serverless", ".yarn", ".pnpm-store",
})
_SOURCE_EXTS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".c", ".h",
    ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".cs", ".rb", ".php", ".swift",
    ".sh", ".bash", ".kt", ".sql", ".html", ".css", ".scss", ".php3", ".phtml",
})
_MAX_FILES = 4000
_MAX_LINES_PER_FILE = 20000
_CTX_RADIUS = 2  # lines of context before/after a match


def _clamp(v, lo=0.1, hi=0.97):
    return max(lo, min(hi, v))


def _compile(patterns):
    out = []
    for name, rx in patterns:
        try:
            out.append((name, re.compile(rx, re.IGNORECASE)))
        except re.error as exc:  # pragma: no cover - defensive only
            raise ValueError("bad pattern %r: %s" % (name, exc))
    return out


def _check_patterns(name_rx_list):
    return [re.compile(rx, re.IGNORECASE) for _, rx in name_rx_list]


# ---------------------------------------------------------------------------
# Root-cause families
# ---------------------------------------------------------------------------

# Each family: classification keywords (description scan), strong triggers,
# CWE ids, code sink patterns, endpoint fingerprints, guard markers that
# neutralise a hit, taint tokens that amplify a hit, and a verification hint.
_FAMILIES = {
    "unchecked_length": {
        "keywords": ("buffer overflow", "stack overflow", "heap overflow",
                     "out-of-bounds", "out of bounds", "integer overflow",
                     "length parameter", "unchecked length", "missing length",
                     "bounds check", "memcpy", "strcpy", "sprintf", "strlen",
                     "signed integer", "size field", "allocation size",
                     "under-allocation", "heap corruption", "memory corruption"),
        "strong": ("overflow", "out-of-bounds", "out of bounds",
                   "memory corruption", "length"),
        "cwes": ("CWE-120", "CWE-122", "CWE-125", "CWE-190", "CWE-787",
                 "CWE-119", "CWE-680"),
        "code": _compile([
            ("memcpy_strcpy", r"\b(?:memcpy|memmove|strcpy|strcat|sprintf|"
                               r"vsprintf|wcscpy|wcscat|strncat)\s*\("),
            ("tainted_alloc", r"\b(?:malloc|realloc|calloc|alloca)\s*\([^)]{0,"
                              r"90}\b(?:len|size|length|count|capacity|n)\w*"),
            ("index_write_len", r"\[[^\]]{0,40}\b(?:len|size|length|count|idx|"
                                r"index|offset|capacity)\b[^\]]{0,40}\]\s*="),
            ("recv_into_buf", r"\b(?:recv|read|fread|fgets|fscanf|scanf)\s*\([^)]"
                              r"{0,80}\b(?:buf|buffer|data|dest|dst)\b"),
            ("arr_index_taint", r"[A-Za-z_]\w*\[[^\]]{0,30}(?:input|request|"
                                r"param|user|arg|data|size|len|idx|offset)"
                                r"[^\]]{0,30}\]\s*(?:=|\[)"),
        ]),
        "endpoints": [
            ("size_params", r"(?:\?|&)(?:size|length|count|offset|chunk|n|"
                            r"capacity|maxlen)="),
        ],
        "guards": _check_patterns([
            ("len_check", r"len\s*[<>]=?\s*|if\s+[^:;]{0,60}(?:<=|>=|<|>)\s*"
                          r"[^:;]{0,40}(?:len|size|count|MAX|LIMIT)"),
            ("safe_api", r"(?:strlcpy|strlcat|snprintf|vsnprintf|checked_|"
                         r"sized|max_length|MAX_|LIMIT|bound|clamp|cap\b)"),
        ]),
        "taint": ("request input user param args argv query form body header "
                  "cookie data payload url filename path size length count "
                  "offset value client json recv read buf buffer n len").split(),
        "test_hint": ("Craft a request whose size/length/count parameter exceeds "
                      "the buffer/array bound; watch for memory corruption, "
                      "truncation or crash. Confirm the sink lacks an upper "
                      "bound on the tainted length."),
    },
    "unsafe_deserialization": {
        "keywords": ("deserialization", "deserialize", "serialization",
                     "pickle", "unserialize", "readobject", "objectinputstream",
                     "yaml", "marshal", "gadget chain", "remote code",
                     "rce via", "xml decoder", "fastjson", "jackson",
                     "type confusion", "untrusted data"),
        "strong": ("deserialization", "deserialize", "pickle", "unserialize",
                   "gadget"),
        "cwes": ("CWE-502", "CWE-913", "CWE-749"),
        "code": _compile([
            ("pickle_loads", r"\b(?:pickle|cPickle|cloudpickle)\.loads?\s*\("),
            ("yaml_load", r"\byaml\.load\s*\("),
            ("read_object", r"\b(?:readObject|readUnshared|ObjectInputStream|"
                             r"XMLDecoder)\s*\("),
            ("php_unserialize", r"\bunserialize\s*\("),
            ("marshal_load", r"\bMarshal\.Load\s*\("),
            ("fastjson", r"\bJSON\.parseObject\s*\(|JSON\.parse\s*\([^)]{0,40}"
                          r"(?:autotype|autoType)"),
            ("jackson_typing", r"\benableDefaultTyping\s*\(|activateDefaultTyping"
                               r"\s*\("),
            ("node_serialize", r"\bnode[\-_]serialize\b"),
        ]),
        "endpoints": [
            ("deser_routes", r"(?:unserialize|deserialize|restore|loadstate|"
                             r"import|decode|parse|upload|restore|hydrate)"
                             r"(?:\b|/|-|_)"),
            ("blob_params", r"(?:\?|&)(?:data|payload|obj|blob|state|session|"
                            r"token|config|body)="),
        ],
        "guards": _check_patterns([
            ("safe_load", r"safe_load|SafeLoader|CSafeLoader|yaml\.safe|"
                          r"allowlist|whitelist|allowed_classes|permit|"
                          r"type[\s_]?whitelist|jsonpickle|defused"),
        ]),
        "taint": ("request input data payload body content blob obj base64 "
                  "token param header cookie upload file json yaml pickle "
                  "state value").split(),
        "test_hint": ("Submit a crafted serialized payload (e.g. pickle "
                      "gadget / ysoserial chain / PHP object injection) "
                      "through every deserialize/decode endpoint and check "
                      "for code execution or stack traces."),
    },
    "insecure_regex": {
        "keywords": ("regex", "regular expression", "redos", "catastrophic "
                     "backtracking", "denial of service", "repeated groups",
                     "nested quantifiers", "re2", "backtracking"),
        "strong": ("redos", "regex", "catastrophic backtracking", "re2"),
        "cwes": ("CWE-1333", "CWE-400", "CWE-185", "CWE-20"),
        "code": _compile([
            ("nested_quant", r"\b(?:re\.(?:match|search|findall|finditer|sub|"
                              r"split|fullmatch)|preg_match|new\s+RegExp)\s*\("
                              r"\s*['\"](?=[^'\"]*[+*])(?:[^'\"\\]|\\.)*?\([^()\\]"
                              r"*(?:\\.[^()\\]*)*[+*](?:[^()\\]*(?:\\.[^()\\]*)*"
                              r"[+*])*\)\s*[+*]"),
            ("input_to_regex", r"\bnew\s+RegExp\s*\(\s*(?:[a-zA-Z_$][\w.$]*\s*\+|"
                               r"['\"][^'\"]+['\"]\s*\+|`[^`]*\$\{)"),
            ("dyn_pattern", r"\b(?:re\.|preg_)\w*\s*\(\s*(?:f['\"]|['\"][^'\"]*"
                            r"['\"]\s*(?:\+|%|\.format)|request|input|data|query|"
                            r"param|pattern|filter)\b[^)]{0,60}"),
        ]),
        "endpoints": [
            ("regex_routes", r"(?:regex|pattern|filter|match|validate|search|"
                             r"check|query)(?:\b|/|-|_)"),
            ("regex_params", r"(?:\?|&)(?:regex|pattern|filter|query|input)="),
        ],
        "guards": _check_patterns([
            ("re_timeout", r"timeout|RE2|re2::|RE2\(|safe\s*regex|pattern.*"
                           r"timeout|max.*(?:len|size).*regex|posix|DFA|"
                           r"linear"),
        ]),
        "taint": ("input data query search param filter value text string "
                  "username email url name pattern regex word term").split(),
        "test_hint": ("Send a pathological input (e.g. long repeating 'a' "
                      "against ^(a+)+$) to the regex-backed endpoint and "
                      "measure response latency / CPU; a huge slowdown with "
                      "no timeout is a ReDoS sibling."),
    },
    "command_injection": {
        "keywords": ("command injection", "shell injection", "os command",
                     "system()", "shell_exec", "subprocess", "popen", "rce",
                     "remote code execution", "code injection", "backtick",
                     "command execution"),
        "strong": ("command injection", "shell injection", "os command"),
        "cwes": ("CWE-78", "CWE-77", "CWE-94"),
        "code": _compile([
            ("os_system", r"\bos\.(?:system|popen)\s*\("),
            ("subprocess_shell", r"\bsubprocess\.(?:run|Popen|call|check_output|"
                                 r"check_call)\s*\([^)]{0,200}shell\s*=\s*"
                                 r"(?:True|1|yes)\b"),
            ("php_exec", r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)"
                          r"\s*\(\s*\$"),
            ("runtime_exec", r"\bRuntime\.getRuntime\(\)\.exec\s*\("),
            ("node_exec", r"\b(?:child_process\.)?(?:exec|execSync|spawn)\s*\("
                          r"\s*(?:['\"][^'\"]*['\"]\s*\+|`[^`]*\$\{)"),
            ("bare_popen", r"\b(?:popen|_popen|winpty)\s*\("),
            ("eval_cmd", r"\beval\s*\(\s*(?:request|input|cmd|data|payload|"
                         r"`|f['\"])"),
        ]),
        "endpoints": [
            ("cmd_routes", r"(?:exec|run|cmd|command|ping|host|whois|nslookup|"
                           r"dig|traceroute|convert|ffmpeg|curl|wget|download|"
                           r"render|screenshot|ssh|telnet|git|zip|tar)(?:\b|/|-|_)"),
            ("cmd_params", r"(?:\?|&)(?:cmd|command|host|ip|domain|file|url|"
                            r"target|arg|args)="),
        ],
        "guards": _check_patterns([
            ("shell_quote", r"shlex\.quote|shlex\.split|escapeshellarg|"
                            r"escapeshellcmd|subprocess\s*\([^)]{0,200}shell\s*="
                            r"\s*(?:False|0)|no_shell|allowlist|whitelist|"
                            r"validate.*(?:cmd|command|host|ip)"),
        ]),
        "taint": ("request input user cmd command host ip domain file filename "
                  "url param args query form body data name arg value").split(),
        "test_hint": ("Inject metacharacters (; | && $() `) plus a marker "
                      "payload into every command-oriented parameter and "
                      "observe execution side-channels (DNS pingback, timing, "
                      "response echo)."),
    },
    "sql_injection": {
        "keywords": ("sql injection", "sqli", "sqli", "sql query", "parameter"
                     "ized", "database", "mysql", "postgres", "injection via",
                     "prepared statement", "query string"),
        "strong": ("sql injection", "sqli", "sql injection vulnerability"),
        "cwes": ("CWE-89", "CWE-564", "CWE-943"),
        "code": _compile([
            ("sql_concat", r"\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE)\b[^\n]{0,"
                            r"160}['\"][^\n]{0,60}['\"]\s*(?:\+|%|\.format|f['\"])"),
            ("execute_concat", r"\b(?:execute|executemany|query|raw_query|"
                                r"exec)\s*\(\s*[^)]{0,140}(?:\+|%|\.format\()"),
            ("php_sql_var", r"\b(?:mysql_query|mysqli_query|pg_query|sqlsrv_query"
                             r"|oci_parse|->query|->prepare)\s*\(\s*[^)]{0,160}\$"),
            ("jdbc_concat", r"\b(?:createStatement|executeQuery|executeUpdate|"
                             r"prepareStatement)\s*\([^)]{0,160}\+"),
            ("string_where", r"\bWHERE\b[^\n]{0,140}(?:['\"][^'\"]*['\"]\s*(?:\+|"
                             r"%|\.format)|f['\"]|\$_)"),
        ]),
        "endpoints": [
            ("sql_routes", r"(?:search|filter|sort|order|detail|view|get|list|"
                            r"export|query|keyword|find|lookup|item)(?:\b|/|-|_)"),
            ("sql_params", r"(?:\?|&)(?:id|q|search|filter|sort|order|keyword|"
                            r"name|user|page|category|type)="),
        ],
        "guards": _check_patterns([
            ("parametrized", r"parametri[sz]e|prepared\s+statement|escape_string|"
                             r"quote_ident|pg_query_params|sp_executesql\s*@|"
                             r"safe\s*sql|execute\([^)]*,\s*(?:\[|\(|\{)|db\.placeholder|"
                             r"\.format_sql|%s\s*\)\s*,\s*"),
        ]),
        "taint": ("request input user param query search filter id name order "
                  "sort keyword value data form get post cookie header json "
                  "arg page category").split(),
        "test_hint": ("Submit classic boolean/union/error payloads (' OR 1=1--, "
                      "' UNION SELECT NULL--) to each SQL-backed parameter and "
                      "look for error disclosure, row-count changes or timing "
                      "differences."),
    },
    "path_traversal": {
        "keywords": ("path traversal", "directory traversal", "local file "
                     "inclusion", "lfi", "traversal", "arbitrary file",
                     "zip slip", "relative path", "dot-dot", "filename"),
        "strong": ("path traversal", "directory traversal", "local file inclusion",
                   "lfi", "arbitrary file"),
        "cwes": ("CWE-22", "CWE-23", "CWE-36", "CWE-73"),
        "code": _compile([
            ("open_user_path", r"\b(?:open|openFile|file_get_contents|readfile|"
                               r"send_file|Image\.open|Files\.readAllBytes|"
                               r"new\s+File|File\.(?:read|copy|delete|readFileSync)"
                               r"|createReadStream|FileReader)\s*\(\s*[^)]{0,100}"
                               r"(?:os\.path\.join|path\.join|f['\"]|\.format|%s|"
                               r"\+|\$|request|input|param|filename|filepath|path|"
                               r"name|url|id)"),
            ("path_join_taint", r"\b(?:os\.path\.join|path\.join)\s*\([^)]{0,80}"
                                r"(?:request|input|param|filename|file|name|path|"
                                r"id|user|url|folder|dir)"),
            ("zip_extract", r"\b(?:ZipFile|zipfile\.ZipFile|extractall|"
                            r"TarFile|unpack_archive)\s*\("),
            ("php_lfi", r"\b(?:file_get_contents|readfile|include|require|"
                         r"fopen)\s*\(\s*\$_(?:GET|POST|REQUEST|FILES)"),
            ("send_file_taint", r"\b(?:send_file|send_from_directory|static_file|"
                                 r"res\.download|Response\.File)\s*\(\s*[^)]{0,60}"
                                 r"(?:request|input|filename|path|name|user|id)"),
        ]),
        "endpoints": [
            ("file_routes", r"(?:download|upload|file|files|image|img|avatar|"
                             r"attachment|export|static|media|document|doc|read|"
                             r"view|thumbnail|thumb|pdf|report)(?:\b|/|-|_)"),
            ("file_params", r"(?:\?|&)(?:file|filename|path|name|dir|folder|"
                             r"url|id|page|lang|template|style|doc)="),
        ],
        "guards": _check_patterns([
            ("path_hardening", r"realpath|abspath|normpath|basename|resolve|"
                               r"sanitize|validate|allowlist|whitelist|base_dir|"
                               r"ROOT|UPLOAD|secure_filename|starts_with|"
                               r"os\.path\.abspath|is_within|commonpath|"
                               r"bail|reject"),
        ]),
        "taint": ("request input param filename file path name id user url "
                  "download upload dir folder lang template page view").split(),
        "test_hint": ("Send ../../../../etc/passwd-style paths through every "
                      "file-oriented parameter (also URL-encoded and nested "
                      "variants) and check for file contents in the response."),
    },
    "xxe": {
        "keywords": ("xml external entity", "xxe", "external entity", "xml "
                     "parsing", "xml parser", "doctype", "entity expansion",
                     "billion laughs", "xml input", "xml decoder"),
        "strong": ("xxe", "xml external entity", "external entity",
                   "billion laughs"),
        "cwes": ("CWE-611", "CWE-776", "CWE-827"),
        "code": _compile([
            ("sax_factories", r"\b(?:DocumentBuilderFactory|SAXParserFactory|"
                              r"TransformerFactory|XMLReader|XMLInputFactory|"
                              r"Unmarshaller|SAXBuilder|XMLStreamReader)\b"),
            ("dom_parse", r"\b(?:DocumentBuilder|SAXParser|XMLReader)\s*\.\s*"
                          r"parse\s*\("),
            ("etree_parse", r"\b(?:xml\.etree|ElementTree|lxml)(?:\.\w+)?\.(?:"
                            r"parse|fromstring|XML|iterparse)\s*\("),
            ("php_xxe", r"\b(?:simplexml_load_(?:string|file)|DOMDocument)"
                        r"[^;\n]{0,60}\bload\w*\s*\(|XMLReader\s*\([^)]{0,40}->open"),
            ("parse_str", r"\bparse_str\s*\(|XMLDecoder\s*\("),
        ]),
        "endpoints": [
            ("xml_routes", r"(?:xml|soap|wsdl|parse|import|upload|svc|service|"
                            r"feed|rss|metadata|config)(?:\b|/|-|_)"),
            ("xml_params", r"(?:\?|&)(?:xml|data|body|content|file|payload)="),
        ],
        "guards": _check_patterns([
            ("entity_disabled", r"setFeature|disallow[\- ]doctype|external[\- ]"
                                r"general[\- ]entities|external[\- ]parameter[\- ]"
                                r"entities|XMLConstants|FEATURE_SECURE_PROCESSING|"
                                r"defusedxml|resolveEntity|isSecureProcessing|"
                                r"expandEntityReferences|false"),
        ]),
        "taint": ("request input xml data body content file upload payload soap "
                  "wsdl config metadata raw").split(),
        "test_hint": ("POST a DOCTYPE payload with an external entity "
                      "(file:///etc/passwd or a DNS-able URL) to every XML "
                      "consuming endpoint and observe entity expansion or "
                      "out-of-band fetches."),
    },
    "ssrf": {
        "keywords": ("server-side request forgery", "ssrf", "url fetch",
                     "open proxy", "arbitrary url", "remote url", "url "
                     "parameter", "webhook fetch", "image url"),
        "strong": ("ssrf", "server-side request forgery", "open proxy",
                   "arbitrary url"),
        "cwes": ("CWE-918", "CWE-441"),
        "code": _compile([
            ("http_lib_url", r"\b(?:requests|httpx|urllib3)\.(?:get|post|put|"
                             r"delete|patch|request)\s*\(\s*[a-zA-Z_$]\w*"),
            ("urlopen", r"\b(?:urllib\.request\.)?urlopen\s*\("),
            ("fetch_var", r"\bfetch\s*\(\s*[a-zA-Z_$]\w*\s*[,)]|axios\.(?:get|"
                           r"post)\s*\(\s*[a-zA-Z_$]\w*"),
            ("php_curl", r"\bcurl_init\s*\([^)]{0,40}(?:\$|url|target)|"
                         r"file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)"),
            ("dotnet_http", r"\bHttpClient\b[^;\n]{0,80}\.Get(?:Async|StringAsync)"
                            r"\s*\(|new\s+WebClient\s*\([^)]*\)\.Download\w*\s*\("),
            ("java_net", r"\bnew\s+java\.net\.URL\s*\(|HttpURLConnection\b|"
                         r"ImageIO\.read\s*\([^)]*URL"),
            ("sock_connect", r"\b(?:socket|Socket)\s*\([^)]*\)\.connect\s*\([^)]"
                             r"{0,60}(?:host|addr|target)"),
        ]),
        "endpoints": [
            ("ssrf_routes", r"(?:proxy|fetch|callback|webhook|url|link|image|"
                             r"thumb|preview|screenshot|ssrf|curl|import|check|"
                             r"validate|ping|host|download|render|resize)(?:\b|/|-|_)"),
            ("ssrf_params", r"(?:\?|&)(?:url|uri|target|host|addr|endpoint|link|"
                             r"href|callback|webhook|src|image|path|domain)="),
        ],
        "guards": _check_patterns([
            ("url_validate", r"validate.*(?:url|host|target)|allowlist|whitelist|"
                             r"is_private|is_internal|is_ip|ipaddress|dns.*re|"
                             r"urlparse|urlsplit|urllib\.parse|resolve.*ip|"
                             r"169\.254|metadata|socks|no_proxy|disallow|"
                             r"block.*(?:localhost|private)"),
        ]),
        "taint": ("url uri target host addr endpoint link href callback webhook "
                  "src image path domain input request param q name").split(),
        "test_hint": ("Point the URL parameter at 127.0.0.1 / 169.254.169.254 / "
                      "a DNS-able collaborator and confirm the server performs "
                      "the request (response content or out-of-band hit)."),
    },
    "template_injection": {
        "keywords": ("template injection", "ssti", "server-side template",
                     "template engine", "freemarker", "twig", "jinja2",
                     "velocity", "mustache", "handlebars", "ejs", "smarty",
                     "template string"),
        "strong": ("ssti", "template injection", "server-side template"),
        "cwes": ("CWE-1336", "CWE-94", "CWE-917"),
        "code": _compile([
            ("render_template_string", r"\brender_template_string\s*\(|Template\s*"
                                        r"\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:\+|"
                                        r"%|\.format)|request|input|user|data)"),
            ("render_concat", r"\b(?:render|renderString|compile|fromString|"
                              r"parseTemplate)\s*\(\s*(?:f['\"]|['\"][^'\"]*['\"]"
                              r"\s*\+|\$\{|request|input|user|data|template)"),
            ("freemarker", r"\bnew\s+Template\s*\([^)]{0,60}(?:input|str|data|"
                           r"request|template)"),
            ("engine_user", r"\b(?:Twig_Environment|Smarty|Velocity|Mustache|"
                            r"Handlebars|nunjucks|ejs)\b[^;\n]{0,80}(?:template|"
                            r"source|render)"),
        ]),
        "endpoints": [
            ("tmpl_routes", r"(?:render|template|preview|mail|email|html|markdown|"
                             r"md|welcome|greet|invite|newsletter)(?:\b|/|-|_)"),
            ("tmpl_params", r"(?:\?|&)(?:template|body|content|html|markdown|"
                             r"message|name|title|text)="),
        ],
        "guards": _check_patterns([
            ("tmpl_safe", r"autoescape|sandbox|safe_render|environment\([^)]*"
                          r"autoescape|Trusted|no_template|allowlist|whitelist|"
                          r"escape"),
        ]),
        "taint": ("template request input user data name content body html "
                  "markdown mail message text value title param").split(),
        "test_hint": ("Inject template syntax ({{7*7}}, ${7*7}, {7*7}) into "
                      "template/render parameters and check whether it is "
                      "evaluated server-side."),
    },
    "xss": {
        "keywords": ("cross-site scripting", "xss", "stored xss", "reflected "
                     "xss", "script injection", "html injection", "sanitization",
                     "escaping"),
        "strong": ("cross-site scripting", "xss", "html injection"),
        "cwes": ("CWE-79", "CWE-80", "CWE-81", "CWE-83", "CWE-84", "CWE-85"),
        "code": _compile([
            ("inner_html", r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|"
                            r"document\.write|v-html|dangerouslySetInnerHTML)"
                            r"\s*[=:]"),
            ("jquery_html", r"\.html\s*\(\s*[a-zA-Z_$]\w*\s*\)|\.append\s*\(\s*"
                            r"[a-zA-Z_$]\w*|\.prepend\s*\(\s*[a-zA-Z_$]\w*"),
            ("echo_get", r"\becho\s*\$_(?:GET|POST|REQUEST|COOKIE)|print\s*"
                          r"\$_(?:GET|POST|REQUEST)"),
            ("resp_write", r"\b(?:response\.write|res\.(?:send|end)|printf|"
                            r"String\.format|fmt\.Sprintf)\s*\([^)]{0,80}(?:request"
                            r"|input|name|msg|search|query|user|param|comment)"),
            ("attr_taint", r"\b(?:setAttribute|attr|prop|value)\s*\(\s*['\"][^'\"]"
                           r"+['\"]\s*,\s*[^)]{0,40}(?:request|input|name|query|"
                           r"user|data|param)"),
        ]),
        "endpoints": [
            ("xss_routes", r"(?:search|comment|message|post|profile|name|echo|"
                            r"render|feedback|review|guestbook|chat)(?:\b|/|-|_)"),
            ("xss_params", r"(?:\?|&)(?:q|search|name|msg|message|comment|title|"
                            r"user|input|value|text|callback|redirect)="),
        ],
        "guards": _check_patterns([
            ("xss_escape", r"escape|htmlspecialchars|htmlentities|strip_tags|"
                           r"Content-Security|sanitize|encodeURIComponent|"
                           r"DOMPurify|textContent|markup|escaped|nl2br|"
                           r"csp|autoescape"),
        ]),
        "taint": ("request input name msg message search query user comment "
                  "content data param value title text body cookie referer "
                  "callback redirect").split(),
        "test_hint": ("Reflect <script>alert(1)</script> and <img src=x "
                      "onerror=...> through each parameter and verify "
                      "execution in a browser; check both stored and "
                      "reflected contexts."),
    },
    "auth_bypass": {
        "keywords": ("authentication bypass", "auth bypass", "authorization "
                     "bypass", "privilege escalation", "hardcoded credential",
                     "hardcoded password", "weak authentication", "jwt",
                     "forgot password", "password reset", "access control",
                     "insecure authentication", "default credential"),
        "strong": ("auth bypass", "authentication bypass", "authorization "
                   "bypass", "privilege escalation", "hardcoded"),
        "cwes": ("CWE-287", "CWE-306", "CWE-307", "CWE-522", "CWE-269",
                 "CWE-863", "CWE-798"),
        "code": _compile([
            ("weak_hash", r"\bmd5\s*\([^)]{0,40}(?:password|pass|pwd|secret)"
                          r"|sha1\s*\([^)]{0,40}(?:password|pass|pwd|secret)"),
            ("hardcoded_cred", r"\b(?:password|passwd|pwd|secret|apikey|api_key|"
                               r"token|access_key)\s*[=:]\s*['\"][^'\"]{4,}['\"]"),
            ("weak_admin", r"\b(?:role|is_admin|isAdmin|privilege|admin)\s*[=:]"
                           r"\s*['\"]?(?:true|1|admin|root)['\"]?\b"),
            ("jwt_noverify", r"\b(?:decode|jwt\.decode|verify)\s*\([^)]{0,80}"
                             r"verify\s*=\s*(?:False|0)|alg\s*:\s*['\"]none"),
            ("cookie_trust", r"\b(?:localStorage|sessionStorage)\.[\w.]*token|"
                             r"document\.cookie\s*=\s*[^;]{0,40}(?:user|admin|role|"
                             r"auth)"),
            ("backdoor", r"\b(?:backdoor|master_password|magic_password|"
                          r"universal_password)\b"),
        ]),
        "endpoints": [
            ("auth_routes", r"(?:login|admin|panel|auth|token|session|impersonate|"
                             r"sudo|privilege|reset|verify|account|user|signin|"
                             r"signup)(?:\b|/|-|_)"),
            ("auth_params", r"(?:\?|&)(?:role|admin|is_admin|user|uid|account|"
                             r"token|session|debug|test)="),
        ],
        "guards": _check_patterns([
            ("strong_auth", r"bcrypt|argon2|scrypt|compare_digest|pbkdf2|oauth|"
                            r"2fa|totp|mfa|verify_token|validate_token|"
                            r"random\.secret|secrets\.token|exp\s*=|expires|"
                            r"revoke|rate.?limit|lockout|realm"),
        ]),
        "taint": ("request cookie input token role user admin uid account "
                  "session header authorization jwt debug test password "
                  "param").split(),
        "test_hint": ("Attempt role/uid/flag tampering (role=admin, is_admin=1), "
                      "algorithm confusion on JWTs, and password-reset token "
                      "reuse against every auth endpoint."),
    },
    "open_redirect": {
        "keywords": ("open redirect", "redirect", "url redirect", "redirect "
                     "vulnerability", "unvalidated redirect"),
        "strong": ("open redirect", "unvalidated redirect"),
        "cwes": ("CWE-601", "CWE-698"),
        "code": _compile([
            ("redirect_next", r"\b(?:redirect|Redirect|redirect_to)\s*\(\s*[^)]"
                              r"{0,60}(?:next|url|return|redirect|target|dest|to|"
                              r"link|callback|goto|return_url|relay)"),
            ("header_location", r"\bheader\s*\(\s*['\"]Location['\"]\s*,\s*[^)]"
                                r"{0,60}(?:\+|\.|request|GET|POST|next|url|return)"),
            ("window_loc", r"\b(?:window\.location|location\.href|document\."
                           r"location)\s*=\s*[^;]{0,40}(?:param|query|url|next|"
                           r"return|redirect|GET|POST|request|href)"),
            ("http_redirect", r"\bHttpResponseRedirect\s*\([^)]{0,60}(?:request|"
                              r"next|url|return|redirect|GET|POST)"),
        ]),
        "endpoints": [
            ("redir_routes", r"(?:redirect|goto|out|link|url|return|next|"
                             r"callback|login|logout|oauth|signin|signup|"
                             r"leave|exit)(?:\b|/|-|_)"),
            ("redir_params", r"(?:\?|&)(?:next|url|return|return_url|redirect|"
                              r"target|dest|to|link|callback|goto|relay|out)="),
        ],
        "guards": _check_patterns([
            ("safe_redirect", r"urlparse|urljoin|startswith\s*\(['\"](?:https?://)?"
                              r"(?:[^/]+\.)?(?:trusted|example|internal)|allowlist|"
                              r"whitelist|validate.*url|safe.*url|is_safe|"
                              r"host.*==|netloc"),
        ]),
        "taint": ("next url return return_url redirect target dest to link "
                  "callback goto relay out path uri q request param").split(),
        "test_hint": ("Pass //evil.com, /\\evil.com, https://evil.com and "
                      "javascript: URLs via each redirect parameter and follow "
                      "the Location header."),
    },
    "race_condition": {
        "keywords": ("race condition", "time-of-check", "toctou", "double "
                     "spend", "double redemption", "concurrency", "atomicity",
                     "check-then-act", "parallel requests"),
        "strong": ("race condition", "toctou", "double spend", "double "
                   "redemption"),
        "cwes": ("CWE-362", "CWE-367", "CWE-366"),
        "code": _compile([
            ("check_then_act", r"\b(?:os\.path\.exists|Path\.exists|file_exists|"
                               r"isfile|isdir|is_file|stat)\s*\("),
            ("file_lock_absent", r"\b(?:open|write|remove|unlink|rename|save|"
                                 r"upload|mkdir)\s*\("),
        ]),
        "endpoints": [
            ("race_routes", r"(?:redeem|coupon|transfer|withdraw|claim|vote|like|"
                             r"bonus|reward|refund|purchase|order|booking|reserve|"
                             r"invite|signup)(?:\b|/|-|_)"),
            ("race_params", r"(?:\?|&)(?:amount|count|qty|quantity|limit|points|"
                             r"id|coupon|code|balance)="),
        ],
        "guards": _check_patterns([
            ("locking", r"threading\.Lock|multiprocessing\.Lock|fcntl|flock|"
                        r"with\s+.*lock|transaction|atomic|BEGIN|locked|"
                        r"SELECT\s+.*FOR\s+UPDATE|unique|optimistic|version|"
                        r"etag|cas\b"),
        ]),
        "taint": ("request input user amount count qty id param coupon code "
                  "balance points token vote like").split(),
        "test_hint": ("Fire N concurrent copies of one valid request (redeem/"
                      "transfer/claim) and count how many succeed - a "
                      "count > 1 proves a non-atomic check-then-act."),
    },
}

# Pair of (check_pattern, act_pattern) used to build the check-then-act
# detection window for race_condition.
_RACE_CHECK = re.compile(r"\b(?:os\.path\.exists|Path\.exists|file_exists|"
                         r"isfile|isdir|is_file|stat)\s*\(", re.IGNORECASE)
_RACE_ACT = re.compile(r"\b(?:open|write|remove|unlink|rename|save|upload|"
                       r"mkdir)\s*\(", re.IGNORECASE)

_CVE_ID_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_COMMENT_STRIP = re.compile(r"(?:^\s*[#//*;]|//|/\*|\*/|<!--|-->)")
_STRONG_SUB = re.compile(r"[^a-z0-9 ]", re.IGNORECASE)

ENDPOINT_PATTERNS = {
    fam: _compile(fam_data["endpoints"]) for fam, fam_data in _FAMILIES.items()
}


# ---------------------------------------------------------------------------
# CVE input handling
# ---------------------------------------------------------------------------

def _fetch_cve(cve_id):
    """Fetch (description, cwe_list) for a CVE id. NVD 2.0 with CIRCL fallback."""
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id}, headers={"User-Agent": UA}, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities") or []
            if vulns:
                cve = vulns[0].get("cve") or {}
                desc = ""
                for d in cve.get("descriptions") or []:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                cwes = [w.get("value") for w in (cve.get("weaknesses") or [])
                        for d in (w.get("description") or []) if d.get("value")]
                if desc:
                    return desc, cwes
    except requests.exceptions.RequestException:
        pass
    except ValueError:
        pass
    try:  # CIRCL fallback
        resp = requests.get("https://cve.circl.lu/api/cve/%s" % cve_id,
                            headers={"User-Agent": UA}, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            desc = data.get("summary") or ""
            cwes = data.get("cwe") or []
            if desc:
                return desc, cwes
    except requests.exceptions.RequestException:
        pass
    except ValueError:
        pass
    return None


def _extract_root_cause(known_cve_details):
    """Return {cve_id, description, cwes, families:[...]} from any input form."""
    cve_id, description, cwes = "", "", []
    raw = known_cve_details
    if isinstance(raw, dict):
        raw = json.dumps(raw, ensure_ascii=False, default=str)
    text = str(raw).strip()
    if not text:
        return None

    m = _CVE_ID_RX.search(text)
    if m:
        cve_id = m.group(0).upper()
        # try to pull structured info out of the JSON blob first
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                description = obj.get("description") or ""
                cwes = [str(c) for c in (obj.get("cwes") or [])]
                if not description and isinstance(obj.get("cve"), dict):
                    cve = obj["cve"]
                    for d in cve.get("descriptions") or []:
                        if d.get("lang") == "en":
                            description = d.get("value", "")
                            break
                    cwes = [w.get("value") for w in (cve.get("weaknesses") or [])
                            for d in (w.get("description") or []) if d.get("value")]
        except (json.JSONDecodeError, ValueError):
            pass
        if not description:
            fetched = _fetch_cve(cve_id)
            if fetched:
                description, cwes = fetched
    else:
        # free-text description, possibly JSON without a CVE id
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                description = obj.get("description") or obj.get("summary") or ""
                cwes = [str(c) for c in (obj.get("cwes") or [])]
                if obj.get("id"):
                    cve_id = str(obj["id"]).upper()
        except (json.JSONDecodeError, ValueError):
            description = text

    if not description and cve_id:
        return {"cve_id": cve_id, "description": "",
                "cwes": cwes, "families": [],
                "offline": True}

    desc_lower = description.lower()
    scored = []
    for fam_name, fam in _FAMILIES.items():
        score = 0.0
        for kw in fam["keywords"]:
            if kw in desc_lower:
                score += 1.0
        for strong in fam["strong"]:
            if strong in desc_lower:
                score += 2.0
        for cwe in cwes:
            if str(cwe).strip().upper() in fam["cwes"]:
                score += 3.0
        if score > 0:
            scored.append((score, fam_name))

    scored.sort(key=lambda x: x[0], reverse=True)
    best = scored[0][0] if scored else 0.0
    families = []
    for score, fam_name in scored[:3]:
        conf = _clamp(0.45 + 0.22 * (score / max(best, 1.0)), 0.45, 0.95)
        families.append({
            "family": fam_name,
            "confidence": round(conf, 2),
            "cwes": [c for c in _FAMILIES[fam_name]["cwes"] if c in
                     [str(w).strip().upper() for w in cwes]],
        })

    return {"cve_id": cve_id, "description": description[:400],
            "cwes": cwes, "families": families, "offline": False}


# ---------------------------------------------------------------------------
# Codebase scanning
# ---------------------------------------------------------------------------

def _iter_source_files(root):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in _IGNORE_DIRS and not d.startswith(".")]
        dirnames.sort()
        for fn in sorted(filenames):
            ext = os.path.splitext(fn)[1].lower()
            if ext not in _SOURCE_EXTS:
                continue
            if fn.startswith(".") or fn.endswith((".min.js", ".min.css")):
                continue
            yield os.path.join(dirpath, fn)
            count += 1
            if count >= _MAX_FILES:
                return


def _read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    except (OSError, UnicodeError):
        return []


def _score_code_match(line_text, ctx_lines, family):
    """Confidence for a code sink: taint proximity up, guards down."""
    ctx = " ".join(ctx_lines)
    score = 0.55
    tainted = any(tok in ctx for tok in family["taint"])
    guarded = any(guard.search(ctx) for guard in family["guards"])
    commented = bool(_COMMENT_STRIP.search(line_text))
    if tainted:
        score += 0.22
    if not guarded:
        score += 0.12
    else:
        score -= 0.30
    if commented:
        score -= 0.15
    return _clamp(score)


def _scan_codebase(root, families, max_results):
    candidates = []
    seen = set()
    for path in _iter_source_files(root):
        lines = _read_lines(path)
        if not lines:
            continue
        rel = os.path.relpath(path, root)
        for i, line in enumerate(lines):
            if i >= _MAX_LINES_PER_FILE:
                break
            for fam_name in families:
                fam = _FAMILIES[fam_name]
                for pat_name, pat in fam["code"]:
                    if pat.search(line):
                        key = (rel, i, fam_name, pat_name)
                        if key in seen:
                            continue
                        seen.add(key)
                        lo = max(0, i - _CTX_RADIUS)
                        hi = min(len(lines), i + _CTX_RADIUS + 1)
                        ctx = [l.strip() for l in lines[lo:hi]]
                        score = _score_code_match(line, ctx, fam)
                        candidates.append({
                            "score": round(score, 2),
                            "family": fam_name,
                            "target": rel,
                            "line": i + 1,
                            "pattern": pat_name,
                            "sink": line.strip()[:200],
                            "context": ctx,
                            "verification": fam["test_hint"],
                        })
        if len(candidates) > max_results * 4:  # bound memory during walk
            candidates.sort(key=lambda c: c["score"], reverse=True)
            candidates = candidates[:max_results * 2]
            seen = {(c["target"], c["line"] - 1, c["family"], c["pattern"])
                    for c in candidates}
    candidates.sort(key=lambda c: c["score"], reverse=True)
    return candidates[:max_results]


def _scan_race_window(lines, rel, max_results):
    """check-then-act: an existence/stat check followed by a file mutation."""
    out = []
    for i, line in enumerate(lines):
        if i >= _MAX_LINES_PER_FILE:
            break
        if not _RACE_CHECK.search(line):
            continue
        window = lines[i:i + 5]
        for j, wline in enumerate(window[1:], start=1):
            if _RACE_ACT.search(wline):
                lo = max(0, i - 1)
                hi = min(len(lines), i + 6)
                ctx = [l.strip() for l in lines[lo:hi]]
                out.append({
                    "score": 0.62,
                    "family": "race_condition",
                    "target": rel,
                    "line": i + 1,
                    "pattern": "check_then_act_window",
                    "sink": " -> ".join(l.strip()[:120] for l in window[:3]),
                    "context": ctx,
                    "verification": _FAMILIES["race_condition"]["test_hint"],
                })
                break
        if len(out) >= max_results:
            break
    return out


# ---------------------------------------------------------------------------
# Endpoint scanning
# ---------------------------------------------------------------------------

def _parse_endpoints(text):
    """Endpoint list from JSON (list/dict), JSON string, or plain text."""
    if isinstance(text, (list, dict)):
        return text
    t = (text or "").strip()
    if not t:
        return []
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    items = [ln.strip() for ln in t.replace(",", "\n").splitlines() if ln.strip()]
    return items


def _endpoint_blob(item):
    """Normalise an endpoint item into (label, blob, snippet)."""
    if isinstance(item, str):
        return item, item, ""
    if not isinstance(item, dict):
        return str(item), str(item), ""
    route = (item.get("route") or item.get("path") or item.get("url")
             or item.get("endpoint") or "")
    method = str(item.get("method") or "")
    params = item.get("params") or item.get("parameters") or []
    if isinstance(params, str):
        params = [p.strip() for p in params.replace(",", " ").split()]
    snippet = str(item.get("code") or item.get("snippet") or "")
    blob = " ".join(str(x) for x in [route, method] + list(params))
    label = str(route or item.get("name") or item.get("id") or blob[:80])
    return label, blob, snippet


def _scan_endpoints(data, families, max_results):
    candidates = []
    seen = set()
    for item in data:
        label, blob, snippet = _endpoint_blob(item)
        if not blob and not snippet:
            continue
        for fam_name in families:
            fam = _FAMILIES[fam_name]
            for pat_name, pat in ENDPOINT_PATTERNS[fam_name]:
                if not pat.search(blob):
                    continue
                key = (label, fam_name, pat_name)
                if key in seen:
                    continue
                seen.add(key)
                score = 0.48
                tainted = any(tok in blob for tok in fam["taint"])
                guarded = any(g.search(blob) for g in fam["guards"])
                if tainted:
                    score += 0.18
                if not guarded:
                    score += 0.10
                else:
                    score -= 0.25
                candidates.append({
                    "score": round(_clamp(score), 2),
                    "family": fam_name,
                    "target": label,
                    "line": None,
                    "pattern": pat_name,
                    "sink": blob[:200],
                    "context": [],
                    "verification": fam["test_hint"],
                })
            if snippet:  # embedded code snippet: run code patterns too
                for pat_name, pat in fam["code"]:
                    if pat.search(snippet):
                        key = (label, fam_name, pat_name, "snippet")
                        if key in seen:
                            continue
                        seen.add(key)
                        score = _score_code_match(snippet, [snippet], fam)
                        candidates.append({
                            "score": round(score, 2),
                            "family": fam_name,
                            "target": label,
                            "line": None,
                            "pattern": pat_name,
                            "sink": snippet.strip()[:200],
                            "context": [snippet.strip()[:300]],
                            "verification": fam["test_hint"],
                        })
    candidates.sort(key=lambda c: c["score"], reverse=True)
    return candidates[:max_results]


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------

def hunt_cve_variants(known_cve_details, codebase_path_or_endpoint_list,
                      max_results=25):
    """Hunt structural siblings of a known CVE across a codebase or endpoints.

    known_cve_details: CVE id ('CVE-2021-44228'), free-text vulnerability
        description, or JSON {"id", "description", "cwes"} / NVD payload.
    codebase_path_or_endpoint_list: directory path to scan for code, or a
        JSON list of endpoints (each may carry params and code snippets),
        or a plain-text list of URLs/routes.
    Returns a JSON document with the extracted root-cause family(s) and
    ranked sibling candidates (evidence snippet + verification hint each).
    """
    if not known_cve_details or not str(known_cve_details).strip():
        return json.dumps({"error": "hunt_cve_variants: known_cve_details "
                                    "is required (CVE id, description or JSON)"})
    surface = codebase_path_or_endpoint_list
    if surface is None or (isinstance(surface, str) and not surface.strip()):
        return json.dumps({"error": "hunt_cve_variants: "
                                    "codebase_path_or_endpoint_list is required"})
    try:
        max_results = int(max_results or 25)
    except (TypeError, ValueError):
        max_results = 25
    max_results = max(1, min(max_results, 200))

    root = _extract_root_cause(known_cve_details)
    if root is None:
        return json.dumps({"error": "hunt_cve_variants: could not parse "
                                    "known_cve_details"})
    if root.get("offline"):
        return json.dumps({
            "error": ("hunt_cve_variants: could not fetch %s from NVD/CIRCL "
                      "(offline or rate-limited) and no description was "
                      "provided. Pass the CVE description or {id, "
                      "description, cwes} JSON instead." % root["cve_id"])})

    families = [f["family"] for f in root["families"]]
    if not families:
        # nothing matched: fall back to a wide scan across all families
        families = list(_FAMILIES.keys())
        root["families"] = [{"family": f, "confidence": 0.4,
                             "cwes": []} for f in families]

    target_type = "unknown"
    candidates = []
    if isinstance(surface, str) and os.path.isdir(surface):
        target_type = "codebase"
        candidates = _scan_codebase(surface, families, max_results)
        if "race_condition" in families:
            candidates += _scan_race_window(
                "\n".join(
                    line for path in _iter_source_files(surface)
                    for line in _read_lines(path)).splitlines(),
                surface, max_results)
        candidates.sort(key=lambda c: c["score"], reverse=True)
        candidates = candidates[:max_results]
    else:
        endpoints = _parse_endpoints(surface)
        if isinstance(endpoints, list) and endpoints:
            target_type = "endpoints"
            candidates = _scan_endpoints(endpoints, families, max_results)
        else:
            return json.dumps({
                "error": "hunt_cve_variants: '%s' is neither an existing "
                         "directory nor a parseable endpoint list"
                         % str(surface)[:120]})

    by_family = {}
    for c in candidates:
        by_family.setdefault(c["family"], []).append(c["target"])

    result = {
        "tool": "hunt_cve_variants",
        "cve": root["cve_id"] or "manual-description",
        "root_cause": {
            "summary": root["description"][:300] or "no description provided",
            "cwes": root["cwes"],
            "families": root["families"],
        },
        "scan_target": surface if target_type == "codebase" else {
            "type": "endpoints",
            "count": len(endpoints) if isinstance(endpoints, list) else 0,
        },
        "target_type": target_type,
        "candidate_count": len(candidates),
        "candidates_by_family": by_family,
        "candidates": candidates,
        "note": ("Candidates are STRUCTURAL SIBLINGS of the known CVE's root "
                 "cause - same dangerous sink pattern, possibly a different "
                 "code path. Validate each with its verification hint before "
                 "reporting."),
    }
    return json.dumps(result, indent=2, ensure_ascii=False)
