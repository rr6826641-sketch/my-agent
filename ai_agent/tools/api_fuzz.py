"""ai_agent/tools/api_fuzz.py -- OpenAPI/Swagger API Fuzz Engine (bundle #4).

Auto-discovers OpenAPI/Swagger specs (swagger.json / openapi.json / api-docs)
and drives a bounded set of API security tests:
  * auth-bypass   - no-token / wrong-token requests against every endpoint
  * IDOR          - object-id tampering in URL path segments
  * mass-assignment - extra privileged fields in POST/PUT/PATCH JSON bodies

Everything is heuristic: results marked 'interesting' MUST be validated
manually before any action is taken against a target.
"""
import json
import re
import urllib.error
import urllib.request

# Common OpenAPI / Swagger spec locations
SWAGGER_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/api/swagger.json", "/api/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/v2/swagger.json", "/v3/api-docs", "/v2/api-docs",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api-docs", "/api/docs", "/api/openapi.json",
    "/api/v1/swagger.json", "/docs/swagger.json",
]

# Auth variants used for the auth-bypass probe
AUTH_HEADERS_BYPASS = [
    ("none", {}),
    ("wrong-bearer", {"Authorization": "Bearer invalid-token-0000"}),
    ("wrong-basic", {"Authorization": "Basic aW52hijoycRkZ2hTb2Q="}),
]

# Extra fields appended for the mass-assignment probe
MASS_ASSIGN_FIELDS = [
    {"isAdmin": True}, {"admin": True}, {"role": "admin"},
    {"is_active": True}, {"isActive": True}, {"permissions": ["*"]},
    {"verified": True}, {"status": "active"}, {"isSuperuser": True},
]

HTTP_METHODS_JSON = ("POST", "PUT", "PATCH")


def _http_req(url, method="GET", headers=None, data=None, timeout=12):
    """One HTTP request. Returns (status, headers, body, error)."""
    req = urllib.request.Request(url, method=method.upper())
    hdrs = {"User-Agent": "Mozilla/5.0 (HackerAI api-fuzz v14)",
            "Accept": "application/json, */*"}
    if headers:
        hdrs.update(headers)
    if data is not None:
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        elif isinstance(data, str):
            body = data.encode("utf-8")
        else:
            body = data
        req.data = body
    for k, v in hdrs.items():
        req.add_header(k, v)
    # bypass system/env proxies: direct connection always (surprise corporate
    # proxies break localhost tests and leak target requests)
    _opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with _opener.open(req, timeout=timeout) as r:
            raw = r.read(200000)
            try:
                body = raw.decode("utf-8", "replace")
            except Exception:
                body = raw.decode("latin-1", "replace")
            return r.status, dict(r.headers), body, None
    except urllib.error.HTTPError as e:
        raw = e.read(50000)
        try:
            body = raw.decode("utf-8", "replace")
        except Exception:
            body = raw.decode("latin-1", "replace")
        return e.code, dict(e.headers), body, None
    except Exception as e:
        return None, {}, "", str(e)


def _guess_scheme(hostport):
    """Turn a bare host/host:port into an http(s) URL."""
    hp = hostport.strip()
    if hp.startswith("http://") or hp.startswith("https://"):
        return hp
    port = ""
    if ":" in hp and not hp.endswith("]"):
        port = hp.rsplit(":", 1)[1]
    if port == "443":
        return "https://" + hp
    return "http://" + hp


def _normalize_target(target):
    """Return base URL (no trailing slash) or '' when unusable."""
    t = (target or "").strip()
    if not t or " " in t:
        return ""
    if not (t.startswith("http://") or t.startswith("https://")):
        t = _guess_scheme(t)
    return t.rstrip("/")


def _looks_like_spec(data):
    if not isinstance(data, dict):
        return False
    return ("swagger" in data) or ("openapi" in data) or ("paths" in data)


def _status2xx(status):
    return status in (200, 201, 202, 204)


def _extract_endpoints(spec):
    """Pull {path: [METHODS]} from a parsed OpenAPI/Swagger dict."""
    paths = {}
    raw = spec.get("paths") if isinstance(spec, dict) else None
    if not isinstance(raw, dict):
        return paths
    for p, methods in raw.items():
        if not isinstance(methods, dict):
            continue
        ops = []
        for m in methods:
            if m.lower() in ("get", "post", "put", "patch", "delete",
                             "options", "head"):
                ops.append(m.upper())
        if ops:
            paths[p] = sorted(set(ops))
    return paths


def _extract_paths_from_text(text):
    """Fallback for YAML specs: regex scan for endpoint blocks.

    Finds lines like '  /users/{id}:' followed by '    get:' / '    post:'
    without requiring a full YAML parser.
    """
    paths = {}
    cur = None
    for ln in (text or "").splitlines():
        m = re.match(r"^(\s*)(/\S+):\s*$", ln)
        if m and not ln.lstrip().startswith("-"):
            cur = m.group(2)
            paths.setdefault(cur, [])
            continue
        if not cur:
            continue
        m2 = re.match(r"^\s{2,}(get|post|put|patch|delete|options|head):\s*$",
                      ln, re.I)
        if m2 and m2.group(1).upper() not in paths[cur]:
            paths[cur].append(m2.group(1).upper())
    # sort methods for determinism
    for k in paths:
        paths[k] = sorted(set(paths[k]))
    return {k: v for k, v in paths.items() if v}


def _discover_spec(base, custom_paths="", timeout=12, max_paths=15):
    """Probe common spec locations; return first that parses.

    Returns {"spec_url", "format", "candidates_tried", "spec"}.
    """
    candidates = []
    for p in str(custom_paths).split(","):
        p = p.strip()
        if p:
            candidates.append(p if p.startswith("/") else "/" + p)
    candidates += SWAGGER_PATHS
    seen, cands = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            cands.append(c)
    cands = cands[:max_paths]

    for c in cands:
        url = base + c
        status, hdrs, body, err = _http_req(url, timeout=timeout)
        if err is not None or status is None or status != 200 or not body:
            continue
        s = body.lstrip()
        if s.startswith(("{", "[")):
            try:
                spec = json.loads(body)
                if _looks_like_spec(spec):
                    return {"spec_url": url, "format": "json",
                            "candidates_tried": len(cands), "spec": spec}
            except Exception:
                pass
        head = body[:4000]
        if "paths" in head or re.search(r"^\s{2,}/\S+:", head, re.M):
            p = _extract_paths_from_text(body)
            if p:
                return {"spec_url": url, "format": "yaml",
                        "candidates_tried": len(cands),
                        "spec": {"paths": p}}
    return {"spec_url": None, "format": None,
            "candidates_tried": len(cands), "spec": None}


def tool_swagger_fetch(target="", paths="", timeout=12, max_paths=15):
    """Discover and parse an OpenAPI/Swagger spec from a target.

    target      - http(s)://host[:port] or bare host[:port]
    paths       - optional comma-separated custom spec locations
    timeout     - per-request timeout (s)
    max_paths   - how many candidate paths to try (default 15)

    Returns the spec summary: format, version, title and every callable
    endpoint (path + methods).
    """
    base = _normalize_target(target)
    if not base:
        return json.dumps({"error": "swagger_fetch: target is required "
                                    "(e.g. https://host[:port])"})
    disc = _discover_spec(base, custom_paths=paths, timeout=timeout,
                          max_paths=max_paths)
    if not disc["spec"]:
        return json.dumps({
            "url": base, "found": False,
            "candidates_tried": disc["candidates_tried"],
            "message": "no swagger/openapi spec found at common paths"},
            indent=1)

    spec = disc["spec"]
    paths_map = _extract_endpoints(spec)
    version = spec.get("swagger") or spec.get("openapi") or "unknown"
    title = "unknown"
    info = spec.get("info") if isinstance(spec, dict) else None
    if isinstance(info, dict):
        title = info.get("title") or title

    if not paths_map:
        return json.dumps({
            "url": base, "found": True, "spec_url": disc["spec_url"],
            "format": disc["format"], "version": version, "title": title,
            "endpoint_count": 0, "endpoints": [],
            "message": "spec parsed but no callable endpoints found"},
            indent=1)

    eps = [{"path": p, "methods": [m.lower() for m in ops]}
           for p, ops in sorted(paths_map.items())]
    return json.dumps({
        "url": base, "found": True, "spec_url": disc["spec_url"],
        "format": disc["format"], "version": version, "title": title,
        "endpoint_count": len(eps), "endpoints": eps,
        "hint": "feed this endpoints JSON to api_fuzz for auth/IDOR/"
                "mass-assignment tests"}, indent=1)


def _flatten_endpoints(paths_map, base_path=""):
    """Resolve {param} placeholders into concrete URLs.

    Numeric-style params become id=1 (IDOR probe uses id=2);
    uuid/guid-style params become uuid-0001 (probe uses uuid-0002).
    """
    out = []
    for p, ops in sorted(paths_map.items()):
        full = p
        if base_path:
            full = base_path.rstrip("/") + "/" + full.lstrip("/")
        placeholders = re.findall(r"\{([^}]+)\}", full)
        id_param = placeholders[0] if placeholders else None
        if id_param:
            if re.search(r"uuid|guid|token|session|ref", id_param, re.I):
                full = full.replace("{%s}" % id_param,
                                    "00000000-0000-0000-0000-000000000001")
            else:
                full = full.replace("{%s}" % id_param, "1")
        for m in ops:
            out.append({"path": full, "method": m, "id_param": id_param})
    return out


def _run_auth_bypass(base, endpoints, token, timeout):
    """No-token / wrong-token probes against every endpoint."""
    results = []
    auth_hdr = {}
    if token:
        auth_hdr["Authorization"] = "Bearer " + token
    for ep in endpoints:
        url = base + ep["path"]
        method = ep["method"]
        # baseline using the operator-provided token (when given)
        sb, _, _, eb = _http_req(url, method=method, headers=auth_hdr,
                                 timeout=timeout)
        for label, hdrs in AUTH_HEADERS_BYPASS:
            s, _, body, err = _http_req(url, method=method, headers=hdrs,
                                        timeout=timeout)
            if err is not None:
                continue
            priv = bool(re.search(
                r"(admin|manage|config|internal|debug|billing|account|"
                r"user|role|scope|secret|token)", ep["path"], re.I))
            interesting = False
            note = ""
            if _status2xx(s):
                if label == "none":
                    if priv:
                        interesting = True
                        note = ("2xx with NO auth on protected-looking path "
                                "-> possible auth bypass")
                else:
                    if s == sb:
                        interesting = True
                        note = ("2xx with invalid credentials, same as "
                                "baseline -> weak/absent auth")
                    elif priv:
                        interesting = True
                        note = ("2xx with invalid credentials on protected "
                                "path -> possible auth bypass")
            results.append({"endpoint": ep["path"], "method": method,
                            "auth_variant": label, "status": s,
                            "interesting": interesting, "note": note})
    return results


def _tampered_path(path, id_param):
    """Return (tampered_url_path, id_type) or None when not tamperable."""
    if id_param:
        if "00000000-0000" in path:
            return (path.replace("00000000-0000-0000-0000-000000000001",
                                 "00000000-0000-0000-0000-000000000002"),
                    "uuid")
        if re.search(r"/1(?=/|$)", path):
            return re.sub(r"/1(?=/|$)", "/2", path), "numeric"
    return None, None


def _run_idor(base, endpoints, token, timeout):
    """Object-id tampering test on endpoints with {id}-style params."""
    results = []
    auth_hdr = {}
    if token:
        auth_hdr["Authorization"] = "Bearer " + token
    for ep in endpoints:
        if not ep.get("id_param"):
            continue
        tampered, id_type = _tampered_path(ep["path"], ep["id_param"])
        if not tampered:
            continue
        s1, _, b1, e1 = _http_req(base + ep["path"], method=ep["method"],
                                  headers=auth_hdr, timeout=timeout)
        s2, _, b2, e2 = _http_req(base + tampered, method=ep["method"],
                                  headers=auth_hdr, timeout=timeout)
        if e1 is not None or e2 is not None:
            continue
        interesting = False
        note = ""
        if s1 == s2 and _status2xx(s1):
            if b1 != b2:
                interesting = True
                note = ("same 2xx for original and tampered id with different "
                        "body -> object enumeration / possible IDOR")
            else:
                note = ("same 2xx but identical body (likely generic "
                        "response, verify manually)")
        elif s1 in (401, 403) and s2 in (200, 204):
            interesting = True
            note = "tampered id bypasses auth (401/403 -> 2xx) -> IDOR"
        results.append({"endpoint": ep["path"], "method": ep["method"],
                        "id_param": ep["id_param"], "id_type": id_type,
                        "original_status": s1, "tampered_status": s2,
                        "interesting": interesting, "note": note})
    return results


def _run_mass_assignment(base, endpoints, token, timeout, cap_per_ep=3):
    """POST/PUT/PATCH with extra privileged fields in the JSON body."""
    results = []
    hdrs = {"Content-Type": "application/json"}
    if token:
        hdrs["Authorization"] = "Bearer " + token
    for ep in endpoints:
        if ep["method"] not in HTTP_METHODS_JSON:
            continue
        for extra in MASS_ASSIGN_FIELDS[:cap_per_ep]:
            body = {"name": "fuzz-probe",
                    "description": "mass-assignment probe from api_fuzz"}
            body.update(extra)
            s, _, _, err = _http_req(base + ep["path"], method=ep["method"],
                                     headers=hdrs, data=body, timeout=timeout)
            if err is not None:
                continue
            interesting = _status2xx(s)
            results.append({
                "endpoint": ep["path"], "method": ep["method"],
                "extra_field": list(extra)[0], "status": s,
                "interesting": interesting,
                "note": ("2xx with extra field %s accepted -> possible "
                         "mass-assignment" % list(extra)[0]
                         if interesting else "")})
    return results


def tool_api_fuzz(target="", endpoints="", base_path="", token="",
                  timeout=10, max_tests=80):
    """Fuzz OpenAPI endpoints: auth-bypass, IDOR and mass-assignment.

    target    - http(s)://host[:port] or bare host[:port] (required)
    endpoints - OPTIONAL. JSON from swagger_fetch ("endpoints" field):
                [{"path": "/users/1", "methods": ["GET"]}, ...] or
                {"/users": ["GET", "POST"], ...}. When omitted the tool
                auto-discovers the spec first.
    base_path - OPTIONAL prefix when the spec lives under /api/v1 etc.
    token     - OPTIONAL bearer token (used as baseline for comparisons)
    timeout   - per-request timeout (s)
    max_tests - approximate overall bound on requests

    Results are heuristics; entries with "interesting": true need manual
    validation before being treated as findings.
    """
    base = _normalize_target(target)
    if not base:
        return json.dumps({"error": "api_fuzz: target is required "
                                    "(e.g. https://host[:port])"})

    paths_map = {}
    source = "provided"
    if endpoints and endpoints.strip().startswith(("{", "[")):
        try:
            data = json.loads(endpoints)
            if isinstance(data, dict):
                paths_map = {k: [m.upper() for m in v]
                             for k, v in data.items()
                             if isinstance(v, list)}
            elif isinstance(data, list):
                for it in data:
                    if isinstance(it, dict) and "path" in it:
                        paths_map[it["path"]] = [
                            m.upper() for m in it.get("methods", ["GET"])]
        except Exception as e:
            return json.dumps({"error": "api_fuzz: could not parse endpoints "
                                        "JSON: %s" % e})
    if not paths_map:
        disc = _discover_spec(base, timeout=timeout)
        if not disc["spec"]:
            return json.dumps({"error": "api_fuzz: no swagger/openapi spec "
                                        "discovered on target",
                               "candidates_tried": disc["candidates_tried"]},
                              indent=1)
        paths_map = _extract_endpoints(disc["spec"])
        source = "discovered (%s)" % disc["spec_url"]

    ep_list = _flatten_endpoints(paths_map, base_path=base_path)
    cap = max(1, min(len(ep_list), max_tests // 10 + 1))
    ep_list = ep_list[:cap]

    auth_res = _run_auth_bypass(base, ep_list, token, timeout)
    idor_res = _run_idor(base, ep_list, token, timeout)
    mass_res = _run_mass_assignment(base, ep_list, token, timeout)

    interesting = [r for r in auth_res + idor_res + mass_res
                   if r.get("interesting")]
    return json.dumps({
        "base_url": base, "endpoint_source": source,
        "endpoints_tested": len(ep_list),
        "auth_bypass_tests": auth_res,
        "idor_tests": idor_res,
        "mass_assignment_tests": mass_res,
        "interesting_total": len(interesting),
        "interesting": interesting[:30],
        "notes": ("heuristic checks - validate 'interesting' entries "
                  "manually before actioning")}, indent=1)
