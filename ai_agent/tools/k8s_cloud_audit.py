"""Cloud & Kubernetes Security Posture Audit Engine.

Three offline-first posture tools for container/orchestration estates:

* k8s_cluster_audit  - audits an active Kubernetes cluster (kubeconfig) for
  privileged pods, root containers, missing NetworkPolicies, cleartext
  secrets and openly exposed API servers. Talks to the API via the
  `kubectl` CLI or the official `kubernetes` client when one exists and
  degrades to a config-level posture read (with a clear "live: false"
  marker) when no backend is available - never hangs, never raises.
* helm_security_scan - inspects a Helm chart (directory or .tgz) for
  insecure default values, literal/hardcoded secrets and over-permissive
  RBAC role/binding definitions.
* iam_policy_analyzer- parses AWS / GCP / Azure IAM policy JSON and flags
  dangerous "*" wildcards, known privilege-escalation action paths and
  roles that are public / unauthenticated.

Every public function returns structured JSON-ready dicts (never raises),
every outbound call has a bounded timeout, and every tool wrapper
serializes to a JSON string for the agent registry.
"""

import base64
import datetime
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
import urllib.parse

try:                                   # PyYAML is optional at import time
    import yaml
except Exception:                       # pragma: no cover - import guard
    yaml = None

DEFAULT_K8S_TIMEOUT = 10.0              # seconds, applied to every API call
_HELM_READ_TIMEOUT = 10.0               # bound on chart reads (file/tgz)
KUBECTL_CMD = "kubectl"

_SECRET_KEY_RE = re.compile(
    r"(?i)(passwd|password|pass|pwd|token|api[_-]?key|secret|credential|"
    r"private[_-]?key|access[_-]?key|auth)")
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(changeme|change[-_]?me|your[-_ ]?[a-z]+|xxx+|xxxx+|todo+|"
    r"example|sample|dummy|<[^>]+>|\{\{.*\}\}|none|null|true|false)$")

_ESCALATION_ACTION_RE = [
    re.compile(r"(?i)^iam:passrole$"),
    re.compile(r"(?i)^iam:create(accesskey|loginprofile|policyversion|"
               r"userpolicy|group|role|user)$"),
    re.compile(r"(?i)^iam:setdefaultpolicyversion$"),
    re.compile(r"(?i)^iam:attach(userpolicy|grouppolicy|rolepolicy)$"),
    re.compile(r"(?i)^iam:put(userpolicy|grouppolicy|rolepolicy)$"),
    re.compile(r"(?i)^iam:addusertogroup$"),
    re.compile(r"(?i)^sts:assumerole$"),
    re.compile(r"(?i)^lambda:(createfunction|updatefunctioncode)$"),
    re.compile(r"(?i)^ec2:runinstances$"),
    re.compile(r"(?i)^s3:putbucketpolicy$"),
    re.compile(r"(?i)^kms:(decrypt|createkey)$"),
    re.compile(r"(?i)^glue:createdevendpoint$"),
    re.compile(r"(?i)^sagemaker:create(notebook|processingjob).*$"),
    re.compile(r"(?i)^cloudformation:createstack$"),
    re.compile(r"(?i)^datapipeline:createpipeline$"),
    re.compile(r"(?i)^codepipeline:createpipeline$"),
]


def _env(name, default):
    v = os.environ.get(name)
    return v if v else default


def _dumps(data):
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


def _now_ms(started):
    return int((time.time() - started) * 1000)


def _finding(fid, severity, title, detail=None, resource=None):
    """Build one normalized finding dict."""
    f = {"id": fid, "severity": severity, "title": title}
    if detail:
        f["detail"] = str(detail)[:500]
    if resource:
        f["resource"] = str(resource)[:300]
    return f


def _summary(findings):
    s = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
         "total": len(findings or [])}
    for f in findings or []:
        sev = f.get("severity", "info")
        if sev in s:
            s[sev] += 1
    return s


def _yaml_available():
    return yaml is not None


def _yaml_load(text):
    """safe_load wrapper -> dict or None on parse error."""
    if yaml is None:
        return None
    try:
        return yaml.safe_load(text)
    except Exception:
        return None


def _yaml_load_all(text):
    """safe_load_all wrapper -> list of docs (parse errors yield [])."""
    if yaml is None:
        return []
    try:
        return [d for d in yaml.safe_load_all(text) if d]
    except Exception:
        return []


# --------------------------------------------------------------------------
# Kubernetes static analyzers (pure dict-in / findings-out - fully testable)
# --------------------------------------------------------------------------

def _ns(item, default="default"):
    md = item.get("metadata") or {}
    return (md.get("namespace") or default)


def _name(item):
    md = item.get("metadata") or {}
    return md.get("name") or "?"


def _container_security(c):
    return (c.get("securityContext") or {}) if isinstance(c, dict) else {}


def _iter_containers(pod_spec):
    """Yield (kind, container_name, container) for all container types."""
    for kind in ("containers", "initContainers", "ephemeralContainers"):
        for c in pod_spec.get(kind) or []:
            if isinstance(c, dict):
                yield kind, c.get("name") or "?", c


def _audit_pod(item):
    """Privileged / root / host-namespace / capability checks per pod."""
    findings = []
    spec = item.get("spec") or {}
    ns = _ns(item)
    pod_name = _name(item)
    res = "%s/%s" % (ns, pod_name)
    pod_sc = spec.get("securityContext") or {}
    pod_root_safe = bool(pod_sc.get("runAsNonRoot"))

    if spec.get("hostPID") is True:
        findings.append(_finding(
            "K8S-HOSTPID", "high", "Pod shares the host PID namespace",
            "hostPID: true exposes host processes to the container",
            res))
    if spec.get("hostIPC") is True:
        findings.append(_finding(
            "K8S-HOSTIPC", "high", "Pod shares the host IPC namespace",
            "hostIPC: true may expose host IPC primitives", res))
    if spec.get("hostNetwork") is True:
        findings.append(_finding(
            "K8S-HOSTNET", "medium", "Pod uses the host network namespace",
            "hostNetwork: true bypasses pod network isolation", res))

    for kind, cname, c in _iter_containers(spec):
        cres = "%s[%s]" % (res, cname)
        csc = _container_security(c)
        if csc.get("privileged") is True:
            findings.append(_finding(
                "K8S-PRIVPOD", "high", "Container runs privileged",
                "securityContext.privileged: true grants host-equivalent "
                "capabilities", cres))
        if csc.get("runAsUser") == 0:
            findings.append(_finding(
                "K8S-ROOT", "high", "Container runs as root (runAsUser 0)",
                "runAsUser is 0; a compromise yields root inside the node",
                cres))
        elif not pod_root_safe and csc.get("runAsNonRoot") is not True \
                and csc.get("runAsUser") not in (None, 0, ""):
            findings.append(_finding(
                "K8S-ROOT", "medium",
                "Container may run as an unconstrained user",
                "runAsNonRoot is not enforced (runAsUser=%r)"
                % csc.get("runAsUser"), cres))
        elif not pod_root_safe and csc.get("runAsNonRoot") is not True:
            findings.append(_finding(
                "K8S-ROOT", "medium",
                "Root default is not disabled for container",
                "set runAsNonRoot/runAsUser>0 at pod or container level",
                cres))
        if csc.get("allowPrivilegeEscalation") is True \
                and not csc.get("privileged"):
            findings.append(_finding(
                "K8S-ESC", "medium", "Explicit privilege escalation allowed",
                "allowPrivilegeEscalation: true permits setuid/no_new_privs "
                "bypass", cres))
        caps = csc.get("capabilities") or {}
        adds = [a for a in (caps.get("add") or []) if isinstance(a, str)]
        for cap in adds:
            if cap == "ALL" or cap.upper() == "SYS_ADMIN":
                findings.append(_finding(
                    "K8S-CAPS", "high",
                    "Dangerous Linux capability added: %s" % cap,
                    "capability grants near-root host control", cres))
            elif cap.upper() in ("NET_ADMIN", "NET_RAW", "SYS_PTRACE",
                                 "SYS_MODULE", "DAC_OVERRIDE"):
                findings.append(_finding(
                    "K8S-CAPS", "medium",
                    "Sensitive Linux capability added: %s" % cap,
                    "review whether the workload needs %s" % cap, cres))
        image = (c.get("image") or "").strip()
        if image:
            tag = image.rsplit(":", 1)[-1] if ":" in image.rsplit("/", 1)[-1] \
                else ""
            if not tag:
                findings.append(_finding(
                    "K8S-IMGTAG", "low", "Container image has no pinned tag",
                    "unpinned image %r drifts over time" % image, cres))
            elif tag == "latest":
                findings.append(_finding(
                    "K8S-IMGTAG", "low",
                    "Container image uses the 'latest' tag",
                    "image %r is not reproducible" % image, cres))
    return findings


def _audit_secret(item):
    """Cleartext secrets: stringData (plaintext) on Opaque secrets."""
    findings = []
    sdata = item.get("stringData") or {}
    stype = item.get("type") or "Opaque"
    if sdata and stype in ("Opaque", ""):
        keys = [k for k, v in sdata.items() if isinstance(v, str) and v]
        if keys:
            findings.append(_finding(
                "K8S-SECPLAIN", "high",
                "Secret stores cleartext values via stringData",
                "stringData fields %r bypass base64 encoding - value is "
                "plaintext at rest" % keys[:8],
                "%s/%s" % (_ns(item), _name(item))))
    return findings


def _audit_configmap(item):
    """Secret-shaped keys carried in cleartext ConfigMap data."""
    findings = []
    data = item.get("data") or {}
    hits = [(k, str(v)[:40]) for k, v in data.items()
            if isinstance(v, str) and _SECRET_KEY_RE.search(k)]
    if hits:
        findings.append(_finding(
            "K8S-CMSECRET", "medium",
            "ConfigMap stores secret-like data in cleartext",
            "keys %r - consider a Secret + projected volume instead"
            % [h[0] for h in hits[:8]],
            "%s/%s" % (_ns(item), _name(item))))
    return findings


def _audit_network_policies(pod_items, netpol_items):
    """Namespace-level coverage: pods without any NetworkPolicy."""
    findings = []
    pod_ns = {(_ns(p)) for p in (pod_items or [])}
    if not pod_ns:
        return findings
    covered = {(_ns(n)) for n in (netpol_items or [])}
    if not netpol_items:
        findings.append(_finding(
            "K8S-NETPOL", "high",
            "Cluster has zero NetworkPolicies",
            "namespaces with workloads: %s - no default-deny isolation "
            "exists anywhere" % sorted(pod_ns)[:10]))
        return findings
    for ns in sorted(pod_ns):
        if ns not in covered:
            findings.append(_finding(
                "K8S-NETPOL", "medium",
                "Namespace %r has workloads but no NetworkPolicy" % ns,
                "add a default-deny ingress/egress policy, then allow-list",
                ns))
    return findings


def _audit_cluster_api(kube_dict):
    """API server exposure from kubeconfig (scheme, TLS, auth posture)."""
    findings = []
    clusters = kube_dict.get("clusters") or []
    if not clusters:
        return findings, None
    current = (kube_dict.get("current-context") or "")
    contexts = {c.get("name"): c for c in kube_dict.get("contexts") or []}
    chosen = contexts.get(current)
    cluster_entry = clusters[0]
    if chosen:
        wanted = (chosen.get("context") or {}).get("cluster")
        for c in clusters:
            if c.get("name") == wanted:
                cluster_entry = c
                break
    cmeta = cluster_entry.get("cluster") or {}
    server = cmeta.get("server") or ""
    profile = {"name": cluster_entry.get("name"),
               "server": server,
               "context": current or None,
               "insecure_skip_tls": bool(cmeta.get(
                   "insecure-skip-tls-verify"))}
    try:
        u = urllib.parse.urlparse(server)
        host = (u.hostname or "").lower()
    except Exception:
        u, host = None, ""
    if u and host:
        loopback = host in ("localhost", "127.0.0.1", "::1")
        if u.scheme == "http":
            sev = "low" if loopback else "high"
            findings.append(_finding(
                "K8S-APISRV", sev,
                "API server uses cleartext http",
                "server=%s - tokens/credentials sent unencrypted" % server))
        if cmeta.get("insecure-skip-tls-verify") and not loopback:
            findings.append(_finding(
                "K8S-APISRV", "medium",
                "API server TLS verification is disabled",
                "insecure-skip-tls-verify: true enables MITM on server=%s"
                % server))
    return findings, profile


# --------------------------------------------------------------------------
# Cluster backend discovery + the main k8s_cluster_audit engine
# --------------------------------------------------------------------------

def _kubectl_path():
    return shutil.which(KUBECTL_CMD)


def _run_kubectl(args, kubeconfig_path=None, timeout=DEFAULT_K8S_TIMEOUT):
    """Run kubectl with a strict timeout. Returns parsed JSON or None.

    Monkeypatch target for tests. Never raises for API-side failures.
    """
    exe = _kubectl_path()
    if not exe:
        return None
    cmd = [exe, "get", "--no-headers", "-o", "json"]
    if kubeconfig_path:
        cmd = [exe, "--kubeconfig", kubeconfig_path,
               "get", "--no-headers", "-o", "json"]
    cmd += list(args)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout or "{}")
    except Exception:
        return None


def _k8s_items(result):
    if not isinstance(result, dict):
        return []
    return [i for i in result.get("items") or [] if isinstance(i, dict)]


def _fetch_resources(kinds, kubeconfig_path=None):
    """Best-effort bulk fetch via kubectl get <kinds>.

    Monkeypatch target for tests.
    """
    out = {}
    for kind in kinds:
        data = _run_kubectl([kind], kubeconfig_path)
        out[kind] = _k8s_items(data)
    return out


def _load_kubeconfig_file(path):
    """Parse a kubeconfig YAML file. Returns dict or None."""
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except Exception:
        return None
    data = _yaml_load(text)
    return data if isinstance(data, dict) else None


def _resolve_kubeconfig(kubeconfig_path=None):
    """Locate a kubeconfig by parameter -> $KUBECONFIG -> ~/.kube/config."""
    candidates = []
    if kubeconfig_path:
        candidates.append(kubeconfig_path)
    env = _env("KUBECONFIG", "")
    if env:
        candidates.extend(p for p in env.split(os.pathsep) if p)
    home = os.path.expanduser("~")
    if home:
        candidates.append(os.path.join(home, ".kube", "config"))
    for c in candidates:
        data = _load_kubeconfig_file(c)
        if data:
            return data, c
    return None, None


def k8s_cluster_audit(kubeconfig_path=None):
    """Audit a live cluster for the core container-security risk set.

    Backend preference: kubectl CLI -> (future) python kubernetes client ->
    config-only posture read. Every branch is bounded; the function never
    raises and always returns a JSON-ready dict.
    """
    started = time.time()
    findings = []
    meta = {"tool": "k8s_cluster_audit",
            "live": False,
            "backend": None,
            "kubeconfig": kubeconfig_path or _env("KUBECONFIG", None),
            "started": datetime.datetime.now(datetime.timezone.utc).isoformat(
                timespec="seconds")}

    if kubeconfig_path and not os.path.isfile(kubeconfig_path):
        findings.append(_finding(
            "K8S-INPUT", "high", "Kubeconfig path does not exist",
            "no such file: %s" % kubeconfig_path, kubeconfig_path))
        meta["error"] = "kubeconfig path not found"
        return {"meta": meta, "findings": findings,
                "summary": _summary(findings), "elapsed_ms": _now_ms(started)}

    kube_dict, kube_path = _resolve_kubeconfig(kubeconfig_path)
    if not kube_dict:
        findings.append(_finding(
            "K8S-CONFIG", "medium",
            "No kubeconfig found - audit is empty",
            "supply kubeconfig_path, KUBECONFIG or ~/.kube/config"))
        meta["error"] = "no kubeconfig available"
        return {"meta": meta, "findings": findings,
                "summary": _summary(findings), "elapsed_ms": _now_ms(started)}

    profile = None
    try:
        api_findings, profile = _audit_cluster_api(kube_dict)
        findings.extend(api_findings)
    except Exception:
        profile = None
    meta["cluster"] = profile

    kinds = ["pods", "secrets", "configmaps", "networkpolicies"]
    live = False
    backend = None
    exe = _kubectl_path()
    if exe:
        backend = "kubectl@%s" % exe
        try:
            resources = _fetch_resources(kinds, kubeconfig_path)
            live = True
            meta["live"] = True
            meta["backend"] = backend
            meta["kubeconfig"] = kube_path or kubeconfig_path
        except Exception:
            resources = {}
    else:
        resources = {}
        meta["backend"] = "static-config"
        meta["note"] = ("kubectl not found - performed config-only posture "
                        "read, no live objects fetched")

    if live:
        for pod in resources.get("pods", []):
            findings.extend(_audit_pod(pod))
        for sec in resources.get("secrets", []):
            findings.extend(_audit_secret(sec))
        for cm in resources.get("configmaps", []):
            findings.extend(_audit_configmap(cm))
        findings.extend(_audit_network_policies(
            resources.get("pods", []),
            resources.get("networkpolicies", [])))
        meta["objects"] = {k: len(resources.get(k, [])) for k in kinds}
    else:
        findings.append(_finding(
            "K8S-LIVECHECK", "info",
            "Live cluster audit not performed (no kubectl backend)",
            "run kubectl install / grant a kubeconfig to enable live checks"))

    findings.sort(key=lambda f: ("critical", "high", "medium", "low",
                                 "info").index(f.get("severity", "info")))
    return {"meta": meta, "findings": findings,
            "summary": _summary(findings), "elapsed_ms": _now_ms(started)}


# --------------------------------------------------------------------------
# Helm chart security scanner
# --------------------------------------------------------------------------

_HELM_INSECURE_DEFAULTS = [
    ("privileged", "true", "high",
     "Insecure default: privileged containers enabled"),
    ("runAsUser", 0, "high", "Insecure default: workload runs as root"),
    ("hostPID", "true", "high", "Insecure default: host PID namespace"),
    ("allowPrivilegeEscalation", "true", "medium",
     "Insecure default: privilege escalation enabled"),
    ("hostNetwork", "true", "medium",
     "Insecure default: host network namespace"),
    ("serviceAccount", "default", "medium",
     "Pod binds the default service account"),
    ("automountServiceAccountToken", "true", "medium",
     "Service-account token automounted by default"),
    ("repository", "latest", "low",
     "Default image tag 'latest' is not reproducible"),
]


def _read_chart(chart_path):
    """Return (files, error) for a chart directory or packaged .tgz."""
    if not chart_path or not os.path.exists(chart_path):
        return None, "chart path does not exist: %r" % chart_path
    files = {}
    if os.path.isdir(chart_path):
        for root, _dirs, names in os.walk(chart_path):
            for n in names:
                p = os.path.join(root, n)
                try:
                    with open(p, "r", encoding="utf-8",
                              errors="replace") as fh:
                        files[os.path.relpath(p, chart_path)] = fh.read()
                except Exception:
                    continue
        return files, None
    try:
        tf = tarfile.open(chart_path, "r:*")
    except Exception as exc:
        return None, "cannot open chart archive: %s" % exc
    try:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            name = member.name
            if name.startswith("/") or ".." in name.split("/"):
                continue            # path-traversal guard
            try:
                fh = tf.extractfile(member)
                raw = fh.read() if fh else b""
                files[name] = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
    finally:
        tf.close()
    return files, None


_HELM_SECRET_TEMPLATE_RE = re.compile(
    r"(?i)((password|passwd|pwd|token|secret|api[_-]?key|private[_-]?key)"
    r"\s*[:=]\s*)(['\"]?)([^'\"\s]+)")
_HELM_VALUE_ASSIGN_RE = re.compile(
    r"(?i)^\s*([a-zA-Z0-9_.\-]+)\s*:\s*(.*?)\s*$")


def _helm_secret_scan(files):
    """Literal secrets in templates/values + placeholder policy checks."""
    findings = []
    for path, text in files.items():
        if not path.endswith((".yaml", ".yml", ".tpl", ".toml")):
            continue
        lowered = path.lower()
        if "/tests/" in "/" + lowered.replace("\\", "/"):
            continue
        is_template = path.startswith("templates/")
        for m in _HELM_SECRET_TEMPLATE_RE.finditer(text):
            value = m.group(4)
            if not value or len(value) < 5 or value.startswith("{{"):
                continue
            if _PLACEHOLDER_RE.match(value):
                continue
            if value.startswith("${") and value.endswith("}"):
                continue
            findings.append(_finding(
                "HELM-SECRET", "high",
                "Hardcoded credential-like value in chart",
                "key %r set to literal %r in %s"
                % (m.group(1).strip(" :="), value[:40], path), path))
        # value defaults that are suspiciously real
        for line in text.splitlines():
            vm = _HELM_VALUE_ASSIGN_RE.match(line)
            if not vm:
                continue
            key = vm.group(1).lower()
            val = vm.group(2).strip().strip('"').strip("'")
            if not _SECRET_KEY_RE.search(key) or not val:
                continue
            if _PLACEHOLDER_RE.match(val) or val.startswith("{{"):
                continue
            if is_template:
                continue        # templates may reference {{ .Values.x }}
            if len(val) < 8:
                continue
            findings.append(_finding(
                "HELM-SECDEFAULT", "medium",
                "Secret-like default value shipped in values",
                "%s=%r - override via --set or a secret ref" % (key, val),
                path))
    return findings


def _deep_value(node, dotted):
    """Resolve a dotted key against nested dicts (helm .Values style)."""
    cur = node
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _helm_insecure_defaults(files):
    """Values.yaml defaults that open obvious security holes."""
    findings = []
    for path in ("values.yaml", "values.yml"):
        text = files.get(path)
        if not text:
            continue
        data = _yaml_load(text)
        if not isinstance(data, dict):
            continue
        for key, bad, sev, msg in _HELM_INSECURE_DEFAULTS:
            val = _deep_value(data, key)
            if val is None:
                continue
            if key == "runAsUser" and isinstance(val, (int, str)) \
                    and str(val).strip() in ("0", "root"):
                findings.append(_finding(
                    "HELM-DEFAULT", sev, msg, "values.yaml: %s=%r" % (key,
                                                                       val),
                    "values.yaml"))
            elif key == "repository" and isinstance(val, str) \
                    and val.rstrip("/").endswith(":latest"):
                findings.append(_finding(
                    "HELM-DEFAULT", sev, msg,
                    "values.yaml: %s=%r" % (key, val), "values.yaml"))
            elif isinstance(val, bool) and str(val).lower() == str(bad):
                findings.append(_finding(
                    "HELM-DEFAULT", sev, msg,
                    "values.yaml: %s=%s" % (key, val), "values.yaml"))
            elif isinstance(val, str) and val.lower() == str(bad).lower():
                findings.append(_finding(
                    "HELM-DEFAULT", sev, msg,
                    "values.yaml: %s=%r" % (key, val), "values.yaml"))
    return findings


def _helm_rbac_scan(files):
    """Over-permissive Roles/ClusterRoles + bindings in chart manifests."""
    findings = []
    for path, text in files.items():
        if not path.endswith((".yaml", ".yml")):
            continue
        if not path.startswith(("templates/", "crds/")) \
                and "/templates/" not in "/" + path.replace("\\", "/"):
            continue
        for doc in _yaml_load_all(text):
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind") or ""
            md = doc.get("metadata") or {}
            if not isinstance(md, dict):
                md = {}
            res = "%s/%s" % (kind, md.get("name") or "?")
            if kind in ("Role", "ClusterRole"):
                rules = doc.get("rules") or []
                for i, rule in enumerate(rules):
                    if not isinstance(rule, dict):
                        continue
                    apis = rule.get("apiGroups") or [""]
                    if isinstance(apis, str):
                        apis = [apis]
                    verbs = rule.get("verbs") or []
                    if isinstance(verbs, str):
                        verbs = [verbs]
                    if any("*" in str(v) for v in verbs):
                        findings.append(_finding(
                            "HELM-RBAC", "high",
                            "RBAC rule grants wildcard verbs (*)",
                            "%s rule[%d] apiGroups=%r verbs=%r"
                            % (res, i, apis[:5], verbs[:10]), path))
                    if "*" in apis:
                        findings.append(_finding(
                            "HELM-RBAC", "medium",
                            "RBAC rule spans all apiGroups (*)",
                            "%s rule[%d] apiGroups=[*]" % (res, i), path))
            elif kind in ("RoleBinding", "ClusterRoleBinding"):
                subs = doc.get("subjects") or []
                for sub in subs:
                    if not isinstance(sub, dict):
                        continue
                    if sub.get("kind") in ("User", "Group") \
                            and sub.get("name") == "system:anonymous":
                        findings.append(_finding(
                            "HELM-RBAC", "high",
                            "Binding grants access to unauthenticated "
                            "users",
                            "%s -> %s/%s"
                            % (res, sub.get("kind"),
                               sub.get("name")), path))
            elif kind == "ServiceAccount" and md.get("name") == "default" \
                    and md.get("namespace") in (None, "default"):
                findings.append(_finding(
                    "HELM-RBAC", "low",
                    "Chart uses the default service account",
                    "mount a purpose-built ServiceAccount instead", path))
    return findings


def helm_security_scan(chart_path, timeout=_HELM_READ_TIMEOUT):
    """Scan a Helm chart (dir or .tgz) for security antipatterns."""
    started = time.time()
    findings = []
    meta = {"tool": "helm_security_scan", "chart_path": chart_path,
            "started": datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="seconds")}
    files, err = _read_chart(chart_path)
    if err:
        meta["error"] = err
        return {"meta": meta, "findings": findings,
                "summary": _summary(findings), "elapsed_ms": _now_ms(started)}
    meta["file_count"] = len(files)
    meta["has_values_yaml"] = any(
        p in ("values.yaml", "values.yml") for p in files)
    findings.extend(_helm_insecure_defaults(files))
    findings.extend(_helm_secret_scan(files))
    findings.extend(_helm_rbac_scan(files))
    findings.sort(key=lambda f: ("critical", "high", "medium", "low",
                                 "info").index(f.get("severity", "info")))
    return {"meta": meta, "findings": findings,
            "summary": _summary(findings), "elapsed_ms": _now_ms(started)}


# --------------------------------------------------------------------------
# IAM policy analyzer (AWS / GCP / Azure)
# --------------------------------------------------------------------------

def _cloud_provider(policy):
    if isinstance(policy, dict):
        if "Statement" in policy or "policyDocument" in policy \
                or "Id" in policy or "Version" in policy:
            return "aws"
        if "bindings" in policy or "role" in policy and "members" in policy:
            return "gcp"
        if "properties" in policy or "permissions" in policy \
                or "dataActions" in policy:
            return "azure"
    return "unknown"


def _aws_statements(policy):
    st = []
    if isinstance(policy, dict):
        if "policyDocument" in policy and isinstance(
                policy.get("policyDocument"), dict):
            policy = policy["policyDocument"]
        raw = policy.get("Statement")
    else:
        raw = None
    if isinstance(raw, dict):
        raw = [raw]
    for s in raw or []:
        if isinstance(s, dict):
            st.append(s)
    return st


def _aws_actions(statement):
    act = statement.get("Action") or statement.get("NotAction")
    if isinstance(act, str):
        act = [act]
    return [a for a in act or [] if isinstance(a, str)]


def _aws_resources(statement):
    r = statement.get("Resource")
    if isinstance(r, str):
        r = [r]
    return [x for x in r or [] if isinstance(x, str)]


def _aws_principal(statement):
    p = statement.get("Principal")
    if p is None:
        return []
    if isinstance(p, str):
        return [p]
    out = []
    for key, vals in p.items() if isinstance(p, dict) else []:
        if isinstance(vals, str):
            vals = [vals]
        out.extend("%s:%s" % (key, v) for v in vals if isinstance(v, str))
    return out


def _aws_findings(statements):
    findings = []
    for idx, s in enumerate(statements):
        effect = str(s.get("Effect") or "").strip()
        actions = _aws_actions(s)
        resources = _aws_resources(s)
        principals = _aws_principal(s)
        res_label = "%s:%s" % (effect, "/".join(actions[:3])) if actions \
            else "statement[%d]" % idx

        if effect == "Deny":
            continue
        if not actions:
            continue
        any_star_res = any(r == "*" for r in resources) or not resources
        any_star_act = any(a == "*" for a in actions)
        wild_actions = [a for a in actions if a != "*" and a.endswith(":*")]

        if any_star_act and any_star_res:
            findings.append(_finding(
                "IAM-WILDCARD", "critical",
                "Statement allows ALL actions on ALL resources",
                "Action:*, Resource:* - full administrative blast radius",
                res_label))
        elif any_star_act:
            findings.append(_finding(
                "IAM-WILDCARD", "high",
                "Statement allows all actions of a service (Action:*)",
                "resource=%r - pair with least-privilege actions"
                % resources[:5], res_label))
        elif wild_actions:
            findings.append(_finding(
                "IAM-WILDCARD", "medium",
                "Wildcard action prefixes grant every <service>:* op",
                "%r on %r" % (wild_actions[:6], resources[:5]), res_label))
        if any_star_res and not any_star_act:
            findings.append(_finding(
                "IAM-RESOURCE", "medium",
                "Statement targets all resources (Resource:*)",
                "scope actions to ARNs/prefixes; %r" % actions[:5],
                res_label))

        for a in actions:
            for rx in _ESCALATION_ACTION_RE:
                if rx.match(a):
                    findings.append(_finding(
                        "IAM-ESCALATION", "high",
                        "Potential privilege-escalation action: %s" % a,
                        "combining this with iam:PassRole / write "
                        "permissions can grant full admin", res_label))
                    break

        for p in principals:
            pl = p.lower()
            if pl in ("*", "arn:aws:iam::*") or pl.endswith(":root"):
                findings.append(_finding(
                    "IAM-PUBLIC", "high",
                    "Principal is public/unauthenticated: %s" % p,
                    "any AWS identity (or anonymous) can invoke this",
                    res_label))
    return findings


def _gcp_findings(policy):
    findings = []
    bindings = policy.get("bindings") or []
    if not isinstance(bindings, list):
        return findings
    for b in bindings:
        if not isinstance(b, dict):
            continue
        role = b.get("role") or "?"
        members = b.get("members") or []
        if isinstance(members, str):
            members = [members]
        for m in members:
            if not isinstance(m, str):
                continue
            if m in ("allUsers", "allAuthenticatedUsers"):
                findings.append(_finding(
                    "IAM-PUBLIC", "high",
                    "GCP member is public: %s" % m,
                    "binding %s - remove or restrict to known principals"
                    % role, "%s:%s" % (role, m)))
            if (("actAs" in str(role) or "serviceAccountUser" in str(role))
                    and str(m).startswith("serviceAccount:")):
                findings.append(_finding(
                    "IAM-ESCALATION", "medium",
                    "Service-account impersonation granted",
                    "role %s on %s" % (role, m), "%s:%s" % (role, m)))
    if policy.get("etag") is None and bindings:
        findings.append(_finding(
            "IAM-ETAG", "low",
            "GCP policy missing etag (concurrent-overwrite risk)",
            "add the etag from getIamPolicy to guard updates", None))
    return findings


def _azure_action_strings(policy):
    """Flatten Azure permissions to plain action strings.

    Handles the assignment shape (permissions: ["Microsoft.x/read"]) and
    the role-definition shape (permissions: [{"actions": [...],
    "notActions": [...], "dataActions": [...]}]).
    """
    props = policy.get("properties")
    raw = policy.get("permissions")
    if raw is None and isinstance(props, dict):
        raw = props.get("permissions")
    if raw is None:
        raw = policy.get("dataActions")
    if raw is None and isinstance(props, dict):
        raw = props.get("dataActions")
    if raw is None:
        raw = []
    if isinstance(raw, dict):
        raw = [raw]
    out = []
    for entry in raw:
        if isinstance(entry, str):
            out.append(entry)
        elif isinstance(entry, dict):
            for key in ("actions", "notActions", "dataActions"):
                val = entry.get(key)
                if isinstance(val, str):
                    val = [val]
                out.extend(x for x in val or [] if isinstance(x, str))
    return out


def _azure_findings(policy):
    findings = []
    perms = _azure_action_strings(policy)
    for p in perms:
        if not isinstance(p, str):
            continue
        if p == "*":
            findings.append(_finding(
                "IAM-WILDCARD", "critical",
                "Azure permission is '*' (full control)",
                "grant scoped actions (e.g. Microsoft.Storage/.../read)",
                p))
        elif p.endswith("/*") or p.endswith("/*/write") \
                or p.endswith("/*/delete"):
            findings.append(_finding(
                "IAM-WILDCARD", "medium",
                "Azure wildcard permission: %s" % p,
                "narrow to specific resource actions", p))
        if p.lower().endswith("/action") or "passrole" in p.lower():
            findings.append(_finding(
                "IAM-ESCALATION", "medium",
                "Azure permission may enable escalation: %s" % p,
                "validate role assignments around this action", p))
    if policy.get("notActions"):
        na = policy.get("notActions")
        if isinstance(na, list) and any(x == "*" for x in na):
            findings.append(_finding(
                "IAM-WILDCARD", "high",
                "Azure notActions excludes '*' (allow-all-minus)",
                "this pattern is easy to get wrong; use explicit actions",
                str(na)[:120]))
    props = policy.get("properties")
    if isinstance(props, dict) and props.get("assignableScopes") in (
            ["/"], ["*"]):
        findings.append(_finding(
            "IAM-PUBLIC", "high",
            "Azure role is assignable at management-group/root scope",
            "narrow assignableScopes to the required subscription/group",
            str(props.get("assignableScopes"))[:120]))
    return findings


def _parse_policy_input(policy_json):
    """Accept a JSON string or an already-parsed dict/list."""
    if isinstance(policy_json, (dict, list)):
        return policy_json, None
    if not isinstance(policy_json, str):
        return None, "policy_json must be a JSON string or dict"
    text = policy_json.strip()
    if not text:
        return None, "policy_json is empty"
    try:
        return json.loads(text), None
    except ValueError as exc:
        return None, "invalid JSON: %s" % exc


def iam_policy_analyzer(policy_json):
    """Analyze an AWS/GCP/Azure IAM policy for dangerous grants."""
    started = time.time()
    findings = []
    meta = {"tool": "iam_policy_analyzer",
            "started": datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="seconds")}
    policy, err = _parse_policy_input(policy_json)
    if err:
        meta["error"] = err
        meta["provider"] = "unknown"
        return {"meta": meta, "findings": findings,
                "summary": _summary(findings), "elapsed_ms": _now_ms(started)}
    provider = _cloud_provider(policy)
    meta["provider"] = provider
    meta["statement_count"] = 0
    if provider == "aws":
        statements = _aws_statements(policy)
        meta["statement_count"] = len(statements)
        findings.extend(_aws_findings(statements))
    elif provider == "gcp":
        bindings = policy.get("bindings") or []
        meta["statement_count"] = len(bindings)
        findings.extend(_gcp_findings(policy))
    elif provider == "azure":
        meta["statement_count"] = len(_azure_action_strings(policy))
        findings.extend(_azure_findings(policy))
    else:
        meta["error"] = "provider detection failed - expected AWS " \
                        "Statement/policyDocument, GCP bindings, or " \
                        "Azure permissions"
    findings.sort(key=lambda f: ("critical", "high", "medium", "low",
                                 "info").index(f.get("severity", "info")))
    return {"meta": meta, "findings": findings,
            "summary": _summary(findings), "elapsed_ms": _now_ms(started)}


def tool_k8s_cluster_audit(kubeconfig_path=None, timeout=20):
    """Tool entry point - JSON-serialized cluster posture result."""
    return _dumps(k8s_cluster_audit(kubeconfig_path))


def tool_helm_security_scan(chart_path, timeout=20):
    """Tool entry point - JSON-serialized helm chart scan result."""
    return _dumps(helm_security_scan(chart_path, timeout=timeout))


def tool_iam_policy_analyzer(policy_json, timeout=20):
    """Tool entry point - JSON-serialized IAM policy analysis result."""
    return _dumps(iam_policy_analyzer(policy_json))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(tool_iam_policy_analyzer(sys.argv[1]))
    else:
        print(tool_k8s_cluster_audit())
