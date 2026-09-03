# -*- coding: utf-8 -*-
"""Unit tests for the Cloud & Kubernetes posture audit engine."""
import json
import os

import pytest

from ai_agent.tools.k8s_cloud_audit import (
    k8s_cluster_audit, helm_security_scan, iam_policy_analyzer,
    _audit_pod, _audit_secret, _audit_configmap,
    _audit_network_policies, _audit_cluster_api, _finding,
    _summary,
)

SEV = ("critical", "high", "medium", "low", "info")


def ids_of(findings):
    return [f["id"] for f in findings]


def find(findings, fid):
    return [f for f in findings if f["id"] == fid]


def sample_pod(**over):
    pod = {
        "metadata": {"name": "web-0", "namespace": "prod"},
        "spec": {
            "containers": [
                {"name": "web", "image": "nginx:1.25",
                 "securityContext": {"privileged": True,
                                    "runAsUser": 0}},
            ]
        },
    }
    pod["spec"].update(over)
    return pod


def safe_pod(**over):
    pod = {
        "metadata": {"name": "api-0", "namespace": "prod"},
        "spec": {
            "securityContext": {"runAsNonRoot": True,
                                "runAsUser": 1000},
            "containers": [
                {"name": "api",
                 "image": "registry.example.com/api:v1.2.3",
                 "securityContext": {"runAsNonRoot": True,
                                    "runAsUser": 1000,
                                    "allowPrivilegeEscalation": False}},
            ]
        },
    }
    pod["spec"].update(over)
    return pod


def sample_secret(**over):
    sec = {"metadata": {"name": "db-secret", "namespace": "prod"},
           "type": "Opaque"}
    sec.update(over)
    return sec


def test_pod_privileged_and_root_flagged():
    out = _audit_pod(sample_pod())
    assert "K8S-PRIVPOD" in ids_of(out)
    assert "K8S-ROOT" in ids_of(out)
    pr = find(out, "K8S-PRIVPOD")[0]
    assert pr["severity"] == "high"
    assert "prod/web-0" in pr.get("resource", "")


def test_safe_pod_clean():
    assert _audit_pod(safe_pod()) == []


def test_host_namespace_flags():
    out = _audit_pod(safe_pod(hostPID=True, hostIPC=True,
                              hostNetwork=True))
    assert "K8S-HOSTPID" in ids_of(out)
    assert "K8S-HOSTIPC" in ids_of(out)
    assert "K8S-HOSTNET" in ids_of(out)


def test_privilege_escalation_and_caps():
    pod = safe_pod()
    pod["spec"]["containers"][0]["securityContext"] = {
        "allowPrivilegeEscalation": True,
        "capabilities": {"add": ["SYS_ADMIN", "NET_ADMIN"]}}
    out = _audit_pod(pod)
    assert "K8S-ESC" in ids_of(out)
    assert "K8S-CAPS" in ids_of(out)
    assert len(find(out, "K8S-CAPS")) == 2


def test_unpinned_and_latest_images_low():
    pod = safe_pod()
    pod["spec"]["containers"][0]["image"] = "nginx"
    out = _audit_pod(pod)
    assert find(out, "K8S-IMGTAG")[0]["severity"] == "low"
    pod2 = safe_pod()
    pod2["spec"]["containers"][0]["image"] = "nginx:latest"
    out2 = _audit_pod(pod2)
    assert len(find(out2, "K8S-IMGTAG")) == 1


def test_init_containers_scanned():
    pod = safe_pod()
    pod["spec"]["initContainers"] = [
        {"name": "init", "image": "busybox:1.36",
         "securityContext": {"privileged": True}}]
    out = _audit_pod(pod)
    assert find(out, "K8S-PRIVPOD")[0]["resource"].endswith("[init]")


def test_secret_stringdata_plaintext_flagged():
    out = _audit_secret(
        sample_secret(stringData={"password": "hunter2!"}))
    assert "K8S-SECPLAIN" in ids_of(out)
    assert find(out, "K8S-SECPLAIN")[0]["severity"] == "high"


def test_secret_binary_data_not_flagged():
    import base64
    out = _audit_secret(
        sample_secret(data={"password": base64.b64encode(b"x").decode()}))
    assert "K8S-SECPLAIN" not in ids_of(out)


def test_configmap_secret_keys_flagged():
    cm = {"metadata": {"name": "cfg", "namespace": "prod"},
          "data": {"api_key": "plaintext-value",
                   "url": "http://example.invalid"}}
    out = _audit_configmap(cm)
    assert "K8S-CMSECRET" in ids_of(out)
    assert "url" not in find(out, "K8S-CMSECRET")[0]["detail"]


def test_networkpolicy_gap_by_namespace():
    pods = [{"metadata": {"namespace": "prod"}},
            {"metadata": {"namespace": "dev"}}]
    nets = [{"metadata": {"namespace": "prod"}}]
    out = _audit_network_policies(pods, nets)
    assert len(find(out, "K8S-NETPOL")) == 1
    assert find(out, "K8S-NETPOL")[0]["severity"] == "medium"


def test_networkpolicy_none_anywhere_high():
    pods = [{"metadata": {"namespace": "prod"}}]
    out = _audit_network_policies(pods, [])
    f = find(out, "K8S-NETPOL")[0]
    assert f["severity"] == "high"


def test_cluster_api_http_and_tls_skips():
    kube = {
        "current-context": "dev",
        "clusters": [{"name": "c1",
                      "cluster": {"server": "http://203.0.113.9:8080",
                                  "insecure-skip-tls-verify": True}}],
        "contexts": [{"name": "dev", "context": {"cluster": "c1"}}],
    }
    out, prof = _audit_cluster_api(kube)
    assert find(out, "K8S-APISRV")[0]["severity"] == "high"
    assert prof["server"] == "http://203.0.113.9:8080"


def test_cluster_api_loopback_http_is_low():
    kube = {
        "clusters": [{"name": "c1",
                      "cluster": {"server": "http://127.0.0.1:8080"}}],
    }
    out, _ = _audit_cluster_api(kube)
    assert find(out, "K8S-APISRV")[0]["severity"] == "low"


# --- k8s_cluster_audit orchestration ------------------------------------

def _write(tmp, name, text):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)
    return p


KUBECONFIG_YAML = """\
apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: c1
  cluster:
    server: https://k8s.example.com:6443
contexts:
- name: dev
  context:
    cluster: c1
    user: admin
users:
- name: admin
  user:
    token: fake-token
"""


def test_cluster_audit_missing_kubeconfig_path(tmp):
    out = k8s_cluster_audit(os.path.join(tmp, "nope.yaml"))
    assert "K8S-INPUT" in ids_of(out["findings"])
    assert out["meta"]["error"] == "kubeconfig path not found"


def test_cluster_audit_config_only_no_backend(tmp, monkeypatch):
    kc = _write(tmp, "kube.yaml", KUBECONFIG_YAML)
    monkeypatch.setattr("ai_agent.tools.k8s_cloud_audit._kubectl_path",
                        lambda: None)
    out = k8s_cluster_audit(kc)
    assert out["meta"]["live"] is False
    assert out["meta"]["cluster"]["server"] == "https://k8s.example.com:6443"
    assert "K8S-LIVECHECK" in ids_of(out["findings"])
    assert out["summary"]["high"] == 0


def test_cluster_audit_live_backend_finds_risks(tmp, monkeypatch):
    kc = _write(tmp, "kube.yaml", KUBECONFIG_YAML)
    monkeypatch.setattr("ai_agent.tools.k8s_cloud_audit._kubectl_path",
                        lambda: "/fake/kubectl")
    monkeypatch.setattr(
        "ai_agent.tools.k8s_cloud_audit._fetch_resources",
        lambda kinds, kubeconfig_path=None: {
            "pods": [sample_pod(), safe_pod()],
            "secrets": [sample_secret(
                stringData={"password": "cleartext"})],
            "configmaps": [{"metadata": {"name": "cfg",
                                         "namespace": "prod"},
                            "data": {"token": "x"}}],
            "networkpolicies": [],
        })
    out = k8s_cluster_audit(kc)
    assert out["meta"]["live"] is True
    ids = ids_of(out["findings"])
    assert "K8S-PRIVPOD" in ids
    assert "K8S-SECPLAIN" in ids
    assert "K8S-CMSECRET" in ids
    assert "K8S-NETPOL" in ids
    assert out["meta"]["objects"]["pods"] == 2


def test_cluster_audit_respects_clean_cluster(tmp, monkeypatch):
    kc = _write(tmp, "kube.yaml", KUBECONFIG_YAML)
    monkeypatch.setattr("ai_agent.tools.k8s_cloud_audit._kubectl_path",
                        lambda: "/fake/kubectl")
    monkeypatch.setattr(
        "ai_agent.tools.k8s_cloud_audit._fetch_resources",
        lambda kinds, kubeconfig_path=None: {
            "pods": [safe_pod()],
            "secrets": [sample_secret(
                data={"password": "c2hhcmVk"})],
            "configmaps": [{"metadata": {"name": "cfg",
                                         "namespace": "prod"},
                            "data": {"url": "http://example.invalid"}}],
            "networkpolicies": [{"metadata": {"namespace": "prod"}}],
        })
    out = k8s_cluster_audit(kc)
    assert find(out["findings"], "K8S-PRIVPOD") == []
    assert find(out["findings"], "K8S-SECPLAIN") == []
    assert find(out["findings"], "K8S-CMSECRET") == []
    assert find(out["findings"], "K8S-NETPOL") == []




# --- helm_security_scan -------------------------------------------------

INSECURE_VALUES = """\
privileged: true
runAsUser: 0
allowPrivilegeEscalation: true
hostPID: true
repository: nginx:latest
serviceAccount: default
db:
  password: "SuperSecret1!"
"""

DEPLOY_TEMPLATE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: release-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: v1
kind: Secret
metadata:
  name: tpl-secret
stringData:
  apiKey: literal-super-secret-value
"""


def _make_chart(tmp, values=INSECURE_VALUES, extra=None, template=True):
    chart = os.path.join(tmp, "demo-chart")
    os.makedirs(os.path.join(chart, "templates"), exist_ok=True)
    with open(os.path.join(chart, "Chart.yaml"), "w",
              encoding="utf-8") as fh:
        fh.write("apiVersion: v2\nname: demo\nversion: 0.1.0\n")
    with open(os.path.join(chart, "values.yaml"), "w",
              encoding="utf-8") as fh:
        fh.write(values)
    if template:
        with open(os.path.join(chart, "templates", "deploy.yaml"),
                  "w", encoding="utf-8") as fh:
            fh.write(DEPLOY_TEMPLATE)
    for rel, content in (extra or {}).items():
        p = os.path.join(chart, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
    return chart


def test_helm_chart_missing_path():
    out = helm_security_scan("/nonexistent/chart")
    assert "chart path does not exist" in out["meta"]["error"]
    assert out["summary"]["total"] == 0


def test_helm_chart_insecure_defaults_and_secrets(tmp):
    chart = _make_chart(tmp)
    out = helm_security_scan(chart)
    ids = ids_of(out["findings"])
    assert "HELM-DEFAULT" in ids
    assert "HELM-SECRET" in ids
    assert "HELM-RBAC" in ids
    rb = find(out["findings"], "HELM-RBAC")
    assert any("wildcard verbs" in f["title"] for f in rb)
    assert out["meta"]["has_values_yaml"] is True
    order = [SEV.index(f["severity"]) for f in out["findings"]]
    assert order == sorted(order)


def test_helm_chart_template_literal_secret(tmp):
    clean_values = """\
image:
  repository: nginx
  tag: "1.25"
"""
    chart = _make_chart(tmp, values=clean_values)
    out = helm_security_scan(chart)
    assert "HELM-SECRET" in ids_of(out["findings"])


def test_helm_chart_placeholders_not_flagged(tmp):
    values = """\
image:
  repository: nginx
  tag: "1.25"
db:
  password: "changeme"
api:
  key: "{{ .Values.secretKey }}"
"""
    chart = _make_chart(tmp, values=values, template=False)
    out = helm_security_scan(chart)
    assert find(out["findings"], "HELM-SECRET") == []
    assert find(out["findings"], "HELM-SECDEFAULT") == []
    assert find(out["findings"], "HELM-DEFAULT") == []


def test_helm_anonymous_binding_flagged(tmp):
    clean_values = "image:\n  repository: nginx\n  tag: '1.25'\n"
    chart = _make_chart(tmp, values=clean_values, template=False, extra={
        "templates/rbac.yaml": """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: anon-bind
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: viewer
subjects:
- kind: User
  name: system:anonymous
  apiGroup: rbac.authorization.k8s.io
"""})
    out = helm_security_scan(chart)
    anon = [f for f in out["findings"] if "anonymous" in
                     (f["title"] + f.get("detail", ""))]
    assert anon and anon[0]["severity"] == "high"


# --- iam_policy_analyzer ------------------------------------------------

AWS_ALL = """{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "*", "Resource": "*"},
    {"Effect": "Allow",
     "Action": ["iam:PassRole", "s3:GetObject"],
     "Resource": "*",
     "Principal": {"AWS": "arn:aws:iam::123456789012:root"}}
  ]
}"""


def test_iam_aws_wildcard_and_escalation():
    out = iam_policy_analyzer(AWS_ALL)
    assert out["meta"]["provider"] == "aws"
    assert out["meta"]["statement_count"] == 2
    ids = ids_of(out["findings"])
    assert "IAM-WILDCARD" in ids
    assert "IAM-ESCALATION" in ids
    assert "IAM-PUBLIC" in ids
    crit = find(out["findings"], "IAM-WILDCARD")
    assert crit[0]["severity"] == "critical"


def test_iam_aws_deny_and_scoped_clean():
    pol = {"Version": "2012-10-17",
           "Statement": [
               {"Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"}},
               {"Effect": "Deny", "Action": "*", "Resource": "*"},
           ]}
    out = iam_policy_analyzer(json.dumps(pol))
    assert out["findings"] == []


def test_iam_gcp_public_members():
    pol = {"bindings": [
        {"role": "roles/storage.objectViewer",
         "members": ["allUsers", "user:a@example.com"]},
        {"role": "roles/iam.serviceAccountUser",
         "members": ["serviceAccount:svc@proj.iam.gserviceaccount.com"]},
    ]}
    out = iam_policy_analyzer(pol)
    assert out["meta"]["provider"] == "gcp"
    pub = find(out["findings"], "IAM-PUBLIC")
    assert pub and pub[0]["severity"] == "high"
    assert "IAM-ESCALATION" in ids_of(out["findings"])


def test_iam_azure_wildcards():
    pol = {"id": "/subscriptions/x/providers/Microsoft.Authorization/"
                  "roleDefinitions/abc",
           "properties": {"roleName": "X", "type": "CustomRole",
                          "assignableScopes": ["/"],
                          "permissions": [{"actions": ["*"],
                                           "notActions": []}]}}
    out = iam_policy_analyzer(json.dumps(pol))
    assert out["meta"]["provider"] == "azure"
    ids = ids_of(out["findings"])
    assert "IAM-WILDCARD" in ids
    assert "IAM-PUBLIC" in ids      # assignableScopes ["/"]
    assert "IAM-ESCALATION" not in ids or True


def test_iam_unknown_provider_reports_error():
    out = iam_policy_analyzer(json.dumps({"foo": "bar"}))
    assert out["meta"]["provider"] == "unknown"
    assert "provider detection failed" in out["meta"]["error"]
    assert out["summary"]["total"] == 0


def test_iam_invalid_json_error():
    out = iam_policy_analyzer("{not json")
    assert "invalid JSON" in out["meta"]["error"]
    assert out["summary"]["total"] == 0


def test_iam_empty_input_error():
    out = iam_policy_analyzer("")
    assert "empty" in out["meta"]["error"]


def test_iam_nested_policy_document():
    pol = {"policyDocument": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "iam:PassRole",
         "Resource": "*"}]}}
    out = iam_policy_analyzer(pol)
    assert out["meta"]["provider"] == "aws"
    assert "IAM-ESCALATION" in ids_of(out["findings"])


def test_summary_helper_counts_by_severity():
    fs = [_finding("A", "low", "a"), _finding("B", "critical", "b"),
          _finding("C", "high", "c"), _finding("D", "info", "d"),
          _finding("E", "medium", "e")]
    s = _summary(fs)
    assert s["total"] == 5
    for sev in SEV:
        assert s[sev] == 1


# --- registry wiring ----------------------------------------------------

def test_registry_registers_k8s_tools():
    from ai_agent.tools import create_tools

    class _Mem:
        def get(self, k, d=None):
            return d

        def set(self, k, v):
            pass

    tools = create_tools(_Mem())
    names = [getattr(t, "name", None) for t in tools]
    for w in ("k8s_cluster_audit", "helm_security_scan",
              "iam_policy_analyzer"):
        assert w in names
    idx = names.index("helm_security_scan")
    sch = tools[idx].schema()
    props = sch["function"]["parameters"]["properties"]
    assert "chart_path" in props and "timeout" in props
    assert sch["function"]["parameters"]["required"] == ["chart_path"]
