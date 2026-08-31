"""Cloud Security & Infrastructure Audit Tools.

Tools:
  - aws_s3_enum(bucket_name): anonymous S3 permission + listing check.
  - cloud_misconfig_scan(target_domain): subdomain takeover fingerprints + exposed cloud endpoints.
  - docker_security_audit(): local/remote Docker daemon exposure checks.

All tools return clean JSON dicts and never raise.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests

from .base import truncate

DEFAULT_TIMEOUT = 8.0
_UA = "HackerAI-CloudAudit/1.0"
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": _UA})


def _err(msg: str) -> Dict[str, Any]:
    return {"error": msg}


def _s3_request(url: str, method: str = "GET", timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    try:
        resp = _SESSION.request(method, url, timeout=timeout, allow_redirects=False)
        return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text[:500]}
    except requests.exceptions.Timeout:
        return {"status": 0, "error": "timeout"}
    except requests.exceptions.RequestException as exc:
        return {"status": 0, "error": str(exc)[:200]}


def aws_s3_enum(bucket_name: str, probe_write: bool = False) -> Dict[str, Any]:
    """Check anonymous (public) access on an S3 bucket: listing, read, and optional write probe."""
    if not isinstance(bucket_name, str) or not bucket_name.strip():
        return _err("bucket_name is required")
    bucket = bucket_name.strip().lower()
    result: Dict[str, Any] = {"bucket": bucket, "findings": [], "public": False}

    endpoints = [
        f"https://{bucket}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket}/",
    ]
    for ep in endpoints:
        r = _s3_request(ep)
        status = r.get("status")
        body = r.get("body", "")
        if r.get("error") and status == 0:
            result["findings"].append({"endpoint": ep, "issue": r["error"]})
            continue
        if status == 200:
            result["public"] = True
            is_list = "<ListBucketResult" in body
            result["findings"].append({
                "endpoint": ep,
                "http_status": status,
                "anonymous_listing": is_list,
                "severity": "critical" if is_list else "high",
                "detail": "bucket publicly readable" + (" with object listing enabled" if is_list else ""),
            })
            if is_list:
                result["anonymous_listing"] = True
        elif status == 403:
            result["findings"].append({"endpoint": ep, "http_status": 403,
                                       "issue": "exists but ListObjects denied (ACL denies anonymous GET)"})
        elif status == 404:
            result["findings"].append({"endpoint": ep, "http_status": 404, "issue": "NoSuchBucket"})
        else:
            result["findings"].append({"endpoint": ep, "http_status": status, "issue": "unexpected status"})

    if probe_write and result["public"]:
        probe_key = f"hackerai-probe-{os.urandom(4).hex()}.txt"
        for ep in endpoints:
            w = _s3_request(ep + probe_key, method="PUT")
            if w.get("status") in (200, 201):
                result["findings"].append({"endpoint": ep, "http_status": w["status"],
                                           "anonymous_write": True, "severity": "critical",
                                           "probe_key": probe_key,
                                           "note": "anonymous PUT succeeded; probe key should be deleted"})
                _s3_request(ep + probe_key, method="DELETE")
                result["anonymous_write"] = True
                break
            if w.get("status"):
                result["findings"].append({"endpoint": ep, "http_status": w["status"],
                                           "anonymous_write": False})
    result["findings_count"] = len(result["findings"])
    return result


_TAKEOVER_FINGERPRINTS: List[Dict[str, Any]] = [
    {"service": "AWS S3", "patterns": ["NoSuchBucket", "The specified bucket does not exist"], "cname": ".s3.amazonaws.com"},
    {"service": "GitHub Pages", "patterns": ["There isn't a GitHub Pages site here"], "cname": ".github.io"},
    {"service": "Azure", "patterns": ["404 Web Site not found", "<title>Microsoft Azure Web App"], "cname": ".azurewebsites.net"},
    {"service": "Azure CDN", "patterns": ["The requested content does not exist"], "cname": ".azureedge.net"},
    {"service": "GCP Storage", "patterns": ["NoSuchBucket", "The specified bucket does not exist"], "cname": ".storage.googleapis.com"},
    {"service": "Fastly", "patterns": ["Fastly error: unknown domain"], "cname": ".fastly.net"},
    {"service": "Heroku", "patterns": ["No such app", "There's nothing here, yet."], "cname": ".herokuapp.com"},
    {"service": "Shopify", "patterns": ["Sorry, this shop is currently unavailable"], "cname": ".myshopify.com"},
    {"service": "CloudFront", "patterns": ["ERROR: The request could not be satisfied", "Bad request."], "cname": ".cloudfront.net"},
]


def _resolve_cname(host: str) -> List[str]:
    try:
        import socket as _s
        return [a for a in _s.getaddrinfo(host, None) if a[0] == socket.AF_INET] and \
               list({ai[4][0] for ai in _s.getaddrinfo(host, None)}) or []
    except Exception:
        return []


def _http_probe(url: str, timeout: float = 6.0) -> Dict[str, Any]:
    try:
        resp = _SESSION.get(url, timeout=timeout, allow_redirects=True)
        return {"status": resp.status_code, "body": resp.text[:800]}
    except requests.exceptions.Timeout:
        return {"status": 0, "error": "timeout"}
    except requests.exceptions.RequestException as exc:
        return {"status": 0, "error": str(exc)[:200]}


def cloud_misconfig_scan(target_domain: str, max_subdomains: int = 15) -> Dict[str, Any]:
    """Scan a domain for subdomain takeover fingerprints and exposed cloud storage endpoints."""
    if not isinstance(target_domain, str) or not target_domain.strip():
        return _err("target_domain is required")
    domain = target_domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    max_subdomains = max(1, min(int(max_subdomains), 50))
    result: Dict[str, Any] = {"domain": domain, "takeover_candidates": [], "exposed_endpoints": [], "checked": []}

    subs = ["", "www.", "dev.", "staging.", "stage.", "test.", "app.", "api.",
            "cdn.", "static.", "assets.", "s3.", "backup.", "old.", "portal.", "admin."]
    candidates: List[Dict[str, Any]] = []
    for sub in subs[: max_subdomains + 1]:
        host = f"{sub}{domain}"
        cname_ips = _resolve_cname(host)
        entry: Dict[str, Any] = {"host": host, "resolved": bool(cname_ips)}
        if not cname_ips:
            entry["note"] = "DNS NXFAIL/NXDOMAIN"
            result["checked"].append(entry)
            continue
        r = _http_probe(f"https://{host}/")
        body = r.get("body", "")
        entry["http_status"] = r.get("status")
        for fp in _TAKEOVER_FINGERPRINTS:
            if any(p in body for p in fp["patterns"]):
                entry.update({"takeover_fingerprint": fp["service"], "cname_hint": fp["cname"],
                              "severity": "critical",
                              "evidence": truncate(body[:300], 300)})
                candidates.append(entry)
                break
        result["checked"].append(entry)
    result["takeover_candidates"] = candidates

    # exposed cloud storage endpoints commonly referenced by the domain
    probes = [
        f"https://{domain}/.env",
        f"https://{domain}/sitemap.xml",
        f"https://s3.amazonaws.com/{domain}/",
        f"https://{domain}.s3.amazonaws.com/",
        f"https://storage.googleapis.com/{domain}/",
        f"https://{domain}.blob.core.windows.net/",
    ]
    for url in probes:
        r = _http_probe(url, timeout=5.0)
        status, body = r.get("status"), r.get("body", "")
        exposed = status == 200 and "ListBucketResult" not in body or (
            status == 200 and "<ListBucketResult" in body)
        if status == 200:
            result["exposed_endpoints"].append({
                "url": url, "http_status": status, "note": "accessible anonymously",
                "preview": truncate(body[:200], 200),
                "severity": "high" if "/.env" in url else "info",
            })
        elif status == 403 and ("ListBucketResult" in body or "AccessDenied" in body):
            result["exposed_endpoints"].append({"url": url, "http_status": status,
                                                "note": "exists; listing denied"})
    result["takeover_candidates_count"] = len(candidates)
    return result


_DOCKER_SOCK_PATHS = ["/var/run/docker.sock", "/run/docker.sock"]
_DOCKER_TCP_PORTS = [2375, 2376]


def docker_security_audit(docker_host: str = "", timeout: float = 3.0) -> Dict[str, Any]:
    """Audit local/remote Docker daemon exposure: sockets, TCP API, privileged containers, exposed ports."""
    result: Dict[str, Any] = {"docker_available": False, "findings": []}
    timeout = max(1.0, min(float(timeout), 15.0))

    findings = result["findings"]

    # 1. local unix sockets (non-Windows)
    if os.name != "nt":
        for sp in _DOCKER_SOCK_PATHS:
            if os.path.exists(sp):
                findings.append({"check": "socket_present", "path": sp, "severity": "info"})
                perms = None
                try:
                    perms = oct(os.stat(sp).st_mode)[-3:]
                except Exception:
                    pass
                if perms and perms != "600":
                    findings.append({"check": "socket_world_accessible", "path": sp,
                                     "mode": perms, "severity": "critical",
                                     "note": "non-root users can reach the Docker daemon (container escape / host root)"})
                daemon = _docker_api_get(f"http://localhost/v1.41/version", sp, timeout)
                if daemon is not None:
                    result["daemon_reachable"] = True
                break
        else:
            findings.append({"check": "socket_present", "note": "no docker socket found"})

    # 2. TCP daemon on localhost and optional remote host
    targets = ["127.0.0.1"] + ([docker_host] if docker_host and docker_host.strip() else [])
    for host in targets:
        for port in _DOCKER_TCP_PORTS:
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    findings.append({"check": "tcp_daemon_exposed", "host": host, "port": port,
                                     "severity": "critical",
                                     "note": "Docker API over unauthenticated TCP = remote root"})
                    ver = _http_probe(f"http://{host}:{port}/version", timeout=timeout)
                    if ver.get("status") == 200:
                        result.setdefault("tcp_daemons", []).append(
                            {"host": host, "port": port, "version": ver.get("body", "")[:200]})
            except (socket.timeout, OSError):
                continue

    # 3. docker CLI: privileged containers + exposed ports
    try:
        import subprocess
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Ports}}"],
            capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0 and proc.stdout.strip():
            result["docker_available"] = True
            for line in proc.stdout.strip().splitlines():
                parts = line.split("\t")
                cid, name, ports = (parts + ["", "", ""])[:3]
                priv = False
                try:
                    insp = subprocess.run(["docker", "inspect", "--format",
                                           "{{.HostConfig.Privileged}} {{.HostConfig.NetworkMode}}",
                                           cid], capture_output=True, text=True, timeout=timeout)
                    if insp.returncode == 0:
                        priv = insp.stdout.strip().split()[0].lower() == "true"
                except Exception:
                    pass
                if priv:
                    findings.append({"check": "privileged_container", "id": cid, "name": name,
                                     "severity": "critical",
                                     "note": "privileged container can escape to host"})
                if ports:
                    findings.append({"check": "published_ports", "container": name,
                                     "ports": ports, "severity": "info"})
        elif proc.returncode != 0 and "docker" not in result:
            findings.append({"check": "docker_cli", "note": "docker CLI unavailable or daemon down"})
    except FileNotFoundError:
        findings.append({"check": "docker_cli", "note": "docker not installed on this host"})
    except subprocess.TimeoutExpired:
        findings.append({"check": "docker_cli", "note": "docker CLI timed out"})

    result["findings_count"] = len(findings)
    result["critical_count"] = sum(1 for f in findings if f.get("severity") == "critical")
    return result


def _docker_api_get(url: str, sock_path: str, timeout: float) -> Any:
    """GET a Docker API endpoint over a unix socket; returns parsed JSON or None."""
    try:
        import http.client
        import http.client as hc

        class UnixConn(hc.HTTPConnection):
            def __init__(self, path: str, timeout: float = 3.0):
                super().__init__("localhost", timeout=timeout)
                self._sock_path = path

            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect(self._sock_path)

        conn = UnixConn(sock_path, timeout)
        conn.request("GET", urlparse(url).path)
        resp = conn.getresponse()
        data = resp.read(4096)
        conn.close()
        return json.loads(data.decode("utf-8", "ignore")) if data else None
    except Exception:
        return None
