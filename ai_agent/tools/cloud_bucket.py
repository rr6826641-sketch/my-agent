# -*- coding: utf-8 -*-
"""
Cloud Bucket Enumerator (bundle #5)

tools:
  s3_bucket_enum     - AWS S3: {keyword}.s3.amazonaws.com brute-force + public
                       listing check (list-type=2); 403=exists/private,
                       404=does-not-exist -> public bucket = data leak
  azure_blob_enum    - Azure Blob Storage: {name}.blob.core.windows.net open
                       container listing check
  gcs_bucket_enum    - Google Cloud Storage: storage.googleapis.com/{name}
                       + {name}.storage.googleapis.com public bucket check
  cloud_bucket_pack  - one-shot sweep across S3 + Azure + GCP

Heuristic engine: "public"/"listing" flags are LEADS for manual validation -
this module never downloads object content.
"""
import json
import re
import ssl
import time
import threading
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

try:
    from concurrent.futures import ThreadPoolExecutor
except Exception:  # pragma: no cover
    ThreadPoolExecutor = None

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) cloud-bucket-enum/1.0"
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def _http_get(url, timeout=10, max_bytes=262144):
    """GET with proxy bypass; returns (status, body, err)."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(max_bytes)
            return (getattr(r, "status", 200), raw.decode("utf-8", "replace"), None)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(max_bytes)
            return (e.code, raw.decode("utf-8", "replace"), None)
        except Exception:
            return (e.code, "", None)
    except Exception as e:
        return (0, "", "%s: %s" % (type(e).__name__, e))


# -- URL builders (monkeypatchable for offline smoke tests) --------------
def _s3_base(name):
    return "https://%s.s3.amazonaws.com" % name


def _azure_base(name):
    return "https://%s.blob.core.windows.net" % name


def _gcs_base(name):
    return "https://storage.googleapis.com/%s" % name


def _gcs_base2(name):
    return "https://%s.storage.googleapis.com" % name


# -- bucket name generation ----------------------------------------------
_CANDIDATES = [
    "", "-prod", "-production", "-dev", "-development", "-test", "-testing",
    "-staging", "-stage", "-qa", "-uat", "-demo", "-sandbox", "-backup",
    "-backups", "-bak", "-old", "-archive", "-archives", "-snapshots",
    "-data", "-db", "-database", "-files", "-file", "-uploads", "-upload",
    "-media", "-assets", "-static", "-public", "-private", "-internal",
    "-external", "-logs", "-log", "-tmp", "-temp", "-downloads", "-download",
    "-images", "-img", "-docs", "-documents", "-storage", "-cdn", "-exports",
    "-imports", "-dump", "-dumps", "-keys", "-secrets", "-config", "-bkp",
    "-copy", "-v2", "-2", "-2020", "-2021", "-2022", "-2023", "-2024",
    "-2025", "-2026",
]
_VALID_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")


def _gen_names(keyword, wordlist="", max_names=40):
    """keyword permutations + optional wordlist -> deduped name list."""
    seen, out = set(), []
    kw = (keyword or "").strip().lower().replace("_", "-")

    def _push(n):
        if n and n not in seen and _VALID_BUCKET.match(n):
            seen.add(n)
            out.append(n)

    if kw:
        _push(kw)
        for c in _CANDIDATES:
            _push(kw + c)
            if len(out) >= max_names:
                break
    if wordlist:
        try:
            with open(wordlist, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    n = line.strip().lower().replace("_", "-")
                    if n and _VALID_BUCKET.match(n) and n not in seen:
                        seen.add(n)
                        out.append(n)
                        if len(out) >= max_names:
                            break
        except Exception as e:
            out.append("__WL_ERR__:%s" % e)
    return out[:max_names]


def _keys_in_xml(xml_text):
    """count <Key>/<Name> entries in S3/Azure/GCS XML listing."""
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return 0, 0
    count, bytes_ = 0, 0
    for el in root.iter():
        tag = el.tag.lower() if isinstance(el.tag, str) else ""
        if tag.endswith("key") or tag.endswith("name"):
            t = (el.text or "").strip()
            if t:
                count += 1
                bytes_ += len(t)
    return count, bytes_


# -- per-cloud checkers -----------------------------------------------
def _check_s3(name, timeout=10):
    """None = not found; else dict with public/listing/objects info."""
    base = _s3_base(name)
    st, body, err = _http_get(base + "/?list-type=2&max-keys=1000", timeout=timeout)
    if st == 200:
        nk, bl = _keys_in_xml(body)
        return {"name": name, "base": base, "exists": True, "public": True,
                "listing": True, "objects_seen": nk, "status": 200,
                "note": "%d object(s) listed (~%d bytes in names) - PUBLIC" % (nk, bl)}
    if st == 403:
        return {"name": name, "base": base, "exists": True, "public": False,
                "listing": False, "objects_seen": 0, "status": 403,
                "note": "bucket exists but access denied (403) - private name lead"}
    if st in (404, 410):
        return None
    if st == 0:
        return {"name": name, "base": base, "exists": None, "public": None,
                "listing": False, "objects_seen": 0, "status": 0,
                "note": "request failed (timeout/DNS/network): %s" % (err or "")}
    return {"name": name, "base": base, "exists": True, "public": None,
            "listing": False, "objects_seen": 0, "status": st,
            "note": "unexpected status %d" % st}


def _check_azure(name, timeout=10):
    """Azure Blob container listing check (container name == bucket name)."""
    base = _azure_base(name)
    st, body, err = _http_get(base + "/?restype=container&comp=list", timeout=timeout)
    if st == 200:
        nk, bl = _keys_in_xml(body)
        return {"name": name, "base": base, "exists": True, "public": True,
                "listing": True, "objects_seen": nk, "status": 200,
                "note": "%d blob(s) listed (~%d bytes) - PUBLIC container" % (nk, bl)}
    if st in (403, 409):
        return {"name": name, "base": base, "exists": True, "public": False,
                "listing": False, "objects_seen": 0, "status": st,
                "note": "container exists but access denied (%d) - private lead" % st}
    if st in (404, 410):
        return None
    if st == 0:
        return {"name": name, "base": base, "exists": None, "public": None,
                "listing": False, "objects_seen": 0, "status": 0,
                "note": "request failed (timeout/DNS/network): %s" % (err or "")}
    return {"name": name, "base": base, "exists": True, "public": None,
            "listing": False, "objects_seen": 0, "status": st,
            "note": "unexpected status %d" % st}


def _check_gcs(name, timeout=10):
    """GCS public bucket check (storage.googleapis.com first, then *.host)."""
    for base in (_gcs_base(name), _gcs_base2(name)):
        st, body, err = _http_get(base + "/", timeout=timeout)
        if st == 200:
            nk, bl = _keys_in_xml(body)
            return {"name": name, "base": base, "exists": True, "public": True,
                    "listing": True, "objects_seen": nk, "status": 200,
                    "note": "%d object(s) listed (~%d bytes) - PUBLIC bucket" % (nk, bl)}
        if st == 403:
            return {"name": name, "base": base, "exists": True, "public": False,
                    "listing": False, "objects_seen": 0, "status": 403,
                    "note": "bucket exists but access denied (403) - private name lead"}
        if st == 0:
            return {"name": name, "base": base, "exists": None, "public": None,
                    "listing": False, "objects_seen": 0, "status": 0,
                    "note": "request failed (timeout/DNS/network): %s" % (err or "")}
    return None


# -- concurrent scan engine -------------------------------------------
def _scan_names(names, checker, timeout=10, workers=4, sleep_ms=150,
                budget_sec=75):
    """Run checker over names with bounded concurrency + time budget."""
    out, errors, t0 = [], 0, time.time()
    lock = threading.Lock()

    def work(n):
        if time.time() - t0 > budget_sec:
            return
        time.sleep(sleep_ms / 1000.0)
        try:
            r = checker(n, timeout=timeout)
        except Exception as e:
            r = {"name": n, "exists": None, "public": None, "listing": False,
                 "objects_seen": 0, "status": 0,
                 "note": "exception: %s" % e}
        if r is None:
            return
        with lock:
            if r.get("status") in (0, None):
                errors += 1
            else:
                out.append(r)

    if ThreadPoolExecutor and len(names) > 1:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(work, names))
    else:
        for n in names:
            work(n)
    return out, errors


def _bundle_result(tool_name, keyword, names, res, errors, wl_err, cloud_label):
    public = sorted([r for r in res if r.get("public")],
                    key=lambda r: -r.get("objects_seen", 0))
    private = sorted([r for r in res if r.get("exists") and not r.get("public")],
                     key=lambda r: r["name"])
    return json.dumps({
        "tool": tool_name,
        "keyword": keyword,
        "names_tested": len(names),
        "public": public,
        "private_but_exists": private,
        "request_errors": errors,
        "wordlist_error": wl_err[0][11:] if wl_err else None,
        "summary": "%s: %d/%d names public, %d private, %d request errors" % (
            cloud_label, len(public), len(names), len(private), errors),
    }, ensure_ascii=False, indent=1)


def tool_s3_bucket_enum(keyword="", wordlist="", max_names=40, timeout=10,
                        workers=4, sleep_ms=150, budget_sec=75):
    """AWS S3 bucket brute-force: {keyword}*.s3.amazonaws.com
    Flags PUBLIC buckets (listing enabled -> data leak) and private-but-existing
    names as leads.
    """
    if not (keyword or wordlist):
        return json.dumps({"tool": "s3_bucket_enum",
                           "error": "keyword or wordlist file is required (e.g. "
                                    "keyword='acme' or wordlist='paths/to/buckets.txt')"},
                          ensure_ascii=False)
    names = _gen_names(keyword, wordlist, max_names=max(max_names, 1))
    wl_err = [n for n in names if n.startswith("__WL_ERR__")]
    names = [n for n in names if not n.startswith("__WL_ERR__")]
    res, errors = _scan_names(names, _check_s3, timeout=timeout, workers=workers,
                              sleep_ms=sleep_ms, budget_sec=budget_sec)
    return _bundle_result("s3_bucket_enum", keyword, names, res, errors,
                          wl_err, "AWS S3")


def tool_azure_blob_enum(keyword="", wordlist="", container="", max_names=40,
                         timeout=10, workers=4, sleep_ms=150, budget_sec=75):
    """Azure Blob Storage open-container scan:
    {name}.blob.core.windows.net/?restype=container&comp=list
    Flags publicly listed containers (data leak) + private-but-existing names.
    """
    if not (keyword or wordlist):
        return json.dumps({"tool": "azure_blob_enum",
                           "error": "keyword or wordlist file is required"},
                          ensure_ascii=False)
    names = _gen_names(keyword, wordlist, max_names=max(max_names, 1))
    wl_err = [n for n in names if n.startswith("__WL_ERR__")]
    names = [n for n in names if not n.startswith("__WL_ERR__")]
    res, errors = _scan_names(names, _check_azure, timeout=timeout, workers=workers,
                              sleep_ms=sleep_ms, budget_sec=budget_sec)
    return _bundle_result("azure_blob_enum", keyword, names, res, errors,
                          wl_err, "Azure Blob")


def tool_gcs_bucket_enum(keyword="", wordlist="", max_names=40, timeout=10,
                         workers=4, sleep_ms=150, budget_sec=75):
    """Google Cloud Storage public bucket scan:
    storage.googleapis.com/{name} (+ {name}.storage.googleapis.com fallback)
    Flags PUBLIC buckets (listing enabled -> data leak) + private name leads.
    """
    if not (keyword or wordlist):
        return json.dumps({"tool": "gcs_bucket_enum",
                           "error": "keyword or wordlist file is required"},
                          ensure_ascii=False)
    names = _gen_names(keyword, wordlist, max_names=max(max_names, 1))
    wl_err = [n for n in names if n.startswith("__WL_ERR__")]
    names = [n for n in names if not n.startswith("__WL_ERR__")]
    res, errors = _scan_names(names, _check_gcs, timeout=timeout, workers=workers,
                              sleep_ms=sleep_ms, budget_sec=budget_sec)
    return _bundle_result("gcs_bucket_enum", keyword, names, res, errors,
                          wl_err, "GCS")


def tool_cloud_bucket_pack(keyword="", wordlist="", clouds="s3,azure,gcs",
                           max_names=40, timeout=10, workers=4, sleep_ms=150,
                           budget_sec=60):
    """One-shot sweep across AWS S3 + Azure Blob + GCS for the same name set.
    clouds='s3,azure,gcs' (any subset). Public bucket = data leak -> easy win.
    """
    if not (keyword or wordlist):
        return json.dumps({"tool": "cloud_bucket_pack",
                           "error": "keyword or wordlist file is required"},
                          ensure_ascii=False)
    sel = [c.strip().lower() for c in (clouds or "s3,azure,gcs").split(",")
           if c.strip().lower() in ("s3", "azure", "gcs")]
    if not sel:
        return json.dumps({"tool": "cloud_bucket_pack",
                           "error": "clouds must be a comma list of s3|azure|gcs"},
                          ensure_ascii=False)
    names = _gen_names(keyword, wordlist, max_names=max(max_names, 1))
    wl_err = [n for n in names if n.startswith("__WL_ERR__")]
    names = [n for n in names if not n.startswith("__WL_ERR__")]
    per_cloud = {}
    total_err = 0
    for c in sel:
        checker = {"s3": _check_s3, "azure": _check_azure, "gcs": _check_gcs}[c]
        res, errors = _scan_names(names, checker, timeout=timeout, workers=workers,
                                  sleep_ms=sleep_ms, budget_sec=budget_sec)
        per_cloud[c] = {"public": [r for r in res if r.get("public")],
                        "private": [r for r in res if r.get("exists")
                                    and not r.get("public")]}
        total_err += errors
    n_public = sum(len(v["public"]) for v in per_cloud.values())
    return json.dumps({
        "tool": "cloud_bucket_pack",
        "keyword": keyword,
        "clouds_scanned": sel,
        "names_tested": len(names),
        "results": per_cloud,
        "request_errors": total_err,
        "wordlist_error": wl_err[0][11:] if wl_err else None,
        "summary": "PACK: %d public bucket(s) across %s from %d names (%d req errors)"
                   % (n_public, "+".join(sel), len(names), total_err),
    }, ensure_ascii=False, indent=1)
