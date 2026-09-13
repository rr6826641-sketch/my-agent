#!/usr/bin/env python3
"""Payload Memory Fusion (ULTRA upgrade).

Fuses payload/loot evidence ACROSS every war-room campaign so the swarm
never re-invents a technique and always reuses the highest-scoring payload
chain. Persists to PROJECT_DIR/payload_memory.json.
"""
from __future__ import annotations

import datetime as _dt
import json
import math
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional

from ai_agent.config import PROJECT_DIR

_DEFAULT_MEMORY_PATH = os.path.join(PROJECT_DIR, "payload_memory.json")
_HALF_LIFE_SEC = 7 * 24 * 3600
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_TECH_TAGS = ("nuclei:", "poc", "exploit", "rce", "sqli", "xss", "ssrf",
              "lfi", "idor", "upload", "deserial", "auth-bypass", "default-creds")


class PayloadMemory:
    """Cross-campaign payload memory with fusion ranking."""

    def __init__(self, path: str = _DEFAULT_MEMORY_PATH):
        self.path = path
        self._records: List[dict] = []
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
            self._records = data.get("records", []) if isinstance(data, dict) else (data or [])
        except Exception:
            self._records = []

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"version": 2, "updated": time.time(),
                           "records": self._records}, fh, indent=1)
            os.replace(tmp, self.path)
        except Exception:
            pass

    @staticmethod
    def _svc_key(service, port) -> str:
        svc = (service or "unknown").strip().lower() or "unknown"
        return "%s/%s" % (svc, port)

    @classmethod
    def extract_from_campaign(cls, d: Dict[str, Any]) -> List[dict]:
        """Pull payload records out of a war-room campaign dict."""
        if not isinstance(d, dict):
            return []
        phases = d.get("phases") or {}
        seen: Dict[str, dict] = {}
        for e in (phases.get("exploit") or {}).get("targets", []) or []:
            if not isinstance(e, dict):
                continue
            key = cls._svc_key(e.get("service"), e.get("port"))
            rec = seen.setdefault(key, {
                "svc_key": key,
                "service": (e.get("service") or "unknown").strip().lower() or "unknown",
                "port": e.get("port"),
                "cves": [], "technique": "", "snippet": "", "hits": 0})
            cves = sorted({c for c in (e.get("cves") or [])
                           if _CVE_RE.fullmatch(str(c).strip())})
            rec["cves"] = sorted(set(rec["cves"]) | set(cves))
            if e.get("snippet"):
                rec["snippet"] = str(e["snippet"])[:240]
            nuclei = (e.get("nuclei") or "").lower()
            tags = [t for t in _TECH_TAGS if t in nuclei]
            if tags:
                t = "nuclei:%s" % ("|".join(tags[:3]))
                cur = set(p.replace("nuclei:", "") for p in (rec["technique"] or "").split("|") if p)
                cur |= set(p.replace("nuclei:", "") for p in t.split("|") if p)
                rec["technique"] = "nuclei:" + "|".join(sorted(cur))
            if cves or tags:
                rec["hits"] += 1
        for h in (phases.get("recon") or {}).get("hosts", []) or []:
            if not isinstance(h, dict):
                continue
            for p in (h.get("ports") or []) or []:
                if not isinstance(p, dict):
                    continue
                key = cls._svc_key(p.get("service"), p.get("port"))
                if key not in seen:
                    seen[key] = {"svc_key": key,
                                 "service": (p.get("service") or "unknown").strip().lower() or "unknown",
                                 "port": p.get("port"),
                                 "cves": [], "technique": "", "snippet": "", "hits": 0}
        return list(seen.values())

    def ingest(self, d: Dict[str, Any], campaign_key: str = "") -> int:
        """Merge one campaign's payloads into memory. Returns # merged."""
        merged = 0
        now = time.time()
        key = campaign_key or str(uuid.uuid4())[:8]
        for rec in self.extract_from_campaign(d):
            target = next((r for r in self._records
                           if r["svc_key"] == rec["svc_key"]), None)
            if target is None:
                rec.update({"campaigns": [key], "first_seen": now,
                            "last_seen": now, "score": 0.0})
                self._records.append(rec)
            else:
                target["hits"] = int(target.get("hits", 0)) + int(rec["hits"])
                target["cves"] = sorted(set(target.get("cves", [])) | set(rec["cves"]))
                if rec.get("technique"):
                    cur = set(p.replace("nuclei:", "") for p in (target.get("technique") or "").split("|") if p)
                    cur |= set(p.replace("nuclei:", "") for p in rec["technique"].split("|") if p)
                    target["technique"] = "nuclei:" + "|".join(sorted(cur))
                if rec.get("snippet") and not target.get("snippet"):
                    target["snippet"] = rec["snippet"]
                camps = target.setdefault("campaigns", [])
                if key not in camps:
                    camps.append(key)
                target["last_seen"] = now
            merged += 1
        self._save()
        return merged

    @staticmethod
    def _fusion_score(rec: dict, now: float) -> float:
        n_camps = max(1, len(rec.get("campaigns") or []))
        hits = int(rec.get("hits", 0))
        cam_hits = int(rec.get("campaign_hits", 0))
        hit_ratio = min(1.0, (cam_hits or hits) / n_camps)
        last = float(rec.get("last_seen", now))
        recency = math.exp(-max(0.0, now - last) / _HALF_LIFE_SEC)
        spread = min(1.0, n_camps / 5.0)
        return round(0.55 * hit_ratio + 0.30 * recency + 0.15 * spread, 3)

    def fuse(self, min_hits: int = 0) -> List[dict]:
        """Return fused payload rankings (highest score first)."""
        now = time.time()
        out = []
        for rec in self._records:
            scored = dict(rec)
            scored["campaign_hits"] = min(
                len(scored.get("campaigns", [])), int(scored.get("hits", 0)))
            scored["score"] = self._fusion_score(scored, now)
            scored["last_seen_iso"] = _dt.datetime.fromtimestamp(
                float(scored.get("last_seen", now))).strftime("%Y-%m-%d %H:%M")
            out.append(scored)
        out.sort(key=lambda r: r["score"], reverse=True)
        return [r for r in out if int(r.get("hits", 0)) >= min_hits]

    def stats(self) -> dict:
        fused = self.fuse()
        return {
            "records": len(self._records),
            "fused": len(fused),
            "cross_campaign": sum(1 for r in fused if len(r.get("campaigns", [])) > 1),
            "top_services": [r["svc_key"] for r in fused[:8]],
            "last_updated": os.path.getmtime(self.path) if os.path.exists(self.path) else None,
        }


def fuse_campaigns(campaigns_dir: Optional[str] = None,
                   memory: Optional[PayloadMemory] = None) -> dict:
    """One-shot: scan every campaign JSON, ingest + fuse, return report."""
    mem = memory or PayloadMemory()
    base = campaigns_dir or os.path.join(PROJECT_DIR, "campaigns")
    ingested = 0
    if os.path.isdir(base):
        for root, _dirs, files in os.walk(base):
            for fn in sorted(files):
                if not fn.endswith(".json"):
                    continue
                full = os.path.join(root, fn)
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
                        d = json.load(fh)
                except Exception:
                    continue
                key = os.path.relpath(full, base)[:-5].replace(os.sep, "/")
                ingested += mem.ingest(d, key)
    return {"ingested": ingested, "stats": mem.stats(),
            "payloads": mem.fuse()}
