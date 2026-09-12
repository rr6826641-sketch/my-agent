# -*- coding: utf-8 -*-
"""End-to-end acceptance driver: captures the /api/chat SSE stream for a
REAL multi-step task and prints the full event timeline (lifecycle +
tool_call + tool_result + final) with a live /api/exec/stream capture."""
import json
import threading
import time
import urllib.request
import urllib.parse

BASE = "http://127.0.0.1:8081"
TASK = ("Run TWO real steps: 1) shell command: cd /e/HackerAI/my-agent && ls *.py | head -5 "
        "2) then use a file-read tool to read the first 5 lines of webui.py. "
        "Finish with one short sentence.")
exec_rows = []


def exec_watch():
    try:
        req = urllib.request.Request(BASE + "/api/exec/stream", headers={"Accept": "text/event-stream"})
        resp = urllib.request.urlopen(req, timeout=300)
        buf = ""
        while True:
            raw = resp.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("data: "):
                try:
                    exec_rows.append(json.loads(line[6:]))
                except Exception:
                    pass
    except Exception as exc:
        exec_rows.append({"capture_error": str(exc)})


t = threading.Thread(target=exec_watch, daemon=True)
t.start()
time.sleep(1.2)

chat_rows = []
url = BASE + "/api/chat?" + urllib.parse.urlencode({"message": TASK})
req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
t0 = time.time()
try:
    resp = urllib.request.urlopen(req, timeout=280)
    xrun = resp.headers.get("X-Run-Id")
    buf = ""
    while True:
        raw = resp.readline()
        if not raw:
            break
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if line.startswith("data: "):
            try:
                chat_rows.append(json.loads(line[6:]))
            except Exception:
                pass
except Exception as exc:
    chat_rows.append({"capture_error": str(exc)})

dur = time.time() - t0
print("== CHAT STREAM ==")
print("run_id:", xrun)
print("duration_s:", round(dur, 1))
print("total events:", len(chat_rows))
seq = []
for ev in chat_rows:
    ty = ev.get("type")
    extra = ""
    if ty == "tool_call":
        extra = " -> " + str(ev.get("name"))
    elif ty in ("final", "llm", "error"):
        extra = " :: " + str(ev.get("content"))[:80]
    seq.append(ty)
    print("  %-22s%s" % (ty, extra))
print()
print("types seen:", {k: seq.count(k) for k in sorted(set(seq))})

time.sleep(1.0)
print("== EXEC STREAM (live) ==")
print("total exec frames:", len(exec_rows))
from collections import Counter
print("status counts:", dict(Counter(ev.get("status") for ev in exec_rows
                                     if "capture_error" not in ev)))
seen = {}
for ev in exec_rows:
    if "capture_error" in ev:
        print("  capture_error:", ev["capture_error"])
        continue
    cmd = (ev.get("command") or "")[:60]
    key = (ev.get("step_type"), cmd, ev.get("status"))
    seen.setdefault(key, 0)
    seen[key] += 1
for (st, cmd, status), n in sorted(seen.items()):
    print("  step=%-9s %-9s x%-3d %s" % (st, status, n, cmd))

with open("_e2e_chat_raw.txt", "w", encoding="utf-8") as f:
    for ev in chat_rows:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")
print()
print("saved _e2e_chat_raw.txt with", len(chat_rows), "chat events")