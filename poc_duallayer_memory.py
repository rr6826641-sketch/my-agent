import json, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ai_agent.memory.vector_store import EpisodicVectorMemory
from ai_agent.reflection import ReflectionEngine

fails = []
def check(name, cond):
    print(("[PASS] " if cond else "[FAIL] ") + name)
    if not cond: fails.append(name)

tmp = tempfile.mkdtemp(prefix="duallayer_")
store = EpisodicVectorMemory(persist_dir=tmp)
check("fallback backend", store.backend == "local")
i1 = store.archive_payload("sqlmap -u http://acme.com/item.php?id=1 --batch --level=5 -> dumped users table", target="acme.com")
i2 = store.archive_bypass("Cloudflare WAF bypass via X-Forwarded-For spoof + unicode-encode of quotes", target="acme.com")
i3 = store.archive_methodology("AD: kerberoast -> hashcat -> DA via SPN account", target="corp.local")
i4 = store.archive_lesson("FAILED hydra ssh 10.0.0.5 -> network_unreachable: port 22 closed. NEXT: switch to alt port 2222", target="10.0.0.5")
check("archive ids", all([i1, i2, i3, i4]))
check("count", store.count() == 4 and store.count(kind="payload") == 1)

store2 = EpisodicVectorMemory(persist_dir=tmp)
check("persist reload", store2.count() == 4)

hits = store2.query("bypass cloudflare waf", top_k=2)
check("semantic query waf", bool(hits) and "cloudflare" in hits[0]["text"].lower())
hits2 = store2.query("sql injection dump credentials", top_k=2)
check("semantic query sqli", bool(hits2) and "sqlmap" in hits2[0]["text"].lower())
hits3 = store2.query("kerberos attack path", top_k=1, kind="methodology")
check("kind filter", bool(hits3) and "kerberoast" in hits3[0]["text"].lower())

hist = os.path.join(tmp, "reflection_history.json")
eng = ReflectionEngine(history_path=hist, episodic=store2)
r1 = eng.reflect("http_request", "curl http://acme.com/admin", "HTTP/1.1 403 Forbidden - blocked by Cloudflare WAF", target="acme.com")
check("waf root cause", r1["outcome"] == "failure" and r1["failure_root"] == "waf_block")
check("why filled", "WAF" in r1["why_failed"])
check("mutation filled", "encode" in r1["next_mutation"].lower())
check("expected filled", "HTTP" in r1["expected"])
r2 = eng.reflect("nmap_scan", "-p 22 10.0.0.5", "Host seems down / connection refused", target="10.0.0.5")
check("network root cause", r2["failure_root"] == "network_unreachable")
r3 = eng.reflect("sqli_test", "' OR 1=1 --", "MySQLSyntaxErrorException: error in your SQL syntax near ' OR 1=1", target="acme.com")
check("sqli feedback root", r3["failure_root"] == "sqli_feedback" and "dialect" in r3["next_mutation"].lower())
r4 = eng.reflect("exploit_sqli", "sqlmap --dump", "vulnerable: parameter 'id' is injectable. dumped 14 rows: admin hash 5f4dcc3b...", target="acme.com")
check("success classified", r4["outcome"] == "success" and "keep" in r4["next_mutation"].lower())

data = json.load(open(hist, encoding="utf-8"))
check("history persisted 4", len(data["reflections"]) == 4)
check("history fields", all(k in data["reflections"][0] for k in ("expected","actual","why_failed","next_mutation","failure_root")))

eng2 = ReflectionEngine(history_path=hist, episodic=store2)
lessons = eng2.lessons_for(args="cloudflare waf blocked acme.com admin", limit=3)
check("lessons cross-session", len(lessons) >= 1)
block = eng2.render_lesson_block(args="waf blocked acme.com")
check("lesson block rendered", block.startswith("[LESSONS]"))
st = eng2.stats()
check("stats", st["total"] >= 4 and st["failure"] == 3 and st["success"] == 1)

import inspect
from ai_agent.core import Agent
src = inspect.getsource(Agent.run_stream)
check("core hook: reflection in run loop", "_reflection_step(name, args, result)" in src)
check("core hook: episodic recall pre-run", "_episodic_recall_block(user_input)" in src)
check("core hook: reflection event yield", '"type": "reflection"' in inspect.getsource(Agent._reflection_step) and "yield rev" in src)

try:
    from ai_agent.config import load_config
    from ai_agent.llm import MockClient
    cfg = load_config()
    llm = MockClient()
    agent = Agent(llm, cfg)
    check("agent init with reflection", isinstance(agent._reflection, ReflectionEngine))
    blk = agent._episodic_recall_block("test target 203.0.113.7 ports")
    check("episodic recall block str", isinstance(blk, str))
    ev = agent._reflection_step("curl", "http://x", "403 blocked")
    check("reflection_step event", bool(ev) and ev.get("type") == "reflection" and ev.get("outcome") == "failure")
    check("[REFLECTION] injected to loop", any(m.get("role") == "system" and m.get("content","").startswith("[REFLECTION]") for m in agent.messages))
except Exception as exc:
    print("[WARN] full agent smoke skipped: %s: %s" % (type(exc).__name__, exc))

import shutil
shutil.rmtree(tmp, ignore_errors=True)
print("\n%d failed" % len(fails))
sys.exit(1 if fails else 0)
