import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_agent.multi_agent_router import (
    AsyncMessageBus, SwarmMessage, SwarmRouter, ReconAgent, AnalyzerAgent,
    ExploitationAgent, MSG_TASK, MSG_DATA, TASK_DONE, TASK_PENDING,
    snapshot_for_memory,
)

fails = []


def check(name, cond):
    print(("[PASS] " if cond else "[FAIL] ") + name)
    if not cond:
        fails.append(name)


NMAP_OUT = (
    "Nmap scan report for 10.0.0.7\n"
    "22/tcp open  ssh\n"
    "80/tcp open  http\n"
    "445/tcp open  microsoft-ds\n"
)


def success_executor(command):
    if command.startswith("nmap"):
        return NMAP_OUT
    return "probe vulnerable - dumped 3 rows (admin hash)"


def waf_executor(command):
    if command.startswith("nmap"):
        return NMAP_OUT
    return "403 Forbidden - blocked by Cloudflare WAF"


# --- 1. Bus basics ---------------------------------------------------------
async def test_bus():
    bus = AsyncMessageBus()
    qa = bus.register("a")
    qb = bus.register("b")
    await bus.send(SwarmMessage(MSG_DATA, "a", recipient="b",
                                payload={"x": 1}))
    m1 = await asyncio.wait_for(qb.get(), 2)
    check("bus point-to-point", m1.payload == {"x": 1})
    await bus.send(SwarmMessage(MSG_DATA, "router", topic="topic_x",
                                payload={"y": 2}))
    ma = await asyncio.wait_for(qa.get(), 2)
    mb = await asyncio.wait_for(qb.get(), 2)
    check("bus broadcast both", ma.payload == {"y": 2}
          and mb.payload == {"y": 2})
    check("bus history", len(bus.history) == 2)
    st = bus.stats()
    check("bus stats", st["messages"] == 2 and set(st["agents"]) == {"a", "b"})
    # duplicate register rejected
    try:
        bus.register("a")
        dup = False
    except ValueError:
        dup = True
    check("bus duplicate rejected", dup)


# --- 2. State machine ------------------------------------------------------
def test_state_machine():
    agent = AnalyzerAgent(AsyncMessageBus())
    ok = agent._set_state("t1", TASK_PENDING)
    check("state initial pending", agent.tasks["t1"] == TASK_PENDING and ok)
    check("state running ok", agent._set_state("t1", "running"))
    check("state done ok", agent._set_state("t1", TASK_DONE))
    bad = agent._set_state("t1", "running")  # done -> running illegal
    check("state illegal rejected", bad is False
          and agent.tasks["t1"] == TASK_DONE)


# --- 3. Recon parsing ------------------------------------------------------
async def test_recon():
    r = ReconAgent(AsyncMessageBus(), tool_executor=success_executor)
    res = await r.execute({"target": "10.0.0.7", "mode": "active"}, {})
    surface = res["surface"]
    host = surface["hosts"].get("10.0.0.7")
    check("recon ports parsed", host and sorted(host["ports"]) ==
          [22, 80, 445])
    check("recon services mapped", "ssh" in host["services"]
          and "http" in host["services"])
    check("recon emit surface topic", res["emit"][0]["topic"] == "surface")


# --- 4. Analyzer -----------------------------------------------------------
async def test_analyzer():
    a = AnalyzerAgent(AsyncMessageBus())
    surface = {"target": "10.0.0.7",
               "hosts": {"10.0.0.7": {"ports": [22, 80, 445],
                                      "services": ["ssh", "http", "smb"]}},
               "tech": ["ssh", "http", "smb"]}
    a.ingest({"surface": surface}, {})
    res = await a.execute({}, a.context)
    classes = {h["vuln_class"] for h in res["hypotheses"]}
    check("analyzer sqli hypo", "sqli" in classes)
    check("analyzer weak_creds hypo", "weak_creds" in classes)
    check("analyzer graph edges", len(res["graph"]["edges"]) >=
          len(res["hypotheses"]))
    pr = [c["priority"] for c in res["candidates"]]
    check("analyzer candidates ranked", pr == sorted(pr, reverse=True))
    check("analyzer ingest context", a.context.get("latest_surface"))


# --- 5. Feedback classification -------------------------------------------
def test_feedback():
    f = ExploitationAgent.analyze_feedback
    check("fb success", f("vulnerable - dumped 5 rows")["outcome"]
          == "success")
    check("fb waf", f("403 blocked by Cloudflare")["outcome"]
          == "needs_mutation")
    check("fb sqli", f("MySQL syntax error near '")["outcome"]
          == "needs_mutation")
    check("fb auth", f("401 authentication failed")["outcome"]
          == "needs_mutation")
    check("fb net", f("connection refused")["outcome"] == "blocked")
    check("fb inconclusive", f("weird output")["outcome"] == "inconclusive")


# --- 6. End-to-end success run --------------------------------------------
def test_e2e_success():
    router = SwarmRouter(tool_executor=success_executor, max_rounds=3)
    summary = router.run_mission_sync("10.0.0.7", mission="full audit")
    check("e2e rounds ran", len(summary["rounds"]) >= 1)
    check("e2e all legs done", all(
        leg["recon"] == "done" and leg["analyzer"] == "done"
        and leg["exploiter"] == "done" for leg in summary["rounds"]))
    check("e2e surface", summary["surface"]
          and summary["surface"]["hosts"])
    check("e2e hypotheses", len(summary["hypotheses"]) >= 3)
    check("e2e pocs recorded", len(summary["pocs"]) >= 1
          and summary["pocs"][0]["steps"])
    check("e2e bus traffic", summary["bus"]["messages"] >= 6)
    check("e2e transcripts", all(
        a.transcript for a in (router.recon, router.analyzer,
                               router.exploiter)))
    blobs = snapshot_for_memory(summary)
    check("e2e memory blobs", any(b["kind"] == "payload" for b in blobs))


# --- 7. Multi-round refinement loop ----------------------------------------
def test_e2e_refinement():
    router = SwarmRouter(tool_executor=waf_executor, max_rounds=2)
    summary = router.run_mission_sync("10.0.0.7")
    check("refine multi-round", len(summary["rounds"]) == 2)
    check("refine no false pocs", len(summary["pocs"]) == 0)
    check("refine feedback logged", all(
        f["outcome"] == "needs_mutation" for f in summary["feedback"]))
    bumped = [c for c in summary["candidates"]
              if c.get("mutations")]
    check("refine priorities bumped", len(bumped) >= 1)


async def run_all():
    await test_bus()
    test_state_machine()
    await test_recon()
    await test_analyzer()
    test_feedback()
    await asyncio.to_thread(test_e2e_success)
    await asyncio.to_thread(test_e2e_refinement)


asyncio.run(run_all())
print("\n%d failed" % len(fails))
sys.exit(1 if fails else 0)
