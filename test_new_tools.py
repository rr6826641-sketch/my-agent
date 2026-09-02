"""Unit tests for the new HackerAI tool families + mock-mode agent run.

Run:  py test_new_tools.py
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] %s %s" % (name, detail))
    else:
        FAIL += 1
        print("[FAIL] %s %s" % (name, detail))


def run_tests():
    tmp = tempfile.mkdtemp(prefix="hackerai_test_")
    try:
        _test_payloads()
        _test_reporting(tmp)
        _test_scope(tmp)
        _test_webtests()
        _test_rag(tmp)
        _test_spawn_cap()
        _test_mock_agent()
        _test_custom_tools(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _test_payloads():
    from ai_agent.tools.payloads import (
        tool_gen_reverse_shell, tool_gen_bind_shell, tool_gen_webshell,
        tool_gen_listener, tool_gen_obfuscate, tool_gen_wordlist,
    )
    rs = tool_gen_reverse_shell(os_type="linux", lhost="10.0.0.5", lport=4444)
    check("reverse_shell linux", "/bin/bash" in rs or "python" in rs.lower()
          or "nc " in rs, "len=%d" % len(rs))
    rs_w = tool_gen_reverse_shell(os_type="windows", lhost="10.0.0.5", lport=4444)
    check("reverse_shell windows", "New-Object" in rs_w or "$c=" in rs_w
          or "powershell" in rs_w.lower(), "len=%d" % len(rs_w))
    bs = tool_gen_bind_shell(os_type="linux", port=4444)
    check("bind_shell linux", "4444" in bs, "")
    bs_w = tool_gen_bind_shell(os_type="windows", port=9999)
    check("bind_shell windows", "9999" in bs_w, "")
    ws = tool_gen_webshell(platform="php", password="p@ss")
    check("webshell php", "p@ss" in ws and "<?php" in ws, "")
    ws_asp = tool_gen_webshell(platform="asp")
    check("webshell asp", "<%" in ws_asp, "")
    ws_jsp = tool_gen_webshell(platform="jsp")
    check("webshell jsp", "jsp" in ws_jsp.lower() or "<%" in ws_jsp, "")
    lst = tool_gen_listener(lhost="0.0.0.0", lport=5555)
    check("listener", "5555" in lst, "")
    lst_up = tool_gen_listener(upgrade=True)
    check("listener upgrade", "python" in lst_up.lower() or "pty" in lst_up.lower(), "")
    ob = tool_gen_obfuscate(payload="echo pwned", technique="b64", os_type="linux")
    check("obfuscate b64", "base64" in ob or "b64" in ob.lower()
          or "echo" in ob, "")
    wl = tool_gen_wordlist(base_words="admin,root,test", l33t=True)
    check("wordlist l33t", "adm1n" in wl or "r00t" in wl or len(wl) > 20, "")


def _test_reporting(tmp):
    from ai_agent.tools import reporting
    # back up any real engagement data and start fresh
    import json as _json
    import os as _os
    fpath = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                          "findings.jsonl")
    rdir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                         "reports")
    had_findings = _os.path.exists(fpath)
    had_reports = _os.path.isdir(rdir)
    backup = None
    if had_findings:
        with open(fpath, "r", encoding="utf-8") as f:
            backup = f.read()
        _os.remove(fpath)
    r = reporting.tool_add_finding(
        asset="http://target.test/login", title="SQLi in login",
        severity="high", cwe="CWE-89",
        evidence="' OR 1=1 -- returned 200 with admin data",
        impact="Auth bypass + data exfil", remediation="Parameterized queries")
    check("add_finding", "F-" in r, r[:80])
    import re as _re
    m = _re.search(r"F-[0-9A-F]{8}", r)
    fid = m.group(0) if m else ""
    check("add_finding id", bool(fid), r[:80])
    lst = reporting.tool_list_findings()
    check("list_findings", "SQLi" in lst and "high" in lst.lower(), lst[:100])
    upd = reporting.tool_update_finding(finding_id=fid, severity="critical",
                                        status="confirmed")
    check("update_finding", "updated" in upd.lower(), upd[:80])
    lst2 = reporting.tool_list_findings(severity="critical")
    check("list filtered", "SQLi" in lst2, "")
    rep = reporting.tool_write_report(target="target.test")
    check("write_report", rep.endswith(".md") or "report" in rep.lower(), rep[:100])
    if os.path.exists(rep):
        with open(rep, "r", encoding="utf-8") as f:
            content = f.read()
        check("report content", "SQLi" in content and "Critical" in content
              and "CWE-89" in content, "len=%d" % len(content))
    d = reporting.tool_delete_finding(finding_id=fid)
    check("delete_finding", "deleted" in d.lower() or "removed" in d.lower(), d[:60])
    # restore real engagement data
    if backup is not None:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(backup)
    elif had_findings is False and _os.path.exists(fpath):
        _os.remove(fpath)
    if not had_reports and _os.path.isdir(rdir):
        import shutil as _sh
        _sh.rmtree(rdir, ignore_errors=True)


def _test_scope(tmp):
    from ai_agent.tools import scope
    real_path = scope.SCOPE_PATH
    scope.SCOPE_PATH = os.path.join(tmp, "scope.json")
    try:
        _do_scope_tests()
    finally:
        scope.SCOPE_PATH = real_path


def _do_scope_tests():
    from ai_agent.tools import scope
    s = scope.tool_set_scope(targets="target.test,10.0.0.0/24",
                             note="authorized engagement")
    check("set_scope", "target.test" in s and "2" in s, s[:80])
    sh = scope.tool_show_scope()
    check("show_scope", "target.test" in sh and "10.0.0.0/24" in sh, "")
    ok = scope.tool_check_scope(host="target.test")
    check("check_scope inside", "ALLOWED" in ok, ok[:60])
    sub = scope.tool_check_scope(host="api.target.test")
    check("check_scope subdomain", "ALLOWED" in sub, sub[:60])
    out = scope.tool_check_scope(host="evil.com")
    check("check_scope outside", "BLOCKED" in out, out[:60])
    sub_net = scope.tool_check_scope(host="10.0.0.15")
    check("check_scope subnet", "ALLOWED" in sub_net, sub_net[:60])


def _test_webtests():
    from ai_agent.tools import webtests
    # tools are detection probes; they must return structured text without crashing
    out = webtests.tool_sqli_test(url="http://127.0.0.1:9/x?id=1", param="id")
    check("sqli_test no-crash", "sqli" in out.lower() or "no" in out.lower()
          or "error" in out.lower() or "unreachable" in out.lower(), out[:80])
    out = webtests.tool_xss_test(url="http://127.0.0.1:9/x?q=1", param="q")
    check("xss_test no-crash", bool(out), out[:60])
    out = webtests.tool_cmd_inject_test(url="http://127.0.0.1:9/x?cmd=id",
                                        param="cmd")
    check("cmd_inject no-crash", bool(out), out[:60])
    out = webtests.tool_path_traversal_test(
        url="http://127.0.0.1:9/x?file=../../etc/passwd", param="file")
    check("traversal no-crash", bool(out), out[:60])
    out = webtests.tool_ssrf_test(url="http://127.0.0.1:9/x?u=1", param="u")
    check("ssrf no-crash", bool(out), out[:60])
    out = webtests.tool_open_redirect_test(
        url="http://127.0.0.1:9/x?r=https://evil.com", param="r")
    check("open_redirect no-crash", bool(out), out[:60])


def _test_rag(tmp):
    from ai_agent.memory_store import MemoryStore
    docdir = os.path.join(tmp, "docs")
    os.makedirs(docdir)
    with open(os.path.join(docdir, "sql_cheatsheet.md"), "w",
              encoding="utf-8") as f:
        f.write("SQL injection cheat sheet. Use ' OR 1=1 -- to bypass login. "
                "Union select extracts columns. Blind boolean payloads "
                "validate with AND 1=1. Error-based uses extractvalue.\n")
    with open(os.path.join(docdir, "notes.txt"), "w", encoding="utf-8") as f:
        f.write("Target: target.test. Admin panel at /admin. Credentials "
                "stored in config. Scan results saved to reports.\n")
    mem = MemoryStore(os.path.join(tmp, "mem.json"))
    res = mem.index_documents(docdir)
    check("rag_index", "Indexed 2 files" in res, res)
    vs = mem.vector_search("sql injection union", top_k=3)
    check("vector_search sql", "sql_cheatsheet" in vs, vs[:80])
    vs2 = mem.vector_search("admin credentials target", top_k=3)
    check("vector_search notes", "notes.txt" in vs2, vs2[:80])
    n, d = mem.doc_stats()
    check("doc_stats", n >= 2, "docs=%d notes=%d" % (n, d))


def _test_spawn_cap():
    from ai_agent.core import Agent
    from ai_agent.llm import MockClient
    agent = Agent(llm=MockClient(), name="tester",
                  max_iterations=5, allow_subagents=True)
    tasks = ["say one", "say two", "say three", "say four", "say five",
             "say six", "say seven", "say eight", "say nine", "say ten"]
    # async single spawn returns agent_id immediately (managed protocol)
    one = agent.spawn_agent("say hello")
    check("spawn_agent async id", "agent_id" in one, one[:80])
    # legacy synchronous single spawn still works (wait=True routing)
    one_sync = agent._spawn_impl("say hello")
    check("spawn_agent single", bool(one_sync), str(one_sync)[:60])
    # string-form with ||| separator, synchronous (wait=True) - drains
    out2 = agent.spawn_agents("task a ||| task b ||| task c", wait=True)
    check("spawn_agents pipe-sep", "Sub-agent 3" in out2, "")
    # json-form, synchronous
    out3 = agent.spawn_agents(json.dumps(["x", "y"]), wait=True)
    check("spawn_agents json", "Sub-agent 2" in out3, "")
    # empty -> error
    err = agent.spawn_agents("")
    check("spawn_agents empty", "Error" in err, err[:60])
    # legacy parallel path: bounded at 4 tracked, sync result shows 1..4
    sync = agent._spawn_parallel_impl(tasks, timeout=30)
    check("spawn_parallel cap4", "Sub-agent 4" in sync
          and "Sub-agent 5" not in sync, "agents listed")
    # async multi-spawn: at most 4 tracked, excess tasks rejected
    out = agent.spawn_agents(tasks)
    data = json.loads(out)
    check("spawn_agents spawned4", data.get("spawned") == 4
          and data.get("rejected") == 6, "spawned=%s rejected=%s"
          % (data.get("spawned"), data.get("rejected")))
    errors = [s for s in data.get("queued_or_running", [])
              if "error" in s]
    check("spawn_agents reject msg", errors
          and "cap (4) reached" in errors[0]["error"], errors)


def _test_mock_agent():
    from ai_agent.core import Agent
    from ai_agent.llm import MockClient
    from ai_agent.memory_store import MemoryStore
    import tempfile as tf
    with tf.TemporaryDirectory() as td:
        mem = MemoryStore(os.path.join(td, "mem.json"))
        agent = Agent(llm=MockClient(), memory=mem, name="HackerAI",
                      max_iterations=10)
        out = agent.run("list tools")
        check("mock run list tools", "run_terminal" in out, out[:80])
        agent.reset()
        out = agent.run("system info")
        check("mock run system info", bool(out.strip()), out[:80])
        agent.reset()
        out = agent.run("spawns [\"say a\", \"say b\"]")
        check("mock run spawns", ("agent_id" in out or "spawned" in out)
              and "UNVERIFIED" in out, out[:120])


def _test_custom_tools(tmp):
    from ai_agent.tools.custom import (
        tool_sha1_quick, tool_strings_extract, tool_html_to_text,
        tool_dedupe_lines, tool_count_lines,
    )
    p = os.path.join(tmp, "sample.txt")
    with open(p, "w", encoding="utf-8") as f:
        f.write("hello world\nhello world\nunique line\n")
    h = tool_sha1_quick(path=p)
    import re as _re2
    m = _re2.search(r"\b[0-9a-f]{40}\b", h)
    check("sha1_quick", bool(m), h)
    s = tool_strings_extract(path=p, min_len=3)
    check("strings_extract", "hello" in s and "unique" in s, s[:60])
    ht = tool_html_to_text(source="<html><body><h1>Title</h1><p>Body text</p></body></html>")
    check("html_to_text", "Title" in ht and "Body text" in ht, ht[:60])
    d = tool_dedupe_lines(path=p)
    check("dedupe_lines", "2" in d or "1" in d, d[:60])
    c = tool_count_lines(path=p)
    check("count_lines", "3" in c, c[:60])

    # ---- Parallel Tool Execution Maximizer regression tests ----
    from ai_agent.core import Agent

    def _mkcall(tag, name, **kwargs):
        return {"id": "call_%s" % tag,
                "function": {"name": name,
                             "arguments": json.dumps(kwargs or {})}}

    ag = Agent(llm=object())

    # independent recon fan-out -> ONE parallel batch
    batch = ag._plan_tool_batches([
        _mkcall("dns", "dns_lookup", host="example.com"),
        _mkcall("scan", "port_scan", host="example.com"),
        _mkcall("hdrs", "check_headers", url="http://example.com"),
    ])
    check("parallel_batch_independent",
          len(batch) == 1 and len(batch[0]) == 3,
          "expected 1 batch of 3, got %s" % [len(b) for b in batch])

    # same stateful family -> strictly sequential
    batch = ag._plan_tool_batches([
        _mkcall("b1", "browse_page", url="http://a"),
        _mkcall("b2", "browse_page", url="http://b"),
    ])
    check("parallel_batch_same_family",
          len(batch) == 2, "expected 2 batches, got %d" % len(batch))

    # cross-family path dependency: write_file -> run_python same path
    batch = ag._plan_tool_batches([
        _mkcall("w", "write_file", path="/tmp/poc.py", content="x"),
        _mkcall("r", "run_python", script_path="/tmp/poc.py"),
    ])
    check("parallel_batch_path_dep",
          len(batch) == 2, "expected 2 batches, got %d" % len(batch))

    # different paths -> independent, same batch
    batch = ag._plan_tool_batches([
        _mkcall("w", "write_file", path="/tmp/a.py", content="x"),
        _mkcall("r", "run_python", script_path="/tmp/b.py"),
    ])
    check("parallel_batch_path_indep",
          len(batch) == 1, "expected 1 batch, got %d" % len(batch))


if __name__ == "__main__":
    print("=== HackerAI new-tools unit tests ===")
    t0 = time.time()
    run_tests()
    dt = time.time() - t0
    print("\n%d passed, %d failed (%.1fs)" % (PASS, FAIL, dt))
    sys.exit(1 if FAIL else 0)
