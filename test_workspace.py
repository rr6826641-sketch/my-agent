"""Unit tests for the workspace repository-mapping & cross-reference indexer.

Covers:
  Part 1 - symbol / import extraction (ai_agent/tools/workspace.py)
  Part 2 - WorkspaceIndex: scan, dependency graph, reverse dependents,
           cross-reference symbol lookup, incremental re-scan
  Part 3 - tool_* entry points (scan / symbols / deps / query / export)
  Part 4 - Agent integration: workspace map injected into the system
           prompt, multi-turn awareness, tool exposure + execution

Run:  py test_workspace.py
"""
import json
import os
import shutil
import sys
import tempfile
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


def make_fixture():
    """Create a small multi-language workspace and return its root path."""
    root = tempfile.mkdtemp(prefix="ws_test_")
    # python package
    pkg = os.path.join(root, "app")
    os.makedirs(pkg)
    with open(os.path.join(pkg, "__init__.py"), "w", encoding="utf-8") as f:
        f.write("")
    with open(os.path.join(pkg, "utils.py"), "w", encoding="utf-8") as f:
        f.write("def helper(x):\n"
                "    return x * 2\n"
                "\n"
                "class Engine:\n"
                "    def start(self):\n"
                "        return 'vroom'\n")
    with open(os.path.join(pkg, "main.py"), "w", encoding="utf-8") as f:
        f.write("from app.utils import helper, Engine\n"
                "import os\n"
                "\n"
                "result = helper(4)\n"
                "engine = Engine()\n")
    # javascript pair with a local + external import
    web = os.path.join(root, "web")
    os.makedirs(web)
    with open(os.path.join(web, "util.js"), "w", encoding="utf-8") as f:
        f.write("export function fmt(n) {\n"
                "  return String(n);\n"
                "}\n")
    with open(os.path.join(web, "index.js"), "w", encoding="utf-8") as f:
        f.write("import { fmt } from './util.js'\n"
                "const s = require('os')\n")
    # ignored dirs must NOT be indexed
    for d in ("node_modules", "__pycache__"):
        os.makedirs(os.path.join(root, d))
        with open(os.path.join(root, d, "junk.py"), "w",
                  encoding="utf-8") as f:
            f.write("def shadow():\n    pass\n")
    return root


# ---------------------------------------------------------------------------
# Part 1 - extraction primitives
# ---------------------------------------------------------------------------

def _test_extract_symbols():
    from ai_agent.tools.workspace import extract_symbols
    src = ("def helper(x):\n"
           "    return x * 2\n"
           "\n"
           "class Engine:\n"
           "    def start(self):\n"
           "        return 'vroom'\n"
           "# def commented(): pass\n")
    syms = extract_symbols(src, "python")
    kinds = [(k, n) for k, n, s, ln in syms]
    check("python function", ("function", "helper") in kinds, str(kinds))
    check("python class", ("class", "Engine") in kinds, str(kinds))
    check("python method", ("function", "start") in kinds, str(kinds))
    check("comments ignored", not any(n == "commented" for _, n in kinds),
          str(kinds))
    js = extract_symbols("export function fmt(n) {\n}", "javascript")
    check("js function", any(n == "fmt" for _, n, _, _ in js), str(js))
    check("unknown lang empty", extract_symbols("def x(): pass", "brainfuck")
          == [])


def _test_extract_imports():
    from ai_agent.tools.workspace import extract_imports
    py = ("from app.utils import helper, Engine\n"
          "import os\n"
          "from . import sibling\n")
    imps = [t for t, ln in extract_imports(py, "python")]
    check("from-import module", "app.utils" in imps, str(imps))
    check("from-import symbol cand", "app.utils.helper" in imps, str(imps))
    check("plain import", "os" in imps, str(imps))
    check("relative import", ".sibling" in imps, str(imps))
    js = extract_imports("import { fmt } from './util.js'\n"
                         "const s = require('os')\n", "javascript")
    jt = [t for t, ln in js]
    check("js es import", "./util.js" in jt, str(jt))
    check("js require", "os" in jt, str(jt))


# ---------------------------------------------------------------------------
# Part 2 - WorkspaceIndex
# ---------------------------------------------------------------------------

def _test_index_scan():
    from ai_agent.tools.workspace import WorkspaceIndex
    root = make_fixture()
    try:
        idx = WorkspaceIndex()
        res = idx.scan(root)
        check("scan ok", "error" not in res, str(res))
        check("files indexed", res["files"] == 5,
              "files=%d" % res["files"])
        check("languages", res["languages"].get("python") == 3
              and res["languages"].get("javascript") == 2,
              str(res["languages"]))
        check("symbols counted", res["symbols"] >= 4,
              "symbols=%d" % res["symbols"])
        rels = [r["rel"].replace("\\", "/") for r in idx.files.values()]
        check("ignored dirs skipped",
              not any("junk.py" in r or "node_modules" in r or
                      "__pycache__" in r for r in rels),
              str(rels))
        rec = idx.files.get(os.path.join(root, "app", "utils.py"))
        check("utils record", rec is not None and rec["symbols"],
              "")
        if rec:
            names = [s["name"] for s in rec["symbols"]]
            check("utils symbols", "helper" in names and "Engine" in names
                  and "start" in names, str(names))
        # duplicate scan (same root) must be a cheap no-op success
        res2 = idx.scan(root)
        check("re-scan idempotent", res2.get("files") == 5,
              str(res2.get("files")))
        check("root is abs", os.path.isabs(res["root"]), res["root"])
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _test_dependency_graph():
    from ai_agent.tools.workspace import WorkspaceIndex
    root = make_fixture()
    try:
        idx = WorkspaceIndex()
        idx.scan(root)
        deps = idx.dependencies("app/main.py")
        check("deps ok", "error" not in deps, str(deps))
        internal = [d["file"] for d in deps["internal_dependencies"]]
        check("internal dep resolved", "app/utils.py" in internal,
              str(internal))
        check("external dep", "os" in deps["external_dependencies"],
              str(deps["external_dependencies"]))
        rev = idx.dependents("app/utils.py")
        check("reverse dependents", "app/main.py" in rev["dependents"],
              str(rev))
        rev_js = idx.dependents("web/util.js")
        check("js dependents", "web/index.js" in rev_js["dependents"],
              str(rev_js))
        deps_js = idx.dependencies("web/index.js")
        js_internal = [d["file"] for d in
                       deps_js["internal_dependencies"]]
        check("js internal dep", "web/util.js" in js_internal, str(js_internal))
        check("js external dep", "os" in deps_js["external_dependencies"],
              str(deps_js["external_dependencies"]))
        bad = idx.dependencies("nope/missing.py")
        check("missing file error", "error" in bad, str(bad))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _test_cross_references():
    from ai_agent.tools.workspace import WorkspaceIndex
    root = make_fixture()
    try:
        idx = WorkspaceIndex()
        idx.scan(root)
        sym = idx.lookup_symbol("helper")
        defs = sym["definitions"]
        check("symbol defined", len(defs) == 1
              and defs[0]["file"] == "app/utils.py"
              and defs[0]["kind"] == "function", str(defs))
        check("symbol referenced", sym["reference_count"] >= 1
              and any(r["file"] == "app/main.py"
                      for r in sym["references"]),
              "refs=%d %s" % (sym["reference_count"], sym["references"]))
        engine = idx.lookup_symbol("Engine")
        check("class definition", any(d["kind"] == "class"
              and d["file"] == "app/utils.py"
              for d in engine["definitions"]), str(engine["definitions"]))
        fmt = idx.lookup_symbol("fmt")
        check("js cross-lang ref", any(d["file"] == "web/util.js"
              for d in fmt["definitions"]) and any(
                  r["file"] == "web/index.js" for r in fmt["references"]),
              str(fmt["definitions"]))
        none = idx.lookup_symbol("totally_missing_symbol_xyz")
        check("missing symbol", not none["definitions"]
              and none["reference_count"] == 0, str(none))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _test_incremental_scan():
    from ai_agent.tools.workspace import WorkspaceIndex
    root = make_fixture()
    try:
        idx = WorkspaceIndex()
        res = idx.scan(root)
        check("initial scan", res["files"] == 5, str(res["files"]))
        # append a new function -> re-scan must pick it up
        with open(os.path.join(root, "app", "utils.py"), "a",
                  encoding="utf-8") as f:
            f.write("\ndef brand_new():\n    return 1\n")
        res2 = idx.scan(root)
        check("rescan keeps files", res2["files"] == 5, str(res2["files"]))
        sym = idx.lookup_symbol("brand_new")
        check("incremental picks change", len(sym["definitions"]) == 1,
              str(sym["definitions"]))
        # delete a file -> record dropped from the cached index
        os.remove(os.path.join(root, "web", "index.js"))
        res3 = idx.scan(root)
        check("deleted file dropped", res3["files"] == 4
              and "web/index.js" not in idx.files,
              "files=%d" % res3["files"])
        rev = idx.dependents("web/util.js")
        check("dependents updated", "web/index.js"
              not in rev["dependents"], str(rev))
        # summary block renders for prompt injection
        summ = idx.summary()
        check("summary non-empty", "## Workspace Map" in summ
              and "Files: 4" in summ, summ[:120])
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Part 3 - tool entry points
# ---------------------------------------------------------------------------

def _test_tool_layer():
    from ai_agent.tools.workspace import (
        tool_workspace_scan, tool_workspace_symbols, tool_workspace_deps,
        tool_workspace_query, tool_workspace_export,
    )
    root = make_fixture()
    try:
        out = tool_workspace_scan(root=root)
        check("scan tool", "Workspace indexed:" in out
              and "Files: 5" in out and "python" in out, out[:80])
        syms = tool_workspace_symbols(root=root, file_pattern="*.py")
        check("symbols tool", "app/utils.py" in syms
              and "helper(x)" in syms and "Engine()" in syms, syms[:80])
        deps = tool_workspace_deps(root=root, file="app/main.py")
        check("deps tool", "app/utils.py" in deps and "External: os" in deps,
              deps[:120])
        graph = tool_workspace_deps(root=root)
        check("graph tool", "app/main.py -> app/utils.py" in graph
              or "app/main.py ->" in graph, graph[:120])
        q1 = tool_workspace_query(root=root, query="helper")
        check("query symbol", "Cross-references for 'helper'" in q1
              and "app/utils.py" in q1 and "Referenced at" in q1, q1[:120])
        q2 = tool_workspace_query(root=root, query="app.utils")
        check("query module", "Imported by:" in q2
              and "app/main.py" in q2, q2[:120])
        q3 = tool_workspace_query(root=root, query="start")
        check("query method", "start()" in q3 or "start" in q3, q3[:80])
        q4 = tool_workspace_query(root=root, query="zzz_nothing_here")
        check("query miss", "no symbol or module" in q4
              or "no matches" in q4, q4[:80])
        exp = tool_workspace_export(root=root)
        data = json.loads(exp)
        check("export json", isinstance(data.get("files"), list)
              and len(data["files"]) == 5, str(data.get("files"))[:80])
        # shared index: tools reuse the same cache
        from ai_agent.tools.workspace import WorkspaceIndex
        idx = WorkspaceIndex()
        tool_workspace_scan(root=root, index=idx)
        q5 = tool_workspace_query(root=root, query="Engine", index=idx)
        check("shared index", "Engine" in q5, q5[:80])
        # error paths
        err = tool_workspace_scan(root=os.path.join(root, "missing_dir"))
        check("scan error", "error" in err, err[:80])
        errq = tool_workspace_query(root=root, query="")
        check("query error", "query is required" in errq, errq[:80])
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Part 4 - Agent integration (multi-turn cross-file awareness)
# ---------------------------------------------------------------------------

def _test_agent_wiring():
    from ai_agent.core import Agent
    from ai_agent.llm import MockClient
    root = make_fixture()
    try:
        agent = Agent(llm=MockClient(), auto_verify=False,
                      reasoning_engine=False)
        # 1) empty index -> prompt renders without a workspace block
        p0 = agent._system_prompt()
        check("empty prompt", "Workspace Map" not in p0
              and "{workspace_block}" not in p0, "")
        # 2) scan -> map injected into the system prompt
        res = agent._workspace_index.scan(root)
        check("agent scan", "error" not in res, str(res))
        p1 = agent._system_prompt()
        check("map injected", "## Workspace Map (indexed:" in p1
              and "Files: 5" in p1, p1[:160])
        check("guidance present", "workspace_query" in p1, "")
        # 3) tools registered and executable via the agent tool path
        names = [t.name for t in agent._tool_list]
        missing = [n for n in ("workspace_scan", "workspace_symbols",
                               "workspace_deps", "workspace_query",
                               "workspace_export") if n not in names]
        check("agent exposes workspace tools", not missing,
              "missing=%s" % missing)
        from ai_agent.tools import execute_tool
        call = {"function": {"name": "workspace_deps",
                             "arguments": json.dumps(
                                 {"root": root, "file": "app/main.py"})}}
        out = execute_tool(agent._tools_by_name, call)
        check("execute deps", "app/utils.py" in str(out), str(out)[:120])
        call2 = {"function": {"name": "workspace_query",
                              "arguments": json.dumps(
                                  {"root": root, "query": "helper"})}}
        out2 = execute_tool(agent._tools_by_name, call2)
        check("execute query", "helper" in str(out2), str(out2)[:120])
        # 4) cross-turn persistence: index survives reset (new turn) and
        #    stays available without re-scanning
        agent.reset()
        p2 = agent._system_prompt()
        check("index persists across turns", "## Workspace Map" in p2
              and "Files: 5" in p2, p2[:160])
        sym = agent._workspace_index.lookup_symbol("fmt")
        check("cross-file lookup after reset",
              any(d["file"] == "web/util.js" for d in sym["definitions"]),
              str(sym["definitions"]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def run_tests():
    _test_extract_symbols()
    _test_extract_imports()
    _test_index_scan()
    _test_dependency_graph()
    _test_cross_references()
    _test_incremental_scan()
    _test_tool_layer()
    _test_agent_wiring()


if __name__ == "__main__":
    print("=== HackerAI workspace indexer / cross-reference tests ===")
    t0 = time.time()
    run_tests()
    dt = time.time() - t0
    print("\n%d passed, %d failed (%.1fs)" % (PASS, FAIL, dt))
    sys.exit(1 if FAIL else 0)
