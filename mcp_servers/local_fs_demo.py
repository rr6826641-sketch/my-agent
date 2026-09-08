"""Local stdio MCP demo server - filesystem tools over the MCP protocol.
Proof-of-concept wired via config.json mcp_servers -> Agent auto-wiring.
Speaks MCP (2025-03-26) over stdin/stdout JSON-RPC 2.0 newline-delimited."""

import json, os, sys, time

def _resp(rid, result):  sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n"); sys.stdout.flush()
def _err(rid, code, msg): sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": msg}}) + "\n"); sys.stdout.flush()

TOOLS = [
    {"name": "fs_ls", "description": "List a directory on the host",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "directory path"}}, "required": ["path"]}},
    {"name": "fs_read", "description": "Read a file from the host (text, first 100KB)",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "fs_stat", "description": "Return size + mtime of a file",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
]

def call(name, args):
    if name == "fs_ls":
        p = args.get("path", ".")
        try: return {"entries": sorted(os.listdir(p))}
        except Exception as e: return {"error": str(e)}
    if name == "fs_read":
        p = args.get("path")
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f: return {"content": f.read(100000)}
        except Exception as e: return {"error": str(e)}
    if name == "fs_stat":
        p = args.get("path")
        try:
            st = os.stat(p); return {"size": st.st_size, "mtime": time.ctime(st.st_mtime)}
        except Exception as e: return {"error": str(e)}
    return {"error": "unknown tool %s" % name}

def main():
    while True:
        line = sys.stdin.readline()
        if not line: break
        try: msg = json.loads(line)
        except Exception: continue
        rid = msg.get("id")
        if rid is None:  # notification
            continue
        m = msg.get("method", "")
        if m == "initialize":
            _resp(rid, {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                        "serverInfo": {"name": "local-fs-demo", "version": "1.0.0"}})
        elif m == "tools/list":
            _resp(rid, {"tools": TOOLS})
        elif m == "tools/call":
            p = msg.get("params", {})
            name = p.get("name"); args = p.get("arguments") or {}
            try: out = call(name, args)
            except Exception as e: out = {"error": str(e)}
            _resp(rid, {"content": [{"type": "text", "text": json.dumps(out)}], "isError": False})
        elif m == "ping":
            _resp(rid, {})
        else:
            _err(rid, -32601, "method not found: %s" % m)

if __name__ == "__main__":
    main()
