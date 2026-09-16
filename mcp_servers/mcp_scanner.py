"""Security scanner MCP server - stdlib only (no deps)."""
import json, socket, sys
from urllib.parse import urlparse


def dns_recon(host="", qtype="A"):
    import socket as s
    try:
        return {"host": host, "resolved": s.gethostbyname_ex(host)[2][:20]}
    except Exception as exc:
        return {"host": host, "error": str(exc)}


def port_scan(host="127.0.0.1", ports="21,22,80,443,3306,3389,8080"):
    open_ports = []
    for p in [int(x) for x in ports.split(",") if x.strip()]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            try:
                if s.connect_ex((host, p)) == 0:
                    open_ports.append(p)
            except Exception:
                pass
    return {"host": host, "open_ports": open_ports}


def http_probe(url="http://127.0.0.1/"):
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            return {"url": url, "status": r.status,
                    "server": r.headers.get("Server", ""),
                    "len": len(r.read(4096))}
    except Exception as exc:
        return {"url": url, "error": str(exc)}


TOOLS = {"dns_recon": dns_recon, "port_scan": port_scan,
         "http_probe": http_probe}
    
if __name__ == "__main__":
    print(json.dumps({"server": "mcp_scanner",
                      "tools": list(TOOLS.keys()), "status": "ready"}))
