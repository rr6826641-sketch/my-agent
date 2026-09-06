"""Access-Control enforcement tests (Phase 1).

Covers ai_agent/tools/access_control.gate_tool():
  full    -> unrestricted (default, operator-owned)
  labonly -> active testing ok, destructive host ops rejected
  readonly-> fail-closed allowlist only
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_agent.tools.access_control import gate_tool, normalize_mode


def test_normalize():
    assert normalize_mode(None) == "full"
    assert normalize_mode("read-only") == "readonly"
    assert normalize_mode("lab only") == "labonly"
    assert normalize_mode("bogus") == "full"


def test_full_unrestricted():
    assert gate_tool("full", "run_terminal", {"command": "rm -rf /"})[0] is True
    assert gate_tool("full", "write_file", {})[0] is True


def test_readonly_fail_closed():
    assert gate_tool("readonly", "nmap_scan", {})[0] is True
    assert gate_tool("readonly", "read_file", {})[0] is True
    assert gate_tool("readonly", "run_terminal", {"command": "dir"})[0] is False
    assert gate_tool("readonly", "run_python", {})[0] is False
    assert gate_tool("readonly", "write_file", {})[0] is False
    assert gate_tool("readonly", "sqli_test", {})[0] is False
    assert gate_tool("readonly", "delete_finding", {})[0] is False


def test_labonly_blocks_destructive():
    assert gate_tool("labonly", "nmap_scan", {})[0] is True
    assert gate_tool("labonly", "dir_fuzz", {"url": "http://t/"})[0] is True
    assert gate_tool("labonly", "run_terminal", {"command": "ls -la"})[0] is True
    assert gate_tool("labonly", "run_terminal", {"command": "rm -rf /tmp/x"})[0] is False
    assert gate_tool("labonly", "run_terminal", {"command": "shutdown /s"})[0] is False
    assert gate_tool("labonly", "run_python", {"code": "Remove-Item C:/x -Recurse"})[0] is False


def test_deny_reason_present():
    ok, reason = gate_tool("readonly", "run_terminal", {"command": "dir"})
    assert ok is False and "ACCESS DENIED" in (reason or "")
