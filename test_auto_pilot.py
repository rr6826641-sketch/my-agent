"""AUTO-PILOT attack mission smoke tests (localhost only).

The full chain (recon -> scan -> vuln -> report) runs against
127.0.0.1 which is always in scope and always reachable.  CVE lookups
fail soft (network-dependent) so the run still completes offline.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_agent.tools.auto_pilot import (
    tool_attack_mission,
    tool_mission_reset,
    tool_mission_status,
)


def test_mission_chain_runs_on_localhost():
    tool_mission_reset("127.0.0.1")
    out = tool_attack_mission("127.0.0.1", budget_sec=115)
    assert "STATUS: ALL PHASES COMPLETE" in out, out
    assert "REPORT:" in out, out
    st = tool_mission_status("127.0.0.1")
    assert "recon: done" in st, st
    assert "scan: done" in st, st
    assert "vuln: done" in st, st
    assert "report: done" in st, st


def test_mission_reset_starts_clean():
    tool_mission_reset("127.0.0.1")
    st = tool_mission_status("127.0.0.1")
    assert "recon: pending" in st, st
    assert "report: pending" in st, st