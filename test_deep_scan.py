"""DEEP-SCAN POSTURE (roadmap #9, v0.8.13) tests.

Verifies the deep-scan attack surface widening:
  - DEEP_PORTS   : 1-1024 + high-value services, superset of DEFAULT_PORTS,
                   sized under the tool_port_scan 2000-port cap
  - DEEP_WORDLIST: superset of DEFAULT_WORDLIST, unique
  - _make_ctx(deep=True) carries the deep flag through to phases
  - tool_mission_deep persists posture=deep and status shows it
    ([deep] tag in the campaign list too)

The integration case runs against 127.0.0.2 (always in scope loopback,
all ports closed) so the deep scan completes quickly.
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_agent.tools.network import DEEP_PORTS, DEFAULT_PORTS
from ai_agent.tools.recon import DEEP_WORDLIST, DEFAULT_WORDLIST
from ai_agent.tools.auto_pilot import (
    _make_ctx,
    tool_mission_deep,
    tool_mission_status,
)


def _ports(pspec):
    return [int(x) for x in str(pspec).split(",") if x]


def test_deep_ports_cover_defaults_and_well_known_range():
    dp = _ports(DEEP_PORTS)
    assert len(dp) == len(set(dp)), "DEEP_PORTS must be unique"
    assert len(dp) <= 2000, "must stay under tool_port_scan 2000-port cap"
    assert set(_ports(DEFAULT_PORTS)) <= set(dp), \
        "DEEP_PORTS must be a superset of DEFAULT_PORTS"
    assert set(range(1, 1025)) <= set(dp), \
        "DEEP_PORTS must cover the full well-known range 1-1024"
    assert max(dp) >= 443, "sanity: high-value web ports included"


def test_deep_wordlist_superset_and_unique():
    dw = list(DEEP_WORDLIST)
    assert len(dw) == len(set(dw)), "DEEP_WORDLIST must be unique"
    assert set(DEFAULT_WORDLIST) <= set(dw), \
        "DEEP_WORDLIST must be a superset of DEFAULT_WORDLIST"
    assert len(dw) > len(DEFAULT_WORDLIST), \
        "deep wordlist must add entries beyond the default set"


def test_make_ctx_deep_flag():
    ctx = _make_ctx(deep=True)
    assert ctx.deep is True
    ctx2 = _make_ctx()
    assert ctx2.deep is False


def test_mission_deep_sets_posture_and_status():
    tmp = tempfile.mkdtemp(prefix="deepcamp_")
    try:
        out = tool_mission_deep("127.0.0.2", campaign_dir=tmp,
                                budget_sec=115)
        assert "STATUS: ALL PHASES COMPLETE" in out, out
        st = tool_mission_status("127.0.0.2", campaign_dir=tmp)
        assert "posture: deep" in st, st
        assert "[DEEP-SCAN]" in st, st
        # campaign list must tag the deep campaign
        lst = tool_mission_status("", campaign_dir=tmp)
        assert " [deep]" in lst, lst
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        for fn in ("attack_mission_127.0.0.2.md",
                   "attack_mission_127_0_0_2.md"):
            p = os.path.join(tempfile.gettempdir(), "reports", fn)
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass