"""Tests for ai_agent.tools.memory (persistent cross-session memory)."""

import os
import sys
import tempfile

import pytest

os.environ.setdefault("LOCALAPPDATA", tempfile.mkdtemp(prefix="hkr_mem_"))

from ai_agent.tools.memory import (  # noqa: E402
    tool_memory_save, tool_memory_get, tool_memory_list, tool_memory_delete,
)


def test_save_and_get_roundtrip():
    assert "saved" in tool_memory_save("k1", "v1")
    assert tool_memory_get("k1") == "v1"


def test_get_missing_key():
    assert "no memory" in tool_memory_get("nope_xyz")


def test_prefix_match():
    tool_memory_save("target/scope1", "a")
    tool_memory_save("target/scope2", "b")
    out = tool_memory_get("target/")
    assert "target/scope1" in out and "target/scope2" in out


def test_list_and_query_filter():
    tool_memory_save("alpha", "apple pie")
    tool_memory_save("beta", "banana")
    out = tool_memory_list("banana")
    assert "beta" in out and "alpha" not in out
    assert "alpha" in tool_memory_list()


def test_overwrite_and_delete():
    tool_memory_save("dup", "one")
    tool_memory_save("dup", "two")
    assert tool_memory_get("dup") == "two"
    assert "deleted" in tool_memory_delete("dup")
    assert "no memory" in tool_memory_delete("dup")


def test_empty_key_rejected():
    assert "Error" in tool_memory_save("", "x")
    assert "Error" in tool_memory_save("  ", "x")


def test_persistence_across_process():
    tool_memory_save("persist", "survives")
    # simulate a fresh agent process: read the store from a new interpreter
    import subprocess
    code = ("from ai_agent.tools.memory import tool_memory_get;"
            "print(tool_memory_get('persist'))")
    out = subprocess.run([sys.executable, "-c", code],
                         capture_output=True, text=True, timeout=60)
    assert "survives" in out.stdout
    tool_memory_delete("persist")
