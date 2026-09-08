"""Backward-compatibility shim for the Context Auto-Compaction Engine.

The full engine lives at ``ai_agent/memory/compactor.py`` (sliding token
window, 70% threshold manager, structured key-finding node pipeline, and
prompt-head note injection with raw-history pruning).  This module keeps
historic imports such as::

    from ai_agent.compaction import CompactionStore, estimate_chars

working unchanged.
"""

from .memory.compactor import (  # noqa: F401
    CompactionStore,
    Compactor,
    DEFAULT_COMPACTION_THRESHOLD,
    DEFAULT_MAX_TOKENS,
    build_keyfinding_nodes,
    estimate_chars,
    estimate_tokens,
    estimate_tokens_for_messages,
    extractive_digest,
    render_nodes,
    summarize_history,
)

__all__ = [
    "CompactionStore", "Compactor", "DEFAULT_MAX_TOKENS",
    "DEFAULT_COMPACTION_THRESHOLD", "estimate_tokens",
    "estimate_tokens_for_messages", "estimate_chars", "build_keyfinding_nodes",
    "render_nodes", "summarize_history", "extractive_digest",
]
