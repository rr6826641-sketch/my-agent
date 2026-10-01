"""AI Agent framework: LLM reasoning + tools + memory + multi-agent."""

# Windows: inject CREATE_NO_WINDOW into every subprocess spawn so console
# children (cmd.exe, nslookup, tasklist, ...) never flash a window when the
# app runs windowed. Must run before any subprocess is created.
from ._winproc import apply as _apply_winproc
_apply_winproc()

from .core import Agent, IntentReformulator, RefusalIntelStore
from .llm import OpenAIClient, MockClient, LLMError
from .memory_store import InstitutionalMemory, MemoryStore
from .orchestration import (
    DEFAULT_MAX_CHILDREN,
    DEFAULT_MAX_SIBLINGS,
    OrchestrationManager,
    SubAgentRecord,
)

__all__ = ["Agent", "IntentReformulator", "RefusalIntelStore",
           "OpenAIClient", "MockClient", "MemoryStore",
           "InstitutionalMemory", "LLMError",
           "OrchestrationManager", "SubAgentRecord",
           "DEFAULT_MAX_SIBLINGS", "DEFAULT_MAX_CHILDREN"]
__version__ = "24.0.0"
