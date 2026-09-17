"""AI Agent framework: LLM reasoning + tools + memory + multi-agent."""

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
__version__ = "18.0.0"
