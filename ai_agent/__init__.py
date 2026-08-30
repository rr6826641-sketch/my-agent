"""AI Agent framework: LLM reasoning + tools + memory + multi-agent."""

from .core import Agent
from .llm import OpenAIClient, MockClient, LLMError
from .memory import InstitutionalMemory, MemoryStore
from .orchestration import (
    DEFAULT_MAX_CHILDREN,
    DEFAULT_MAX_SIBLINGS,
    OrchestrationManager,
    SubAgentRecord,
)

__all__ = ["Agent", "OpenAIClient", "MockClient", "MemoryStore",
           "InstitutionalMemory", "LLMError",
           "OrchestrationManager", "SubAgentRecord",
           "DEFAULT_MAX_SIBLINGS", "DEFAULT_MAX_CHILDREN"]
__version__ = "1.0.0"
