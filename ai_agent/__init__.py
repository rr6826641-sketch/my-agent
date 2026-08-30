"""AI Agent framework: LLM reasoning + tools + memory + multi-agent."""

from .core import Agent
from .llm import OpenAIClient, MockClient, LLMError
from .memory import InstitutionalMemory, MemoryStore

__all__ = ["Agent", "OpenAIClient", "MockClient", "MemoryStore",
           "InstitutionalMemory", "LLMError"]
__version__ = "1.0.0"
