from __future__ import annotations

from summer_puppy.llm.client import AnthropicClient, InMemoryLLMClient, LLMClient
from summer_puppy.llm.fallback import FallbackLLMClient
from summer_puppy.llm.models import LLMResponse, LLMUsage, PromptTemplate
from summer_puppy.llm.prompts import ANALYZE_EVENT, GENERATE_RECOMMENDATION
from summer_puppy.llm.providers import OllamaClient

__all__ = [
    "ANALYZE_EVENT",
    "AnthropicClient",
    "FallbackLLMClient",
    "GENERATE_RECOMMENDATION",
    "InMemoryLLMClient",
    "LLMClient",
    "LLMResponse",
    "LLMUsage",
    "OllamaClient",
    "PromptTemplate",
]
