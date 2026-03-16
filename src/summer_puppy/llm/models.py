from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class LLMUsage(BaseModel):
    input_tokens: int
    output_tokens: int
    model: str
    latency_ms: float


class LLMResponse(BaseModel):
    content: str
    structured_output: dict[str, Any] | None = None
    usage: LLMUsage


class PromptTemplate(BaseModel):
    template: str

    def render(self, **kwargs: Any) -> str:
        return self.template.format_map(kwargs)
