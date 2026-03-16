from __future__ import annotations

import asyncio
import time
from typing import Any, Protocol, runtime_checkable

import anthropic

from summer_puppy.llm.models import LLMResponse, LLMUsage


@runtime_checkable
class LLMClient(Protocol):
    async def analyze(self, prompt: str, system: str | None = None) -> LLMResponse: ...

    async def generate_structured(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        system: str | None = None,
    ) -> LLMResponse: ...


class AnthropicClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-20250514",
        max_retries: int = 3,
    ) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model
        self._max_retries = max_retries

    async def _call_with_retry(self, **kwargs: Any) -> Any:
        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                return await self._client.messages.create(**kwargs)
            except anthropic.APIError as exc:
                last_error = exc
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(2**attempt)
        raise last_error  # type: ignore[misc]

    async def analyze(self, prompt: str, system: str | None = None) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system is not None:
            kwargs["system"] = system

        start = time.monotonic()
        response = await self._call_with_retry(**kwargs)
        latency_ms = (time.monotonic() - start) * 1000

        content = ""
        for block in response.content:
            if block.type == "text":
                content = block.text
                break

        return LLMResponse(
            content=content,
            usage=LLMUsage(
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                model=self._model,
                latency_ms=latency_ms,
            ),
        )

    async def generate_structured(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        system: str | None = None,
    ) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
            "tools": [
                {
                    "name": "extract_data",
                    "description": "Extract structured data from the analysis.",
                    "input_schema": output_schema,
                }
            ],
            "tool_choice": {"type": "tool", "name": "extract_data"},
        }
        if system is not None:
            kwargs["system"] = system

        start = time.monotonic()
        response = await self._call_with_retry(**kwargs)
        latency_ms = (time.monotonic() - start) * 1000

        structured_output: dict[str, Any] = {}
        content = ""
        for block in response.content:
            if block.type == "tool_use":
                structured_output = block.input
            elif block.type == "text":
                content = block.text

        return LLMResponse(
            content=content,
            structured_output=structured_output,
            usage=LLMUsage(
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                model=self._model,
                latency_ms=latency_ms,
            ),
        )


class InMemoryLLMClient:
    def __init__(
        self,
        default_content: str = "Mock analysis",
        default_structured: dict[str, Any] | None = None,
    ) -> None:
        self._default_content = default_content
        self._default_structured = default_structured
        self.calls: list[dict[str, Any]] = []
        self._queued_responses: list[LLMResponse] = []
        self._pending_error: Exception | None = None

    def set_responses(self, responses: list[LLMResponse]) -> None:
        self._queued_responses = list(responses)

    def set_error(self, error: Exception) -> None:
        self._pending_error = error

    def _check_error(self) -> None:
        if self._pending_error is not None:
            error = self._pending_error
            self._pending_error = None
            raise error

    def _next_response(self, default_structured: dict[str, Any] | None = None) -> LLMResponse:
        if self._queued_responses:
            return self._queued_responses.pop(0)
        return LLMResponse(
            content=self._default_content,
            structured_output=default_structured,
            usage=LLMUsage(
                input_tokens=0,
                output_tokens=0,
                model="in-memory",
                latency_ms=0.0,
            ),
        )

    async def analyze(self, prompt: str, system: str | None = None) -> LLMResponse:
        self._check_error()
        self.calls.append({"method": "analyze", "prompt": prompt, "system": system})
        return self._next_response()

    async def generate_structured(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        system: str | None = None,
    ) -> LLMResponse:
        self._check_error()
        self.calls.append(
            {
                "method": "generate_structured",
                "prompt": prompt,
                "output_schema": output_schema,
                "system": system,
            }
        )
        fallback = self._default_structured if self._default_structured is not None else {}
        return self._next_response(default_structured=fallback)
