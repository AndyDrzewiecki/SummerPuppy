"""OllamaClient — LLMClient implementation backed by a local Ollama inference server."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx

from summer_puppy.llm.models import LLMResponse, LLMUsage


class OllamaClient:
    """Calls a local Ollama server for inference.

    Compatible with the LLMClient protocol. Uses httpx for async HTTP.

    Args:
        base_url: Ollama server base URL, e.g. "http://localhost:11434"
        model: Model name, e.g. "llama3" or "mistral"
        timeout_seconds: Request timeout
        max_retries: Number of retries on transient errors
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3",
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = httpx.Timeout(timeout_seconds)
        self._max_retries = max_retries

    def _build_prompt(self, prompt: str, system: str | None) -> str:
        if system is not None:
            return f"[SYSTEM]\n{system}\n\n[USER]\n{prompt}"
        return prompt

    async def _post_with_retry(self, payload: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.post(
                        f"{self._base_url}/api/generate",
                        json=payload,
                    )
                    response.raise_for_status()
                    return response.json()  # type: ignore[no-any-return]
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(2**attempt)
        raise last_error  # type: ignore[misc]

    async def analyze(self, prompt: str, system: str | None = None) -> LLMResponse:
        """Send a prompt to Ollama /api/generate and return LLMResponse."""
        full_prompt = self._build_prompt(prompt, system)
        payload = {
            "model": self._model,
            "prompt": full_prompt,
            "stream": False,
        }

        start = time.monotonic()
        data = await self._post_with_retry(payload)
        latency_ms = (time.monotonic() - start) * 1000

        content = data.get("response", "")
        return LLMResponse(
            content=content,
            usage=LLMUsage(
                input_tokens=0,
                output_tokens=0,
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
        """Generate structured output by asking Ollama to respond with JSON matching schema.

        Strategy: append JSON instructions to prompt, parse the response.
        If JSON parsing fails, return empty structured_output.
        """
        schema_str = json.dumps(output_schema)
        json_instruction = f"\n\nRespond ONLY with valid JSON matching this schema: {schema_str}"
        full_prompt = self._build_prompt(prompt + json_instruction, system)
        payload = {
            "model": self._model,
            "prompt": full_prompt,
            "stream": False,
        }

        start = time.monotonic()
        data = await self._post_with_retry(payload)
        latency_ms = (time.monotonic() - start) * 1000

        content = data.get("response", "")
        structured_output: dict[str, Any] = {}
        try:
            structured_output = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            structured_output = {}

        return LLMResponse(
            content=content,
            structured_output=structured_output,
            usage=LLMUsage(
                input_tokens=0,
                output_tokens=0,
                model=self._model,
                latency_ms=latency_ms,
            ),
        )
