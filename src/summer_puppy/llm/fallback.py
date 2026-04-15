"""FallbackLLMClient — tries providers in order, falling back on failure."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from summer_puppy.llm.models import LLMResponse  # noqa: TC004


class FallbackLLMClient:
    """Tries each provider in order; uses the first that succeeds.

    Primary use case: cloud LLM (AnthropicClient) with local fallback (OllamaClient).

    Args:
        providers: Ordered list of LLMClient implementations. First is primary.
    """

    def __init__(self, providers: list[Any]) -> None:
        self._providers = providers

    async def analyze(self, prompt: str, system: str | None = None) -> LLMResponse:
        """Try each provider in order; return first success. Raise last error if all fail."""
        last_error: Exception | None = None
        for provider in self._providers:
            try:
                return await provider.analyze(prompt, system)
            except Exception as exc:
                last_error = exc
        raise last_error  # type: ignore[misc]

    async def generate_structured(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        system: str | None = None,
    ) -> LLMResponse:
        """Try each provider in order; return first success. Raise last error if all fail."""
        last_error: Exception | None = None
        for provider in self._providers:
            try:
                return await provider.generate_structured(prompt, output_schema, system)
            except Exception as exc:
                last_error = exc
        raise last_error  # type: ignore[misc]

    @property
    def provider_count(self) -> int:
        """Number of configured providers."""
        return len(self._providers)
