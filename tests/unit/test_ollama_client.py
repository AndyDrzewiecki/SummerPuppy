"""Tests for OllamaClient, FallbackLLMClient, and Ollama Settings (Phase 10)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from summer_puppy.api.settings import Settings
from summer_puppy.llm.fallback import FallbackLLMClient
from summer_puppy.llm.models import LLMResponse, LLMUsage
from summer_puppy.llm.providers import OllamaClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ollama_response(text: str) -> MagicMock:
    """Build a mock httpx.Response for Ollama /api/generate."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"response": text}
    return mock_resp


def _make_llm_response(content: str = "ok") -> LLMResponse:
    return LLMResponse(
        content=content,
        usage=LLMUsage(input_tokens=0, output_tokens=0, model="test", latency_ms=1.0),
    )


# ---------------------------------------------------------------------------
# TestOllamaClient
# ---------------------------------------------------------------------------


class TestOllamaClient:
    async def test_analyze_sends_correct_payload(self) -> None:
        client = OllamaClient(base_url="http://localhost:11434", model="llama3")
        mock_response = _make_ollama_response("analysis result")

        with patch("httpx.AsyncClient") as mock_class:
            mock_http = AsyncMock()
            mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_class.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_http.post = AsyncMock(return_value=mock_response)

            await client.analyze("my prompt")

            mock_http.post.assert_called_once()
            call_kwargs = mock_http.post.call_args
            url = call_kwargs[0][0] if call_kwargs[0] else call_kwargs[1].get("url") or call_kwargs[0][0]
            # Check URL contains /api/generate
            assert "/api/generate" in str(call_kwargs)
            # Check payload
            payload = call_kwargs[1].get("json") or call_kwargs[0][1]
            assert payload["model"] == "llama3"
            assert payload["prompt"] == "my prompt"
            assert payload["stream"] is False

    async def test_analyze_returns_llm_response(self) -> None:
        client = OllamaClient(model="llama3")
        mock_response = _make_ollama_response("security analysis")

        with patch("httpx.AsyncClient") as mock_class:
            mock_http = AsyncMock()
            mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_class.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_http.post = AsyncMock(return_value=mock_response)

            result = await client.analyze("test prompt")

        assert isinstance(result, LLMResponse)
        assert result.content == "security analysis"
        assert result.usage.model == "llama3"
        assert result.usage.input_tokens == 0
        assert result.usage.output_tokens == 0
        assert result.usage.latency_ms >= 0

    async def test_analyze_with_system_prompt(self) -> None:
        client = OllamaClient(model="llama3")
        mock_response = _make_ollama_response("response")

        with patch("httpx.AsyncClient") as mock_class:
            mock_http = AsyncMock()
            mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_class.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_http.post = AsyncMock(return_value=mock_response)

            await client.analyze("user question", system="you are helpful")

            call_kwargs = mock_http.post.call_args
            payload = call_kwargs[1].get("json") or call_kwargs[0][1]
            # System prompt should be prepended in the prompt field
            assert "[SYSTEM]" in payload["prompt"]
            assert "you are helpful" in payload["prompt"]
            assert "user question" in payload["prompt"]

    async def test_generate_structured_requests_json(self) -> None:
        client = OllamaClient(model="llama3")
        schema = {"type": "object", "properties": {"severity": {"type": "string"}}}
        mock_response = _make_ollama_response('{"severity": "HIGH"}')

        with patch("httpx.AsyncClient") as mock_class:
            mock_http = AsyncMock()
            mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_class.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_http.post = AsyncMock(return_value=mock_response)

            await client.generate_structured("analyze this", schema)

            call_kwargs = mock_http.post.call_args
            payload = call_kwargs[1].get("json") or call_kwargs[0][1]
            # Should include JSON instruction in the prompt
            assert "JSON" in payload["prompt"]
            assert json.dumps(schema) in payload["prompt"]

    async def test_generate_structured_parses_valid_json(self) -> None:
        client = OllamaClient(model="llama3")
        schema = {"type": "object"}
        mock_response = _make_ollama_response('{"severity": "HIGH", "action": "block"}')

        with patch("httpx.AsyncClient") as mock_class:
            mock_http = AsyncMock()
            mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_class.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_http.post = AsyncMock(return_value=mock_response)

            result = await client.generate_structured("analyze this", schema)

        assert result.structured_output == {"severity": "HIGH", "action": "block"}

    async def test_generate_structured_handles_invalid_json(self) -> None:
        client = OllamaClient(model="llama3")
        schema = {"type": "object"}
        mock_response = _make_ollama_response("not valid json at all!!!")

        with patch("httpx.AsyncClient") as mock_class:
            mock_http = AsyncMock()
            mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_class.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_http.post = AsyncMock(return_value=mock_response)

            result = await client.generate_structured("analyze this", schema)

        # Should not raise; structured_output should be empty dict
        assert result.structured_output == {}

    async def test_retries_on_http_error(self) -> None:
        import httpx

        client = OllamaClient(model="llama3", max_retries=3)
        mock_response = _make_ollama_response("ok after retry")

        with patch("httpx.AsyncClient") as mock_class:
            mock_http = AsyncMock()
            mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_class.return_value.__aexit__ = AsyncMock(return_value=False)
            # Fail twice, then succeed
            mock_http.post = AsyncMock(
                side_effect=[
                    httpx.ConnectError("connection refused"),
                    httpx.ConnectError("connection refused"),
                    mock_response,
                ]
            )

            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await client.analyze("test")

        assert result.content == "ok after retry"
        assert mock_http.post.call_count == 3


# ---------------------------------------------------------------------------
# TestFallbackLLMClient
# ---------------------------------------------------------------------------


class TestFallbackLLMClient:
    async def test_uses_first_provider_on_success(self) -> None:
        primary = AsyncMock()
        primary.analyze = AsyncMock(return_value=_make_llm_response("from primary"))
        secondary = AsyncMock()
        secondary.analyze = AsyncMock(return_value=_make_llm_response("from secondary"))

        client = FallbackLLMClient([primary, secondary])
        result = await client.analyze("test")

        assert result.content == "from primary"
        secondary.analyze.assert_not_called()

    async def test_falls_back_to_second_on_first_failure(self) -> None:
        primary = AsyncMock()
        primary.analyze = AsyncMock(side_effect=RuntimeError("primary failed"))
        secondary = AsyncMock()
        secondary.analyze = AsyncMock(return_value=_make_llm_response("from secondary"))

        client = FallbackLLMClient([primary, secondary])
        result = await client.analyze("test")

        assert result.content == "from secondary"

    async def test_raises_when_all_providers_fail(self) -> None:
        primary = AsyncMock()
        primary.analyze = AsyncMock(side_effect=RuntimeError("primary failed"))
        secondary = AsyncMock()
        secondary.analyze = AsyncMock(side_effect=RuntimeError("secondary failed"))

        client = FallbackLLMClient([primary, secondary])

        with pytest.raises(RuntimeError, match="secondary failed"):
            await client.analyze("test")

    def test_provider_count(self) -> None:
        p1 = AsyncMock()
        p2 = AsyncMock()
        p3 = AsyncMock()
        client = FallbackLLMClient([p1, p2, p3])
        assert client.provider_count == 3


# ---------------------------------------------------------------------------
# TestSettings
# ---------------------------------------------------------------------------


class TestSettings:
    def test_ollama_defaults(self) -> None:
        settings = Settings()
        assert settings.ollama_enabled is False
        assert settings.ollama_base_url == "http://localhost:11434"
        assert settings.ollama_model == "llama3"
        assert settings.ollama_timeout_seconds == 60.0
