from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from summer_puppy.llm.client import AnthropicClient, InMemoryLLMClient, LLMClient
from summer_puppy.llm.models import LLMResponse, LLMUsage

# ── LLMUsage tests ──────────────────────────────────────────────────────────


class TestLLMUsage:
    def test_creation(self) -> None:
        usage = LLMUsage(
            input_tokens=100,
            output_tokens=200,
            model="claude-sonnet-4-20250514",
            latency_ms=1234.5,
        )
        assert usage.input_tokens == 100
        assert usage.output_tokens == 200
        assert usage.model == "claude-sonnet-4-20250514"
        assert usage.latency_ms == 1234.5

    def test_all_fields_required(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            LLMUsage()  # type: ignore[call-arg]

    def test_serialization_round_trip(self) -> None:
        usage = LLMUsage(input_tokens=10, output_tokens=20, model="test-model", latency_ms=50.0)
        data = usage.model_dump()
        restored = LLMUsage(**data)
        assert restored == usage


# ── LLMResponse tests ───────────────────────────────────────────────────────


class TestLLMResponse:
    def test_without_structured_output(self) -> None:
        usage = LLMUsage(input_tokens=10, output_tokens=20, model="test", latency_ms=100.0)
        resp = LLMResponse(content="Hello world", usage=usage)
        assert resp.content == "Hello world"
        assert resp.structured_output is None
        assert resp.usage == usage

    def test_with_structured_output(self) -> None:
        usage = LLMUsage(input_tokens=10, output_tokens=20, model="test", latency_ms=100.0)
        structured = {"threat_type": "malware", "confidence": 0.9}
        resp = LLMResponse(
            content="Analysis complete",
            structured_output=structured,
            usage=usage,
        )
        assert resp.structured_output == structured

    def test_serialization_round_trip(self) -> None:
        usage = LLMUsage(input_tokens=10, output_tokens=20, model="test", latency_ms=100.0)
        resp = LLMResponse(
            content="test",
            structured_output={"key": "value"},
            usage=usage,
        )
        data = resp.model_dump()
        restored = LLMResponse(**data)
        assert restored == resp


# ── InMemoryLLMClient tests ─────────────────────────────────────────────────


class TestInMemoryLLMClient:
    async def test_analyze_returns_default_content(self) -> None:
        client = InMemoryLLMClient(default_content="Test analysis result")
        result = await client.analyze("Some prompt")
        assert result.content == "Test analysis result"
        assert result.structured_output is None
        assert result.usage.input_tokens == 0
        assert result.usage.output_tokens == 0
        assert result.usage.model == "in-memory"
        assert result.usage.latency_ms == 0.0

    async def test_analyze_with_system_prompt(self) -> None:
        client = InMemoryLLMClient()
        result = await client.analyze("prompt", system="system instructions")
        assert result.content == "Mock analysis"

    async def test_generate_structured_returns_default(self) -> None:
        structured = {"action": "block", "confidence": 0.95}
        client = InMemoryLLMClient(default_structured=structured)
        result = await client.generate_structured("prompt", output_schema={"type": "object"})
        assert result.structured_output == structured

    async def test_generate_structured_returns_empty_dict_when_none(self) -> None:
        client = InMemoryLLMClient()
        result = await client.generate_structured("prompt", output_schema={"type": "object"})
        assert result.structured_output == {}

    async def test_calls_are_recorded_analyze(self) -> None:
        client = InMemoryLLMClient()
        await client.analyze("prompt1", system="sys1")
        await client.analyze("prompt2")
        assert len(client.calls) == 2
        assert client.calls[0]["method"] == "analyze"
        assert client.calls[0]["prompt"] == "prompt1"
        assert client.calls[0]["system"] == "sys1"
        assert client.calls[1]["prompt"] == "prompt2"
        assert client.calls[1]["system"] is None

    async def test_calls_are_recorded_generate_structured(self) -> None:
        client = InMemoryLLMClient()
        schema: dict[str, Any] = {"type": "object"}
        await client.generate_structured("prompt1", output_schema=schema, system="sys")
        assert len(client.calls) == 1
        assert client.calls[0]["method"] == "generate_structured"
        assert client.calls[0]["prompt"] == "prompt1"
        assert client.calls[0]["output_schema"] == schema
        assert client.calls[0]["system"] == "sys"

    async def test_set_responses_queues_specific_responses(self) -> None:
        client = InMemoryLLMClient()
        usage = LLMUsage(input_tokens=5, output_tokens=10, model="custom", latency_ms=42.0)
        r1 = LLMResponse(content="Response 1", usage=usage)
        r2 = LLMResponse(content="Response 2", usage=usage)
        client.set_responses([r1, r2])
        result1 = await client.analyze("p1")
        result2 = await client.analyze("p2")
        assert result1.content == "Response 1"
        assert result2.content == "Response 2"

    async def test_set_responses_exhausted_falls_back_to_default(self) -> None:
        client = InMemoryLLMClient(default_content="fallback")
        usage = LLMUsage(input_tokens=1, output_tokens=1, model="m", latency_ms=1.0)
        client.set_responses([LLMResponse(content="queued", usage=usage)])
        result1 = await client.analyze("p1")
        result2 = await client.analyze("p2")
        assert result1.content == "queued"
        assert result2.content == "fallback"

    async def test_set_error_makes_next_call_raise(self) -> None:
        client = InMemoryLLMClient()
        client.set_error(ValueError("boom"))
        with pytest.raises(ValueError, match="boom"):
            await client.analyze("prompt")

    async def test_set_error_clears_after_raising(self) -> None:
        client = InMemoryLLMClient()
        client.set_error(RuntimeError("fail"))
        with pytest.raises(RuntimeError):
            await client.analyze("p")
        # Next call should succeed
        result = await client.analyze("p2")
        assert result.content == "Mock analysis"

    async def test_set_error_affects_generate_structured(self) -> None:
        client = InMemoryLLMClient()
        client.set_error(ConnectionError("network"))
        with pytest.raises(ConnectionError, match="network"):
            await client.generate_structured("prompt", output_schema={})

    def test_protocol_conformance(self) -> None:
        client = InMemoryLLMClient()
        assert isinstance(client, LLMClient)


# ── AnthropicClient tests ───────────────────────────────────────────────────


def _make_mock_message(
    content_text: str = "Analyzed result",
    input_tokens: int = 50,
    output_tokens: int = 100,
    tool_use_input: dict[str, Any] | None = None,
) -> MagicMock:
    """Build a mock anthropic Message response."""
    msg = MagicMock()
    msg.usage.input_tokens = input_tokens
    msg.usage.output_tokens = output_tokens

    if tool_use_input is not None:
        # tool_use content block
        tool_block = MagicMock()
        tool_block.type = "tool_use"
        tool_block.input = tool_use_input
        msg.content = [tool_block]
    else:
        # text content block
        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = content_text
        msg.content = [text_block]

    return msg


class TestAnthropicClient:
    @patch("summer_puppy.llm.client.anthropic")
    async def test_analyze_returns_llm_response(self, mock_anthropic: MagicMock) -> None:
        mock_msg = _make_mock_message(content_text="Threat detected")
        mock_client_instance = MagicMock()
        mock_client_instance.messages = MagicMock()
        mock_client_instance.messages.create = AsyncMock(return_value=mock_msg)
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        client = AnthropicClient(api_key="test-key")
        result = await client.analyze("Analyze this event")

        assert result.content == "Threat detected"
        assert result.structured_output is None
        assert result.usage.input_tokens == 50
        assert result.usage.output_tokens == 100
        assert result.usage.model == "claude-sonnet-4-20250514"
        assert result.usage.latency_ms >= 0

    @patch("summer_puppy.llm.client.anthropic")
    async def test_analyze_with_system_prompt(self, mock_anthropic: MagicMock) -> None:
        mock_msg = _make_mock_message(content_text="Result")
        mock_client_instance = MagicMock()
        mock_client_instance.messages = MagicMock()
        mock_client_instance.messages.create = AsyncMock(return_value=mock_msg)
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        client = AnthropicClient(api_key="test-key")
        await client.analyze("prompt", system="Be a security analyst")

        call_kwargs = mock_client_instance.messages.create.call_args
        assert call_kwargs.kwargs.get("system") == "Be a security analyst"

    @patch("summer_puppy.llm.client.anthropic")
    async def test_analyze_without_system_prompt(self, mock_anthropic: MagicMock) -> None:
        mock_msg = _make_mock_message(content_text="Result")
        mock_client_instance = MagicMock()
        mock_client_instance.messages = MagicMock()
        mock_client_instance.messages.create = AsyncMock(return_value=mock_msg)
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        client = AnthropicClient(api_key="test-key")
        await client.analyze("prompt")

        call_kwargs = mock_client_instance.messages.create.call_args
        # system should not be passed when None
        assert "system" not in call_kwargs.kwargs or call_kwargs.kwargs["system"] is None

    @patch("summer_puppy.llm.client.anthropic")
    async def test_generate_structured_parses_tool_use(self, mock_anthropic: MagicMock) -> None:
        tool_data = {"threat_type": "ransomware", "severity": "HIGH"}
        mock_msg = _make_mock_message(tool_use_input=tool_data)
        mock_client_instance = MagicMock()
        mock_client_instance.messages = MagicMock()
        mock_client_instance.messages.create = AsyncMock(return_value=mock_msg)
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        client = AnthropicClient(api_key="test-key")
        schema: dict[str, Any] = {
            "type": "object",
            "properties": {"threat_type": {"type": "string"}},
        }
        result = await client.generate_structured("Analyze", output_schema=schema)

        assert result.structured_output == tool_data
        assert result.usage.input_tokens == 50
        assert result.usage.output_tokens == 100

    @patch("summer_puppy.llm.client.anthropic")
    async def test_generate_structured_sends_tool_definition(
        self, mock_anthropic: MagicMock
    ) -> None:
        mock_msg = _make_mock_message(tool_use_input={"key": "val"})
        mock_client_instance = MagicMock()
        mock_client_instance.messages = MagicMock()
        mock_client_instance.messages.create = AsyncMock(return_value=mock_msg)
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        client = AnthropicClient(api_key="test-key")
        schema: dict[str, Any] = {"type": "object", "properties": {"key": {"type": "string"}}}
        await client.generate_structured("prompt", output_schema=schema)

        call_kwargs = mock_client_instance.messages.create.call_args.kwargs
        assert "tools" in call_kwargs
        tools = call_kwargs["tools"]
        assert len(tools) == 1
        assert tools[0]["name"] == "extract_data"
        assert tools[0]["input_schema"] == schema
        assert call_kwargs["tool_choice"] == {"type": "tool", "name": "extract_data"}

    @patch("summer_puppy.llm.client.anthropic")
    async def test_retry_on_api_error(self, mock_anthropic: MagicMock) -> None:
        mock_anthropic.APIError = type("APIError", (Exception,), {})
        api_error = mock_anthropic.APIError("rate limited")

        mock_msg = _make_mock_message(content_text="Success after retry")
        mock_client_instance = MagicMock()
        mock_client_instance.messages = MagicMock()
        mock_client_instance.messages.create = AsyncMock(side_effect=[api_error, mock_msg])
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        client = AnthropicClient(api_key="test-key", max_retries=3)
        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await client.analyze("prompt")

        assert result.content == "Success after retry"
        assert mock_client_instance.messages.create.call_count == 2

    @patch("summer_puppy.llm.client.anthropic")
    async def test_all_retries_exhausted_raises(self, mock_anthropic: MagicMock) -> None:
        mock_anthropic.APIError = type("APIError", (Exception,), {})
        api_error = mock_anthropic.APIError("server error")

        mock_client_instance = MagicMock()
        mock_client_instance.messages = MagicMock()
        mock_client_instance.messages.create = AsyncMock(
            side_effect=[api_error, api_error, api_error]
        )
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        client = AnthropicClient(api_key="test-key", max_retries=3)
        with (
            patch("asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(Exception, match="server error"),
        ):
            await client.analyze("prompt")

        assert mock_client_instance.messages.create.call_count == 3

    @patch("summer_puppy.llm.client.anthropic")
    async def test_retry_on_generate_structured(self, mock_anthropic: MagicMock) -> None:
        mock_anthropic.APIError = type("APIError", (Exception,), {})
        api_error = mock_anthropic.APIError("timeout")

        mock_msg = _make_mock_message(tool_use_input={"result": "ok"})
        mock_client_instance = MagicMock()
        mock_client_instance.messages = MagicMock()
        mock_client_instance.messages.create = AsyncMock(side_effect=[api_error, mock_msg])
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        client = AnthropicClient(api_key="test-key", max_retries=3)
        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await client.generate_structured("p", output_schema={"type": "object"})

        assert result.structured_output == {"result": "ok"}

    @patch("summer_puppy.llm.client.anthropic")
    async def test_custom_model(self, mock_anthropic: MagicMock) -> None:
        mock_msg = _make_mock_message(content_text="result")
        mock_client_instance = MagicMock()
        mock_client_instance.messages = MagicMock()
        mock_client_instance.messages.create = AsyncMock(return_value=mock_msg)
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        client = AnthropicClient(api_key="test-key", model="claude-3-haiku-20240307")
        result = await client.analyze("prompt")

        assert result.usage.model == "claude-3-haiku-20240307"
        call_kwargs = mock_client_instance.messages.create.call_args.kwargs
        assert call_kwargs["model"] == "claude-3-haiku-20240307"

    @patch("summer_puppy.llm.client.anthropic")
    def test_protocol_conformance(self, mock_anthropic: MagicMock) -> None:
        mock_anthropic.AsyncAnthropic.return_value = MagicMock()
        client = AnthropicClient(api_key="test-key")
        assert isinstance(client, LLMClient)

    @patch("summer_puppy.llm.client.anthropic")
    async def test_latency_is_measured(self, mock_anthropic: MagicMock) -> None:
        mock_msg = _make_mock_message(content_text="fast")
        mock_client_instance = MagicMock()
        mock_client_instance.messages = MagicMock()
        mock_client_instance.messages.create = AsyncMock(return_value=mock_msg)
        mock_anthropic.AsyncAnthropic.return_value = mock_client_instance

        client = AnthropicClient(api_key="test-key")
        result = await client.analyze("prompt")

        assert isinstance(result.usage.latency_ms, float)
        assert result.usage.latency_ms >= 0
