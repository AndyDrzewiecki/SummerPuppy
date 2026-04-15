"""Unit tests for PatchGenerator."""

from __future__ import annotations

import pytest

from summer_puppy.dev_bot.models import PatchCandidate, PatchType, UserStory
from summer_puppy.dev_bot.patch_generator import PatchGenerator
from summer_puppy.llm.client import InMemoryLLMClient
from summer_puppy.llm.models import LLMResponse, LLMUsage
from summer_puppy.sandbox.models import FindingSeverity


def make_story(**kwargs: object) -> UserStory:
    defaults: dict[str, object] = {
        "finding_id": "f-1",
        "customer_id": "cust-1",
        "correlation_id": "corr-1",
        "title": "Test Story",
        "description": "As a security engineer...",
        "severity": FindingSeverity.HIGH,
        "recommended_patch_types": [PatchType.FIREWALL_RULE],
    }
    defaults.update(kwargs)
    return UserStory(**defaults)  # type: ignore[arg-type]


def make_llm_response(structured: dict[str, object]) -> LLMResponse:
    return LLMResponse(
        content="",
        structured_output=structured,
        usage=LLMUsage(input_tokens=0, output_tokens=0, model="test", latency_ms=0.0),
    )


def firewall_structured() -> dict[str, object]:
    return {
        "patch_type": "firewall_rule",
        "title": "Block C2 traffic",
        "description": "Blocks outbound traffic to known C2 addresses.",
        "content": "iptables -A OUTPUT -d 10.0.0.1 -j DROP",
        "target_files": ["/etc/iptables/rules.v4"],
        "language": "bash",
        "confidence_score": 0.85,
        "reasoning": "Observed C2 callback traffic",
        "rollback_content": "iptables -D OUTPUT -d 10.0.0.1 -j DROP",
    }


class TestPatchGeneratorGenerate:
    @pytest.mark.asyncio
    async def test_calls_llm_with_structured_output(self) -> None:
        llm = InMemoryLLMClient(default_structured=firewall_structured())
        gen = PatchGenerator(llm_client=llm)
        story = make_story()
        candidates = await gen.generate(story)
        assert len(llm.calls) == 1
        call = llm.calls[0]
        assert call["method"] == "generate_structured"
        assert "output_schema" in call

    @pytest.mark.asyncio
    async def test_returns_patch_candidate_from_llm(self) -> None:
        llm = InMemoryLLMClient(default_structured=firewall_structured())
        gen = PatchGenerator(llm_client=llm, model_id="test-model")
        story = make_story()
        candidates = await gen.generate(story)
        assert len(candidates) == 1
        patch = candidates[0]
        assert isinstance(patch, PatchCandidate)
        assert patch.title == "Block C2 traffic"
        assert patch.confidence_score == 0.85
        assert patch.generation_model == "test-model"

    @pytest.mark.asyncio
    async def test_generate_with_specific_patch_type(self) -> None:
        iam_structured = {
            **firewall_structured(),
            "patch_type": "iam_policy",
            "title": "Restrict IAM permissions",
        }
        llm = InMemoryLLMClient(default_structured=iam_structured)
        gen = PatchGenerator(llm_client=llm)
        story = make_story(recommended_patch_types=[PatchType.FIREWALL_RULE, PatchType.EDR_CONFIG])
        candidates = await gen.generate(story, patch_type=PatchType.IAM_POLICY)
        # Only 1 call even though story has 2 patch types
        assert len(llm.calls) == 1
        assert len(candidates) == 1

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_llm_raises(self) -> None:
        llm = InMemoryLLMClient()
        llm.set_error(RuntimeError("LLM unavailable"))
        gen = PatchGenerator(llm_client=llm)
        story = make_story()
        candidates = await gen.generate(story)
        assert candidates == []

    @pytest.mark.asyncio
    async def test_generates_multiple_candidates_for_multiple_patch_types(self) -> None:
        responses = [
            make_llm_response({**firewall_structured(), "patch_type": "firewall_rule"}),
            make_llm_response({**firewall_structured(), "patch_type": "edr_config"}),
        ]
        llm = InMemoryLLMClient()
        llm.set_responses(responses)
        gen = PatchGenerator(llm_client=llm)
        story = make_story(
            recommended_patch_types=[PatchType.FIREWALL_RULE, PatchType.EDR_CONFIG]
        )
        candidates = await gen.generate(story)
        assert len(candidates) == 2
        assert len(llm.calls) == 2

    @pytest.mark.asyncio
    async def test_empty_patch_types_returns_empty_list(self) -> None:
        llm = InMemoryLLMClient(default_structured=firewall_structured())
        gen = PatchGenerator(llm_client=llm)
        story = make_story(recommended_patch_types=[])
        candidates = await gen.generate(story)
        assert candidates == []
        assert len(llm.calls) == 0

    @pytest.mark.asyncio
    async def test_patch_linked_to_story(self) -> None:
        llm = InMemoryLLMClient(default_structured=firewall_structured())
        gen = PatchGenerator(llm_client=llm)
        story = make_story()
        candidates = await gen.generate(story)
        assert candidates[0].story_id == story.story_id
        assert candidates[0].customer_id == story.customer_id
        assert candidates[0].correlation_id == story.correlation_id

    @pytest.mark.asyncio
    async def test_llm_prompt_includes_patch_type(self) -> None:
        llm = InMemoryLLMClient(default_structured=firewall_structured())
        gen = PatchGenerator(llm_client=llm)
        story = make_story()
        await gen.generate(story, patch_type=PatchType.IAM_POLICY)
        prompt = llm.calls[0]["prompt"]
        assert "iam_policy" in prompt

    @pytest.mark.asyncio
    async def test_partial_llm_failure_returns_successful_candidates(self) -> None:
        """If LLM fails for one patch_type, still return candidates for others."""
        responses = [
            make_llm_response({**firewall_structured(), "patch_type": "firewall_rule"}),
        ]
        llm = InMemoryLLMClient()
        llm.set_responses(responses)
        # Second call will fail since no more queued responses and default_structured is {}
        gen = PatchGenerator(llm_client=llm)
        story = make_story(
            recommended_patch_types=[PatchType.FIREWALL_RULE, PatchType.EDR_CONFIG]
        )
        candidates = await gen.generate(story)
        # First succeeds, second returns PatchCandidate with empty patch_type from default {}
        # (empty string won't be a valid PatchType → raises ValueError → logged and skipped)
        # So we get at least 1 candidate
        assert len(candidates) >= 1
