"""Unit tests for Phase 9A enrichment wiring (TDD — tests written first)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.events.models import EventSource, SecurityEvent, Severity
from summer_puppy.llm.client import InMemoryLLMClient
from summer_puppy.llm.models import LLMResponse, LLMUsage
from summer_puppy.memory.store import InMemoryKnowledgeStore
from summer_puppy.pipeline.handlers import LLMAnalyzeHandler, LLMRecommendHandler
from summer_puppy.pipeline.models import PipelineContext, PipelineStage
from summer_puppy.skills.prompt_enricher import NullPromptEnricher, PromptEnricher
from summer_puppy.trust.models import TrustPhase, TrustProfile

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _llm_analyze_response() -> LLMResponse:
    return LLMResponse(
        content="",
        structured_output={
            "threat_type": "BruteForce",
            "attack_vector": "Network",
            "severity_assessment": "HIGH",
            "confidence": 0.9,
            "reasoning": "Multiple failed logins",
        },
        usage=LLMUsage(input_tokens=0, output_tokens=0, model="in-memory", latency_ms=0.0),
    )


def _llm_recommend_response() -> LLMResponse:
    return LLMResponse(
        content="",
        structured_output={
            "action_class": "account_lockout",
            "description": "Lock the account",
            "reasoning": "Brute force detected",
            "confidence_score": 0.85,
            "estimated_risk": "LOW",
        },
        usage=LLMUsage(input_tokens=0, output_tokens=0, model="in-memory", latency_ms=0.0),
    )


def _make_event(**overrides: Any) -> SecurityEvent:
    defaults: dict[str, Any] = {
        "customer_id": "cust-enrich",
        "source": EventSource.SIEM,
        "severity": Severity.HIGH,
        "title": "Enrichment Test Event",
        "description": "Testing enrichment injection",
        "affected_assets": ["srv-01"],
        "raw_payload": {},
        "tags": ["brute-force", "auth"],
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


def _make_trust_profile(**overrides: Any) -> TrustProfile:
    defaults: dict[str, Any] = {
        "customer_id": "cust-enrich",
        "trust_phase": TrustPhase.MANUAL,
    }
    defaults.update(overrides)
    return TrustProfile(**defaults)


def _make_ctx(event: SecurityEvent | None = None, **overrides: Any) -> PipelineContext:
    ev = event or _make_event()
    tp = _make_trust_profile()
    ctx = PipelineContext(
        event=ev,
        customer_id=ev.customer_id,
        correlation_id="corr-enrich-001",
        trust_profile=tp,
        policies=[],
    )
    ctx.current_stage = PipelineStage.ANALYZE
    for k, v in overrides.items():
        setattr(ctx, k, v)
    return ctx


def _make_analyze_handler(
    enricher: Any | None = None,
    structured: dict[str, Any] | None = None,
) -> tuple[LLMAnalyzeHandler, InMemoryLLMClient]:
    llm = InMemoryLLMClient(
        default_structured=structured
        or {
            "threat_type": "BruteForce",
            "attack_vector": "Network",
            "severity_assessment": "HIGH",
            "confidence": 0.9,
            "reasoning": "test",
        }
    )
    handler = LLMAnalyzeHandler(
        llm_client=llm,
        audit_logger=InMemoryAuditLogger(),
        event_bus=InMemoryEventBus(),
        prompt_enricher=enricher,
    )
    return handler, llm


def _make_recommend_handler(
    enricher: Any | None = None,
    structured: dict[str, Any] | None = None,
) -> tuple[LLMRecommendHandler, InMemoryLLMClient]:
    llm = InMemoryLLMClient(
        default_structured=structured
        or {
            "action_class": "account_lockout",
            "description": "Lock account",
            "reasoning": "Brute force",
            "confidence_score": 0.85,
            "estimated_risk": "LOW",
        }
    )
    handler = LLMRecommendHandler(
        llm_client=llm,
        audit_logger=InMemoryAuditLogger(),
        event_bus=InMemoryEventBus(),
        prompt_enricher=enricher,
    )
    return handler, llm


# ---------------------------------------------------------------------------
# TestLLMAnalyzeHandlerEnrichment
# ---------------------------------------------------------------------------


class TestLLMAnalyzeHandlerEnrichment:
    async def test_enricher_context_injected_into_prompt(self) -> None:
        """Enriched context string should appear in the LLM prompt."""
        enricher = AsyncMock(spec=PromptEnricher)
        enricher.build_context.return_value = "ENRICHED_PLAYBOOK_DATA"

        handler, llm = _make_analyze_handler(enricher=enricher)
        ctx = _make_ctx()
        await handler.handle(ctx)

        assert llm.calls, "Expected at least one LLM call"
        prompt_text = llm.calls[-1]["prompt"]
        assert "ENRICHED_PLAYBOOK_DATA" in prompt_text, (
            f"Expected enriched context in prompt, got: {prompt_text[:300]}"
        )
        enricher.build_context.assert_awaited_once()

    async def test_null_enricher_does_not_crash(self) -> None:
        """NullPromptEnricher should work without error and call LLM normally."""
        null_enricher = NullPromptEnricher()
        handler, llm = _make_analyze_handler(enricher=null_enricher)
        ctx = _make_ctx()
        result = await handler.handle(ctx)
        assert result.current_stage == PipelineStage.RECOMMEND
        assert len(llm.calls) == 1

    async def test_enricher_not_required(self) -> None:
        """No enricher → handler works exactly as before."""
        handler, llm = _make_analyze_handler(enricher=None)
        ctx = _make_ctx()
        result = await handler.handle(ctx)
        assert result.current_stage == PipelineStage.RECOMMEND
        assert len(llm.calls) == 1

    async def test_enricher_context_merged_with_existing_knowledge_context(self) -> None:
        """Enriched context is appended to any existing knowledge_context in metadata."""
        enricher = AsyncMock(spec=PromptEnricher)
        enricher.build_context.return_value = "ENRICHED_DATA"

        handler, llm = _make_analyze_handler(enricher=enricher)
        ctx = _make_ctx()
        ctx.metadata["knowledge_context"] = "EXISTING_CONTEXT"
        await handler.handle(ctx)

        prompt_text = llm.calls[-1]["prompt"]
        assert "EXISTING_CONTEXT" in prompt_text
        assert "ENRICHED_DATA" in prompt_text

    async def test_enricher_called_with_correct_args(self) -> None:
        """Enricher must be called with customer_id, event_tags, and action_class=None."""
        enricher = AsyncMock(spec=PromptEnricher)
        enricher.build_context.return_value = "ctx"

        handler, _ = _make_analyze_handler(enricher=enricher)
        event = _make_event(customer_id="cust-x", tags=["tag-a", "tag-b"])
        ctx = _make_ctx(event=event)
        await handler.handle(ctx)

        enricher.build_context.assert_awaited_once_with(
            customer_id="cust-x",
            event_tags=["tag-a", "tag-b"],
            action_class=None,
        )


# ---------------------------------------------------------------------------
# TestLLMRecommendHandlerEnrichment
# ---------------------------------------------------------------------------


class TestLLMRecommendHandlerEnrichment:
    async def test_enricher_playbook_context_in_prompt(self) -> None:
        """Enricher output should appear in the recommendation prompt."""
        enricher = AsyncMock(spec=PromptEnricher)
        enricher.build_context.return_value = "PLAYBOOK_CONTEXT_FOR_RECOMMEND"

        handler, llm = _make_recommend_handler(enricher=enricher)
        ctx = _make_ctx()
        # Provide minimal analysis metadata
        ctx.metadata["analysis"] = {
            "threat_type": "BruteForce",
            "attack_vector": "Network",
            "severity_assessment": "HIGH",
            "confidence": 0.9,
            "reasoning": "test",
        }
        await handler.handle(ctx)

        prompt_text = llm.calls[-1]["prompt"]
        assert "PLAYBOOK_CONTEXT_FOR_RECOMMEND" in prompt_text

    async def test_recommend_handler_without_enricher(self) -> None:
        """No enricher → handler works as before."""
        handler, llm = _make_recommend_handler(enricher=None)
        ctx = _make_ctx()
        ctx.metadata["analysis"] = {
            "threat_type": "BruteForce",
            "attack_vector": "Network",
            "severity_assessment": "HIGH",
            "confidence": 0.9,
            "reasoning": "test",
        }
        result = await handler.handle(ctx)
        assert result.current_stage == PipelineStage.APPROVE
        assert len(llm.calls) == 1

    async def test_enricher_called_with_action_class(self) -> None:
        """Recommend handler should call enricher with action_class from recommendation."""
        enricher = AsyncMock(spec=PromptEnricher)
        enricher.build_context.return_value = "ctx"

        handler, _ = _make_recommend_handler(enricher=enricher)
        ctx = _make_ctx()
        ctx.metadata["analysis"] = {
            "threat_type": "BruteForce",
            "attack_vector": "Network",
            "severity_assessment": "HIGH",
            "confidence": 0.9,
            "reasoning": "test",
        }
        await handler.handle(ctx)

        # The enricher should have been called with customer_id
        enricher.build_context.assert_awaited_once()
        call_kwargs = enricher.build_context.call_args.kwargs
        assert call_kwargs["customer_id"] == "cust-enrich"


# ---------------------------------------------------------------------------
# TestSecurityAnalysisGraphEnrichment
# ---------------------------------------------------------------------------


class TestSecurityAnalysisGraphEnrichment:
    async def test_enricher_context_passed_to_initial_state(self) -> None:
        """Graph should call enricher and merge context into initial_state knowledge_context."""
        from summer_puppy.agents.graph import SecurityAnalysisGraph
        from summer_puppy.events.models import SecurityEvent

        enricher = AsyncMock(spec=PromptEnricher)
        enricher.build_context.return_value = "GRAPH_ENRICHED_CONTEXT"

        llm = InMemoryLLMClient(
            default_structured={
                "threat_type": "BruteForce",
                "attack_vector": "Network",
                "severity_assessment": "HIGH",
                "confidence": 0.9,
                "reasoning": "test",
                "action_class": "account_lockout",
                "description": "desc",
                "confidence_score": 0.8,
                "estimated_risk": "LOW",
            }
        )
        graph = SecurityAnalysisGraph(llm_client=llm, prompt_enricher=enricher)
        event = _make_event(severity=Severity.HIGH)
        trust_profile = _make_trust_profile()

        await graph.run(event=event, trust_profile=trust_profile)

        enricher.build_context.assert_awaited_once()
        call_kwargs = enricher.build_context.call_args.kwargs
        assert call_kwargs["customer_id"] == "cust-enrich"

    async def test_graph_works_without_enricher(self) -> None:
        """Graph without enricher should run normally."""
        from summer_puppy.agents.graph import SecurityAnalysisGraph

        llm = InMemoryLLMClient(
            default_structured={
                "threat_type": "BruteForce",
                "attack_vector": "Network",
                "severity_assessment": "HIGH",
                "confidence": 0.9,
                "reasoning": "test",
                "action_class": "account_lockout",
                "description": "desc",
                "confidence_score": 0.8,
                "estimated_risk": "LOW",
            }
        )
        graph = SecurityAnalysisGraph(llm_client=llm)
        event = _make_event(severity=Severity.HIGH)
        trust_profile = _make_trust_profile()

        result = await graph.run(event=event, trust_profile=trust_profile)
        assert result.analysis is not None


# ---------------------------------------------------------------------------
# TestRunSkillInjectionHandler
# ---------------------------------------------------------------------------


class TestRunSkillInjectionHandler:
    async def test_returns_zero_when_no_injector(self) -> None:
        """When skill_injector is None, return skipped=True and total_injected=0."""
        from summer_puppy.scheduler.jobs import run_skill_injection_handler

        result = await run_skill_injection_handler(skill_injector=None, customer_ids=["cust-1"])
        assert result["skipped"] is True
        assert result["total_injected"] == 0

    async def test_aggregates_results_across_customers(self) -> None:
        """Results across multiple customers should be summed into totals."""
        from summer_puppy.scheduler.jobs import run_skill_injection_handler

        injector = AsyncMock()
        injector.run_injection_cycle.side_effect = [
            {"playbooks_injected": 2, "articles_injected": 1, "total_injected": 3},
            {"playbooks_injected": 1, "articles_injected": 2, "total_injected": 3},
        ]

        result = await run_skill_injection_handler(
            skill_injector=injector,
            customer_ids=["cust-1", "cust-2"],
        )
        assert result["total_injected"] == 6
        assert result["customers_processed"] == 2
        assert injector.run_injection_cycle.await_count == 2

    async def test_empty_customer_list_returns_zero(self) -> None:
        """Empty customer list → zero injections without calling injector."""
        from summer_puppy.scheduler.jobs import run_skill_injection_handler

        injector = AsyncMock()
        result = await run_skill_injection_handler(
            skill_injector=injector,
            customer_ids=[],
        )
        assert result["total_injected"] == 0
        assert result["customers_processed"] == 0
        injector.run_injection_cycle.assert_not_awaited()

    async def test_none_customer_ids_treated_as_empty(self) -> None:
        """customer_ids=None is treated as empty list."""
        from summer_puppy.scheduler.jobs import run_skill_injection_handler

        injector = AsyncMock()
        result = await run_skill_injection_handler(skill_injector=injector, customer_ids=None)
        assert result["total_injected"] == 0
        injector.run_injection_cycle.assert_not_awaited()
