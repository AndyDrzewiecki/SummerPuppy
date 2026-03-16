"""Tests for LLMRecommendHandler (Story 3)."""

from __future__ import annotations

from typing import Any

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.audit.models import AuditEntryType
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.channel.models import Topic
from summer_puppy.events.models import (
    EventSource,
    QAStatus,
    Recommendation,
    SecurityEvent,
    Severity,
)
from summer_puppy.llm.client import InMemoryLLMClient
from summer_puppy.llm.models import LLMResponse, LLMUsage
from summer_puppy.pipeline.handlers import (
    LLMRecommendHandler,
    PassthroughRecommendHandler,
)
from summer_puppy.pipeline.models import PipelineContext, PipelineStage
from summer_puppy.pipeline.orchestrator import Orchestrator
from summer_puppy.trust.models import ActionClass, TrustPhase, TrustProfile

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**overrides: Any) -> SecurityEvent:
    defaults: dict[str, Any] = {
        "customer_id": "cust-rec-test",
        "source": EventSource.SIEM,
        "severity": Severity.HIGH,
        "title": "Suspicious Login Activity",
        "description": "Multiple failed login attempts detected from unusual IP",
        "affected_assets": ["server-01", "server-02"],
        "raw_payload": {"ip": "10.0.0.99", "attempts": 50},
        "correlation_id": "corr-recommend-001",
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


def _make_trust_profile(**overrides: Any) -> TrustProfile:
    defaults: dict[str, Any] = {
        "customer_id": "cust-rec-test",
        "trust_phase": TrustPhase.MANUAL,
        "positive_outcome_rate": 0.75,
    }
    defaults.update(overrides)
    return TrustProfile(**defaults)


def _make_context(
    event: SecurityEvent | None = None,
    trust_profile: TrustProfile | None = None,
    **overrides: Any,
) -> PipelineContext:
    ev = event or _make_event()
    tp = trust_profile or _make_trust_profile()
    defaults: dict[str, Any] = {
        "event": ev,
        "customer_id": ev.customer_id,
        "correlation_id": ev.correlation_id or "corr-recommend-001",
        "trust_profile": tp,
        "current_stage": PipelineStage.RECOMMEND,
    }
    defaults.update(overrides)
    return PipelineContext(**defaults)


def _valid_recommendation_output() -> dict[str, Any]:
    """Return a valid structured output dict matching Recommendation schema."""
    return {
        "action_class": "patch_deployment",
        "description": "Deploy emergency patch to affected servers",
        "reasoning": "Analysis indicates brute force attack requiring immediate patching",
        "confidence_score": 0.85,
        "estimated_risk": "MEDIUM",
        "rollback_plan": "Revert patch via configuration management",
        "affected_asset_classes": ["server", "network"],
    }


def _make_llm_response(structured: dict[str, Any] | None = None) -> LLMResponse:
    return LLMResponse(
        content="Recommendation generated",
        structured_output=structured or _valid_recommendation_output(),
        usage=LLMUsage(
            input_tokens=150,
            output_tokens=250,
            model="test-model",
            latency_ms=75.0,
        ),
    )


# ===========================================================================
# LLMRecommendHandler tests
# ===========================================================================


class TestLLMRecommendHandler:
    async def test_happy_path_creates_recommendation_on_ctx(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert isinstance(result.recommendation, Recommendation)

    async def test_recommendation_action_class_matches_llm_output(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.action_class == ActionClass.PATCH_DEPLOYMENT

    async def test_recommendation_description_matches_llm_output(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.description == ("Deploy emergency patch to affected servers")

    async def test_recommendation_reasoning_matches_llm_output(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert "brute force" in result.recommendation.reasoning.lower()

    async def test_recommendation_confidence_matches_llm_output(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.confidence_score == 0.85

    async def test_recommendation_estimated_risk_matches_llm_output(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.estimated_risk == Severity.MEDIUM

    async def test_recommendation_event_id_matches_ctx(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.event_id == ctx.event.event_id

    async def test_recommendation_customer_id_matches_ctx(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.customer_id == "cust-rec-test"

    async def test_recommendation_qa_status_is_pending(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.qa_status == QAStatus.PENDING

    async def test_recommendation_rollback_plan_from_output(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.rollback_plan == ("Revert patch via configuration management")

    async def test_recommendation_affected_asset_classes_from_output(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.affected_asset_classes == ["server", "network"]

    async def test_recommendation_to_approval_dict_works(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        approval = result.recommendation.to_approval_dict()
        assert isinstance(approval, dict)
        assert approval["action_class"] == "patch_deployment"
        assert approval["confidence_score"] == 0.85

    async def test_audit_entry_recommendation_generated(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        entries = await audit_logger.get_chain(result.correlation_id)
        entry_types = [e.entry_type for e in entries]
        assert AuditEntryType.RECOMMENDATION_GENERATED in entry_types

    async def test_event_bus_publishes_to_recommendations_topic(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        await handler.handle(ctx)

        messages = event_bus.get_history(Topic.RECOMMENDATIONS)
        assert len(messages) == 1
        assert messages[0].customer_id == "cust-rec-test"

    async def test_stage_advances_to_approve(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.APPROVE

    async def test_analysis_context_included_in_prompt(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        analysis = {"threat_type": "Brute Force", "confidence": 0.85}
        ctx = _make_context(metadata={"analysis": analysis})
        await handler.handle(ctx)

        prompt = llm_client.calls[0]["prompt"]
        assert "Brute Force" in prompt

    async def test_no_analysis_context_works(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()  # no "analysis" in metadata
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.current_stage == PipelineStage.APPROVE

    async def test_llm_failure_fallback_uses_compensating_control(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient()
        llm_client.set_error(Exception("LLM service unavailable"))

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.action_class == ActionClass.COMPENSATING_CONTROL

    async def test_llm_failure_fallback_confidence_low(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient()
        llm_client.set_error(RuntimeError("Connection refused"))

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.confidence_score == 0.1

    async def test_llm_failure_fallback_reasoning(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient()
        llm_client.set_error(Exception("timeout"))

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert "fallback" in result.recommendation.reasoning.lower()

    async def test_llm_failure_fallback_estimated_risk_matches_event(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient()
        llm_client.set_error(Exception("fail"))

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context(event=_make_event(severity=Severity.CRITICAL))
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.estimated_risk == Severity.CRITICAL

    async def test_llm_failure_fallback_still_advances_to_approve(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient()
        llm_client.set_error(Exception("LLM down"))

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.APPROVE

    async def test_invalid_action_class_from_llm_triggers_fallback(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        bad_output = _valid_recommendation_output()
        bad_output["action_class"] = "totally_bogus_action"
        llm_client = InMemoryLLMClient(default_structured=bad_output)

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.action_class == ActionClass.COMPENSATING_CONTROL
        assert result.recommendation.confidence_score == 0.1

    async def test_calls_generate_structured(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        await handler.handle(ctx)

        assert len(llm_client.calls) == 1
        assert llm_client.calls[0]["method"] == "generate_structured"

    async def test_prompt_includes_event_title(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        await handler.handle(ctx)

        prompt = llm_client.calls[0]["prompt"]
        assert "Suspicious Login Activity" in prompt

    async def test_prompt_includes_severity(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        await handler.handle(ctx)

        prompt = llm_client.calls[0]["prompt"]
        assert "HIGH" in prompt

    async def test_prompt_includes_action_classes(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        await handler.handle(ctx)

        prompt = llm_client.calls[0]["prompt"]
        assert "patch_deployment" in prompt
        assert "compensating_control" in prompt

    async def test_rollback_plan_none_from_llm(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        output = _valid_recommendation_output()
        output["rollback_plan"] = None
        llm_client = InMemoryLLMClient(default_structured=output)

        handler = LLMRecommendHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.recommendation is not None
        assert result.recommendation.rollback_plan is None


# ===========================================================================
# Orchestrator.build_default with LLMRecommendHandler tests
# ===========================================================================


class TestBuildDefaultWithLLMRecommend:
    async def test_with_llm_client_uses_llm_recommend_handler(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            llm_client=llm_client,
        )

        handler = orch._handlers[PipelineStage.RECOMMEND]
        assert isinstance(handler, LLMRecommendHandler)

    async def test_with_llm_client_also_uses_llm_analyze_handler(self) -> None:
        from summer_puppy.pipeline.handlers import LLMAnalyzeHandler

        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            llm_client=llm_client,
        )

        handler = orch._handlers[PipelineStage.ANALYZE]
        assert isinstance(handler, LLMAnalyzeHandler)

    async def test_without_llm_client_uses_passthrough_recommend(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
        )

        handler = orch._handlers[PipelineStage.RECOMMEND]
        assert isinstance(handler, PassthroughRecommendHandler)

    async def test_without_llm_client_backward_compatible(self) -> None:
        from summer_puppy.pipeline.handlers import PassthroughAnalyzeHandler

        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            llm_client=None,
        )

        analyze_handler = orch._handlers[PipelineStage.ANALYZE]
        recommend_handler = orch._handlers[PipelineStage.RECOMMEND]
        assert isinstance(analyze_handler, PassthroughAnalyzeHandler)
        assert isinstance(recommend_handler, PassthroughRecommendHandler)
