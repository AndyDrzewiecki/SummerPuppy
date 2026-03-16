"""Comprehensive tests for the pipeline orchestration module (Story 5)."""

from __future__ import annotations

from typing import Any

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.audit.models import AuditEntryType
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.channel.models import Topic
from summer_puppy.events.models import (
    ActionOutcome,
    ActionRequest,
    ApprovalMethod,
    EventSource,
    EventStatus,
    QAStatus,
    Recommendation,
    SecurityEvent,
    Severity,
)
from summer_puppy.pipeline.handlers import (
    CloseHandler,
    IntakeHandler,
    PassthroughAnalyzeHandler,
    PassthroughRecommendHandler,
    PassthroughTriageHandler,
    StubExecuteHandler,
    TrustApprovalHandler,
    VerifyHandler,
)
from summer_puppy.pipeline.models import (
    PipelineContext,
    PipelineStage,
    PipelineStatus,
)
from summer_puppy.pipeline.orchestrator import Orchestrator
from summer_puppy.trust.models import (
    ActionClass,
    ApprovalConditions,
    AutoApprovalPolicy,
    TrustPhase,
    TrustProfile,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**overrides: Any) -> SecurityEvent:
    defaults: dict[str, Any] = {
        "customer_id": "cust-test",
        "source": EventSource.SIEM,
        "severity": Severity.MEDIUM,
        "title": "Test Security Event",
        "description": "A test event for pipeline testing",
        "correlation_id": "corr-001",
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


def _make_trust_profile(**overrides: Any) -> TrustProfile:
    defaults: dict[str, Any] = {
        "customer_id": "cust-test",
        "trust_phase": TrustPhase.MANUAL,
    }
    defaults.update(overrides)
    return TrustProfile(**defaults)


def _make_recommendation(event: SecurityEvent, **overrides: Any) -> Recommendation:
    defaults: dict[str, Any] = {
        "event_id": event.event_id,
        "customer_id": event.customer_id,
        "action_class": ActionClass.PATCH_DEPLOYMENT,
        "description": "Apply patch",
        "reasoning": "Vulnerability detected",
        "confidence_score": 0.95,
        "estimated_risk": Severity.LOW,
        "qa_status": QAStatus.PASSED,
        "rollback_plan": "Revert patch",
    }
    defaults.update(overrides)
    return Recommendation(**defaults)


def _make_policy(**overrides: Any) -> AutoApprovalPolicy:
    defaults: dict[str, Any] = {
        "customer_id": "cust-test",
        "action_class": ActionClass.PATCH_DEPLOYMENT,
        "max_severity": "MEDIUM",
        "conditions": ApprovalConditions(
            min_confidence_score=0.8,
            require_qa_passed=True,
            require_rollback_available=True,
            max_estimated_risk="MEDIUM",
        ),
    }
    defaults.update(overrides)
    return AutoApprovalPolicy(**defaults)


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
        "correlation_id": ev.correlation_id or "corr-001",
        "trust_profile": tp,
    }
    defaults.update(overrides)
    return PipelineContext(**defaults)


# ===========================================================================
# PipelineStage / PipelineStatus enum tests
# ===========================================================================


class TestPipelineStage:
    def test_member_values(self) -> None:
        assert PipelineStage.INTAKE == "INTAKE"
        assert PipelineStage.TRIAGE == "TRIAGE"
        assert PipelineStage.ANALYZE == "ANALYZE"
        assert PipelineStage.RECOMMEND == "RECOMMEND"
        assert PipelineStage.APPROVE == "APPROVE"
        assert PipelineStage.EXECUTE == "EXECUTE"
        assert PipelineStage.VERIFY == "VERIFY"
        assert PipelineStage.CLOSE == "CLOSE"
        assert PipelineStage.ERROR == "ERROR"

    def test_member_count(self) -> None:
        assert len(PipelineStage) == 9


class TestPipelineStatus:
    def test_member_values(self) -> None:
        assert PipelineStatus.RUNNING == "RUNNING"
        assert PipelineStatus.PAUSED_FOR_APPROVAL == "PAUSED_FOR_APPROVAL"
        assert PipelineStatus.COMPLETED == "COMPLETED"
        assert PipelineStatus.FAILED == "FAILED"

    def test_member_count(self) -> None:
        assert len(PipelineStatus) == 4


# ===========================================================================
# PipelineContext tests
# ===========================================================================


class TestPipelineContext:
    def test_minimal_creation(self) -> None:
        event = _make_event()
        profile = _make_trust_profile()
        ctx = PipelineContext(
            event=event,
            customer_id="cust-test",
            correlation_id="corr-001",
            trust_profile=profile,
        )
        assert ctx.customer_id == "cust-test"
        assert ctx.event is event
        assert ctx.trust_profile is profile
        assert ctx.context_id  # auto-generated uuid

    def test_default_values(self) -> None:
        ctx = _make_context()
        assert ctx.current_stage == PipelineStage.INTAKE
        assert ctx.status == PipelineStatus.RUNNING
        assert ctx.recommendation is None
        assert ctx.action_request is None
        assert ctx.outcome is None
        assert ctx.policies == []
        assert ctx.audit_entry_ids == []
        assert ctx.error_detail is None
        assert ctx.metadata == {}


# ===========================================================================
# Individual handler tests
# ===========================================================================


class TestIntakeHandler:
    async def test_advances_to_triage(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = IntakeHandler(audit_logger=audit_logger, event_bus=event_bus)
        ctx = _make_context()

        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.TRIAGE

    async def test_creates_audit_entry(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = IntakeHandler(audit_logger=audit_logger, event_bus=event_bus)
        ctx = _make_context()

        result = await handler.handle(ctx)

        entries = await audit_logger.get_chain(result.correlation_id)
        assert len(entries) >= 1
        assert entries[0].entry_type == AuditEntryType.EVENT_RECEIVED
        assert result.audit_entry_ids  # should have recorded the entry id


class TestPassthroughTriageHandler:
    async def test_advances_to_analyze(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = PassthroughTriageHandler(audit_logger=audit_logger, event_bus=event_bus)
        ctx = _make_context(current_stage=PipelineStage.TRIAGE)

        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.ANALYZE


class TestPassthroughAnalyzeHandler:
    async def test_advances_to_recommend(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = PassthroughAnalyzeHandler(audit_logger=audit_logger, event_bus=event_bus)
        ctx = _make_context(current_stage=PipelineStage.ANALYZE)

        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.RECOMMEND


class TestPassthroughRecommendHandler:
    async def test_creates_recommendation_and_advances(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = PassthroughRecommendHandler(audit_logger=audit_logger, event_bus=event_bus)
        ctx = _make_context(current_stage=PipelineStage.RECOMMEND)

        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.APPROVE
        assert result.recommendation is not None
        assert result.recommendation.event_id == ctx.event.event_id
        assert result.recommendation.customer_id == ctx.customer_id


class TestTrustApprovalHandler:
    async def test_auto_approves_with_matching_policy(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = TrustApprovalHandler(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        rec = _make_recommendation(event)
        policy = _make_policy()
        ctx = _make_context(
            event=event,
            recommendation=rec,
            policies=[policy],
            current_stage=PipelineStage.APPROVE,
        )

        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.EXECUTE
        assert result.action_request is not None
        assert result.action_request.approval_method == ApprovalMethod.AUTO_APPROVED

    async def test_pauses_without_policy_manual_trust(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = TrustApprovalHandler(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        rec = _make_recommendation(event)
        profile = _make_trust_profile(trust_phase=TrustPhase.MANUAL)
        ctx = _make_context(
            event=event,
            trust_profile=profile,
            recommendation=rec,
            policies=[],
            current_stage=PipelineStage.APPROVE,
        )

        result = await handler.handle(ctx)

        assert result.status == PipelineStatus.PAUSED_FOR_APPROVAL
        assert result.action_request is None

    async def test_pauses_without_policy_supervised_trust(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = TrustApprovalHandler(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        rec = _make_recommendation(event)
        profile = _make_trust_profile(trust_phase=TrustPhase.SUPERVISED)
        ctx = _make_context(
            event=event,
            trust_profile=profile,
            recommendation=rec,
            policies=[],
            current_stage=PipelineStage.APPROVE,
        )

        result = await handler.handle(ctx)

        assert result.status == PipelineStatus.PAUSED_FOR_APPROVAL

    async def test_proceeds_without_policy_autonomous_trust(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = TrustApprovalHandler(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        rec = _make_recommendation(event)
        profile = _make_trust_profile(trust_phase=TrustPhase.AUTONOMOUS)
        ctx = _make_context(
            event=event,
            trust_profile=profile,
            recommendation=rec,
            policies=[],
            current_stage=PipelineStage.APPROVE,
        )

        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.EXECUTE
        assert result.action_request is not None

    async def test_proceeds_without_policy_full_autonomy_trust(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = TrustApprovalHandler(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        rec = _make_recommendation(event)
        profile = _make_trust_profile(trust_phase=TrustPhase.FULL_AUTONOMY)
        ctx = _make_context(
            event=event,
            trust_profile=profile,
            recommendation=rec,
            policies=[],
            current_stage=PipelineStage.APPROVE,
        )

        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.EXECUTE
        assert result.action_request is not None

    async def test_creates_audit_entry_on_auto_approval(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = TrustApprovalHandler(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        rec = _make_recommendation(event)
        policy = _make_policy()
        ctx = _make_context(
            event=event,
            recommendation=rec,
            policies=[policy],
            current_stage=PipelineStage.APPROVE,
        )

        result = await handler.handle(ctx)

        entries = await audit_logger.get_chain(result.correlation_id)
        entry_types = [e.entry_type for e in entries]
        assert AuditEntryType.AUTO_APPROVED in entry_types


class TestStubExecuteHandler:
    async def test_creates_outcome_and_advances(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = StubExecuteHandler(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        rec = _make_recommendation(event)
        action_req = ActionRequest(
            recommendation_id=rec.recommendation_id,
            customer_id="cust-test",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            approval_method=ApprovalMethod.AUTO_APPROVED,
            approved_by="system",
        )
        ctx = _make_context(
            event=event,
            recommendation=rec,
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.VERIFY
        assert result.outcome is not None
        assert result.outcome.success is True
        assert result.outcome.request_id == action_req.request_id


class TestVerifyHandler:
    async def test_calculates_trust_score_and_advances(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = VerifyHandler(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        rec = _make_recommendation(event)
        action_req = ActionRequest(
            recommendation_id=rec.recommendation_id,
            customer_id="cust-test",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            approval_method=ApprovalMethod.AUTO_APPROVED,
            approved_by="system",
        )
        outcome = ActionOutcome(
            request_id=action_req.request_id,
            customer_id="cust-test",
            success=True,
            result_summary="Patch applied successfully",
        )
        ctx = _make_context(
            event=event,
            recommendation=rec,
            action_request=action_req,
            outcome=outcome,
            current_stage=PipelineStage.VERIFY,
        )

        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.CLOSE


class TestCloseHandler:
    async def test_sets_completed_status(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = CloseHandler(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        ctx = _make_context(event=event, current_stage=PipelineStage.CLOSE)

        result = await handler.handle(ctx)

        assert result.status == PipelineStatus.COMPLETED
        assert result.event.status == EventStatus.CLOSED


# ===========================================================================
# Orchestrator tests
# ===========================================================================


class TestOrchestrator:
    async def test_process_event_happy_path(self) -> None:
        """Full pipeline run: event flows through all stages to COMPLETED."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        orch = Orchestrator.build_default(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        # Use AUTONOMOUS trust to avoid pausing for approval
        profile = _make_trust_profile(trust_phase=TrustPhase.AUTONOMOUS)

        result = await orch.process_event(event, profile)

        assert result.status == PipelineStatus.COMPLETED
        assert result.current_stage == PipelineStage.CLOSE

    async def test_process_event_auto_approval(self) -> None:
        """Matching policy triggers auto-approval and full pipeline completion."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        orch = Orchestrator.build_default(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        profile = _make_trust_profile(trust_phase=TrustPhase.MANUAL)
        policy = _make_policy()

        result = await orch.process_event(event, profile, policies=[policy])

        assert result.status == PipelineStatus.COMPLETED
        assert result.action_request is not None
        assert result.action_request.approval_method == ApprovalMethod.AUTO_APPROVED

    async def test_process_event_pauses_for_manual_approval(self) -> None:
        """No matching policy + MANUAL trust causes pause at APPROVE."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        orch = Orchestrator.build_default(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        profile = _make_trust_profile(trust_phase=TrustPhase.MANUAL)

        result = await orch.process_event(event, profile)

        assert result.status == PipelineStatus.PAUSED_FOR_APPROVAL
        assert result.current_stage == PipelineStage.APPROVE

    async def test_process_event_error_handling(self) -> None:
        """Handler that raises sets ERROR stage and captures error_detail."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        orch = Orchestrator(audit_logger=audit_logger, event_bus=event_bus)

        class BrokenHandler:
            def __init__(self, audit_logger: InMemoryAuditLogger, event_bus: InMemoryEventBus):
                pass

            async def handle(self, ctx: PipelineContext) -> PipelineContext:
                msg = "Something exploded"
                raise RuntimeError(msg)

        orch.register_handler(PipelineStage.INTAKE, BrokenHandler(audit_logger, event_bus))

        event = _make_event()
        profile = _make_trust_profile()

        result = await orch.process_event(event, profile)

        assert result.current_stage == PipelineStage.ERROR
        assert result.status == PipelineStatus.FAILED
        assert result.error_detail is not None
        assert "Something exploded" in result.error_detail

    async def test_build_default_registers_all_handlers(self) -> None:
        """build_default creates an orchestrator with handlers for all non-error stages."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        orch = Orchestrator.build_default(audit_logger=audit_logger, event_bus=event_bus)

        expected_stages = [
            PipelineStage.INTAKE,
            PipelineStage.TRIAGE,
            PipelineStage.ANALYZE,
            PipelineStage.RECOMMEND,
            PipelineStage.APPROVE,
            PipelineStage.EXECUTE,
            PipelineStage.VERIFY,
            PipelineStage.CLOSE,
        ]
        for stage in expected_stages:
            assert stage in orch._handlers

    async def test_audit_trail_created(self) -> None:
        """Verify audit entries are created through the pipeline."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        orch = Orchestrator.build_default(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        profile = _make_trust_profile(trust_phase=TrustPhase.AUTONOMOUS)

        result = await orch.process_event(event, profile)

        entries = await audit_logger.get_chain(result.correlation_id)
        assert len(entries) >= 1  # at least intake audit entry
        entry_types = [e.entry_type for e in entries]
        assert AuditEntryType.EVENT_RECEIVED in entry_types

    async def test_event_bus_publishes_at_transitions(self) -> None:
        """Verify messages published at key pipeline transitions."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        orch = Orchestrator.build_default(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event()
        profile = _make_trust_profile(trust_phase=TrustPhase.AUTONOMOUS)

        await orch.process_event(event, profile)

        # Check that key topics received messages
        security_msgs = event_bus.get_history(Topic.SECURITY_EVENTS)
        assert len(security_msgs) >= 1

        recommendation_msgs = event_bus.get_history(Topic.RECOMMENDATIONS)
        assert len(recommendation_msgs) >= 1

    async def test_correlation_id_propagated(self) -> None:
        """Correlation ID from event flows through the pipeline context."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        orch = Orchestrator.build_default(audit_logger=audit_logger, event_bus=event_bus)

        event = _make_event(correlation_id="my-corr-id")
        profile = _make_trust_profile(trust_phase=TrustPhase.AUTONOMOUS)

        result = await orch.process_event(event, profile)

        assert result.correlation_id == "my-corr-id"
