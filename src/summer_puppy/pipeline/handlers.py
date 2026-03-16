"""Step handlers for the security operations pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from summer_puppy.audit.logger import InMemoryAuditLogger, log_event_received  # noqa: TC001
from summer_puppy.audit.models import AuditEntry, AuditEntryType
from summer_puppy.channel.bus import InMemoryEventBus  # noqa: TC001
from summer_puppy.channel.models import Topic
from summer_puppy.events.models import (
    ActionOutcome,
    ActionRequest,
    ApprovalMethod,
    EventStatus,
    QAStatus,
    Recommendation,
    Severity,
)
from summer_puppy.pipeline.models import PipelineContext, PipelineStage, PipelineStatus
from summer_puppy.trust.models import ActionClass, TrustPhase
from summer_puppy.trust.scoring import (
    calculate_trust_score,
    check_auto_approval,
    evaluate_phase_transition,
)


@runtime_checkable
class StepHandler(Protocol):
    """Protocol for pipeline step handlers."""

    async def handle(self, ctx: PipelineContext) -> PipelineContext: ...


class IntakeHandler:
    """Sets stage to TRIAGE, logs event received via audit logger."""

    def __init__(self, audit_logger: InMemoryAuditLogger, event_bus: InMemoryEventBus) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        entry = log_event_received(
            customer_id=ctx.customer_id,
            event_id=ctx.event.event_id,
            correlation_id=ctx.correlation_id,
        )
        await self._audit_logger.append(entry)
        ctx.audit_entry_ids.append(entry.entry_id)

        await self._event_bus.publish(
            topic=Topic.SECURITY_EVENTS,
            message=ctx.event,
            customer_id=ctx.customer_id,
            correlation_id=ctx.correlation_id,
        )

        ctx.current_stage = PipelineStage.TRIAGE
        return ctx


class PassthroughTriageHandler:
    """Stub: sets stage to ANALYZE."""

    def __init__(self, audit_logger: InMemoryAuditLogger, event_bus: InMemoryEventBus) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        ctx.current_stage = PipelineStage.ANALYZE
        return ctx


class PassthroughAnalyzeHandler:
    """Stub: sets stage to RECOMMEND."""

    def __init__(self, audit_logger: InMemoryAuditLogger, event_bus: InMemoryEventBus) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        ctx.current_stage = PipelineStage.RECOMMEND
        return ctx


class PassthroughRecommendHandler:
    """Creates a stub Recommendation from event data, sets stage to APPROVE."""

    def __init__(self, audit_logger: InMemoryAuditLogger, event_bus: InMemoryEventBus) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        rec = Recommendation(
            event_id=ctx.event.event_id,
            customer_id=ctx.customer_id,
            action_class=ActionClass.PATCH_DEPLOYMENT,
            description=f"Recommended action for event {ctx.event.title}",
            reasoning="Automated stub recommendation",
            confidence_score=0.9,
            estimated_risk=Severity.LOW,
            qa_status=QAStatus.PASSED,
            rollback_plan="Automated rollback available",
        )
        ctx.recommendation = rec

        await self._event_bus.publish(
            topic=Topic.RECOMMENDATIONS,
            message=rec,
            customer_id=ctx.customer_id,
            correlation_id=ctx.correlation_id,
        )

        ctx.current_stage = PipelineStage.APPROVE
        return ctx


class TrustApprovalHandler:
    """Real approval handler using trust scoring and auto-approval policies."""

    def __init__(self, audit_logger: InMemoryAuditLogger, event_bus: InMemoryEventBus) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        assert ctx.recommendation is not None, "Recommendation required at APPROVE stage"

        approval_dict = ctx.recommendation.to_approval_dict()
        result = check_auto_approval(
            recommendation=approval_dict,
            policies=ctx.policies,
            current_utc=datetime.now(tz=UTC),
        )

        if result.auto_approved:
            # Auto-approved by policy
            action_request = ActionRequest(
                recommendation_id=ctx.recommendation.recommendation_id,
                customer_id=ctx.customer_id,
                action_class=ctx.recommendation.action_class,
                approval_method=ApprovalMethod.AUTO_APPROVED,
                approved_by=f"policy:{result.policy_id}",
            )
            ctx.action_request = action_request
            ctx.current_stage = PipelineStage.EXECUTE

            entry = AuditEntry(
                customer_id=ctx.customer_id,
                entry_type=AuditEntryType.AUTO_APPROVED,
                actor="system",
                correlation_id=ctx.correlation_id,
                resource_id=ctx.recommendation.recommendation_id,
                details={"policy_id": result.policy_id, "reason": result.reason},
            )
            await self._audit_logger.append(entry)
            ctx.audit_entry_ids.append(entry.entry_id)

        elif ctx.trust_profile.trust_phase in (TrustPhase.MANUAL, TrustPhase.SUPERVISED):
            # Requires human approval
            ctx.status = PipelineStatus.PAUSED_FOR_APPROVAL

            entry = AuditEntry(
                customer_id=ctx.customer_id,
                entry_type=AuditEntryType.APPROVAL_REQUESTED,
                actor="system",
                correlation_id=ctx.correlation_id,
                resource_id=ctx.recommendation.recommendation_id,
                details={"reason": "No matching policy; human approval required"},
            )
            await self._audit_logger.append(entry)
            ctx.audit_entry_ids.append(entry.entry_id)

        else:
            # AUTONOMOUS or FULL_AUTONOMY — trust level permits action
            action_request = ActionRequest(
                recommendation_id=ctx.recommendation.recommendation_id,
                customer_id=ctx.customer_id,
                action_class=ctx.recommendation.action_class,
                approval_method=ApprovalMethod.AUTO_APPROVED,
                approved_by=f"trust_phase:{ctx.trust_profile.trust_phase.value}",
            )
            ctx.action_request = action_request
            ctx.current_stage = PipelineStage.EXECUTE

            entry = AuditEntry(
                customer_id=ctx.customer_id,
                entry_type=AuditEntryType.AUTO_APPROVED,
                actor="system",
                correlation_id=ctx.correlation_id,
                resource_id=ctx.recommendation.recommendation_id,
                details={
                    "reason": "Trust phase permits autonomous action",
                    "trust_phase": ctx.trust_profile.trust_phase.value,
                },
            )
            await self._audit_logger.append(entry)
            ctx.audit_entry_ids.append(entry.entry_id)

        return ctx


class StubExecuteHandler:
    """Creates a successful ActionOutcome, sets stage to VERIFY."""

    def __init__(self, audit_logger: InMemoryAuditLogger, event_bus: InMemoryEventBus) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        assert ctx.action_request is not None, "ActionRequest required at EXECUTE stage"

        outcome = ActionOutcome(
            request_id=ctx.action_request.request_id,
            customer_id=ctx.customer_id,
            success=True,
            result_summary="Action executed successfully (stub)",
            completed_utc=datetime.now(tz=UTC),
        )
        ctx.outcome = outcome

        await self._event_bus.publish(
            topic=Topic.ACTION_OUTCOMES,
            message=outcome,
            customer_id=ctx.customer_id,
            correlation_id=ctx.correlation_id,
        )

        ctx.current_stage = PipelineStage.VERIFY
        return ctx


class VerifyHandler:
    """Calculates trust score from outcome, checks phase transition, advances to CLOSE."""

    def __init__(self, audit_logger: InMemoryAuditLogger, event_bus: InMemoryEventBus) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        assert ctx.outcome is not None, "ActionOutcome required at VERIFY stage"

        outcome_history = [{"success": ctx.outcome.success}]
        score = calculate_trust_score(outcome_history)
        _ = evaluate_phase_transition(ctx.trust_profile, score)

        ctx.current_stage = PipelineStage.CLOSE
        return ctx


class CloseHandler:
    """Sets status to COMPLETED, sets event status to CLOSED."""

    def __init__(self, audit_logger: InMemoryAuditLogger, event_bus: InMemoryEventBus) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        ctx.status = PipelineStatus.COMPLETED
        ctx.event.status = EventStatus.CLOSED
        return ctx
