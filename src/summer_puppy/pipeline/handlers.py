"""Step handlers for the security operations pipeline."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from summer_puppy.audit.logger import (  # noqa: TC001
    AuditLogger,
    log_event_received,
    log_predictive_alert,
)
from summer_puppy.audit.models import AuditEntry, AuditEntryType
from summer_puppy.channel.bus import EventBus  # noqa: TC001
from summer_puppy.channel.models import Topic
from summer_puppy.events.models import (
    ActionOutcome,
    ActionRequest,
    AnalysisResult,
    ApprovalMethod,
    EventStatus,
    PredictiveAlert,
    PredictiveAlertType,
    QAStatus,
    Recommendation,
    Severity,
)
from summer_puppy.llm.client import LLMClient  # noqa: TC001
from summer_puppy.llm.prompts import ANALYZE_EVENT, GENERATE_RECOMMENDATION
from summer_puppy.memory.store import KnowledgeStore  # noqa: TC001
from summer_puppy.pipeline.models import PipelineContext, PipelineStage, PipelineStatus
from summer_puppy.trust.models import ActionClass, TrustPhase
from summer_puppy.trust.scoring import (
    calculate_trust_score,
    check_auto_approval,
    evaluate_phase_transition,
)

_logger = logging.getLogger(__name__)


@runtime_checkable
class StepHandler(Protocol):
    """Protocol for pipeline step handlers."""

    async def handle(self, ctx: PipelineContext) -> PipelineContext: ...


class IntakeHandler:
    """Sets stage to TRIAGE, logs event received via audit logger."""

    def __init__(self, audit_logger: AuditLogger, event_bus: EventBus) -> None:
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

    def __init__(self, audit_logger: AuditLogger, event_bus: EventBus) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        ctx.current_stage = PipelineStage.ANALYZE
        return ctx


class TriageHandler:
    """Enriches pipeline context with knowledge graph data for affected assets."""

    def __init__(
        self,
        knowledge_store: KnowledgeStore,
        audit_logger: AuditLogger,
        event_bus: EventBus,
    ) -> None:
        self._knowledge_store = knowledge_store
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        try:
            asset_contexts = []
            for asset_id in ctx.event.affected_assets:
                context = await self._knowledge_store.get_asset_context(asset_id)
                if context is not None:
                    asset_contexts.append(context)
            knowledge_context: dict[str, Any] = {
                "assets": [context.model_dump() for context in asset_contexts],
            }
        except Exception:
            _logger.warning(
                "Knowledge store unavailable for event %s",
                ctx.event.event_id,
                exc_info=True,
            )
            knowledge_context = {
                "assets": [],
                "error": "Knowledge store unavailable",
            }

        ctx.metadata["knowledge_context"] = knowledge_context
        ctx.current_stage = PipelineStage.ANALYZE
        return ctx


class PassthroughAnalyzeHandler:
    """Stub: sets stage to RECOMMEND."""

    def __init__(self, audit_logger: AuditLogger, event_bus: EventBus) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        ctx.current_stage = PipelineStage.RECOMMEND
        return ctx


class LLMAnalyzeHandler:
    """Analyzes security events using an LLM to produce structured threat assessments."""

    def __init__(
        self,
        llm_client: LLMClient,
        audit_logger: AuditLogger,
        event_bus: EventBus,
    ) -> None:
        self._llm_client = llm_client
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        try:
            analysis_result = await self._run_llm_analysis(ctx)
        except Exception:
            _logger.warning(
                "LLM analysis failed for event %s, using fallback",
                ctx.event.event_id,
                exc_info=True,
            )
            analysis_result = AnalysisResult(
                threat_type="Unknown",
                attack_vector="Unknown",
                severity_assessment=ctx.event.severity,
                confidence=0.1,
                reasoning="LLM analysis unavailable; fallback based on event severity",
            )

        ctx.metadata["analysis"] = analysis_result.model_dump()

        entry = AuditEntry(
            customer_id=ctx.customer_id,
            entry_type=AuditEntryType.ANALYSIS_COMPLETED,
            actor="system",
            correlation_id=ctx.correlation_id,
            resource_id=ctx.event.event_id,
            details={"threat_type": analysis_result.threat_type},
        )
        await self._audit_logger.append(entry)
        ctx.audit_entry_ids.append(entry.entry_id)

        await self._event_bus.publish(
            topic=Topic.ANALYSIS_RESULTS,
            message=analysis_result,
            customer_id=ctx.customer_id,
            correlation_id=ctx.correlation_id,
        )

        ctx.current_stage = PipelineStage.RECOMMEND
        return ctx

    async def _run_llm_analysis(self, ctx: PipelineContext) -> AnalysisResult:
        knowledge_context = ctx.metadata.get(
            "knowledge_context", "No historical context available"
        )
        prompt = ANALYZE_EVENT.render(
            title=ctx.event.title,
            source=ctx.event.source,
            severity=ctx.event.severity,
            description=ctx.event.description,
            affected_assets=", ".join(ctx.event.affected_assets),
            raw_payload=str(ctx.event.raw_payload),
            knowledge_context=knowledge_context,
        )

        output_schema: dict[str, Any] = {
            "type": "object",
            "properties": {
                "threat_type": {"type": "string"},
                "attack_vector": {"type": "string"},
                "affected_systems": {"type": "array", "items": {"type": "string"}},
                "ioc_indicators": {"type": "array", "items": {"type": "string"}},
                "severity_assessment": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                },
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "reasoning": {"type": "string"},
                "recommended_actions": {"type": "array", "items": {"type": "string"}},
                "mitre_attack_ids": {"type": "array", "items": {"type": "string"}},
            },
            "required": [
                "threat_type",
                "attack_vector",
                "severity_assessment",
                "confidence",
                "reasoning",
            ],
        }

        response = await self._llm_client.generate_structured(prompt, output_schema)
        return AnalysisResult.model_validate(response.structured_output)


class PassthroughRecommendHandler:
    """Creates a stub Recommendation from event data, sets stage to APPROVE."""

    def __init__(self, audit_logger: AuditLogger, event_bus: EventBus) -> None:
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


class LLMRecommendHandler:
    """Generates remediation recommendations using an LLM."""

    def __init__(
        self,
        llm_client: LLMClient,
        audit_logger: AuditLogger,
        event_bus: EventBus,
    ) -> None:
        self._llm_client = llm_client
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        try:
            recommendation = await self._run_llm_recommendation(ctx)
        except Exception:
            _logger.warning(
                "LLM recommendation failed for event %s, using fallback",
                ctx.event.event_id,
                exc_info=True,
            )
            recommendation = Recommendation(
                event_id=ctx.event.event_id,
                customer_id=ctx.customer_id,
                action_class=ActionClass.COMPENSATING_CONTROL,
                description=f"Fallback recommendation for event {ctx.event.title}",
                reasoning="Automated fallback - LLM unavailable",
                confidence_score=0.1,
                estimated_risk=ctx.event.severity,
                qa_status=QAStatus.PENDING,
            )

        ctx.recommendation = recommendation

        await self._event_bus.publish(
            topic=Topic.RECOMMENDATIONS,
            message=recommendation,
            customer_id=ctx.customer_id,
            correlation_id=ctx.correlation_id,
        )

        entry = AuditEntry(
            customer_id=ctx.customer_id,
            entry_type=AuditEntryType.RECOMMENDATION_GENERATED,
            actor="system",
            correlation_id=ctx.correlation_id,
            resource_id=recommendation.recommendation_id,
            details={"action_class": recommendation.action_class.value},
        )
        await self._audit_logger.append(entry)
        ctx.audit_entry_ids.append(entry.entry_id)

        ctx.current_stage = PipelineStage.APPROVE
        return ctx

    async def _run_llm_recommendation(self, ctx: PipelineContext) -> Recommendation:
        analysis = ctx.metadata.get("analysis", {})
        prompt = GENERATE_RECOMMENDATION.render(
            analysis_summary=str(analysis),
            title=ctx.event.title,
            severity=ctx.event.severity.value,
            affected_assets=str(ctx.event.affected_assets),
            customer_id=ctx.customer_id,
            trust_phase=ctx.trust_profile.trust_phase.value,
            positive_outcome_rate=str(ctx.trust_profile.positive_outcome_rate),
            action_classes=str([ac.value for ac in ActionClass]),
        )

        output_schema: dict[str, Any] = {
            "type": "object",
            "properties": {
                "action_class": {"type": "string"},
                "description": {"type": "string"},
                "reasoning": {"type": "string"},
                "confidence_score": {"type": "number", "minimum": 0, "maximum": 1},
                "estimated_risk": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                },
                "rollback_plan": {"type": ["string", "null"]},
                "affected_asset_classes": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": [
                "action_class",
                "description",
                "reasoning",
                "confidence_score",
                "estimated_risk",
            ],
        }

        response = await self._llm_client.generate_structured(prompt, output_schema)
        output = response.structured_output or {}

        # Validate action_class is a real ActionClass — raises ValueError if not
        action_class = ActionClass(output["action_class"])

        return Recommendation(
            event_id=ctx.event.event_id,
            customer_id=ctx.customer_id,
            action_class=action_class,
            description=output["description"],
            reasoning=output["reasoning"],
            confidence_score=output["confidence_score"],
            estimated_risk=Severity(output["estimated_risk"]),
            rollback_plan=output.get("rollback_plan"),
            affected_asset_classes=output.get("affected_asset_classes", []),
            qa_status=QAStatus.PENDING,
        )


class TrustApprovalHandler:
    """Real approval handler using trust scoring and auto-approval policies."""

    def __init__(self, audit_logger: AuditLogger, event_bus: EventBus) -> None:
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

    def __init__(self, audit_logger: AuditLogger, event_bus: EventBus) -> None:
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

    def __init__(self, audit_logger: AuditLogger, event_bus: EventBus) -> None:
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

    def __init__(self, audit_logger: AuditLogger, event_bus: EventBus) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        ctx.status = PipelineStatus.COMPLETED
        ctx.event.status = EventStatus.CLOSED
        return ctx


class PredictiveMonitorHandler:
    """Queries knowledge store for unpatched assets and generates PredictiveAlerts.

    Called on schedule; does not advance PipelineStage.
    """

    def __init__(
        self,
        audit_logger: AuditLogger,
        knowledge_store: KnowledgeStore,
        patch_age_threshold_days: int = 30,
        risk_score_threshold: float = 0.6,
    ) -> None:
        self._audit_logger = audit_logger
        self._knowledge_store = knowledge_store
        self._patch_age_threshold_days = patch_age_threshold_days
        self._risk_score_threshold = risk_score_threshold

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        alerts: list[dict[str, Any]] = []

        for asset_id in ctx.event.affected_assets:
            asset_context = await self._knowledge_store.get_asset_context(asset_id)
            if asset_context is None:
                continue

            # Check for vulnerabilities as indicator of unpatched state
            if asset_context.vulnerabilities:
                risk_score = min(1.0, len(asset_context.vulnerabilities) * 0.3)
                if risk_score >= self._risk_score_threshold:
                    alert = PredictiveAlert(
                        customer_id=ctx.customer_id,
                        alert_type=PredictiveAlertType.UNPATCHED_ASSET,
                        affected_assets=[asset_id],
                        cve_ids=[v.cve_id for v in asset_context.vulnerabilities],
                        risk_score=risk_score,
                        reasoning=(
                            f"Asset {asset_id} has "
                            f"{len(asset_context.vulnerabilities)} unpatched vulnerabilities"
                        ),
                        recommended_action_class=ActionClass.PATCH_DEPLOYMENT,
                        correlation_id=ctx.correlation_id,
                    )
                    alerts.append(alert.model_dump())

                    await self._audit_logger.append(
                        log_predictive_alert(
                            customer_id=ctx.customer_id,
                            alert_id=alert.alert_id,
                            alert_type=alert.alert_type.value,
                            risk_score=alert.risk_score,
                            correlation_id=ctx.correlation_id,
                        )
                    )

        ctx.metadata["predictive_alerts"] = alerts
        # Do NOT change ctx.current_stage — this is a background handler
        return ctx
