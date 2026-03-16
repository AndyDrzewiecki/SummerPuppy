"""Adapter to plug the LangGraph SecurityAnalysisGraph into the pipeline as a StepHandler."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from summer_puppy.audit.models import AuditEntry, AuditEntryType
from summer_puppy.events.models import Recommendation, Severity
from summer_puppy.pipeline.models import PipelineContext, PipelineStage
from summer_puppy.trust.models import ActionClass

if TYPE_CHECKING:
    from summer_puppy.agents.graph import SecurityAnalysisGraph
    from summer_puppy.audit.logger import AuditLogger
    from summer_puppy.channel.bus import EventBus

_logger = logging.getLogger(__name__)


class LangGraphStepHandler:
    """Pipeline StepHandler that delegates to SecurityAnalysisGraph.

    The graph handles both analysis and recommendation in a single invocation,
    so this handler advances the pipeline directly to APPROVE.
    """

    def __init__(
        self,
        graph: SecurityAnalysisGraph,
        audit_logger: AuditLogger,
        event_bus: EventBus,
    ) -> None:
        self._graph = graph
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        """Run the LangGraph agent and populate pipeline context from the result."""
        try:
            result = await self._graph.run(
                ctx.event,
                ctx.trust_profile,
                ctx.metadata.get("knowledge_context"),
            )

            if result.analysis is not None:
                ctx.metadata["analysis"] = result.analysis

                entry = AuditEntry(
                    customer_id=ctx.customer_id,
                    entry_type=AuditEntryType.ANALYSIS_COMPLETED,
                    actor="system",
                    correlation_id=ctx.correlation_id,
                    resource_id=ctx.event.event_id,
                    details={
                        "threat_type": result.analysis.get("threat_type", "Unknown"),
                    },
                )
                await self._audit_logger.append(entry)
                ctx.audit_entry_ids.append(entry.entry_id)

            if result.recommendation is not None:
                rec_data = result.recommendation
                action_class_val = rec_data.get("action_class", "compensating_control")
                recommendation = Recommendation(
                    event_id=ctx.event.event_id,
                    customer_id=ctx.customer_id,
                    action_class=ActionClass(action_class_val),
                    description=rec_data.get("description", ""),
                    reasoning=rec_data.get("reasoning", ""),
                    confidence_score=rec_data.get("confidence_score", 0.5),
                    estimated_risk=Severity(rec_data.get("estimated_risk", "MEDIUM")),
                    rollback_plan=rec_data.get("rollback_plan"),
                    affected_asset_classes=rec_data.get("affected_asset_classes", []),
                )
                ctx.recommendation = recommendation

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

        except Exception:
            _logger.warning(
                "LangGraph agent failed for event %s",
                ctx.event.event_id,
                exc_info=True,
            )
            # Fall through to next stage without blocking
            ctx.current_stage = PipelineStage.RECOMMEND

        return ctx
