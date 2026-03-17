"""Pipeline orchestrator that wires together all security operation stages."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from summer_puppy.audit.logger import AuditLogger  # noqa: TC001
from summer_puppy.channel.bus import EventBus  # noqa: TC001
from summer_puppy.events.models import SecurityEvent  # noqa: TC001
from summer_puppy.execution.sandbox import ExecutionSandbox  # noqa: TC001
from summer_puppy.llm.client import LLMClient  # noqa: TC001
from summer_puppy.logging.config import correlation_context, get_logger
from summer_puppy.memory.store import KnowledgeStore  # noqa: TC001
from summer_puppy.pipeline.handlers import (
    CloseHandler,
    IntakeHandler,
    LLMAnalyzeHandler,
    LLMRecommendHandler,
    PassthroughAnalyzeHandler,
    PassthroughRecommendHandler,
    PassthroughTriageHandler,
    SandboxExecuteHandler,
    StepHandler,
    StubExecuteHandler,
    TriageHandler,
    TrustApprovalHandler,
    VerifyHandler,
)
from summer_puppy.pipeline.models import (
    PipelineContext,
    PipelineStage,
    PipelineStatus,
)
from summer_puppy.trust.models import AutoApprovalPolicy, TrustProfile  # noqa: TC001

logger = get_logger(__name__)

# Ordered stages the orchestrator walks through (excludes ERROR).
_STAGE_ORDER: list[PipelineStage] = [
    PipelineStage.INTAKE,
    PipelineStage.TRIAGE,
    PipelineStage.ANALYZE,
    PipelineStage.RECOMMEND,
    PipelineStage.APPROVE,
    PipelineStage.EXECUTE,
    PipelineStage.VERIFY,
    PipelineStage.CLOSE,
]


class Orchestrator:
    """Drives a SecurityEvent through the operations pipeline."""

    def __init__(
        self,
        audit_logger: AuditLogger,
        event_bus: EventBus,
    ) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus
        self._handlers: dict[PipelineStage, StepHandler] = {}

    def register_handler(self, stage: PipelineStage, handler: StepHandler) -> None:
        self._handlers[stage] = handler

    async def process_event(
        self,
        event: SecurityEvent,
        trust_profile: TrustProfile,
        policies: list[AutoApprovalPolicy] | None = None,
    ) -> PipelineContext:
        corr_id = event.correlation_id or str(uuid4())
        ctx = PipelineContext(
            event=event,
            customer_id=event.customer_id,
            correlation_id=corr_id,
            trust_profile=trust_profile,
            policies=policies or [],
        )

        async with correlation_context(corr_id):
            for stage in _STAGE_ORDER:
                if ctx.current_stage != stage:
                    continue

                handler = self._handlers.get(stage)
                if handler is None:
                    continue

                try:
                    ctx = await handler.handle(ctx)
                except Exception as exc:
                    ctx.current_stage = PipelineStage.ERROR
                    ctx.status = PipelineStatus.FAILED
                    ctx.error_detail = str(exc)
                    await logger.ainfo(
                        "pipeline_error",
                        stage=stage.value,
                        error=str(exc),
                    )
                    return ctx

                if ctx.status == PipelineStatus.PAUSED_FOR_APPROVAL:
                    return ctx

        return ctx

    async def resume_from_context(self, ctx: PipelineContext) -> PipelineContext:
        """Resume a paused pipeline from its current stage."""
        async with correlation_context(ctx.correlation_id):
            start_index = _STAGE_ORDER.index(ctx.current_stage)
            for stage in _STAGE_ORDER[start_index:]:
                if ctx.current_stage != stage:
                    continue
                handler = self._handlers.get(stage)
                if handler is None:
                    continue
                try:
                    ctx = await handler.handle(ctx)
                except Exception as exc:
                    ctx.current_stage = PipelineStage.ERROR
                    ctx.status = PipelineStatus.FAILED
                    ctx.error_detail = str(exc)
                    return ctx
                if ctx.status == PipelineStatus.PAUSED_FOR_APPROVAL:
                    return ctx
        return ctx

    @classmethod
    def build_default(
        cls,
        audit_logger: AuditLogger,
        event_bus: EventBus,
        llm_client: LLMClient | None = None,
        knowledge_store: KnowledgeStore | None = None,
        execution_sandbox: ExecutionSandbox | None = None,
        # NotificationDispatcher | None -- typed as Any to avoid circular import
        notification_dispatcher: Any | None = None,
    ) -> Orchestrator:
        """Create an orchestrator with all default handlers registered."""
        orch = cls(audit_logger=audit_logger, event_bus=event_bus)
        orch.register_handler(
            PipelineStage.INTAKE,
            IntakeHandler(audit_logger=audit_logger, event_bus=event_bus),
        )
        if knowledge_store is not None:
            orch.register_handler(
                PipelineStage.TRIAGE,
                TriageHandler(
                    knowledge_store=knowledge_store,
                    audit_logger=audit_logger,
                    event_bus=event_bus,
                ),
            )
        else:
            orch.register_handler(
                PipelineStage.TRIAGE,
                PassthroughTriageHandler(audit_logger=audit_logger, event_bus=event_bus),
            )
        if llm_client is not None:
            orch.register_handler(
                PipelineStage.ANALYZE,
                LLMAnalyzeHandler(
                    llm_client=llm_client,
                    audit_logger=audit_logger,
                    event_bus=event_bus,
                ),
            )
        else:
            orch.register_handler(
                PipelineStage.ANALYZE,
                PassthroughAnalyzeHandler(audit_logger=audit_logger, event_bus=event_bus),
            )
        if llm_client is not None:
            orch.register_handler(
                PipelineStage.RECOMMEND,
                LLMRecommendHandler(
                    llm_client=llm_client,
                    audit_logger=audit_logger,
                    event_bus=event_bus,
                ),
            )
        else:
            orch.register_handler(
                PipelineStage.RECOMMEND,
                PassthroughRecommendHandler(audit_logger=audit_logger, event_bus=event_bus),
            )
        orch.register_handler(
            PipelineStage.APPROVE,
            TrustApprovalHandler(
                audit_logger=audit_logger,
                event_bus=event_bus,
                notification_dispatcher=notification_dispatcher,
            ),
        )
        if execution_sandbox is not None:
            orch.register_handler(
                PipelineStage.EXECUTE,
                SandboxExecuteHandler(
                    execution_sandbox=execution_sandbox,
                    audit_logger=audit_logger,
                    event_bus=event_bus,
                ),
            )
        else:
            orch.register_handler(
                PipelineStage.EXECUTE,
                StubExecuteHandler(audit_logger=audit_logger, event_bus=event_bus),
            )
        orch.register_handler(
            PipelineStage.VERIFY,
            VerifyHandler(audit_logger=audit_logger, event_bus=event_bus),
        )
        orch.register_handler(
            PipelineStage.CLOSE,
            CloseHandler(audit_logger=audit_logger, event_bus=event_bus),
        )
        return orch
