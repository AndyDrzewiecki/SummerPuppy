"""Full end-to-end pipeline integration tests.

These tests exercise the Orchestrator with InMemoryLLMClient and
InMemoryKnowledgeStore — no Docker or external services required.
"""

from __future__ import annotations

from summer_puppy.audit.logger import InMemoryAuditLogger, verify_chain
from summer_puppy.channel.bus import InMemoryEventBus  # noqa: TC001
from summer_puppy.events.models import ApprovalMethod, SecurityEvent
from summer_puppy.llm.client import InMemoryLLMClient  # noqa: TC001
from summer_puppy.memory.store import InMemoryKnowledgeStore  # noqa: TC001
from summer_puppy.pipeline.models import PipelineStage, PipelineStatus
from summer_puppy.pipeline.orchestrator import Orchestrator
from summer_puppy.trust.models import AutoApprovalPolicy, TrustPhase, TrustProfile


class TestFullPipelineWithLLMHandlers:
    """Test the full pipeline with LLM analyze + recommend handlers."""

    async def test_full_pipeline_with_llm_handlers(
        self,
        mock_llm_client: InMemoryLLMClient,
        memory_store: InMemoryKnowledgeStore,
        sample_event: SecurityEvent,
        sample_trust_profile: TrustProfile,
        sample_policies: list[AutoApprovalPolicy],
        audit_logger: InMemoryAuditLogger,
        event_bus: InMemoryEventBus,
    ) -> None:
        """Build orchestrator with LLM client and knowledge store, process event end-to-end."""
        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            llm_client=mock_llm_client,
            knowledge_store=memory_store,
        )

        ctx = await orch.process_event(
            event=sample_event,
            trust_profile=sample_trust_profile,
            policies=sample_policies,
        )

        assert ctx.status == PipelineStatus.COMPLETED
        assert ctx.recommendation is not None
        assert ctx.outcome is not None
        assert ctx.outcome.success is True
        assert "analysis" in ctx.metadata
        assert "knowledge_context" in ctx.metadata
        # Verify asset data was enriched by TriageHandler
        knowledge_ctx = ctx.metadata["knowledge_context"]
        assert "assets" in knowledge_ctx
        assert len(knowledge_ctx["assets"]) > 0

    async def test_pipeline_pauses_for_manual_trust(
        self,
        mock_llm_client: InMemoryLLMClient,
        memory_store: InMemoryKnowledgeStore,
        sample_event: SecurityEvent,
        audit_logger: InMemoryAuditLogger,
        event_bus: InMemoryEventBus,
    ) -> None:
        """Pipeline should pause for approval when trust_phase is MANUAL."""
        manual_profile = TrustProfile(
            customer_id="customer-1",
            trust_phase=TrustPhase.MANUAL,
            total_recommendations=5,
            positive_outcome_rate=0.5,
        )

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            llm_client=mock_llm_client,
            knowledge_store=memory_store,
        )

        ctx = await orch.process_event(
            event=sample_event,
            trust_profile=manual_profile,
            policies=[],
        )

        assert ctx.status == PipelineStatus.PAUSED_FOR_APPROVAL
        assert ctx.current_stage == PipelineStage.APPROVE

    async def test_pipeline_auto_approves_with_matching_policy(
        self,
        mock_llm_client: InMemoryLLMClient,
        memory_store: InMemoryKnowledgeStore,
        sample_event: SecurityEvent,
        sample_trust_profile: TrustProfile,
        sample_policies: list[AutoApprovalPolicy],
        audit_logger: InMemoryAuditLogger,
        event_bus: InMemoryEventBus,
    ) -> None:
        """AUTONOMOUS trust with matching policy should auto-approve and complete."""
        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            llm_client=mock_llm_client,
            knowledge_store=memory_store,
        )

        ctx = await orch.process_event(
            event=sample_event,
            trust_profile=sample_trust_profile,
            policies=sample_policies,
        )

        assert ctx.status == PipelineStatus.COMPLETED
        assert ctx.action_request is not None
        assert ctx.action_request.approval_method == ApprovalMethod.AUTO_APPROVED

    async def test_pipeline_without_llm_uses_passthroughs(
        self,
        sample_event: SecurityEvent,
        sample_trust_profile: TrustProfile,
        audit_logger: InMemoryAuditLogger,
        event_bus: InMemoryEventBus,
    ) -> None:
        """Build with no llm_client to verify backward compatibility with stub handlers."""
        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
        )

        ctx = await orch.process_event(
            event=sample_event,
            trust_profile=sample_trust_profile,
        )

        assert ctx.status == PipelineStatus.COMPLETED

    async def test_audit_trail_integrity(
        self,
        mock_llm_client: InMemoryLLMClient,
        memory_store: InMemoryKnowledgeStore,
        sample_event: SecurityEvent,
        sample_trust_profile: TrustProfile,
        sample_policies: list[AutoApprovalPolicy],
        audit_logger: InMemoryAuditLogger,
        event_bus: InMemoryEventBus,
    ) -> None:
        """Run full pipeline, collect all audit entries, verify chain integrity."""
        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            llm_client=mock_llm_client,
            knowledge_store=memory_store,
        )

        ctx = await orch.process_event(
            event=sample_event,
            trust_profile=sample_trust_profile,
            policies=sample_policies,
        )

        assert ctx.status == PipelineStatus.COMPLETED

        # Retrieve the full audit chain for this correlation
        chain = await audit_logger.get_chain(ctx.correlation_id)
        assert len(chain) > 0

        # Verify cryptographic chain integrity
        assert verify_chain(chain) is True
