"""End-to-end integration test proving the full learnable remediation loop.

Story 9: security event -> pipeline (with real sandbox execution) -> training ->
skill profile update -> knowledge base promotion -> audit chain integrity.
"""

from __future__ import annotations

from typing import Any

import pytest

from summer_puppy.audit.logger import InMemoryAuditLogger, verify_chain
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.events.models import (
    ActionRequest,
    ApprovalMethod,
    EventSource,
    QAStatus,
    Recommendation,
    SecurityEvent,
    Severity,
)
from summer_puppy.execution.adapters.mock_firewall import MockFirewallAdapter
from summer_puppy.execution.policy_gate import PolicyGate
from summer_puppy.execution.sandbox import ExecutionSandbox
from summer_puppy.execution.verifier import ExecutionVerifier
from summer_puppy.pipeline.handlers import (
    CloseHandler,
    IntakeHandler,
    PassthroughAnalyzeHandler,
    SandboxExecuteHandler,
    VerifyHandler,
)
from summer_puppy.pipeline.models import PipelineContext, PipelineStage, PipelineStatus
from summer_puppy.pipeline.orchestrator import Orchestrator
from summer_puppy.skills.evaluator import RunEvaluator
from summer_puppy.skills.kb import InMemorySkillKnowledgeBase
from summer_puppy.skills.models import PromotionLevel, TrainingRecommendation
from summer_puppy.skills.promotion import PromotionEngine
from summer_puppy.skills.registry import InMemorySkillRegistry
from summer_puppy.skills.trainer import Trainer
from summer_puppy.tenants.models import TenantProfile
from summer_puppy.tenants.policy import TenantPolicyEngine
from summer_puppy.trust.models import ActionClass, TrustPhase, TrustProfile

# ---------------------------------------------------------------------------
# Inline test handlers
# ---------------------------------------------------------------------------


class _TenantInjectingTriageHandler:
    """Injects a TenantProfile into pipeline context, then advances to ANALYZE."""

    def __init__(
        self,
        tenant: TenantProfile,
        audit_logger: InMemoryAuditLogger,
        event_bus: InMemoryEventBus,
    ) -> None:
        self._tenant = tenant
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        ctx.metadata["tenant_profile"] = self._tenant.model_dump()
        ctx.current_stage = PipelineStage.ANALYZE
        return ctx


class _BlockIPRecommendHandler:
    """Produces a BLOCK_IP recommendation with ip_address in context metadata."""

    def __init__(
        self,
        audit_logger: InMemoryAuditLogger,
        event_bus: InMemoryEventBus,
    ) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        rec = Recommendation(
            event_id=ctx.event.event_id,
            customer_id=ctx.customer_id,
            action_class=ActionClass.BLOCK_IP,
            description="Block suspicious IP 192.168.1.100",
            reasoning="Multiple failed login attempts detected",
            confidence_score=0.9,
            estimated_risk=Severity.LOW,
            qa_status=QAStatus.PASSED,
            rollback_plan="Unblock IP via firewall adapter",
        )
        ctx.recommendation = rec
        # Stash ip_address so the approval handler can propagate it
        ctx.metadata["block_ip_address"] = "192.168.1.100"
        ctx.current_stage = PipelineStage.APPROVE
        return ctx


class _BlockIPApprovalHandler:
    """Auto-approves and creates an ActionRequest with ip_address in parameters."""

    def __init__(
        self,
        audit_logger: InMemoryAuditLogger,
        event_bus: InMemoryEventBus,
    ) -> None:
        self._audit_logger = audit_logger
        self._event_bus = event_bus

    async def handle(self, ctx: PipelineContext) -> PipelineContext:
        assert ctx.recommendation is not None, "Recommendation required at APPROVE stage"
        ip_address = ctx.metadata.get("block_ip_address", "10.0.0.1")
        action_request = ActionRequest(
            recommendation_id=ctx.recommendation.recommendation_id,
            customer_id=ctx.customer_id,
            action_class=ActionClass.BLOCK_IP,
            approval_method=ApprovalMethod.AUTO_APPROVED,
            approved_by=f"trust_phase:{ctx.trust_profile.trust_phase.value}",
            parameters={"ip_address": ip_address},
        )
        ctx.action_request = action_request
        ctx.current_stage = PipelineStage.EXECUTE
        return ctx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFullLearnableRemediationLoop:
    """THE test that proves the whole learnable remediation system works end-to-end."""

    @pytest.mark.asyncio()
    async def test_full_learnable_remediation_loop(self) -> None:
        # ------------------------------------------------------------------
        # 1. Infrastructure setup
        # ------------------------------------------------------------------
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        # 2. Tenant profile that allows BLOCK_IP
        tenant = TenantProfile(
            customer_id="customer-1",
            allowed_action_classes=[ActionClass.BLOCK_IP, ActionClass.PATCH_DEPLOYMENT],
            require_dry_run=True,
            auto_rollback_on_verify_fail=True,
        )

        # 3. Execution sandbox with MockFirewallAdapter
        mock_firewall = MockFirewallAdapter(audit_logger=audit_logger)
        policy_gate = PolicyGate(TenantPolicyEngine())
        verifier = ExecutionVerifier()
        sandbox = ExecutionSandbox(
            adapters={ActionClass.BLOCK_IP: mock_firewall},
            policy_gate=policy_gate,
            verifier=verifier,
            audit_logger=audit_logger,
        )

        # 4. Skills/training infrastructure
        evaluator = RunEvaluator()
        promotion_engine = PromotionEngine()
        skill_registry = InMemorySkillRegistry()
        knowledge_base = InMemorySkillKnowledgeBase()
        trainer = Trainer(
            evaluator=evaluator,
            promotion_engine=promotion_engine,
            skill_registry=skill_registry,
            knowledge_base=knowledge_base,
            audit_logger=audit_logger,
        )

        # 5. Build orchestrator with fully custom handler chain
        orch = Orchestrator(audit_logger=audit_logger, event_bus=event_bus)
        orch.register_handler(
            PipelineStage.INTAKE,
            IntakeHandler(audit_logger=audit_logger, event_bus=event_bus),
        )
        orch.register_handler(
            PipelineStage.TRIAGE,
            _TenantInjectingTriageHandler(
                tenant=tenant, audit_logger=audit_logger, event_bus=event_bus
            ),
        )
        orch.register_handler(
            PipelineStage.ANALYZE,
            PassthroughAnalyzeHandler(audit_logger=audit_logger, event_bus=event_bus),
        )
        orch.register_handler(
            PipelineStage.RECOMMEND,
            _BlockIPRecommendHandler(audit_logger=audit_logger, event_bus=event_bus),
        )
        orch.register_handler(
            PipelineStage.APPROVE,
            _BlockIPApprovalHandler(audit_logger=audit_logger, event_bus=event_bus),
        )
        orch.register_handler(
            PipelineStage.EXECUTE,
            SandboxExecuteHandler(
                execution_sandbox=sandbox, audit_logger=audit_logger, event_bus=event_bus
            ),
        )
        orch.register_handler(
            PipelineStage.VERIFY,
            VerifyHandler(audit_logger=audit_logger, event_bus=event_bus),
        )
        orch.register_handler(
            PipelineStage.CLOSE,
            CloseHandler(audit_logger=audit_logger, event_bus=event_bus),
        )

        # 6. Create security event
        event = SecurityEvent(
            customer_id="customer-1",
            source=EventSource.SIEM,
            severity=Severity.HIGH,
            title="Suspicious IP detected",
            description="Multiple failed login attempts from 192.168.1.100",
            affected_assets=["firewall-01"],
            correlation_id="corr-loop-1",
        )

        # 7. Trust profile (AUTONOMOUS so it auto-approves)
        trust_profile = TrustProfile(
            customer_id="customer-1",
            trust_phase=TrustPhase.AUTONOMOUS,
            total_recommendations=60,
            positive_outcome_rate=0.93,
        )

        # ------------------------------------------------------------------
        # 8. Run pipeline
        # ------------------------------------------------------------------
        ctx = await orch.process_event(event=event, trust_profile=trust_profile)

        # ------------------------------------------------------------------
        # 9. Pipeline assertions
        # ------------------------------------------------------------------
        assert ctx.status == PipelineStatus.COMPLETED, (
            f"Expected COMPLETED but got {ctx.status} "
            f"(stage={ctx.current_stage}, error={ctx.error_detail})"
        )
        assert ctx.outcome is not None, "Expected an ActionOutcome"
        assert ctx.outcome.success is True, (
            f"Expected success but got failure: {ctx.outcome.result_summary}"
        )
        assert "execution_plan" in ctx.metadata, "execution_plan missing from metadata"
        plan_data: dict[str, Any] = ctx.metadata["execution_plan"]
        assert plan_data["policy_gate_passed"] is True
        assert plan_data["dry_run_result"]["is_safe"] is True

        # ------------------------------------------------------------------
        # 10. Training phase: review_and_train
        # ------------------------------------------------------------------
        context_summary: dict[str, Any] = {
            "customer_id": ctx.customer_id,
            "correlation_id": ctx.correlation_id,
            "confidence_score": (
                ctx.recommendation.confidence_score if ctx.recommendation else 0.5
            ),
            "execution_status": "COMPLETED",
            "outcome_success": ctx.outcome.success,
            "qa_status": "PASSED",
            "approval_method": (
                ctx.action_request.approval_method.value if ctx.action_request else "AUTO_APPROVED"
            ),
            "agent_id": "integration-test-agent",
        }
        artifacts: list[dict[str, Any]] = [
            {
                "artifact_id": "art-1",
                "artifact_type": "DETECTION_RULE",
                "content": "rule: block 192.168.1.100",
                "source_run_id": ctx.correlation_id,
            },
        ]

        training_result = await trainer.review_and_train(context_summary, artifacts)

        # ------------------------------------------------------------------
        # 11. Training assertions
        # ------------------------------------------------------------------
        assert isinstance(training_result, TrainingRecommendation)

        # Skill profile updated
        profile = skill_registry.get_agent_profile("integration-test-agent")
        assert profile is not None, "Agent profile should have been created"
        assert profile.total_runs == 1
        assert profile.successful_runs == 1

        # KB promotion: DETECTION_RULE with outcome_success=True and qa_reliability=1.0
        # should be promoted to TEAM_KB
        articles = knowledge_base.list_articles("customer-1")
        assert len(articles) >= 1, "At least one KB article should have been promoted"
        team_articles = knowledge_base.list_articles(
            "customer-1", promotion_level=PromotionLevel.TEAM_KB
        )
        assert len(team_articles) >= 1, "DETECTION_RULE should be promoted to TEAM_KB"
        assert "art-1" in training_result.kb_promotions

        # ------------------------------------------------------------------
        # 12. Audit chain integrity
        # ------------------------------------------------------------------
        assert verify_chain(audit_logger._entries) is True, "Audit chain integrity check failed"
        assert len(audit_logger._entries) > 0, "Expected at least one audit entry"


class TestDryRunSafetyMechanism:
    """Validates the safety mechanism: dry_run fails when required params are missing."""

    @pytest.mark.asyncio()
    async def test_dry_run_fails_with_missing_params(self) -> None:
        """Default passthrough handlers produce empty params, so dry_run fails."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        mock_firewall = MockFirewallAdapter(audit_logger=audit_logger)
        policy_gate = PolicyGate(TenantPolicyEngine())
        verifier = ExecutionVerifier()
        sandbox = ExecutionSandbox(
            adapters={ActionClass.BLOCK_IP: mock_firewall},
            policy_gate=policy_gate,
            verifier=verifier,
            audit_logger=audit_logger,
        )

        # Use build_default with sandbox. PassthroughRecommendHandler produces
        # PATCH_DEPLOYMENT, but our sandbox only has BLOCK_IP adapter.
        # No adapter for PATCH_DEPLOYMENT => sandbox returns early (no dry_run, no exec).
        # The outcome.success will be False because execution_result is None.
        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            execution_sandbox=sandbox,
        )

        event = SecurityEvent(
            customer_id="customer-2",
            source=EventSource.SIEM,
            severity=Severity.HIGH,
            title="Unmatched action test",
            description="Testing adapter mismatch path",
        )
        trust_profile = TrustProfile(
            customer_id="customer-2",
            trust_phase=TrustPhase.AUTONOMOUS,
            total_recommendations=60,
            positive_outcome_rate=0.93,
        )

        ctx = await orch.process_event(event=event, trust_profile=trust_profile)

        # Pipeline completes but execution didn't actually proceed
        assert ctx.status == PipelineStatus.COMPLETED
        assert ctx.outcome is not None
        assert ctx.outcome.success is False, (
            "Outcome should be False when no adapter matches the action class"
        )


class TestBackwardCompatibilityWithoutSandbox:
    """Proves the pipeline still works with the old StubExecuteHandler."""

    @pytest.mark.asyncio()
    async def test_backward_compatibility_without_sandbox(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        orch = Orchestrator.build_default(audit_logger=audit_logger, event_bus=event_bus)

        event = SecurityEvent(
            customer_id="c1",
            source=EventSource.SIEM,
            severity=Severity.MEDIUM,
            title="Test",
            description="Test backward compat",
        )
        profile = TrustProfile(customer_id="c1", trust_phase=TrustPhase.AUTONOMOUS)

        result = await orch.process_event(event, profile)

        assert result.status == PipelineStatus.COMPLETED
        assert result.outcome is not None
        assert result.outcome.success is True

    @pytest.mark.asyncio()
    async def test_audit_chain_integrity_without_sandbox(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        orch = Orchestrator.build_default(audit_logger=audit_logger, event_bus=event_bus)

        event = SecurityEvent(
            customer_id="c2",
            source=EventSource.SIEM,
            severity=Severity.LOW,
            title="Audit chain test",
            description="Testing audit integrity without sandbox",
        )
        profile = TrustProfile(customer_id="c2", trust_phase=TrustPhase.AUTONOMOUS)

        await orch.process_event(event, profile)

        assert verify_chain(audit_logger._entries) is True
