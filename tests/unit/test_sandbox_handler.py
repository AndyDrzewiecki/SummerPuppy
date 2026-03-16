"""Tests for SandboxExecuteHandler, Orchestrator wiring, and PoolOrchestrator trainer (Story 8)."""

from __future__ import annotations

from typing import Any

import pytest

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.channel.models import Topic
from summer_puppy.events.models import (
    ActionRequest,
    ApprovalMethod,
    EventSource,
    ExecutorStatus,
    SecurityEvent,
    Severity,
)
from summer_puppy.execution.adapters.mock_firewall import MockFirewallAdapter
from summer_puppy.execution.adapters.mock_patch import MockPatchAdapter
from summer_puppy.execution.policy_gate import PolicyGate
from summer_puppy.execution.sandbox import ExecutionSandbox
from summer_puppy.execution.verifier import ExecutionVerifier
from summer_puppy.memory.store import InMemoryKnowledgeStore
from summer_puppy.pipeline.handlers import (
    SandboxExecuteHandler,
    StubExecuteHandler,
)
from summer_puppy.pipeline.models import (
    PipelineContext,
    PipelineStage,
)
from summer_puppy.pipeline.orchestrator import Orchestrator
from summer_puppy.pool.models import AgentPool, PoolType
from summer_puppy.pool.orchestrator import PoolOrchestrator
from summer_puppy.pool.registry import InMemoryPoolRegistry
from summer_puppy.skills.evaluator import RunEvaluator
from summer_puppy.skills.kb import InMemorySkillKnowledgeBase
from summer_puppy.skills.promotion import PromotionEngine
from summer_puppy.skills.registry import InMemorySkillRegistry
from summer_puppy.skills.trainer import Trainer
from summer_puppy.tenants.models import TenantProfile
from summer_puppy.tenants.policy import TenantPolicyEngine
from summer_puppy.trust.models import ActionClass, TrustPhase, TrustProfile
from summer_puppy.work.models import (
    Artifact,
    ArtifactType,
    WorkItem,
    WorkItemStatus,
    WorkItemType,
)
from summer_puppy.work.store import InMemoryWorkItemStore

# ===========================================================================
# Helpers
# ===========================================================================


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
        "trust_phase": TrustPhase.AUTONOMOUS,
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
        "correlation_id": ev.correlation_id or "corr-001",
        "trust_profile": tp,
    }
    defaults.update(overrides)
    return PipelineContext(**defaults)


def _make_action_request(**overrides: Any) -> ActionRequest:
    defaults: dict[str, Any] = {
        "recommendation_id": "rec-1",
        "customer_id": "cust-test",
        "action_class": ActionClass.BLOCK_IP,
        "approval_method": ApprovalMethod.AUTO_APPROVED,
        "approved_by": "system",
        "parameters": {"ip_address": "10.0.0.1"},
    }
    defaults.update(overrides)
    return ActionRequest(**defaults)


def _make_sandbox(
    audit_logger: InMemoryAuditLogger | None = None,
) -> ExecutionSandbox:
    logger = audit_logger or InMemoryAuditLogger()
    adapter = MockFirewallAdapter(audit_logger=logger)
    gate = PolicyGate(TenantPolicyEngine())
    verifier = ExecutionVerifier()
    return ExecutionSandbox(
        adapters={ActionClass.BLOCK_IP: adapter},
        policy_gate=gate,
        verifier=verifier,
        audit_logger=logger,
    )


def _make_handler(
    audit_logger: InMemoryAuditLogger | None = None,
    event_bus: InMemoryEventBus | None = None,
    sandbox: ExecutionSandbox | None = None,
) -> tuple[SandboxExecuteHandler, InMemoryAuditLogger, InMemoryEventBus]:
    al = audit_logger or InMemoryAuditLogger()
    eb = event_bus or InMemoryEventBus()
    sb = sandbox or _make_sandbox(audit_logger=al)
    handler = SandboxExecuteHandler(
        execution_sandbox=sb,
        audit_logger=al,
        event_bus=eb,
    )
    return handler, al, eb


def _build_trainer() -> tuple[
    Trainer, InMemorySkillRegistry, InMemorySkillKnowledgeBase, InMemoryAuditLogger
]:
    evaluator = RunEvaluator()
    promotion_engine = PromotionEngine()
    registry = InMemorySkillRegistry()
    kb = InMemorySkillKnowledgeBase()
    audit = InMemoryAuditLogger()
    trainer = Trainer(
        evaluator=evaluator,
        promotion_engine=promotion_engine,
        skill_registry=registry,
        knowledge_base=kb,
        audit_logger=audit,
    )
    return trainer, registry, kb, audit


# ===========================================================================
# SandboxExecuteHandler tests
# ===========================================================================


class TestSandboxExecuteHandlerHappyPath:
    async def test_happy_path_success_true(self) -> None:
        """Sandbox executes successfully: ctx.outcome.success is True."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert result.outcome.success is True

    async def test_happy_path_stage_advances_to_verify(self) -> None:
        """After successful execution, stage advances to VERIFY."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.VERIFY

    async def test_happy_path_result_summary_contains_completed(self) -> None:
        """Result summary mentions COMPLETED status."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert "COMPLETED" in result.outcome.result_summary

    async def test_happy_path_request_id_matches(self) -> None:
        """Outcome request_id matches the action_request request_id."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert result.outcome.request_id == action_req.request_id


class TestSandboxExecuteHandlerDryRunFails:
    async def test_dry_run_fails_outcome_not_success(self) -> None:
        """Dry run fails: ctx.outcome.success is False."""
        handler, _, _ = _make_handler()
        # Missing ip_address => dry run fails
        action_req = _make_action_request(parameters={})
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert result.outcome.success is False

    async def test_dry_run_fails_summary_mentions_dry_run(self) -> None:
        """Dry run failure: result_summary mentions dry run."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request(parameters={})
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert "dry run" in result.outcome.result_summary.lower()

    async def test_dry_run_fails_stage_still_verify(self) -> None:
        """Stage still advances to VERIFY even on dry-run failure."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request(parameters={})
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.VERIFY


class TestSandboxExecuteHandlerPolicyGateDenied:
    async def test_policy_gate_denied_outcome_not_success(self) -> None:
        """Policy gate denied: ctx.outcome.success is False."""
        al = InMemoryAuditLogger()
        adapter = MockFirewallAdapter(audit_logger=al)
        gate = PolicyGate(TenantPolicyEngine())
        verifier = ExecutionVerifier()
        sandbox = ExecutionSandbox(
            adapters={ActionClass.BLOCK_IP: adapter},
            policy_gate=gate,
            verifier=verifier,
            audit_logger=al,
        )
        handler, _, _ = _make_handler(audit_logger=al, sandbox=sandbox)

        # Tenant blocks BLOCK_IP
        tenant_data = TenantProfile(
            customer_id="cust-test",
            blocked_action_classes=[ActionClass.BLOCK_IP],
        ).model_dump()

        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
            metadata={"tenant_profile": tenant_data},
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert result.outcome.success is False

    async def test_policy_gate_denied_summary_mentions_policy(self) -> None:
        """Policy gate denied: result_summary mentions policy."""
        al = InMemoryAuditLogger()
        adapter = MockFirewallAdapter(audit_logger=al)
        gate = PolicyGate(TenantPolicyEngine())
        verifier = ExecutionVerifier()
        sandbox = ExecutionSandbox(
            adapters={ActionClass.BLOCK_IP: adapter},
            policy_gate=gate,
            verifier=verifier,
            audit_logger=al,
        )
        handler, _, _ = _make_handler(audit_logger=al, sandbox=sandbox)

        tenant_data = TenantProfile(
            customer_id="cust-test",
            blocked_action_classes=[ActionClass.BLOCK_IP],
        ).model_dump()

        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
            metadata={"tenant_profile": tenant_data},
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert "policy gate" in result.outcome.result_summary.lower()


class TestSandboxExecuteHandlerMetadata:
    async def test_execution_plan_stored_in_metadata(self) -> None:
        """execution_plan is stored in ctx.metadata after execution."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert "execution_plan" in result.metadata
        assert isinstance(result.metadata["execution_plan"], dict)

    async def test_execution_plan_has_plan_id(self) -> None:
        """execution_plan in metadata contains plan_id."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        plan_data = result.metadata["execution_plan"]
        assert "plan_id" in plan_data


class TestSandboxExecuteHandlerEventBus:
    async def test_publishes_action_outcomes(self) -> None:
        """Event bus receives ACTION_OUTCOMES message."""
        handler, _, eb = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        await handler.handle(ctx)

        history = eb.get_history(Topic.ACTION_OUTCOMES)
        assert len(history) >= 1

    async def test_published_outcome_matches_ctx_outcome(self) -> None:
        """Published outcome has same request_id as ctx.outcome."""
        handler, _, eb = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        history = eb.get_history(Topic.ACTION_OUTCOMES)
        assert len(history) >= 1
        assert result.outcome is not None
        assert history[0].payload["request_id"] == result.outcome.request_id


class TestSandboxExecuteHandlerTenant:
    async def test_default_tenant_when_no_tenant_profile(self) -> None:
        """When no tenant_profile in metadata, uses default permissive tenant."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )
        # No tenant_profile in metadata
        assert "tenant_profile" not in ctx.metadata

        result = await handler.handle(ctx)

        # Should still succeed (permissive default)
        assert result.outcome is not None
        assert result.outcome.success is True

    async def test_with_tenant_profile_dict_in_metadata(self) -> None:
        """When tenant_profile is a dict in metadata, it is used."""
        al = InMemoryAuditLogger()
        adapter = MockFirewallAdapter(audit_logger=al)
        gate = PolicyGate(TenantPolicyEngine())
        verifier = ExecutionVerifier()
        sandbox = ExecutionSandbox(
            adapters={ActionClass.BLOCK_IP: adapter},
            policy_gate=gate,
            verifier=verifier,
            audit_logger=al,
        )
        handler, _, _ = _make_handler(audit_logger=al, sandbox=sandbox)

        # Tenant that allows BLOCK_IP explicitly
        tenant_data = TenantProfile(
            customer_id="cust-test",
            allowed_action_classes=[ActionClass.BLOCK_IP],
        ).model_dump()

        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
            metadata={"tenant_profile": tenant_data},
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert result.outcome.success is True

    async def test_with_non_dict_tenant_profile_uses_default(self) -> None:
        """Non-dict tenant_profile in metadata falls back to default."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
            metadata={"tenant_profile": "not-a-dict"},
        )

        result = await handler.handle(ctx)

        # Should succeed with default permissive tenant
        assert result.outcome is not None
        assert result.outcome.success is True


class TestSandboxExecuteHandlerRollback:
    async def test_rollback_triggered_flag(self) -> None:
        """When rollback occurs, outcome.rollback_triggered is True."""
        al = InMemoryAuditLogger()
        # Use an adapter where execution fails -> verify fails -> rollback happens
        adapter = _FailingAdapter(al)
        gate = PolicyGate(TenantPolicyEngine())
        verifier = ExecutionVerifier()
        sandbox = ExecutionSandbox(
            adapters={ActionClass.BLOCK_IP: adapter},
            policy_gate=gate,
            verifier=verifier,
            audit_logger=al,
        )
        handler, _, _ = _make_handler(audit_logger=al, sandbox=sandbox)

        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert result.outcome.rollback_triggered is True


class TestSandboxExecuteHandlerAssert:
    async def test_asserts_action_request_present(self) -> None:
        """AssertionError raised when action_request is None."""
        handler, _, _ = _make_handler()
        ctx = _make_context(current_stage=PipelineStage.EXECUTE)
        assert ctx.action_request is None

        with pytest.raises(AssertionError, match="ActionRequest required"):
            await handler.handle(ctx)


class TestSandboxExecuteHandlerOutcomeFields:
    async def test_outcome_customer_id(self) -> None:
        """Outcome customer_id matches context."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert result.outcome.customer_id == "cust-test"

    async def test_outcome_completed_utc_set(self) -> None:
        """Outcome completed_utc is set."""
        handler, _, _ = _make_handler()
        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert result.outcome.completed_utc is not None

    async def test_failed_execution_error_detail(self) -> None:
        """When execution fails, error_detail is propagated."""
        al = InMemoryAuditLogger()
        adapter = _FailingAdapter(al)
        gate = PolicyGate(TenantPolicyEngine())
        verifier = ExecutionVerifier()
        sandbox = ExecutionSandbox(
            adapters={ActionClass.BLOCK_IP: adapter},
            policy_gate=gate,
            verifier=verifier,
            audit_logger=al,
        )
        handler, _, _ = _make_handler(audit_logger=al, sandbox=sandbox)

        action_req = _make_action_request()
        ctx = _make_context(
            action_request=action_req,
            current_stage=PipelineStage.EXECUTE,
        )

        result = await handler.handle(ctx)

        assert result.outcome is not None
        assert result.outcome.success is False
        assert result.outcome.error_detail is not None
        assert "Simulated failure" in result.outcome.error_detail


# ===========================================================================
# Orchestrator wiring tests
# ===========================================================================


class TestOrchestratorWiring:
    async def test_build_default_without_sandbox_uses_stub(self) -> None:
        """Orchestrator.build_default() without execution_sandbox uses StubExecuteHandler."""
        al = InMemoryAuditLogger()
        eb = InMemoryEventBus()
        orch = Orchestrator.build_default(audit_logger=al, event_bus=eb)

        handler = orch._handlers.get(PipelineStage.EXECUTE)
        assert isinstance(handler, StubExecuteHandler)

    async def test_build_default_with_sandbox_uses_sandbox_handler(self) -> None:
        """Orchestrator.build_default() with execution_sandbox uses SandboxExecuteHandler."""
        al = InMemoryAuditLogger()
        eb = InMemoryEventBus()
        sandbox = _make_sandbox(audit_logger=al)
        orch = Orchestrator.build_default(
            audit_logger=al,
            event_bus=eb,
            execution_sandbox=sandbox,
        )

        handler = orch._handlers.get(PipelineStage.EXECUTE)
        assert isinstance(handler, SandboxExecuteHandler)

    async def test_full_pipeline_with_sandbox_handler(self) -> None:
        """Full pipeline run with SandboxExecuteHandler completes successfully."""
        al = InMemoryAuditLogger()
        eb = InMemoryEventBus()
        # PassthroughRecommendHandler creates PATCH_DEPLOYMENT recommendations,
        # so the sandbox needs a MockPatchAdapter for that action class.
        patch_adapter = MockPatchAdapter(audit_logger=al)
        gate = PolicyGate(TenantPolicyEngine())
        verifier = ExecutionVerifier()
        sandbox = ExecutionSandbox(
            adapters={ActionClass.PATCH_DEPLOYMENT: patch_adapter},
            policy_gate=gate,
            verifier=verifier,
            audit_logger=al,
        )
        orch = Orchestrator.build_default(
            audit_logger=al,
            event_bus=eb,
            execution_sandbox=sandbox,
        )

        # PassthroughRecommendHandler creates recommendations with empty parameters,
        # but MockPatchAdapter requires 'patch_id'. We need to pass through the
        # full pipeline where the action_request has the right parameters.
        # Since PassthroughRecommendHandler creates the recommendation and
        # TrustApprovalHandler creates the action_request from it (with empty params),
        # and MockPatchAdapter.dry_run needs 'patch_id', the dry_run will fail,
        # which is still a valid test: the handler processes the dry_run failure.
        event = _make_event()
        profile = _make_trust_profile()

        result = await orch.process_event(event, profile)

        # The pipeline completes, outcome is set (dry_run fails => success=False)
        assert result.outcome is not None
        assert result.current_stage == PipelineStage.CLOSE


# ===========================================================================
# PoolOrchestrator trainer wiring tests
# ===========================================================================


class TestPoolOrchestratorTrainerNone:
    @pytest.mark.asyncio()
    async def test_backward_compatible_without_trainer(self) -> None:
        """PoolOrchestrator with trainer=None: _complete_work_item works normally."""
        eb = InMemoryEventBus()
        registry = InMemoryPoolRegistry()
        eng_pool = AgentPool(
            pool_id="eng-pool-1",
            name="Engineering",
            pool_type=PoolType.ENGINEERING,
            can_consume=[WorkItemType.THREAT_REPORT],
            current_load=0,
            max_capacity=10,
        )
        registry.register(eng_pool)
        wis = InMemoryWorkItemStore()
        al = InMemoryAuditLogger()
        ks = InMemoryKnowledgeStore()

        orch = PoolOrchestrator(
            event_bus=eb,
            pool_registry=registry,
            work_item_store=wis,
            audit_logger=al,
            knowledge_store=ks,
        )
        await orch.start()

        artifact = Artifact(
            artifact_id="art-1",
            work_item_id="wi-1",
            artifact_type=ArtifactType.THREAT_REPORT,
            content="report content",
        )
        item = WorkItem(
            item_type=WorkItemType.THREAT_REPORT,
            status=WorkItemStatus.COMPLETED,
            title="Test Work Item",
            context={"customer_id": "cust-1"},
            artifacts=[artifact],
        )
        await eb.publish(topic=Topic.WORK_ITEMS, message=item, customer_id="cust-1")

        # Artifacts stored
        assert "art-1" in ks._artifacts_store

        await orch.stop()

    @pytest.mark.asyncio()
    async def test_init_signature_accepts_no_trainer(self) -> None:
        """PoolOrchestrator can be constructed without trainer parameter (backward compatible)."""
        eb = InMemoryEventBus()
        registry = InMemoryPoolRegistry()
        wis = InMemoryWorkItemStore()
        al = InMemoryAuditLogger()
        ks = InMemoryKnowledgeStore()

        # Should NOT raise
        orch = PoolOrchestrator(
            event_bus=eb,
            pool_registry=registry,
            work_item_store=wis,
            audit_logger=al,
            knowledge_store=ks,
        )
        assert orch is not None


class TestPoolOrchestratorTrainerIntegration:
    @pytest.mark.asyncio()
    async def test_complete_work_item_calls_trainer(self) -> None:
        """PoolOrchestrator with trainer: _complete_work_item calls trainer.review_and_train."""
        eb = InMemoryEventBus()
        registry = InMemoryPoolRegistry()
        eng_pool = AgentPool(
            pool_id="eng-pool-1",
            name="Engineering",
            pool_type=PoolType.ENGINEERING,
            can_consume=[WorkItemType.THREAT_REPORT],
            current_load=0,
            max_capacity=10,
        )
        registry.register(eng_pool)
        wis = InMemoryWorkItemStore()
        al = InMemoryAuditLogger()
        ks = InMemoryKnowledgeStore()

        trainer, skill_registry, kb, _ = _build_trainer()

        orch = PoolOrchestrator(
            event_bus=eb,
            pool_registry=registry,
            work_item_store=wis,
            audit_logger=al,
            knowledge_store=ks,
            trainer=trainer,
        )
        await orch.start()

        artifact = Artifact(
            artifact_id="art-train-1",
            work_item_id="wi-train-1",
            artifact_type=ArtifactType.CODE_PATCH,
            content="patch content",
        )
        item = WorkItem(
            item_type=WorkItemType.THREAT_REPORT,
            status=WorkItemStatus.COMPLETED,
            title="Training Test Item",
            context={"customer_id": "cust-train"},
            artifacts=[artifact],
        )

        await eb.publish(topic=Topic.WORK_ITEMS, message=item, customer_id="cust-train")

        # Verify the skill registry was updated (trainer was called)
        profile = skill_registry.get_agent_profile("default")
        assert profile is not None
        assert profile.total_runs >= 1

        await orch.stop()

    @pytest.mark.asyncio()
    async def test_trainer_receives_correct_context_summary(self) -> None:
        """Trainer receives context_summary with expected fields."""
        eb = InMemoryEventBus()
        registry = InMemoryPoolRegistry()
        eng_pool = AgentPool(
            pool_id="eng-pool-1",
            name="Engineering",
            pool_type=PoolType.ENGINEERING,
            can_consume=[WorkItemType.THREAT_REPORT],
            current_load=0,
            max_capacity=10,
        )
        registry.register(eng_pool)
        wis = InMemoryWorkItemStore()
        al = InMemoryAuditLogger()
        ks = InMemoryKnowledgeStore()

        trainer, skill_registry, _, _ = _build_trainer()

        orch = PoolOrchestrator(
            event_bus=eb,
            pool_registry=registry,
            work_item_store=wis,
            audit_logger=al,
            knowledge_store=ks,
            trainer=trainer,
        )
        await orch.start()

        item = WorkItem(
            item_type=WorkItemType.THREAT_REPORT,
            status=WorkItemStatus.COMPLETED,
            title="Context Test Item",
            context={"customer_id": "cust-ctx"},
        )

        await eb.publish(topic=Topic.WORK_ITEMS, message=item, customer_id="cust-ctx")

        # The trainer should have been invoked: profile should have total_runs == 1
        profile = skill_registry.get_agent_profile("default")
        assert profile is not None
        assert profile.total_runs == 1
        # The outcome was COMPLETED -> outcome_success = True
        assert profile.successful_runs == 1

        await orch.stop()


# ===========================================================================
# Failing adapter helper for rollback tests
# ===========================================================================


class _FailingAdapter:
    """Adapter that passes dry_run but returns FAILED execution."""

    def __init__(self, audit_logger: InMemoryAuditLogger) -> None:
        self._audit_logger = audit_logger

    async def dry_run(self, customer_id: str, parameters: dict[str, Any]) -> object:
        from summer_puppy.events.models import DryRunResult

        return DryRunResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id=customer_id,
            is_safe=True,
            reason="Pre-flight passed",
            validated_parameters=parameters,
        )

    async def execute(
        self, customer_id: str, parameters: dict[str, Any], correlation_id: str
    ) -> object:
        from summer_puppy.events.models import ExecutionResult

        return ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id=customer_id,
            status=ExecutorStatus.FAILED,
            error_detail="Simulated failure",
            parameters_applied=parameters,
        )

    async def rollback(self, execution_result: object) -> object:
        from summer_puppy.events.models import ExecutionResult, RollbackRecord

        assert isinstance(execution_result, ExecutionResult)
        return RollbackRecord(
            execution_id=execution_result.execution_id,
            customer_id=execution_result.customer_id,
            action_class=execution_result.action_class,
            reason="Rollback executed",
            success=True,
        )
