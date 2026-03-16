"""Tests for execution sandbox, policy gate, and verifier (Story 4)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.events.models import (
    DryRunResult,
    ExecutionResult,
    ExecutorStatus,
    RollbackRecord,
)
from summer_puppy.execution.adapters.mock_firewall import MockFirewallAdapter
from summer_puppy.execution.models import (
    ExecutionPlan,
    ExecutionStep,
    VerificationReport,
)
from summer_puppy.execution.policy_gate import PolicyGate
from summer_puppy.execution.sandbox import ExecutionSandbox
from summer_puppy.execution.verifier import ExecutionVerifier
from summer_puppy.tenants.models import ProtectedAsset, TenantProfile
from summer_puppy.tenants.policy import TenantPolicyEngine
from summer_puppy.trust.models import ActionClass, TrustPhase

if TYPE_CHECKING:
    from summer_puppy.pipeline.executors import ActionExecutor


# ===========================================================================
# Helpers
# ===========================================================================


def _make_tenant(
    customer_id: str = "cust-1",
    *,
    allowed: list[ActionClass] | None = None,
    blocked: list[ActionClass] | None = None,
    auto_rollback: bool = True,
) -> TenantProfile:
    return TenantProfile(
        customer_id=customer_id,
        allowed_action_classes=allowed or [],
        blocked_action_classes=blocked or [],
        auto_rollback_on_verify_fail=auto_rollback,
    )


def _make_plan(
    customer_id: str = "cust-1",
    action_class: ActionClass = ActionClass.BLOCK_IP,
    parameters: dict[str, Any] | None = None,
    correlation_id: str = "corr-1",
) -> ExecutionPlan:
    if parameters is None:
        parameters = {"ip_address": "10.0.0.1"}
    return ExecutionPlan(
        customer_id=customer_id,
        action_class=action_class,
        parameters=parameters,
        correlation_id=correlation_id,
    )


def _make_sandbox(
    adapters: dict[ActionClass, ActionExecutor] | None = None,
    audit_logger: InMemoryAuditLogger | None = None,
) -> ExecutionSandbox:
    logger = audit_logger or InMemoryAuditLogger()
    if adapters is None:
        adapters = {ActionClass.BLOCK_IP: MockFirewallAdapter(audit_logger=logger)}
    gate = PolicyGate(TenantPolicyEngine())
    verifier = ExecutionVerifier()
    return ExecutionSandbox(
        adapters=adapters,
        policy_gate=gate,
        verifier=verifier,
        audit_logger=logger,
    )


# ===========================================================================
# PolicyGate tests
# ===========================================================================


class TestPolicyGate:
    async def test_check_allowed_action(self) -> None:
        """Allowed action returns (True, reason)."""
        gate = PolicyGate(TenantPolicyEngine())
        tenant = _make_tenant()
        plan = _make_plan()

        allowed, reason = await gate.check(plan, tenant, TrustPhase.SUPERVISED)

        assert allowed is True
        assert reason == "Action permitted"

    async def test_check_blocked_action(self) -> None:
        """Blocked action returns (False, reason)."""
        gate = PolicyGate(TenantPolicyEngine())
        tenant = _make_tenant(blocked=[ActionClass.BLOCK_IP])
        plan = _make_plan()

        allowed, reason = await gate.check(plan, tenant, TrustPhase.SUPERVISED)

        assert allowed is False
        assert "blocked" in reason.lower()

    async def test_check_extracts_asset_ids_from_parameters(self) -> None:
        """Asset IDs are extracted from plan.parameters['asset_ids']."""
        gate = PolicyGate(TenantPolicyEngine())
        tenant = _make_tenant()
        tenant.protected_assets = [
            ProtectedAsset(asset_id="asset-1", reason="Critical server"),
        ]
        plan = _make_plan(parameters={"ip_address": "10.0.0.1", "asset_ids": ["asset-1"]})

        allowed, reason = await gate.check(plan, tenant, TrustPhase.SUPERVISED)

        assert allowed is False
        assert "protected" in reason.lower()

    async def test_check_no_asset_ids_in_parameters(self) -> None:
        """When no asset_ids in parameters, no protected asset check fails."""
        gate = PolicyGate(TenantPolicyEngine())
        tenant = _make_tenant()
        tenant.protected_assets = [
            ProtectedAsset(asset_id="asset-1", reason="Critical server"),
        ]
        plan = _make_plan(parameters={"ip_address": "10.0.0.1"})

        allowed, reason = await gate.check(plan, tenant, TrustPhase.SUPERVISED)

        assert allowed is True

    async def test_check_allowlist_denies_unlisted(self) -> None:
        """If allowlist is set, unlisted action class is denied."""
        gate = PolicyGate(TenantPolicyEngine())
        tenant = _make_tenant(allowed=[ActionClass.DISABLE_ACCOUNT])
        plan = _make_plan(action_class=ActionClass.BLOCK_IP)

        allowed, reason = await gate.check(plan, tenant, TrustPhase.SUPERVISED)

        assert allowed is False
        assert "not in allowed list" in reason.lower()


# ===========================================================================
# ExecutionVerifier tests
# ===========================================================================


class TestExecutionVerifier:
    async def test_verify_completed_result_overall_success(self) -> None:
        """COMPLETED status with no error => overall_success=True, 2 checks pass."""
        verifier = ExecutionVerifier()
        exec_result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
        )

        report = await verifier.verify(exec_result, "cust-1")

        assert report.overall_success is True
        assert len(report.checks) == 2
        assert all(c.passed for c in report.checks)
        assert report.execution_id == exec_result.execution_id
        assert report.customer_id == "cust-1"

    async def test_verify_failed_result_overall_failure(self) -> None:
        """FAILED status => overall_success=False."""
        verifier = ExecutionVerifier()
        exec_result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.FAILED,
        )

        report = await verifier.verify(exec_result, "cust-1")

        assert report.overall_success is False
        completed_check = next(c for c in report.checks if c.check_name == "execution_completed")
        assert completed_check.passed is False

    async def test_verify_result_with_error_detail(self) -> None:
        """Result with error_detail => no_errors check fails."""
        verifier = ExecutionVerifier()
        exec_result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
            error_detail="Something went wrong",
        )

        report = await verifier.verify(exec_result, "cust-1")

        assert report.overall_success is False
        no_errors_check = next(c for c in report.checks if c.check_name == "no_errors")
        assert no_errors_check.passed is False
        assert "Something went wrong" in no_errors_check.detail

    async def test_verify_returns_verification_report(self) -> None:
        """Result type is VerificationReport with correct fields."""
        verifier = ExecutionVerifier()
        exec_result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
        )

        report = await verifier.verify(exec_result, "cust-1")

        assert isinstance(report, VerificationReport)
        assert report.report_id is not None
        assert report.verified_utc is not None

    async def test_verify_check_names(self) -> None:
        """Verification report contains expected check names."""
        verifier = ExecutionVerifier()
        exec_result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
        )

        report = await verifier.verify(exec_result, "cust-1")

        check_names = {c.check_name for c in report.checks}
        assert check_names == {"execution_completed", "no_errors"}

    async def test_verify_failed_with_error_both_checks_fail(self) -> None:
        """FAILED status with error_detail => both checks fail."""
        verifier = ExecutionVerifier()
        exec_result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.FAILED,
            error_detail="Timeout",
        )

        report = await verifier.verify(exec_result, "cust-1")

        assert report.overall_success is False
        assert all(not c.passed for c in report.checks)


# ===========================================================================
# ExecutionSandbox tests
# ===========================================================================


class TestExecutionSandbox:
    async def test_happy_path_all_steps_pass(self) -> None:
        """Full happy path: dry_run -> gate -> execute -> verify."""
        sandbox = _make_sandbox()
        tenant = _make_tenant()
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.dry_run_result is not None
        assert result.dry_run_result.is_safe is True
        assert result.policy_gate_passed is True
        assert result.execution_result is not None
        assert result.execution_result.status == ExecutorStatus.COMPLETED
        assert result.verification_report is not None
        assert result.verification_report.overall_success is True
        assert result.completed_utc is not None

    async def test_happy_path_current_step_is_verify(self) -> None:
        """After successful run, current_step is VERIFY."""
        sandbox = _make_sandbox()
        tenant = _make_tenant()
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.current_step == ExecutionStep.VERIFY

    async def test_dry_run_fails_returns_early(self) -> None:
        """Dry run failure: plan returned with is_safe=False, no execution."""
        sandbox = _make_sandbox()
        tenant = _make_tenant()
        plan = _make_plan(parameters={})  # Missing ip_address => dry_run fails

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.dry_run_result is not None
        assert result.dry_run_result.is_safe is False
        assert result.current_step == ExecutionStep.DRY_RUN
        assert result.execution_result is None
        assert result.completed_utc is not None

    async def test_policy_gate_denies_returns_early(self) -> None:
        """Policy gate denial: plan returned with policy_gate_passed=False."""
        sandbox = _make_sandbox()
        tenant = _make_tenant(blocked=[ActionClass.BLOCK_IP])
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.dry_run_result is not None
        assert result.dry_run_result.is_safe is True
        assert result.policy_gate_passed is False
        assert result.policy_gate_reason != ""
        assert result.current_step == ExecutionStep.POLICY_GATE
        assert result.execution_result is None
        assert result.completed_utc is not None

    async def test_verify_fails_with_auto_rollback_true(self) -> None:
        """Verify failure + auto_rollback => rollback_record populated."""
        logger = InMemoryAuditLogger()
        adapter = _FailingAdapter(logger)
        sandbox = _make_sandbox(
            adapters={ActionClass.BLOCK_IP: adapter},
            audit_logger=logger,
        )
        tenant = _make_tenant(auto_rollback=True)
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.verification_report is not None
        assert result.verification_report.overall_success is False
        assert result.rollback_record is not None
        assert result.rollback_record.success is True
        assert result.current_step == ExecutionStep.ROLLBACK

    async def test_verify_fails_with_auto_rollback_false(self) -> None:
        """Verify failure + auto_rollback=False => no rollback_record."""
        logger = InMemoryAuditLogger()
        adapter = _FailingAdapter(logger)
        sandbox = _make_sandbox(
            adapters={ActionClass.BLOCK_IP: adapter},
            audit_logger=logger,
        )
        tenant = _make_tenant(auto_rollback=False)
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.verification_report is not None
        assert result.verification_report.overall_success is False
        assert result.rollback_record is None
        assert result.current_step == ExecutionStep.VERIFY

    async def test_missing_adapter_returns_early(self) -> None:
        """Missing adapter for action_class: plan returned early."""
        sandbox = _make_sandbox(adapters={})  # No adapters
        tenant = _make_tenant()
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.current_step == ExecutionStep.EXECUTE
        assert result.dry_run_result is None
        assert result.execution_result is None
        assert result.completed_utc is not None

    async def test_completed_utc_set_on_dry_run_fail(self) -> None:
        """completed_utc set when dry_run fails."""
        sandbox = _make_sandbox()
        tenant = _make_tenant()
        plan = _make_plan(parameters={})

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.completed_utc is not None

    async def test_completed_utc_set_on_policy_gate_deny(self) -> None:
        """completed_utc set when policy gate denies."""
        sandbox = _make_sandbox()
        tenant = _make_tenant(blocked=[ActionClass.BLOCK_IP])
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.completed_utc is not None

    async def test_completed_utc_set_on_missing_adapter(self) -> None:
        """completed_utc set when adapter is missing."""
        sandbox = _make_sandbox(adapters={})
        tenant = _make_tenant()
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.completed_utc is not None

    async def test_completed_utc_set_on_happy_path(self) -> None:
        """completed_utc set on successful run."""
        sandbox = _make_sandbox()
        tenant = _make_tenant()
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.completed_utc is not None

    async def test_plan_is_returned_same_instance(self) -> None:
        """The returned plan is the same mutated instance."""
        sandbox = _make_sandbox()
        tenant = _make_tenant()
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result is plan

    async def test_policy_gate_reason_populated(self) -> None:
        """Policy gate populates reason on both allow and deny."""
        sandbox = _make_sandbox()
        tenant = _make_tenant()
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.policy_gate_reason != ""

    async def test_dry_run_step_set_before_dry_run(self) -> None:
        """current_step is set to DRY_RUN during dry_run phase."""
        sandbox = _make_sandbox()
        tenant = _make_tenant()
        plan = _make_plan(parameters={})

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        # Plan ended on DRY_RUN since it failed
        assert result.current_step == ExecutionStep.DRY_RUN

    async def test_execution_result_has_correct_customer_id(self) -> None:
        """Execution result uses the plan's customer_id."""
        sandbox = _make_sandbox()
        tenant = _make_tenant(customer_id="cust-42")
        plan = _make_plan(customer_id="cust-42")

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.execution_result is not None
        assert result.execution_result.customer_id == "cust-42"

    async def test_sandbox_with_different_trust_phases(self) -> None:
        """Sandbox works with different trust phases."""
        sandbox = _make_sandbox()
        tenant = _make_tenant()

        for phase in [TrustPhase.MANUAL, TrustPhase.AUTONOMOUS, TrustPhase.FULL_AUTONOMY]:
            plan = _make_plan()
            result = await sandbox.run(plan, tenant, phase)
            assert result.completed_utc is not None

    async def test_rollback_step_set_on_rollback(self) -> None:
        """current_step is ROLLBACK after rollback."""
        logger = InMemoryAuditLogger()
        adapter = _FailingAdapter(logger)
        sandbox = _make_sandbox(
            adapters={ActionClass.BLOCK_IP: adapter},
            audit_logger=logger,
        )
        tenant = _make_tenant(auto_rollback=True)
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.current_step == ExecutionStep.ROLLBACK

    async def test_verify_report_execution_id_matches(self) -> None:
        """Verification report execution_id matches execution result."""
        sandbox = _make_sandbox()
        tenant = _make_tenant()
        plan = _make_plan()

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.verification_report is not None
        assert result.execution_result is not None
        assert result.verification_report.execution_id == result.execution_result.execution_id

    async def test_plan_correlation_id_used_in_execute(self) -> None:
        """Plan's correlation_id is passed through to execution."""
        sandbox = _make_sandbox()
        tenant = _make_tenant()
        plan = _make_plan(correlation_id="my-corr-id")

        result = await sandbox.run(plan, tenant, TrustPhase.SUPERVISED)

        assert result.execution_result is not None
        assert result.correlation_id == "my-corr-id"


# ===========================================================================
# Failing adapter helper for rollback tests
# ===========================================================================


class _FailingAdapter:
    """Adapter that passes dry_run but returns FAILED execution."""

    def __init__(self, audit_logger: InMemoryAuditLogger) -> None:
        self._audit_logger = audit_logger

    async def dry_run(self, customer_id: str, parameters: dict[str, Any]) -> DryRunResult:
        return DryRunResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id=customer_id,
            is_safe=True,
            reason="Pre-flight passed",
            validated_parameters=parameters,
        )

    async def execute(
        self,
        customer_id: str,
        parameters: dict[str, Any],
        correlation_id: str,  # noqa: ARG002
    ) -> ExecutionResult:
        return ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id=customer_id,
            status=ExecutorStatus.FAILED,
            error_detail="Simulated failure",
            parameters_applied=parameters,
        )

    async def rollback(self, execution_result: ExecutionResult) -> RollbackRecord:
        return RollbackRecord(
            execution_id=execution_result.execution_id,
            customer_id=execution_result.customer_id,
            action_class=execution_result.action_class,
            reason="Rollback executed",
            success=True,
        )
