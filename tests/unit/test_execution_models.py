"""Tests for execution models: ExecutionStep, VerificationCheck, VerificationReport."""

from __future__ import annotations

from datetime import UTC, datetime

from summer_puppy.events.models import (
    DryRunResult,
    ExecutionResult,
    ExecutorStatus,
    RollbackRecord,
)
from summer_puppy.execution.models import (
    ExecutionPlan,
    ExecutionStep,
    VerificationCheck,
    VerificationReport,
)
from summer_puppy.trust.models import ActionClass

# ---------------------------------------------------------------------------
# ExecutionStep tests
# ---------------------------------------------------------------------------


class TestExecutionStep:
    def test_dry_run_value(self) -> None:
        assert ExecutionStep.DRY_RUN == "DRY_RUN"

    def test_policy_gate_value(self) -> None:
        assert ExecutionStep.POLICY_GATE == "POLICY_GATE"

    def test_execute_value(self) -> None:
        assert ExecutionStep.EXECUTE == "EXECUTE"

    def test_verify_value(self) -> None:
        assert ExecutionStep.VERIFY == "VERIFY"

    def test_rollback_value(self) -> None:
        assert ExecutionStep.ROLLBACK == "ROLLBACK"

    def test_member_count(self) -> None:
        assert len(ExecutionStep) == 5


# ---------------------------------------------------------------------------
# VerificationCheck tests
# ---------------------------------------------------------------------------


class TestVerificationCheck:
    def test_creation_minimal(self) -> None:
        check = VerificationCheck(check_name="connectivity", passed=True)
        assert check.check_name == "connectivity"
        assert check.passed is True
        assert check.detail == ""

    def test_creation_with_detail(self) -> None:
        check = VerificationCheck(
            check_name="dns_resolution",
            passed=False,
            detail="DNS lookup failed for target host",
        )
        assert check.check_name == "dns_resolution"
        assert check.passed is False
        assert check.detail == "DNS lookup failed for target host"


# ---------------------------------------------------------------------------
# VerificationReport tests
# ---------------------------------------------------------------------------


class TestVerificationReport:
    def test_creation_minimal(self) -> None:
        report = VerificationReport(
            execution_id="exec-1",
            customer_id="cust-1",
        )
        assert report.report_id  # auto-generated uuid
        assert report.execution_id == "exec-1"
        assert report.customer_id == "cust-1"
        assert report.checks == []
        assert report.overall_success is False
        assert isinstance(report.verified_utc, datetime)

    def test_default_checks_empty(self) -> None:
        report = VerificationReport(
            execution_id="exec-1",
            customer_id="cust-1",
        )
        assert report.checks == []
        assert len(report.checks) == 0

    def test_creation_with_checks(self) -> None:
        checks = [
            VerificationCheck(check_name="connectivity", passed=True),
            VerificationCheck(check_name="dns", passed=False, detail="timeout"),
        ]
        report = VerificationReport(
            execution_id="exec-1",
            customer_id="cust-1",
            checks=checks,
            overall_success=False,
        )
        assert len(report.checks) == 2
        assert report.checks[0].check_name == "connectivity"
        assert report.checks[1].passed is False
        assert report.overall_success is False

    def test_serialization_round_trip(self) -> None:
        checks = [VerificationCheck(check_name="test", passed=True, detail="ok")]
        report = VerificationReport(
            execution_id="exec-1",
            customer_id="cust-1",
            checks=checks,
            overall_success=True,
        )
        data = report.model_dump()
        restored = VerificationReport.model_validate(data)
        assert restored.report_id == report.report_id
        assert restored.execution_id == report.execution_id
        assert restored.overall_success is True
        assert len(restored.checks) == 1
        assert restored.checks[0].check_name == "test"

    def test_unique_report_ids(self) -> None:
        r1 = VerificationReport(execution_id="e1", customer_id="c1")
        r2 = VerificationReport(execution_id="e1", customer_id="c1")
        assert r1.report_id != r2.report_id


# ---------------------------------------------------------------------------
# ExecutionPlan tests
# ---------------------------------------------------------------------------


class TestExecutionPlan:
    def test_minimal_creation(self) -> None:
        plan = ExecutionPlan(
            customer_id="cust-1",
            correlation_id="corr-1",
            action_class=ActionClass.NETWORK_ISOLATION,
        )
        assert plan.plan_id  # auto-generated uuid
        assert plan.customer_id == "cust-1"
        assert plan.correlation_id == "corr-1"
        assert plan.action_class == ActionClass.NETWORK_ISOLATION
        assert plan.parameters == {}
        assert plan.current_step == ExecutionStep.DRY_RUN
        assert plan.dry_run_result is None
        assert plan.policy_gate_passed is False
        assert plan.policy_gate_reason == ""
        assert plan.execution_result is None
        assert plan.verification_report is None
        assert plan.rollback_record is None
        assert isinstance(plan.created_utc, datetime)
        assert plan.completed_utc is None

    def test_all_fields_populated(self) -> None:
        now = datetime(2026, 3, 16, 12, 0, 0, tzinfo=UTC)
        completed = datetime(2026, 3, 16, 12, 5, 0, tzinfo=UTC)

        dry_run = DryRunResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            is_safe=True,
            reason="ok",
        )
        exec_result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
        )
        verification = VerificationReport(
            execution_id=exec_result.execution_id,
            customer_id="cust-1",
            overall_success=True,
        )
        rollback = RollbackRecord(
            execution_id=exec_result.execution_id,
            customer_id="cust-1",
            action_class=ActionClass.BLOCK_IP,
            reason="Rolled back",
            success=True,
        )

        plan = ExecutionPlan(
            plan_id="plan-custom",
            customer_id="cust-1",
            correlation_id="corr-99",
            action_class=ActionClass.BLOCK_IP,
            parameters={"ip_address": "10.0.0.1"},
            current_step=ExecutionStep.VERIFY,
            dry_run_result=dry_run,
            policy_gate_passed=True,
            policy_gate_reason="Auto-approved",
            execution_result=exec_result,
            verification_report=verification,
            rollback_record=rollback,
            created_utc=now,
            completed_utc=completed,
        )
        assert plan.plan_id == "plan-custom"
        assert plan.parameters == {"ip_address": "10.0.0.1"}
        assert plan.current_step == ExecutionStep.VERIFY
        assert plan.dry_run_result is not None
        assert plan.dry_run_result.is_safe is True
        assert plan.policy_gate_passed is True
        assert plan.policy_gate_reason == "Auto-approved"
        assert plan.execution_result is not None
        assert plan.execution_result.status == ExecutorStatus.COMPLETED
        assert plan.verification_report is not None
        assert plan.verification_report.overall_success is True
        assert plan.rollback_record is not None
        assert plan.rollback_record.success is True
        assert plan.created_utc == now
        assert plan.completed_utc == completed

    def test_serialization_round_trip(self) -> None:
        plan = ExecutionPlan(
            customer_id="cust-1",
            correlation_id="corr-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            parameters={"patch_id": "KB123"},
        )
        data = plan.model_dump()
        restored = ExecutionPlan.model_validate(data)
        assert restored.plan_id == plan.plan_id
        assert restored.customer_id == plan.customer_id
        assert restored.action_class == plan.action_class
        assert restored.parameters == plan.parameters
        assert restored.current_step == ExecutionStep.DRY_RUN

    def test_unique_plan_ids(self) -> None:
        p1 = ExecutionPlan(
            customer_id="c1",
            correlation_id="corr-1",
            action_class=ActionClass.DISABLE_ACCOUNT,
        )
        p2 = ExecutionPlan(
            customer_id="c1",
            correlation_id="corr-1",
            action_class=ActionClass.DISABLE_ACCOUNT,
        )
        assert p1.plan_id != p2.plan_id
