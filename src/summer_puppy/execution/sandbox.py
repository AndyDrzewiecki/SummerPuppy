"""Execution sandbox orchestrating dry-run, policy gate, execute, verify, and rollback."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from summer_puppy.execution.models import ExecutionPlan, ExecutionStep

if TYPE_CHECKING:
    from summer_puppy.audit.logger import AuditLogger
    from summer_puppy.execution.policy_gate import PolicyGate
    from summer_puppy.execution.verifier import ExecutionVerifier
    from summer_puppy.pipeline.executors import ActionExecutor
    from summer_puppy.tenants.models import TenantProfile
    from summer_puppy.trust.models import ActionClass, TrustPhase


class ExecutionSandbox:
    """Orchestrates the full execution lifecycle for an ExecutionPlan."""

    def __init__(
        self,
        adapters: dict[ActionClass, ActionExecutor],
        policy_gate: PolicyGate,
        verifier: ExecutionVerifier,
        audit_logger: AuditLogger,
    ) -> None:
        self._adapters = adapters
        self._policy_gate = policy_gate
        self._verifier = verifier
        self._audit_logger = audit_logger

    async def run(
        self,
        plan: ExecutionPlan,
        tenant: TenantProfile,
        trust_phase: TrustPhase,
    ) -> ExecutionPlan:
        """Execute the plan through all sandbox steps.

        Steps: DRY_RUN -> POLICY_GATE -> EXECUTE -> VERIFY -> (optional ROLLBACK)
        Returns the mutated plan with results from each completed step.
        """
        # 1. Get adapter for action class
        adapter = self._adapters.get(plan.action_class)
        if adapter is None:
            plan.current_step = ExecutionStep.EXECUTE
            plan.completed_utc = datetime.now(tz=UTC)
            return plan

        # 2. DRY_RUN step
        plan.current_step = ExecutionStep.DRY_RUN
        dry_result = await adapter.dry_run(plan.customer_id, plan.parameters)
        plan.dry_run_result = dry_result
        if not dry_result.is_safe:
            plan.completed_utc = datetime.now(tz=UTC)
            return plan

        # 3. POLICY_GATE step
        plan.current_step = ExecutionStep.POLICY_GATE
        allowed, reason = await self._policy_gate.check(plan, tenant, trust_phase)
        plan.policy_gate_passed = allowed
        plan.policy_gate_reason = reason
        if not allowed:
            plan.completed_utc = datetime.now(tz=UTC)
            return plan

        # 4. EXECUTE step
        plan.current_step = ExecutionStep.EXECUTE
        exec_result = await adapter.execute(plan.customer_id, plan.parameters, plan.correlation_id)
        plan.execution_result = exec_result

        # 5. VERIFY step
        plan.current_step = ExecutionStep.VERIFY
        report = await self._verifier.verify(exec_result, plan.customer_id)
        plan.verification_report = report

        if not report.overall_success and tenant.auto_rollback_on_verify_fail:
            plan.current_step = ExecutionStep.ROLLBACK
            rollback_record = await adapter.rollback(exec_result)
            plan.rollback_record = rollback_record

        # 6. Complete
        plan.completed_utc = datetime.now(tz=UTC)
        return plan
