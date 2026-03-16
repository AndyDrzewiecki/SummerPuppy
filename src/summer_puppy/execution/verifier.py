"""Post-execution verification of results."""

from __future__ import annotations

from summer_puppy.events.models import ExecutionResult, ExecutorStatus
from summer_puppy.execution.models import VerificationCheck, VerificationReport


class ExecutionVerifier:
    """Verifies execution results to determine overall success."""

    async def verify(
        self,
        execution_result: ExecutionResult,
        customer_id: str,
    ) -> VerificationReport:
        """Run verification checks against an execution result."""
        checks: list[VerificationCheck] = []

        # Check 1: execution completed successfully
        completed = execution_result.status == ExecutorStatus.COMPLETED
        checks.append(
            VerificationCheck(
                check_name="execution_completed",
                passed=completed,
                detail=f"Status: {execution_result.status.value}",
            )
        )

        # Check 2: no error
        no_error = execution_result.error_detail is None
        checks.append(
            VerificationCheck(
                check_name="no_errors",
                passed=no_error,
                detail=execution_result.error_detail or "No errors",
            )
        )

        overall = all(c.passed for c in checks)
        return VerificationReport(
            execution_id=execution_result.execution_id,
            customer_id=customer_id,
            checks=checks,
            overall_success=overall,
        )
