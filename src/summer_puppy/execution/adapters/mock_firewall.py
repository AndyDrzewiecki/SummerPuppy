from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from summer_puppy.audit.logger import (
    AuditLogger,
    log_executor_completed,
    log_executor_rolled_back,
)
from summer_puppy.events.models import (
    DryRunResult,
    ExecutionResult,
    ExecutorStatus,
    RollbackRecord,
)
from summer_puppy.execution.adapters.base import BaseAdapter
from summer_puppy.trust.models import ActionClass


class MockFirewallAdapter(BaseAdapter):
    """Mock adapter for firewall actions: BLOCK_IP, UPDATE_FIREWALL_RULE."""

    def __init__(self, audit_logger: AuditLogger) -> None:
        super().__init__(audit_logger)

    async def dry_run(self, customer_id: str, parameters: dict[str, Any]) -> DryRunResult:
        if "ip_address" not in parameters and "rule_id" not in parameters:
            return DryRunResult(
                action_class=ActionClass.BLOCK_IP,
                customer_id=customer_id,
                is_safe=False,
                reason="Missing 'ip_address' or 'rule_id' parameter",
            )
        return DryRunResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id=customer_id,
            is_safe=True,
            reason="Pre-flight checks passed",
            validated_parameters=parameters,
        )

    async def execute(
        self, customer_id: str, parameters: dict[str, Any], correlation_id: str
    ) -> ExecutionResult:
        if not customer_id:
            raise ValueError("customer_id must not be empty")
        result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id=customer_id,
            status=ExecutorStatus.COMPLETED,
            parameters_applied=parameters,
            completed_utc=datetime.now(tz=UTC),
        )
        await self._audit_logger.append(
            log_executor_completed(
                customer_id=customer_id,
                execution_id=result.execution_id,
                action_class=result.action_class.value,
                correlation_id=correlation_id,
            )
        )
        return result

    async def rollback(self, execution_result: ExecutionResult) -> RollbackRecord:
        record = RollbackRecord(
            execution_id=execution_result.execution_id,
            customer_id=execution_result.customer_id,
            action_class=execution_result.action_class,
            reason="Rollback executed",
            success=True,
        )
        await self._audit_logger.append(
            log_executor_rolled_back(
                customer_id=execution_result.customer_id,
                rollback_id=record.rollback_id,
                execution_id=execution_result.execution_id,
            )
        )
        return record
