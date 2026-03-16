from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from summer_puppy.audit.logger import (
    AuditLogger,
    log_executor_failed,
    log_executor_rolled_back,
)
from summer_puppy.events.models import (
    DryRunResult,
    ExecutionResult,
    ExecutorStatus,
    RollbackRecord,
)
from summer_puppy.trust.models import ActionClass

_logger = logging.getLogger(__name__)


@runtime_checkable
class ActionExecutor(Protocol):
    async def dry_run(self, customer_id: str, parameters: dict[str, Any]) -> DryRunResult: ...

    async def execute(
        self, customer_id: str, parameters: dict[str, Any], correlation_id: str
    ) -> ExecutionResult: ...

    async def rollback(self, execution_result: ExecutionResult) -> RollbackRecord: ...


class BlockIPExecutor:
    """Executor for blocking IP addresses via firewall API."""

    def __init__(self, audit_logger: AuditLogger) -> None:
        self._audit_logger = audit_logger

    async def dry_run(self, customer_id: str, parameters: dict[str, Any]) -> DryRunResult:
        api_url = os.environ.get("SP_FIREWALL_API_URL")
        if not api_url:
            return DryRunResult(
                action_class=ActionClass.BLOCK_IP,
                customer_id=customer_id,
                is_safe=False,
                reason="SP_FIREWALL_API_URL environment variable is not set",
                validated_parameters=parameters,
            )
        if "ip_address" not in parameters:
            return DryRunResult(
                action_class=ActionClass.BLOCK_IP,
                customer_id=customer_id,
                is_safe=False,
                reason="Missing required parameter: ip_address",
                validated_parameters=parameters,
            )
        return DryRunResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id=customer_id,
            is_safe=True,
            reason="All preconditions met",
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
            status=ExecutorStatus.EXECUTING,
            parameters_applied=parameters,
        )
        try:
            msg = "BlockIP integration not yet implemented"
            raise NotImplementedError(msg)
        except NotImplementedError as e:
            result.status = ExecutorStatus.FAILED
            result.error_detail = str(e)
            result.completed_utc = datetime.now(tz=UTC)
            await self._audit_logger.append(
                log_executor_failed(
                    customer_id=customer_id,
                    execution_id=result.execution_id,
                    action_class=ActionClass.BLOCK_IP.value,
                    correlation_id=correlation_id,
                    error_detail=str(e),
                )
            )
            _logger.info(
                "Executor failed: customer_id=%s action_class=%s correlation_id=%s",
                customer_id,
                ActionClass.BLOCK_IP.value,
                correlation_id,
            )
            return result

    async def rollback(self, execution_result: ExecutionResult) -> RollbackRecord:
        record = RollbackRecord(
            execution_id=execution_result.execution_id,
            customer_id=execution_result.customer_id,
            action_class=ActionClass.BLOCK_IP,
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


class DisableAccountExecutor:
    """Executor for disabling user accounts via directory service."""

    def __init__(self, audit_logger: AuditLogger) -> None:
        self._audit_logger = audit_logger

    async def dry_run(self, customer_id: str, parameters: dict[str, Any]) -> DryRunResult:
        api_url = os.environ.get("SP_DIRECTORY_SERVICE_URL")
        if not api_url:
            return DryRunResult(
                action_class=ActionClass.DISABLE_ACCOUNT,
                customer_id=customer_id,
                is_safe=False,
                reason="SP_DIRECTORY_SERVICE_URL environment variable is not set",
                validated_parameters=parameters,
            )
        if "account_id" not in parameters:
            return DryRunResult(
                action_class=ActionClass.DISABLE_ACCOUNT,
                customer_id=customer_id,
                is_safe=False,
                reason="Missing required parameter: account_id",
                validated_parameters=parameters,
            )
        return DryRunResult(
            action_class=ActionClass.DISABLE_ACCOUNT,
            customer_id=customer_id,
            is_safe=True,
            reason="All preconditions met",
            validated_parameters=parameters,
        )

    async def execute(
        self, customer_id: str, parameters: dict[str, Any], correlation_id: str
    ) -> ExecutionResult:
        if not customer_id:
            raise ValueError("customer_id must not be empty")
        result = ExecutionResult(
            action_class=ActionClass.DISABLE_ACCOUNT,
            customer_id=customer_id,
            status=ExecutorStatus.EXECUTING,
            parameters_applied=parameters,
        )
        try:
            msg = "DisableAccount integration not yet implemented"
            raise NotImplementedError(msg)
        except NotImplementedError as e:
            result.status = ExecutorStatus.FAILED
            result.error_detail = str(e)
            result.completed_utc = datetime.now(tz=UTC)
            await self._audit_logger.append(
                log_executor_failed(
                    customer_id=customer_id,
                    execution_id=result.execution_id,
                    action_class=ActionClass.DISABLE_ACCOUNT.value,
                    correlation_id=correlation_id,
                    error_detail=str(e),
                )
            )
            _logger.info(
                "Executor failed: customer_id=%s action_class=%s correlation_id=%s",
                customer_id,
                ActionClass.DISABLE_ACCOUNT.value,
                correlation_id,
            )
            return result

    async def rollback(self, execution_result: ExecutionResult) -> RollbackRecord:
        record = RollbackRecord(
            execution_id=execution_result.execution_id,
            customer_id=execution_result.customer_id,
            action_class=ActionClass.DISABLE_ACCOUNT,
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


class UpdateFirewallRuleExecutor:
    """Executor for updating firewall rules via firewall API."""

    def __init__(self, audit_logger: AuditLogger) -> None:
        self._audit_logger = audit_logger

    async def dry_run(self, customer_id: str, parameters: dict[str, Any]) -> DryRunResult:
        api_url = os.environ.get("SP_FIREWALL_API_URL")
        if not api_url:
            return DryRunResult(
                action_class=ActionClass.UPDATE_FIREWALL_RULE,
                customer_id=customer_id,
                is_safe=False,
                reason="SP_FIREWALL_API_URL environment variable is not set",
                validated_parameters=parameters,
            )
        if "rule_id" not in parameters:
            return DryRunResult(
                action_class=ActionClass.UPDATE_FIREWALL_RULE,
                customer_id=customer_id,
                is_safe=False,
                reason="Missing required parameter: rule_id",
                validated_parameters=parameters,
            )
        return DryRunResult(
            action_class=ActionClass.UPDATE_FIREWALL_RULE,
            customer_id=customer_id,
            is_safe=True,
            reason="All preconditions met",
            validated_parameters=parameters,
        )

    async def execute(
        self, customer_id: str, parameters: dict[str, Any], correlation_id: str
    ) -> ExecutionResult:
        if not customer_id:
            raise ValueError("customer_id must not be empty")
        result = ExecutionResult(
            action_class=ActionClass.UPDATE_FIREWALL_RULE,
            customer_id=customer_id,
            status=ExecutorStatus.EXECUTING,
            parameters_applied=parameters,
        )
        try:
            msg = "UpdateFirewallRule integration not yet implemented"
            raise NotImplementedError(msg)
        except NotImplementedError as e:
            result.status = ExecutorStatus.FAILED
            result.error_detail = str(e)
            result.completed_utc = datetime.now(tz=UTC)
            await self._audit_logger.append(
                log_executor_failed(
                    customer_id=customer_id,
                    execution_id=result.execution_id,
                    action_class=ActionClass.UPDATE_FIREWALL_RULE.value,
                    correlation_id=correlation_id,
                    error_detail=str(e),
                )
            )
            _logger.info(
                "Executor failed: customer_id=%s action_class=%s correlation_id=%s",
                customer_id,
                ActionClass.UPDATE_FIREWALL_RULE.value,
                correlation_id,
            )
            return result

    async def rollback(self, execution_result: ExecutionResult) -> RollbackRecord:
        record = RollbackRecord(
            execution_id=execution_result.execution_id,
            customer_id=execution_result.customer_id,
            action_class=ActionClass.UPDATE_FIREWALL_RULE,
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
