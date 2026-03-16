"""Tests for mock execution adapters: EDR, IAM, Firewall, Patch."""

from __future__ import annotations

import pytest

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.events.models import ExecutionResult, ExecutorStatus
from summer_puppy.execution.adapters.mock_edr import MockEDRAdapter
from summer_puppy.execution.adapters.mock_firewall import MockFirewallAdapter
from summer_puppy.execution.adapters.mock_iam import MockIAMAdapter
from summer_puppy.execution.adapters.mock_patch import MockPatchAdapter
from summer_puppy.pipeline.executors import ActionExecutor
from summer_puppy.trust.models import ActionClass

# ===========================================================================
# MockEDRAdapter tests
# ===========================================================================


class TestMockEDRAdapter:
    async def test_dry_run_passes_with_valid_params(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockEDRAdapter(audit_logger=logger)

        result = await adapter.dry_run("cust-1", {"target_host": "host-01"})

        assert result.is_safe is True
        assert result.action_class == ActionClass.NETWORK_ISOLATION
        assert result.customer_id == "cust-1"
        assert result.validated_parameters == {"target_host": "host-01"}

    async def test_dry_run_fails_missing_target_host(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockEDRAdapter(audit_logger=logger)

        result = await adapter.dry_run("cust-1", {})

        assert result.is_safe is False
        assert "target_host" in result.reason

    async def test_execute_completed_status(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockEDRAdapter(audit_logger=logger)

        result = await adapter.execute("cust-1", {"target_host": "host-01"}, "corr-1")

        assert result.status == ExecutorStatus.COMPLETED
        assert result.action_class == ActionClass.NETWORK_ISOLATION
        assert result.customer_id == "cust-1"
        assert result.completed_utc is not None

    async def test_execute_raises_on_empty_customer_id(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockEDRAdapter(audit_logger=logger)

        with pytest.raises(ValueError, match="customer_id must not be empty"):
            await adapter.execute("", {"target_host": "host-01"}, "corr-1")

    async def test_execute_audits_via_logger(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockEDRAdapter(audit_logger=logger)

        await adapter.execute("cust-1", {"target_host": "host-01"}, "corr-1")

        assert len(logger._entries) == 1

    async def test_rollback_success(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockEDRAdapter(audit_logger=logger)
        exec_result = ExecutionResult(
            action_class=ActionClass.NETWORK_ISOLATION,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
        )

        record = await adapter.rollback(exec_result)

        assert record.success is True
        assert record.execution_id == exec_result.execution_id
        assert record.customer_id == "cust-1"
        assert record.action_class == ActionClass.NETWORK_ISOLATION

    async def test_isinstance_action_executor(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockEDRAdapter(audit_logger=logger)

        assert isinstance(adapter, ActionExecutor)


# ===========================================================================
# MockIAMAdapter tests
# ===========================================================================


class TestMockIAMAdapter:
    async def test_dry_run_passes_with_valid_params(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockIAMAdapter(audit_logger=logger)

        result = await adapter.dry_run("cust-1", {"account_id": "acc-42"})

        assert result.is_safe is True
        assert result.action_class == ActionClass.DISABLE_ACCOUNT
        assert result.customer_id == "cust-1"
        assert result.validated_parameters == {"account_id": "acc-42"}

    async def test_dry_run_fails_missing_account_id(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockIAMAdapter(audit_logger=logger)

        result = await adapter.dry_run("cust-1", {})

        assert result.is_safe is False
        assert "account_id" in result.reason

    async def test_execute_completed_status(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockIAMAdapter(audit_logger=logger)

        result = await adapter.execute("cust-1", {"account_id": "acc-42"}, "corr-1")

        assert result.status == ExecutorStatus.COMPLETED
        assert result.action_class == ActionClass.DISABLE_ACCOUNT
        assert result.customer_id == "cust-1"
        assert result.completed_utc is not None

    async def test_execute_raises_on_empty_customer_id(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockIAMAdapter(audit_logger=logger)

        with pytest.raises(ValueError, match="customer_id must not be empty"):
            await adapter.execute("", {"account_id": "acc-42"}, "corr-1")

    async def test_execute_audits_via_logger(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockIAMAdapter(audit_logger=logger)

        await adapter.execute("cust-1", {"account_id": "acc-42"}, "corr-1")

        assert len(logger._entries) == 1

    async def test_rollback_success(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockIAMAdapter(audit_logger=logger)
        exec_result = ExecutionResult(
            action_class=ActionClass.DISABLE_ACCOUNT,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
        )

        record = await adapter.rollback(exec_result)

        assert record.success is True
        assert record.execution_id == exec_result.execution_id
        assert record.customer_id == "cust-1"
        assert record.action_class == ActionClass.DISABLE_ACCOUNT

    async def test_isinstance_action_executor(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockIAMAdapter(audit_logger=logger)

        assert isinstance(adapter, ActionExecutor)


# ===========================================================================
# MockFirewallAdapter tests
# ===========================================================================


class TestMockFirewallAdapter:
    async def test_dry_run_passes_with_ip_address(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockFirewallAdapter(audit_logger=logger)

        result = await adapter.dry_run("cust-1", {"ip_address": "10.0.0.1"})

        assert result.is_safe is True
        assert result.action_class == ActionClass.BLOCK_IP
        assert result.customer_id == "cust-1"
        assert result.validated_parameters == {"ip_address": "10.0.0.1"}

    async def test_dry_run_passes_with_rule_id(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockFirewallAdapter(audit_logger=logger)

        result = await adapter.dry_run("cust-1", {"rule_id": "rule-42"})

        assert result.is_safe is True
        assert result.action_class == ActionClass.BLOCK_IP

    async def test_dry_run_fails_missing_params(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockFirewallAdapter(audit_logger=logger)

        result = await adapter.dry_run("cust-1", {})

        assert result.is_safe is False
        assert "ip_address" in result.reason or "rule_id" in result.reason

    async def test_execute_completed_status(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockFirewallAdapter(audit_logger=logger)

        result = await adapter.execute("cust-1", {"ip_address": "10.0.0.1"}, "corr-1")

        assert result.status == ExecutorStatus.COMPLETED
        assert result.action_class == ActionClass.BLOCK_IP
        assert result.customer_id == "cust-1"
        assert result.completed_utc is not None

    async def test_execute_raises_on_empty_customer_id(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockFirewallAdapter(audit_logger=logger)

        with pytest.raises(ValueError, match="customer_id must not be empty"):
            await adapter.execute("", {"ip_address": "10.0.0.1"}, "corr-1")

    async def test_execute_audits_via_logger(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockFirewallAdapter(audit_logger=logger)

        await adapter.execute("cust-1", {"ip_address": "10.0.0.1"}, "corr-1")

        assert len(logger._entries) == 1

    async def test_rollback_success(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockFirewallAdapter(audit_logger=logger)
        exec_result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
        )

        record = await adapter.rollback(exec_result)

        assert record.success is True
        assert record.execution_id == exec_result.execution_id
        assert record.customer_id == "cust-1"
        assert record.action_class == ActionClass.BLOCK_IP

    async def test_isinstance_action_executor(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockFirewallAdapter(audit_logger=logger)

        assert isinstance(adapter, ActionExecutor)


# ===========================================================================
# MockPatchAdapter tests
# ===========================================================================


class TestMockPatchAdapter:
    async def test_dry_run_passes_with_valid_params(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockPatchAdapter(audit_logger=logger)

        result = await adapter.dry_run("cust-1", {"patch_id": "KB999"})

        assert result.is_safe is True
        assert result.action_class == ActionClass.PATCH_DEPLOYMENT
        assert result.customer_id == "cust-1"
        assert result.validated_parameters == {"patch_id": "KB999"}

    async def test_dry_run_fails_missing_patch_id(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockPatchAdapter(audit_logger=logger)

        result = await adapter.dry_run("cust-1", {})

        assert result.is_safe is False
        assert "patch_id" in result.reason

    async def test_execute_completed_status(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockPatchAdapter(audit_logger=logger)

        result = await adapter.execute("cust-1", {"patch_id": "KB999"}, "corr-1")

        assert result.status == ExecutorStatus.COMPLETED
        assert result.action_class == ActionClass.PATCH_DEPLOYMENT
        assert result.customer_id == "cust-1"
        assert result.completed_utc is not None

    async def test_execute_raises_on_empty_customer_id(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockPatchAdapter(audit_logger=logger)

        with pytest.raises(ValueError, match="customer_id must not be empty"):
            await adapter.execute("", {"patch_id": "KB999"}, "corr-1")

    async def test_execute_audits_via_logger(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockPatchAdapter(audit_logger=logger)

        await adapter.execute("cust-1", {"patch_id": "KB999"}, "corr-1")

        assert len(logger._entries) == 1

    async def test_rollback_success(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockPatchAdapter(audit_logger=logger)
        exec_result = ExecutionResult(
            action_class=ActionClass.PATCH_DEPLOYMENT,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
        )

        record = await adapter.rollback(exec_result)

        assert record.success is True
        assert record.execution_id == exec_result.execution_id
        assert record.customer_id == "cust-1"
        assert record.action_class == ActionClass.PATCH_DEPLOYMENT

    async def test_isinstance_action_executor(self) -> None:
        logger = InMemoryAuditLogger()
        adapter = MockPatchAdapter(audit_logger=logger)

        assert isinstance(adapter, ActionExecutor)
