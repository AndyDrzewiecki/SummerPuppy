"""Tests for pipeline action executors."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from summer_puppy.events.models import ExecutionResult, ExecutorStatus
from summer_puppy.pipeline.executors import (
    BlockIPExecutor,
    DisableAccountExecutor,
    UpdateFirewallRuleExecutor,
)
from summer_puppy.trust.models import ActionClass

# ===========================================================================
# BlockIPExecutor tests
# ===========================================================================


class TestBlockIPExecutor:
    async def test_dry_run_passes_with_valid_params(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SP_FIREWALL_API_URL", "https://firewall.example.com")
        audit_logger = AsyncMock()
        executor = BlockIPExecutor(audit_logger=audit_logger)

        result = await executor.dry_run("cust-1", {"ip_address": "10.0.0.1"})

        assert result.is_safe is True
        assert result.action_class == ActionClass.BLOCK_IP

    async def test_dry_run_fails_without_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SP_FIREWALL_API_URL", raising=False)
        audit_logger = AsyncMock()
        executor = BlockIPExecutor(audit_logger=audit_logger)

        result = await executor.dry_run("cust-1", {"ip_address": "10.0.0.1"})

        assert result.is_safe is False
        assert "SP_FIREWALL_API_URL" in result.reason

    async def test_dry_run_fails_without_ip_address(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SP_FIREWALL_API_URL", "https://firewall.example.com")
        audit_logger = AsyncMock()
        executor = BlockIPExecutor(audit_logger=audit_logger)

        result = await executor.dry_run("cust-1", {})

        assert result.is_safe is False
        assert "ip_address" in result.reason

    async def test_execute_raises_on_empty_customer_id(self) -> None:
        audit_logger = AsyncMock()
        executor = BlockIPExecutor(audit_logger=audit_logger)

        with pytest.raises(ValueError, match="customer_id must not be empty"):
            await executor.execute("", {"ip_address": "10.0.0.1"}, "corr-1")

    async def test_execute_returns_failed_result(self) -> None:
        audit_logger = AsyncMock()
        executor = BlockIPExecutor(audit_logger=audit_logger)

        result = await executor.execute("cust-1", {"ip_address": "10.0.0.1"}, "corr-1")

        assert result.status == ExecutorStatus.FAILED
        assert result.error_detail is not None
        assert "not yet implemented" in result.error_detail
        assert result.action_class == ActionClass.BLOCK_IP
        assert result.completed_utc is not None

    async def test_execute_creates_audit_entry(self) -> None:
        audit_logger = AsyncMock()
        executor = BlockIPExecutor(audit_logger=audit_logger)

        await executor.execute("cust-1", {"ip_address": "10.0.0.1"}, "corr-1")

        audit_logger.append.assert_called_once()

    async def test_rollback_produces_record(self) -> None:
        audit_logger = AsyncMock()
        executor = BlockIPExecutor(audit_logger=audit_logger)
        exec_result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.FAILED,
        )

        record = await executor.rollback(exec_result)

        assert record.execution_id == exec_result.execution_id
        assert record.customer_id == "cust-1"
        assert record.action_class == ActionClass.BLOCK_IP
        assert record.success is True
        assert record.reason == "Rollback executed"

    async def test_rollback_audits(self) -> None:
        audit_logger = AsyncMock()
        executor = BlockIPExecutor(audit_logger=audit_logger)
        exec_result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.FAILED,
        )

        await executor.rollback(exec_result)

        audit_logger.append.assert_called_once()


# ===========================================================================
# DisableAccountExecutor tests
# ===========================================================================


class TestDisableAccountExecutor:
    async def test_dry_run_passes_with_valid_params(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SP_DIRECTORY_SERVICE_URL", "https://directory.example.com")
        audit_logger = AsyncMock()
        executor = DisableAccountExecutor(audit_logger=audit_logger)

        result = await executor.dry_run("cust-1", {"account_id": "acc-1"})

        assert result.is_safe is True
        assert result.action_class == ActionClass.DISABLE_ACCOUNT

    async def test_dry_run_fails_without_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SP_DIRECTORY_SERVICE_URL", raising=False)
        audit_logger = AsyncMock()
        executor = DisableAccountExecutor(audit_logger=audit_logger)

        result = await executor.dry_run("cust-1", {"account_id": "acc-1"})

        assert result.is_safe is False
        assert "SP_DIRECTORY_SERVICE_URL" in result.reason

    async def test_dry_run_fails_without_account_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SP_DIRECTORY_SERVICE_URL", "https://directory.example.com")
        audit_logger = AsyncMock()
        executor = DisableAccountExecutor(audit_logger=audit_logger)

        result = await executor.dry_run("cust-1", {})

        assert result.is_safe is False
        assert "account_id" in result.reason

    async def test_execute_raises_on_empty_customer_id(self) -> None:
        audit_logger = AsyncMock()
        executor = DisableAccountExecutor(audit_logger=audit_logger)

        with pytest.raises(ValueError, match="customer_id must not be empty"):
            await executor.execute("", {"account_id": "acc-1"}, "corr-1")

    async def test_execute_returns_failed_result(self) -> None:
        audit_logger = AsyncMock()
        executor = DisableAccountExecutor(audit_logger=audit_logger)

        result = await executor.execute("cust-1", {"account_id": "acc-1"}, "corr-1")

        assert result.status == ExecutorStatus.FAILED
        assert result.error_detail is not None
        assert "not yet implemented" in result.error_detail
        assert result.action_class == ActionClass.DISABLE_ACCOUNT

    async def test_execute_creates_audit_entry(self) -> None:
        audit_logger = AsyncMock()
        executor = DisableAccountExecutor(audit_logger=audit_logger)

        await executor.execute("cust-1", {"account_id": "acc-1"}, "corr-1")

        audit_logger.append.assert_called_once()

    async def test_rollback_produces_record(self) -> None:
        audit_logger = AsyncMock()
        executor = DisableAccountExecutor(audit_logger=audit_logger)
        exec_result = ExecutionResult(
            action_class=ActionClass.DISABLE_ACCOUNT,
            customer_id="cust-1",
            status=ExecutorStatus.FAILED,
        )

        record = await executor.rollback(exec_result)

        assert record.execution_id == exec_result.execution_id
        assert record.customer_id == "cust-1"
        assert record.action_class == ActionClass.DISABLE_ACCOUNT
        assert record.success is True
        assert record.reason == "Rollback executed"

    async def test_rollback_audits(self) -> None:
        audit_logger = AsyncMock()
        executor = DisableAccountExecutor(audit_logger=audit_logger)
        exec_result = ExecutionResult(
            action_class=ActionClass.DISABLE_ACCOUNT,
            customer_id="cust-1",
            status=ExecutorStatus.FAILED,
        )

        await executor.rollback(exec_result)

        audit_logger.append.assert_called_once()


# ===========================================================================
# UpdateFirewallRuleExecutor tests
# ===========================================================================


class TestUpdateFirewallRuleExecutor:
    async def test_dry_run_passes_with_valid_params(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SP_FIREWALL_API_URL", "https://firewall.example.com")
        audit_logger = AsyncMock()
        executor = UpdateFirewallRuleExecutor(audit_logger=audit_logger)

        result = await executor.dry_run("cust-1", {"rule_id": "rule-1"})

        assert result.is_safe is True
        assert result.action_class == ActionClass.UPDATE_FIREWALL_RULE

    async def test_dry_run_fails_without_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SP_FIREWALL_API_URL", raising=False)
        audit_logger = AsyncMock()
        executor = UpdateFirewallRuleExecutor(audit_logger=audit_logger)

        result = await executor.dry_run("cust-1", {"rule_id": "rule-1"})

        assert result.is_safe is False
        assert "SP_FIREWALL_API_URL" in result.reason

    async def test_dry_run_fails_without_rule_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SP_FIREWALL_API_URL", "https://firewall.example.com")
        audit_logger = AsyncMock()
        executor = UpdateFirewallRuleExecutor(audit_logger=audit_logger)

        result = await executor.dry_run("cust-1", {})

        assert result.is_safe is False
        assert "rule_id" in result.reason

    async def test_execute_raises_on_empty_customer_id(self) -> None:
        audit_logger = AsyncMock()
        executor = UpdateFirewallRuleExecutor(audit_logger=audit_logger)

        with pytest.raises(ValueError, match="customer_id must not be empty"):
            await executor.execute("", {"rule_id": "rule-1"}, "corr-1")

    async def test_execute_returns_failed_result(self) -> None:
        audit_logger = AsyncMock()
        executor = UpdateFirewallRuleExecutor(audit_logger=audit_logger)

        result = await executor.execute("cust-1", {"rule_id": "rule-1"}, "corr-1")

        assert result.status == ExecutorStatus.FAILED
        assert result.error_detail is not None
        assert "not yet implemented" in result.error_detail
        assert result.action_class == ActionClass.UPDATE_FIREWALL_RULE

    async def test_execute_creates_audit_entry(self) -> None:
        audit_logger = AsyncMock()
        executor = UpdateFirewallRuleExecutor(audit_logger=audit_logger)

        await executor.execute("cust-1", {"rule_id": "rule-1"}, "corr-1")

        audit_logger.append.assert_called_once()

    async def test_rollback_produces_record(self) -> None:
        audit_logger = AsyncMock()
        executor = UpdateFirewallRuleExecutor(audit_logger=audit_logger)
        exec_result = ExecutionResult(
            action_class=ActionClass.UPDATE_FIREWALL_RULE,
            customer_id="cust-1",
            status=ExecutorStatus.FAILED,
        )

        record = await executor.rollback(exec_result)

        assert record.execution_id == exec_result.execution_id
        assert record.customer_id == "cust-1"
        assert record.action_class == ActionClass.UPDATE_FIREWALL_RULE
        assert record.success is True
        assert record.reason == "Rollback executed"

    async def test_rollback_audits(self) -> None:
        audit_logger = AsyncMock()
        executor = UpdateFirewallRuleExecutor(audit_logger=audit_logger)
        exec_result = ExecutionResult(
            action_class=ActionClass.UPDATE_FIREWALL_RULE,
            customer_id="cust-1",
            status=ExecutorStatus.FAILED,
        )

        await executor.rollback(exec_result)

        audit_logger.append.assert_called_once()
