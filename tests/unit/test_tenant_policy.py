"""Comprehensive tests for Tenant Policy Engine (Story 2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from summer_puppy.tenants.models import ProtectedAsset, TenantProfile
from summer_puppy.tenants.policy import PolicyCheckResult, TenantPolicyEngine
from summer_puppy.trust.models import ActionClass, TrustPhase


@pytest.fixture()
def engine() -> TenantPolicyEngine:
    return TenantPolicyEngine()


@pytest.fixture()
def base_tenant() -> TenantProfile:
    """Tenant with no restrictions at all."""
    return TenantProfile(customer_id="cust-test")


# ---------------------------------------------------------------------------
# PolicyCheckResult model tests
# ---------------------------------------------------------------------------


class TestPolicyCheckResult:
    def test_allowed_result(self) -> None:
        r = PolicyCheckResult(allowed=True, reason="Action permitted")
        assert r.allowed is True
        assert r.reason == "Action permitted"

    def test_denied_result(self) -> None:
        r = PolicyCheckResult(allowed=False, reason="Blocked")
        assert r.allowed is False
        assert r.reason == "Blocked"


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


class TestPolicyEngineHappyPath:
    def test_no_restrictions_allows_action(
        self, engine: TenantPolicyEngine, base_tenant: TenantProfile
    ) -> None:
        result = engine.check_action_allowed(
            tenant=base_tenant,
            action_class=ActionClass.PATCH_DEPLOYMENT,
            asset_ids=["asset-1"],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is True
        assert result.reason == "Action permitted"

    def test_no_restrictions_empty_asset_ids(
        self, engine: TenantPolicyEngine, base_tenant: TenantProfile
    ) -> None:
        result = engine.check_action_allowed(
            tenant=base_tenant,
            action_class=ActionClass.CONFIGURATION_CHANGE,
            asset_ids=[],
            trust_phase=TrustPhase.AUTONOMOUS,
        )
        assert result.allowed is True
        assert result.reason == "Action permitted"


# ---------------------------------------------------------------------------
# Blocked action class tests
# ---------------------------------------------------------------------------


class TestBlockedActionClass:
    def test_blocked_action_class_denied(self, engine: TenantPolicyEngine) -> None:
        tenant = TenantProfile(
            customer_id="cust-blocked",
            blocked_action_classes=[ActionClass.NETWORK_ISOLATION],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.NETWORK_ISOLATION,
            asset_ids=[],
            trust_phase=TrustPhase.MANUAL,
        )
        assert result.allowed is False
        assert "network_isolation" in result.reason.lower()
        assert "blocked" in result.reason.lower()

    def test_unblocked_action_class_allowed(self, engine: TenantPolicyEngine) -> None:
        tenant = TenantProfile(
            customer_id="cust-blocked",
            blocked_action_classes=[ActionClass.NETWORK_ISOLATION],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.PATCH_DEPLOYMENT,
            asset_ids=[],
            trust_phase=TrustPhase.MANUAL,
        )
        assert result.allowed is True

    def test_multiple_blocked_classes(self, engine: TenantPolicyEngine) -> None:
        tenant = TenantProfile(
            customer_id="cust-multi-blocked",
            blocked_action_classes=[
                ActionClass.ACCOUNT_LOCKOUT,
                ActionClass.PROCESS_TERMINATION,
            ],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.PROCESS_TERMINATION,
            asset_ids=[],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is False
        assert "process_termination" in result.reason.lower()


# ---------------------------------------------------------------------------
# Allowed action class list tests
# ---------------------------------------------------------------------------


class TestAllowedActionClassList:
    def test_action_not_in_allowed_list_denied(self, engine: TenantPolicyEngine) -> None:
        tenant = TenantProfile(
            customer_id="cust-allow",
            allowed_action_classes=[ActionClass.PATCH_DEPLOYMENT],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.NETWORK_ISOLATION,
            asset_ids=[],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is False
        assert "not in allowed list" in result.reason.lower()

    def test_action_in_allowed_list_permitted(self, engine: TenantPolicyEngine) -> None:
        tenant = TenantProfile(
            customer_id="cust-allow",
            allowed_action_classes=[
                ActionClass.PATCH_DEPLOYMENT,
                ActionClass.CONFIGURATION_CHANGE,
            ],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.PATCH_DEPLOYMENT,
            asset_ids=[],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is True

    def test_empty_allowed_list_means_all_allowed(
        self, engine: TenantPolicyEngine, base_tenant: TenantProfile
    ) -> None:
        """When allowed_action_classes is empty, no allowlist filter is applied."""
        result = engine.check_action_allowed(
            tenant=base_tenant,
            action_class=ActionClass.BLOCK_IP,
            asset_ids=[],
            trust_phase=TrustPhase.FULL_AUTONOMY,
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Protected asset tests
# ---------------------------------------------------------------------------


class TestProtectedAssets:
    def test_protected_asset_no_expiry_denied(self, engine: TenantPolicyEngine) -> None:
        tenant = TenantProfile(
            customer_id="cust-pa",
            protected_assets=[
                ProtectedAsset(asset_id="db-prod-01", reason="Critical production database"),
            ],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.PATCH_DEPLOYMENT,
            asset_ids=["db-prod-01"],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is False
        assert "db-prod-01" in result.reason
        assert "Critical production database" in result.reason

    def test_protected_asset_expired_protection_allowed(self, engine: TenantPolicyEngine) -> None:
        past = datetime.now(tz=UTC) - timedelta(days=1)
        tenant = TenantProfile(
            customer_id="cust-expired",
            protected_assets=[
                ProtectedAsset(
                    asset_id="db-staging-01",
                    reason="Audit freeze",
                    protected_until=past,
                ),
            ],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.CONFIGURATION_CHANGE,
            asset_ids=["db-staging-01"],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is True

    def test_protected_asset_future_protection_denied(self, engine: TenantPolicyEngine) -> None:
        future = datetime.now(tz=UTC) + timedelta(days=30)
        tenant = TenantProfile(
            customer_id="cust-future",
            protected_assets=[
                ProtectedAsset(
                    asset_id="web-prod-01",
                    reason="Change freeze until next quarter",
                    protected_until=future,
                ),
            ],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.PATCH_DEPLOYMENT,
            asset_ids=["web-prod-01"],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is False
        assert "web-prod-01" in result.reason
        assert "Change freeze until next quarter" in result.reason

    def test_unrelated_asset_ids_allowed(self, engine: TenantPolicyEngine) -> None:
        tenant = TenantProfile(
            customer_id="cust-unrelated",
            protected_assets=[
                ProtectedAsset(asset_id="db-prod-01", reason="Production DB"),
            ],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.PATCH_DEPLOYMENT,
            asset_ids=["web-server-01", "web-server-02"],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is True

    def test_empty_asset_ids_with_protected_assets_allowed(
        self, engine: TenantPolicyEngine
    ) -> None:
        """If no asset_ids are supplied, protected assets don't block."""
        tenant = TenantProfile(
            customer_id="cust-no-assets",
            protected_assets=[
                ProtectedAsset(asset_id="db-prod-01", reason="Production DB"),
            ],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.DETECTION_RULE_UPDATE,
            asset_ids=[],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is True

    def test_multiple_protected_assets_first_match_wins(self, engine: TenantPolicyEngine) -> None:
        tenant = TenantProfile(
            customer_id="cust-multi-pa",
            protected_assets=[
                ProtectedAsset(asset_id="db-01", reason="Database frozen"),
                ProtectedAsset(asset_id="web-01", reason="Web frozen"),
            ],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.CONFIGURATION_CHANGE,
            asset_ids=["web-01", "db-01"],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is False
        # Should match on the first asset_id checked that hits a protected asset
        assert "protected" in result.reason.lower() or "frozen" in result.reason.lower()


# ---------------------------------------------------------------------------
# Priority / ordering tests
# ---------------------------------------------------------------------------


class TestCheckOrdering:
    def test_blocked_takes_priority_over_allowed_list(self, engine: TenantPolicyEngine) -> None:
        """Blocked check runs before allowed-list check."""
        tenant = TenantProfile(
            customer_id="cust-priority",
            blocked_action_classes=[ActionClass.PATCH_DEPLOYMENT],
            allowed_action_classes=[ActionClass.PATCH_DEPLOYMENT],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.PATCH_DEPLOYMENT,
            asset_ids=[],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is False
        assert "blocked" in result.reason.lower()

    def test_blocked_takes_priority_over_protected_asset(self, engine: TenantPolicyEngine) -> None:
        """Blocked check runs before protected asset check."""
        tenant = TenantProfile(
            customer_id="cust-priority-2",
            blocked_action_classes=[ActionClass.CONFIGURATION_CHANGE],
            protected_assets=[
                ProtectedAsset(asset_id="asset-1", reason="Frozen"),
            ],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.CONFIGURATION_CHANGE,
            asset_ids=["asset-1"],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is False
        assert "blocked" in result.reason.lower()

    def test_allowed_list_checked_before_protected_assets(
        self, engine: TenantPolicyEngine
    ) -> None:
        """Allowed-list check runs before protected asset check."""
        tenant = TenantProfile(
            customer_id="cust-priority-3",
            allowed_action_classes=[ActionClass.PATCH_DEPLOYMENT],
            protected_assets=[
                ProtectedAsset(asset_id="asset-1", reason="Frozen"),
            ],
        )
        result = engine.check_action_allowed(
            tenant=tenant,
            action_class=ActionClass.CONFIGURATION_CHANGE,
            asset_ids=["asset-1"],
            trust_phase=TrustPhase.SUPERVISED,
        )
        assert result.allowed is False
        assert "not in allowed list" in result.reason.lower()
