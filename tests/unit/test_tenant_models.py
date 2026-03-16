"""Comprehensive tests for Tenant Models & Store (Story 1)."""

from __future__ import annotations

from datetime import UTC, datetime, time

import pytest
from pydantic import ValidationError

from summer_puppy.tenants.models import (
    LocalSwarmConfig,
    MaintenanceWindow,
    ProtectedAsset,
    TenantProfile,
)
from summer_puppy.tenants.store import InMemoryTenantStore, TenantStore
from summer_puppy.trust.models import ActionClass

# ---------------------------------------------------------------------------
# MaintenanceWindow model tests
# ---------------------------------------------------------------------------


class TestMaintenanceWindow:
    def test_creation(self) -> None:
        mw = MaintenanceWindow(
            day_of_week=0,
            start_time=time(2, 0),
            end_time=time(6, 0),
        )
        assert mw.day_of_week == 0
        assert mw.start_time == time(2, 0)
        assert mw.end_time == time(6, 0)

    def test_day_of_week_min_boundary(self) -> None:
        mw = MaintenanceWindow(day_of_week=0, start_time=time(0, 0), end_time=time(1, 0))
        assert mw.day_of_week == 0

    def test_day_of_week_max_boundary(self) -> None:
        mw = MaintenanceWindow(day_of_week=6, start_time=time(0, 0), end_time=time(1, 0))
        assert mw.day_of_week == 6

    def test_day_of_week_below_min_raises(self) -> None:
        with pytest.raises(ValidationError):
            MaintenanceWindow(day_of_week=-1, start_time=time(0, 0), end_time=time(1, 0))

    def test_day_of_week_above_max_raises(self) -> None:
        with pytest.raises(ValidationError):
            MaintenanceWindow(day_of_week=7, start_time=time(0, 0), end_time=time(1, 0))


# ---------------------------------------------------------------------------
# ProtectedAsset model tests
# ---------------------------------------------------------------------------


class TestProtectedAsset:
    def test_creation(self) -> None:
        pa = ProtectedAsset(asset_id="asset-1", reason="Critical production database")
        assert pa.asset_id == "asset-1"
        assert pa.reason == "Critical production database"
        assert pa.protected_until is None

    def test_optional_protected_until(self) -> None:
        deadline = datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)
        pa = ProtectedAsset(
            asset_id="asset-2",
            reason="Audit freeze",
            protected_until=deadline,
        )
        assert pa.protected_until == deadline

    def test_protected_until_defaults_none(self) -> None:
        pa = ProtectedAsset(asset_id="asset-3", reason="No deadline")
        assert pa.protected_until is None


# ---------------------------------------------------------------------------
# TenantProfile model tests
# ---------------------------------------------------------------------------


class TestTenantProfile:
    def test_minimal_creation(self) -> None:
        tp = TenantProfile(customer_id="cust-1")
        assert tp.customer_id == "cust-1"
        assert tp.tenant_id  # auto-generated uuid
        assert tp.allowed_action_classes == []
        assert tp.blocked_action_classes == []
        assert tp.protected_assets == []
        assert tp.maintenance_windows == []
        assert tp.max_concurrent_executions == 5
        assert tp.require_dry_run is True
        assert tp.auto_rollback_on_verify_fail is True
        assert isinstance(tp.created_utc, datetime)

    def test_all_fields(self) -> None:
        now = datetime(2026, 3, 16, 10, 0, 0, tzinfo=UTC)
        pa = ProtectedAsset(asset_id="asset-1", reason="prod db")
        mw = MaintenanceWindow(day_of_week=5, start_time=time(2, 0), end_time=time(6, 0))
        tp = TenantProfile(
            tenant_id="tenant-custom",
            customer_id="cust-2",
            allowed_action_classes=[ActionClass.PATCH_DEPLOYMENT],
            blocked_action_classes=[ActionClass.ACCOUNT_LOCKOUT],
            protected_assets=[pa],
            maintenance_windows=[mw],
            max_concurrent_executions=10,
            require_dry_run=False,
            auto_rollback_on_verify_fail=False,
            created_utc=now,
        )
        assert tp.tenant_id == "tenant-custom"
        assert tp.customer_id == "cust-2"
        assert tp.allowed_action_classes == [ActionClass.PATCH_DEPLOYMENT]
        assert tp.blocked_action_classes == [ActionClass.ACCOUNT_LOCKOUT]
        assert tp.protected_assets == [pa]
        assert tp.maintenance_windows == [mw]
        assert tp.max_concurrent_executions == 10
        assert tp.require_dry_run is False
        assert tp.auto_rollback_on_verify_fail is False
        assert tp.created_utc == now

    def test_default_values(self) -> None:
        tp = TenantProfile(customer_id="cust-defaults")
        assert tp.max_concurrent_executions == 5
        assert tp.require_dry_run is True
        assert tp.auto_rollback_on_verify_fail is True

    def test_unique_tenant_ids(self) -> None:
        t1 = TenantProfile(customer_id="cust-1")
        t2 = TenantProfile(customer_id="cust-2")
        assert t1.tenant_id != t2.tenant_id

    def test_serialization_round_trip(self) -> None:
        pa = ProtectedAsset(asset_id="asset-1", reason="prod db")
        mw = MaintenanceWindow(day_of_week=3, start_time=time(1, 0), end_time=time(5, 0))
        tp = TenantProfile(
            customer_id="cust-rt",
            allowed_action_classes=[ActionClass.CONFIGURATION_CHANGE],
            blocked_action_classes=[ActionClass.NETWORK_ISOLATION],
            protected_assets=[pa],
            maintenance_windows=[mw],
            max_concurrent_executions=8,
            require_dry_run=False,
            auto_rollback_on_verify_fail=True,
        )
        data = tp.model_dump()
        restored = TenantProfile.model_validate(data)
        assert restored.tenant_id == tp.tenant_id
        assert restored.customer_id == tp.customer_id
        assert restored.allowed_action_classes == tp.allowed_action_classes
        assert restored.blocked_action_classes == tp.blocked_action_classes
        assert len(restored.protected_assets) == 1
        assert restored.protected_assets[0].asset_id == "asset-1"
        assert len(restored.maintenance_windows) == 1
        assert restored.maintenance_windows[0].day_of_week == 3
        assert restored.max_concurrent_executions == tp.max_concurrent_executions
        assert restored.require_dry_run == tp.require_dry_run
        assert restored.auto_rollback_on_verify_fail == tp.auto_rollback_on_verify_fail


# ---------------------------------------------------------------------------
# LocalSwarmConfig model tests
# ---------------------------------------------------------------------------


class TestLocalSwarmConfig:
    def test_creation(self) -> None:
        lsc = LocalSwarmConfig(tenant_id="tenant-1", customer_id="cust-1")
        assert lsc.tenant_id == "tenant-1"
        assert lsc.customer_id == "cust-1"
        assert lsc.max_agents == 10
        assert lsc.preferred_pool_types == []
        assert lsc.custom_policies == {}

    def test_defaults(self) -> None:
        lsc = LocalSwarmConfig(tenant_id="t-2", customer_id="c-2")
        assert lsc.max_agents == 10
        assert lsc.preferred_pool_types == []
        assert lsc.custom_policies == {}

    def test_all_fields(self) -> None:
        lsc = LocalSwarmConfig(
            tenant_id="t-3",
            customer_id="c-3",
            max_agents=25,
            preferred_pool_types=["THREAT_RESEARCH", "ENGINEERING"],
            custom_policies={"auto_scale": True, "priority": "high"},
        )
        assert lsc.max_agents == 25
        assert lsc.preferred_pool_types == ["THREAT_RESEARCH", "ENGINEERING"]
        assert lsc.custom_policies == {"auto_scale": True, "priority": "high"}


# ---------------------------------------------------------------------------
# InMemoryTenantStore tests
# ---------------------------------------------------------------------------


class TestInMemoryTenantStore:
    def test_save_and_get_round_trip(self) -> None:
        store = InMemoryTenantStore()
        profile = TenantProfile(customer_id="cust-1")
        store.save(profile)
        result = store.get("cust-1")
        assert result is not None
        assert result.customer_id == "cust-1"
        assert result.tenant_id == profile.tenant_id

    def test_get_returns_none_for_missing(self) -> None:
        store = InMemoryTenantStore()
        assert store.get("nonexistent") is None

    def test_list_all(self) -> None:
        store = InMemoryTenantStore()
        p1 = TenantProfile(customer_id="cust-1")
        p2 = TenantProfile(customer_id="cust-2")
        store.save(p1)
        store.save(p2)
        all_profiles = store.list_all()
        assert len(all_profiles) == 2
        customer_ids = {p.customer_id for p in all_profiles}
        assert customer_ids == {"cust-1", "cust-2"}

    def test_save_overwrites_existing(self) -> None:
        store = InMemoryTenantStore()
        p1 = TenantProfile(customer_id="cust-1", max_concurrent_executions=5)
        store.save(p1)
        p2 = TenantProfile(customer_id="cust-1", max_concurrent_executions=20)
        store.save(p2)
        result = store.get("cust-1")
        assert result is not None
        assert result.max_concurrent_executions == 20
        assert store.list_all().__len__() == 1

    def test_list_all_empty(self) -> None:
        store = InMemoryTenantStore()
        assert store.list_all() == []

    def test_protocol_conformance(self) -> None:
        store = InMemoryTenantStore()
        assert isinstance(store, TenantStore)
