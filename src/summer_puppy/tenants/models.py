"""Tenant profile and configuration models."""

from __future__ import annotations

from datetime import UTC, datetime, time
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from summer_puppy.trust.models import ActionClass, AutoApprovalPolicy  # noqa: TC001


class MaintenanceWindow(BaseModel):
    """Defines a recurring maintenance window for a tenant."""

    day_of_week: int = Field(ge=0, le=6)  # 0=Monday
    start_time: time
    end_time: time


class ProtectedAsset(BaseModel):
    """An asset that is protected from automated actions."""

    asset_id: str
    reason: str
    protected_until: datetime | None = None


class TenantProfile(BaseModel):
    """Core tenant profile controlling behaviour and guardrails."""

    tenant_id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str
    allowed_action_classes: list[ActionClass] = Field(default_factory=list)
    blocked_action_classes: list[ActionClass] = Field(default_factory=list)
    protected_assets: list[ProtectedAsset] = Field(default_factory=list)
    maintenance_windows: list[MaintenanceWindow] = Field(default_factory=list)
    max_concurrent_executions: int = 5
    require_dry_run: bool = True
    auto_rollback_on_verify_fail: bool = True
    auto_approval_policies: list[AutoApprovalPolicy] = Field(default_factory=list)
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class LocalSwarmConfig(BaseModel):
    """Per-tenant configuration for local agent swarm behaviour."""

    tenant_id: str
    customer_id: str
    max_agents: int = 10
    preferred_pool_types: list[str] = Field(default_factory=list)
    custom_policies: dict[str, Any] = Field(default_factory=dict)
