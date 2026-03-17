"""Pydantic schemas for Policy Management CRUD API."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003

from pydantic import BaseModel, Field

from summer_puppy.trust.models import ActionClass, PolicyStatus  # noqa: TC001


class CreatePolicyRequest(BaseModel):
    action_class: ActionClass
    max_severity: str = "MEDIUM"
    expires_utc: datetime | None = None
    created_by: str = "api"


class PatchPolicyRequest(BaseModel):
    max_severity: str | None = None
    expires_utc: datetime | None = None
    status: PolicyStatus | None = None


class PolicyResponse(BaseModel):
    policy_id: str
    customer_id: str
    action_class: ActionClass
    status: PolicyStatus
    max_severity: str
    expires_utc: datetime | None


class ProtectedAssetRequest(BaseModel):
    asset_id: str = Field(min_length=1)
    reason: str = ""
    protected_until: datetime | None = None


class ProtectedAssetResponse(BaseModel):
    asset_id: str
    reason: str
    protected_until: datetime | None
