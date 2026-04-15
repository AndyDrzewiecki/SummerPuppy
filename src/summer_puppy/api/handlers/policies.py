"""Policy Management CRUD handlers — auto-approval policies and protected assets."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from summer_puppy.api.middleware.auth_middleware import verify_customer_path
from summer_puppy.api.schemas.policies import (
    CreatePolicyRequest,
    PatchPolicyRequest,
    PolicyResponse,
    ProtectedAssetRequest,
    ProtectedAssetResponse,
)
from summer_puppy.api.state import AppState, get_app_state
from summer_puppy.audit.models import AuditEntry, AuditEntryType
from summer_puppy.tenants.models import ProtectedAsset, TenantProfile
from summer_puppy.trust.models import AutoApprovalPolicy, PolicyStatus

router = APIRouter()


def _get_or_create_profile(state: AppState, customer_id: str) -> TenantProfile:
    profile = state.tenant_store.get(customer_id)
    if profile is None:
        profile = TenantProfile(customer_id=customer_id)
        state.tenant_store.save(profile)
    return profile


def _policy_to_response(policy: AutoApprovalPolicy, customer_id: str) -> PolicyResponse:
    return PolicyResponse(
        policy_id=policy.policy_id,
        customer_id=customer_id,
        action_class=policy.action_class,
        status=policy.status,
        max_severity=policy.max_severity,
        expires_utc=policy.expires_utc,
    )


# ---------------------------------------------------------------------------
# Auto-Approval Policy endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/{customer_id}/policies/auto-approval",
    status_code=201,
    response_model=PolicyResponse,
    dependencies=[Depends(verify_customer_path)],
)
async def create_policy(
    customer_id: str,
    body: CreatePolicyRequest,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> PolicyResponse:
    """Create a new auto-approval policy for a tenant."""
    profile = _get_or_create_profile(state, customer_id)
    policy = AutoApprovalPolicy(
        customer_id=customer_id,
        action_class=body.action_class,
        max_severity=body.max_severity,
        expires_utc=body.expires_utc,
        created_by=body.created_by,
    )
    profile.auto_approval_policies.append(policy)
    state.tenant_store.save(profile)

    entry = AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.POLICY_CHANGED,
        actor="api",
        details={"action": "create", "policy_id": policy.policy_id},
    )
    asyncio.create_task(state.audit_logger.append(entry))

    return _policy_to_response(policy, customer_id)


@router.get(
    "/{customer_id}/policies/auto-approval",
    response_model=list[PolicyResponse],
    dependencies=[Depends(verify_customer_path)],
)
async def list_policies(
    customer_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> list[PolicyResponse]:
    """List all auto-approval policies for a tenant."""
    profile = state.tenant_store.get(customer_id)
    if profile is None:
        return []
    return [_policy_to_response(p, customer_id) for p in profile.auto_approval_policies]


@router.patch(
    "/{customer_id}/policies/auto-approval/{policy_id}",
    response_model=PolicyResponse,
    dependencies=[Depends(verify_customer_path)],
)
async def patch_policy(
    customer_id: str,
    policy_id: str,
    body: PatchPolicyRequest,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> PolicyResponse:
    """Partially update an auto-approval policy."""
    profile = _get_or_create_profile(state, customer_id)
    for i, p in enumerate(profile.auto_approval_policies):
        if p.policy_id == policy_id:
            updates: dict[str, object] = {}
            if body.max_severity is not None:
                updates["max_severity"] = body.max_severity
            if body.expires_utc is not None:
                updates["expires_utc"] = body.expires_utc
            if body.status is not None:
                updates["status"] = body.status
            updated = p.model_copy(update=updates)
            profile.auto_approval_policies[i] = updated
            state.tenant_store.save(profile)
            return _policy_to_response(updated, customer_id)
    raise HTTPException(status_code=404, detail="Policy not found")


@router.delete(
    "/{customer_id}/policies/auto-approval/{policy_id}",
    status_code=204,
    response_class=Response,
    dependencies=[Depends(verify_customer_path)],
)
async def delete_policy(
    customer_id: str,
    policy_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> Response:
    """Soft-delete (revoke) an auto-approval policy."""
    profile = _get_or_create_profile(state, customer_id)
    for i, p in enumerate(profile.auto_approval_policies):
        if p.policy_id == policy_id:
            profile.auto_approval_policies[i] = p.model_copy(
                update={"status": PolicyStatus.REVOKED}
            )
            state.tenant_store.save(profile)
            entry = AuditEntry(
                customer_id=customer_id,
                entry_type=AuditEntryType.POLICY_CHANGED,
                actor="api",
                details={"action": "delete", "policy_id": policy_id},
            )
            asyncio.create_task(state.audit_logger.append(entry))
            return Response(status_code=204)
    raise HTTPException(status_code=404, detail="Policy not found")


# ---------------------------------------------------------------------------
# Protected Assets endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/{customer_id}/policies/protected-assets",
    status_code=201,
    response_model=ProtectedAssetResponse,
    dependencies=[Depends(verify_customer_path)],
)
async def add_protected_asset(
    customer_id: str,
    body: ProtectedAssetRequest,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> ProtectedAssetResponse:
    """Add a protected asset to a tenant profile."""
    profile = _get_or_create_profile(state, customer_id)
    asset = ProtectedAsset(
        asset_id=body.asset_id,
        reason=body.reason,
        protected_until=body.protected_until,
    )
    profile.protected_assets.append(asset)
    state.tenant_store.save(profile)
    return ProtectedAssetResponse(
        asset_id=asset.asset_id,
        reason=asset.reason,
        protected_until=asset.protected_until,
    )


@router.get(
    "/{customer_id}/policies/protected-assets",
    response_model=list[ProtectedAssetResponse],
    dependencies=[Depends(verify_customer_path)],
)
async def list_protected_assets(
    customer_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> list[ProtectedAssetResponse]:
    """List all protected assets for a tenant."""
    profile = state.tenant_store.get(customer_id)
    if profile is None:
        return []
    return [
        ProtectedAssetResponse(
            asset_id=a.asset_id,
            reason=a.reason,
            protected_until=a.protected_until,
        )
        for a in profile.protected_assets
    ]


@router.delete(
    "/{customer_id}/policies/protected-assets/{asset_id}",
    status_code=204,
    response_class=Response,
    dependencies=[Depends(verify_customer_path)],
)
async def remove_protected_asset(
    customer_id: str,
    asset_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> Response:
    """Remove a protected asset from a tenant profile."""
    profile = _get_or_create_profile(state, customer_id)
    original_len = len(profile.protected_assets)
    profile.protected_assets = [a for a in profile.protected_assets if a.asset_id != asset_id]
    if len(profile.protected_assets) == original_len:
        raise HTTPException(status_code=404, detail="Protected asset not found")
    state.tenant_store.save(profile)
    return Response(status_code=204)
