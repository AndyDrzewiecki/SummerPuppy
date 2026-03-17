"""Built-in background job handlers for SummerPuppy."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from summer_puppy.trust.models import AutoApprovalPolicy, PolicyStatus

if TYPE_CHECKING:
    from summer_puppy.tenants.store import InMemoryTenantStore


async def expire_protected_assets_handler(tenant_store: InMemoryTenantStore) -> int:
    """Remove ProtectedAssets whose protected_until timestamp is in the past.

    Returns the total count of assets removed across all tenants.
    """
    now = datetime.now(tz=UTC)
    removed = 0
    for profile in tenant_store.list_all():
        active = [
            a
            for a in profile.protected_assets
            if a.protected_until is None or a.protected_until > now
        ]
        if len(active) < len(profile.protected_assets):
            removed += len(profile.protected_assets) - len(active)
            updated = profile.model_copy(update={"protected_assets": active})
            tenant_store.save(updated)
    return removed


async def expire_policies_handler(
    policy_store: dict[str, list[AutoApprovalPolicy]],
) -> int:
    """Mark AutoApprovalPolicies as EXPIRED when their expires_utc is in the past.

    Accepts a dict mapping customer_id -> list[AutoApprovalPolicy].
    Mutates the policy objects in place (Pydantic v2 models allow direct field
    assignment when model_config allows it; we replace list entries here to be safe).
    Returns the count of policies that were transitioned to EXPIRED.
    """
    now = datetime.now(tz=UTC)
    expired_count = 0
    for customer_id, policies in policy_store.items():
        updated: list[AutoApprovalPolicy] = []
        for policy in policies:
            if (
                policy.status == PolicyStatus.ACTIVE
                and policy.expires_utc is not None
                and policy.expires_utc <= now
            ):
                policy = policy.model_copy(update={"status": PolicyStatus.EXPIRED})
                expired_count += 1
            updated.append(policy)
        policy_store[customer_id] = updated
    return expired_count


async def cleanup_stale_work_items_handler(pool_orchestrator: Any | None) -> int:
    """Detect stalled work items via the pool orchestrator.

    Returns 0 if no orchestrator is provided.
    """
    if pool_orchestrator is None:
        return 0
    return int(await pool_orchestrator.detect_stalled())
