"""Tenant policy engine for action authorization checks."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel

if TYPE_CHECKING:
    from summer_puppy.tenants.models import TenantProfile
    from summer_puppy.trust.models import ActionClass, TrustPhase


class PolicyCheckResult(BaseModel):
    """Result of a tenant policy check."""

    allowed: bool
    reason: str


class TenantPolicyEngine:
    """Evaluates tenant policies to determine if an action is allowed."""

    def check_action_allowed(
        self,
        tenant: TenantProfile,
        action_class: ActionClass,
        asset_ids: list[str],
        trust_phase: TrustPhase,  # noqa: ARG002
    ) -> PolicyCheckResult:
        """Check whether an action is allowed under the tenant's policy.

        Checks are evaluated in order; the first failure wins:
        1. Blocked action classes
        2. Allowed action classes (allowlist)
        3. Protected assets
        """
        # 1. Blocked action class check
        if action_class in tenant.blocked_action_classes:
            return PolicyCheckResult(
                allowed=False,
                reason=f"Action class {action_class} is blocked for this tenant",
            )

        # 2. Allowed action class check (only when allowlist is non-empty)
        if tenant.allowed_action_classes and action_class not in tenant.allowed_action_classes:
            return PolicyCheckResult(
                allowed=False,
                reason=f"Action class {action_class} is not in allowed list",
            )

        # 3. Protected asset check
        now = datetime.now(tz=UTC)
        for asset_id in asset_ids:
            for protected in tenant.protected_assets:
                if protected.asset_id == asset_id and (
                    protected.protected_until is None or protected.protected_until > now
                ):
                    return PolicyCheckResult(
                        allowed=False,
                        reason=f"Asset {asset_id} is protected: {protected.reason}",
                    )

        return PolicyCheckResult(allowed=True, reason="Action permitted")
