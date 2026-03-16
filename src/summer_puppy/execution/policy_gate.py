"""Policy gate for pre-execution authorization checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from summer_puppy.execution.models import ExecutionPlan
    from summer_puppy.tenants.models import TenantProfile
    from summer_puppy.tenants.policy import TenantPolicyEngine
    from summer_puppy.trust.models import TrustPhase


class PolicyGate:
    """Checks tenant policy before allowing execution to proceed."""

    def __init__(self, tenant_policy_engine: TenantPolicyEngine) -> None:
        self._engine = tenant_policy_engine

    async def check(
        self,
        plan: ExecutionPlan,
        tenant: TenantProfile,
        trust_phase: TrustPhase,
    ) -> tuple[bool, str]:
        """Return (allowed, reason) based on tenant policy evaluation."""
        asset_ids: list[str] = plan.parameters.get("asset_ids", [])
        result = self._engine.check_action_allowed(
            tenant=tenant,
            action_class=plan.action_class,
            asset_ids=asset_ids,
            trust_phase=trust_phase,
        )
        return (result.allowed, result.reason)
