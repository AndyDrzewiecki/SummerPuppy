from __future__ import annotations

from datetime import datetime

from summer_puppy.trust.models import (
    ApprovalCheckResult,
    AutoApprovalPolicy,
    PolicyStatus,
    TrustPhase,
    TrustProfile,
)


def calculate_trust_score(outcome_history: list[dict]) -> float:
    if not outcome_history:
        return 0.0
    positive = sum(1 for o in outcome_history if o.get("success", False))
    return positive / len(outcome_history)


def evaluate_phase_transition(profile: TrustProfile, score: float) -> TrustPhase | None:
    total = profile.total_recommendations
    phase = profile.trust_phase
    if phase == TrustPhase.MANUAL and score >= 0.85 and total >= 20:
        return TrustPhase.SUPERVISED
    if phase == TrustPhase.SUPERVISED and score >= 0.92 and total >= 50:
        return TrustPhase.AUTONOMOUS
    if phase == TrustPhase.AUTONOMOUS and score >= 0.97 and total >= 100:
        return TrustPhase.FULL_AUTONOMY
    return None


def check_auto_approval(
    recommendation: dict,
    policies: list[AutoApprovalPolicy],
    current_utc: datetime,
) -> ApprovalCheckResult:
    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    rec_action = recommendation.get("action_class", "")
    rec_severity = recommendation.get("severity", "CRITICAL")
    rec_confidence = recommendation.get("confidence_score", 0.0)
    rec_qa = recommendation.get("qa_passed", False)
    rec_rollback = recommendation.get("rollback_available", False)
    rec_risk = recommendation.get("estimated_risk", "CRITICAL")
    rec_assets = recommendation.get("affected_asset_classes", [])

    for policy in policies:
        if policy.status != PolicyStatus.ACTIVE:
            continue
        if policy.expires_utc and current_utc > policy.expires_utc:
            continue
        if policy.action_class.value != rec_action:
            continue
        if severity_order.get(rec_severity, 3) > severity_order.get(policy.max_severity, 1):
            continue
        cond = policy.conditions
        if rec_confidence < cond.min_confidence_score:
            continue
        if cond.require_qa_passed and not rec_qa:
            continue
        if cond.require_rollback_available and not rec_rollback:
            continue
        if severity_order.get(rec_risk, 3) > severity_order.get(cond.max_estimated_risk, 1):
            continue
        if cond.time_window_start and cond.time_window_end:
            current_time = current_utc.time()
            if not (cond.time_window_start <= current_time <= cond.time_window_end):
                continue
        if cond.excluded_asset_classes:
            if any(ac in cond.excluded_asset_classes for ac in rec_assets):
                continue
        return ApprovalCheckResult(
            policy_matched=True,
            policy_id=policy.policy_id,
            auto_approved=True,
            reason=f"Matched policy {policy.policy_id} for {policy.action_class}",
        )
    return ApprovalCheckResult(
        policy_matched=False,
        auto_approved=False,
        reason="No matching active policy found",
    )
