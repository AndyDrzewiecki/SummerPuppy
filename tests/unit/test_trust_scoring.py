from datetime import datetime, time

from summer_puppy.trust.models import (
    ActionClass,
    ApprovalConditions,
    AutoApprovalPolicy,
    PolicyStatus,
    TrustPhase,
    TrustProfile,
)
from summer_puppy.trust.scoring import (
    calculate_trust_score,
    check_auto_approval,
    evaluate_phase_transition,
)


class TestCalculateTrustScore:
    def test_empty_history(self):
        assert calculate_trust_score([]) == 0.0

    def test_all_success(self):
        history = [{"success": True}] * 10
        assert calculate_trust_score(history) == 1.0

    def test_all_failure(self):
        history = [{"success": False}] * 10
        assert calculate_trust_score(history) == 0.0

    def test_mixed(self):
        history = [{"success": True}] * 7 + [{"success": False}] * 3
        assert calculate_trust_score(history) == 0.7

    def test_missing_success_key(self):
        history = [{"other": "data"}, {"success": True}]
        assert calculate_trust_score(history) == 0.5


class TestEvaluatePhaseTransition:
    def test_manual_to_supervised_at_threshold(self):
        profile = TrustProfile(
            customer_id="c",
            trust_phase=TrustPhase.MANUAL,
            total_recommendations=20,
        )
        assert evaluate_phase_transition(profile, 0.85) == TrustPhase.SUPERVISED

    def test_manual_to_supervised_below_score(self):
        profile = TrustProfile(
            customer_id="c",
            trust_phase=TrustPhase.MANUAL,
            total_recommendations=20,
        )
        assert evaluate_phase_transition(profile, 0.84) is None

    def test_manual_to_supervised_below_recommendations(self):
        profile = TrustProfile(
            customer_id="c",
            trust_phase=TrustPhase.MANUAL,
            total_recommendations=19,
        )
        assert evaluate_phase_transition(profile, 0.85) is None

    def test_supervised_to_autonomous_at_threshold(self):
        profile = TrustProfile(
            customer_id="c",
            trust_phase=TrustPhase.SUPERVISED,
            total_recommendations=50,
        )
        assert evaluate_phase_transition(profile, 0.92) == TrustPhase.AUTONOMOUS

    def test_supervised_to_autonomous_below_score(self):
        profile = TrustProfile(
            customer_id="c",
            trust_phase=TrustPhase.SUPERVISED,
            total_recommendations=50,
        )
        assert evaluate_phase_transition(profile, 0.91) is None

    def test_supervised_to_autonomous_below_recommendations(self):
        profile = TrustProfile(
            customer_id="c",
            trust_phase=TrustPhase.SUPERVISED,
            total_recommendations=49,
        )
        assert evaluate_phase_transition(profile, 0.92) is None

    def test_autonomous_to_full_autonomy_at_threshold(self):
        profile = TrustProfile(
            customer_id="c",
            trust_phase=TrustPhase.AUTONOMOUS,
            total_recommendations=100,
        )
        assert evaluate_phase_transition(profile, 0.97) == TrustPhase.FULL_AUTONOMY

    def test_autonomous_to_full_autonomy_below_score(self):
        profile = TrustProfile(
            customer_id="c",
            trust_phase=TrustPhase.AUTONOMOUS,
            total_recommendations=100,
        )
        assert evaluate_phase_transition(profile, 0.96) is None

    def test_autonomous_to_full_autonomy_below_recommendations(self):
        profile = TrustProfile(
            customer_id="c",
            trust_phase=TrustPhase.AUTONOMOUS,
            total_recommendations=99,
        )
        assert evaluate_phase_transition(profile, 0.97) is None

    def test_full_autonomy_no_transition(self):
        profile = TrustProfile(
            customer_id="c",
            trust_phase=TrustPhase.FULL_AUTONOMY,
            total_recommendations=200,
        )
        assert evaluate_phase_transition(profile, 1.0) is None


def _make_policy(**overrides) -> AutoApprovalPolicy:
    defaults = {
        "policy_id": "pol-1",
        "customer_id": "cust-1",
        "action_class": ActionClass.PATCH_DEPLOYMENT,
        "status": PolicyStatus.ACTIVE,
        "max_severity": "MEDIUM",
        "conditions": ApprovalConditions(),
    }
    defaults.update(overrides)
    return AutoApprovalPolicy(**defaults)


def _make_recommendation(**overrides) -> dict:
    defaults = {
        "action_class": "patch_deployment",
        "severity": "LOW",
        "confidence_score": 0.9,
        "qa_passed": True,
        "rollback_available": True,
        "estimated_risk": "LOW",
        "affected_asset_classes": [],
    }
    defaults.update(overrides)
    return defaults


class TestCheckAutoApproval:
    def test_matching_policy(self):
        policy = _make_policy()
        rec = _make_recommendation()
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is True
        assert result.auto_approved is True
        assert result.policy_id == "pol-1"

    def test_expired_policy(self):
        policy = _make_policy(expires_utc=datetime(2026, 1, 1))
        rec = _make_recommendation()
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is False
        assert result.auto_approved is False

    def test_wrong_action_class(self):
        policy = _make_policy(action_class=ActionClass.ROLLBACK)
        rec = _make_recommendation(action_class="patch_deployment")
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is False
        assert result.auto_approved is False

    def test_severity_too_high(self):
        policy = _make_policy(max_severity="LOW")
        rec = _make_recommendation(severity="HIGH")
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is False
        assert result.auto_approved is False

    def test_confidence_too_low(self):
        policy = _make_policy(
            conditions=ApprovalConditions(min_confidence_score=0.95),
        )
        rec = _make_recommendation(confidence_score=0.9)
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is False
        assert result.auto_approved is False

    def test_qa_not_passed(self):
        policy = _make_policy()
        rec = _make_recommendation(qa_passed=False)
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is False
        assert result.auto_approved is False

    def test_rollback_not_available(self):
        policy = _make_policy()
        rec = _make_recommendation(rollback_available=False)
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is False
        assert result.auto_approved is False

    def test_risk_too_high(self):
        policy = _make_policy(
            conditions=ApprovalConditions(max_estimated_risk="LOW"),
        )
        rec = _make_recommendation(estimated_risk="HIGH")
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is False
        assert result.auto_approved is False

    def test_time_window_mismatch(self):
        policy = _make_policy(
            conditions=ApprovalConditions(
                time_window_start=time(9, 0),
                time_window_end=time(17, 0),
            ),
        )
        rec = _make_recommendation()
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 20, 0))
        assert result.policy_matched is False
        assert result.auto_approved is False

    def test_time_window_match(self):
        policy = _make_policy(
            conditions=ApprovalConditions(
                time_window_start=time(9, 0),
                time_window_end=time(17, 0),
            ),
        )
        rec = _make_recommendation()
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is True
        assert result.auto_approved is True

    def test_excluded_asset_class(self):
        policy = _make_policy(
            conditions=ApprovalConditions(excluded_asset_classes=["database"]),
        )
        rec = _make_recommendation(affected_asset_classes=["database", "web"])
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is False
        assert result.auto_approved is False

    def test_no_policies(self):
        rec = _make_recommendation()
        result = check_auto_approval(rec, [], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is False
        assert result.auto_approved is False
        assert result.reason == "No matching active policy found"

    def test_revoked_policy_skipped(self):
        policy = _make_policy(status=PolicyStatus.REVOKED)
        rec = _make_recommendation()
        result = check_auto_approval(rec, [policy], datetime(2026, 6, 15, 12, 0))
        assert result.policy_matched is False
        assert result.auto_approved is False
