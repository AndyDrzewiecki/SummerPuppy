from datetime import datetime, time

import pytest
from pydantic import ValidationError

from summer_puppy.trust.models import (
    ActionClass,
    ApprovalCheckResult,
    ApprovalConditions,
    AutoApprovalPolicy,
    PhaseTransition,
    PolicyStatus,
    TrustPhase,
    TrustProfile,
)


class TestTrustPhase:
    def test_enum_values(self):
        assert TrustPhase.MANUAL == "manual"
        assert TrustPhase.SUPERVISED == "supervised"
        assert TrustPhase.AUTONOMOUS == "autonomous"
        assert TrustPhase.FULL_AUTONOMY == "full_autonomy"

    def test_all_members(self):
        assert len(TrustPhase) == 4


class TestActionClass:
    def test_enum_values(self):
        assert ActionClass.PATCH_DEPLOYMENT == "patch_deployment"
        assert ActionClass.CONFIGURATION_CHANGE == "configuration_change"
        assert ActionClass.NETWORK_ISOLATION == "network_isolation"
        assert ActionClass.PROCESS_TERMINATION == "process_termination"
        assert ActionClass.ACCOUNT_LOCKOUT == "account_lockout"
        assert ActionClass.DETECTION_RULE_UPDATE == "detection_rule_update"
        assert ActionClass.COMPENSATING_CONTROL == "compensating_control"
        assert ActionClass.ROLLBACK == "rollback"

    def test_all_members(self):
        assert len(ActionClass) == 8


class TestPolicyStatus:
    def test_enum_values(self):
        assert PolicyStatus.ACTIVE == "active"
        assert PolicyStatus.EXPIRED == "expired"
        assert PolicyStatus.REVOKED == "revoked"


class TestApprovalConditions:
    def test_defaults(self):
        cond = ApprovalConditions()
        assert cond.time_window_start is None
        assert cond.time_window_end is None
        assert cond.min_confidence_score == 0.8
        assert cond.require_qa_passed is True
        assert cond.require_rollback_available is True
        assert cond.max_estimated_risk == "MEDIUM"
        assert cond.excluded_asset_classes == []

    def test_custom_values(self):
        cond = ApprovalConditions(
            time_window_start=time(9, 0),
            time_window_end=time(17, 0),
            min_confidence_score=0.95,
            require_qa_passed=False,
            require_rollback_available=False,
            max_estimated_risk="LOW",
            excluded_asset_classes=["database", "firewall"],
        )
        assert cond.time_window_start == time(9, 0)
        assert cond.time_window_end == time(17, 0)
        assert cond.min_confidence_score == 0.95
        assert cond.require_qa_passed is False
        assert cond.excluded_asset_classes == ["database", "firewall"]

    def test_confidence_score_validation_too_high(self):
        with pytest.raises(ValidationError):
            ApprovalConditions(min_confidence_score=1.5)

    def test_confidence_score_validation_too_low(self):
        with pytest.raises(ValidationError):
            ApprovalConditions(min_confidence_score=-0.1)


class TestAutoApprovalPolicy:
    def test_minimal_creation(self):
        policy = AutoApprovalPolicy(
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
        )
        assert policy.customer_id == "cust-1"
        assert policy.action_class == ActionClass.PATCH_DEPLOYMENT
        assert policy.status == PolicyStatus.ACTIVE
        assert policy.max_severity == "MEDIUM"
        assert isinstance(policy.conditions, ApprovalConditions)
        assert policy.expires_utc is None
        assert policy.created_by == "system"
        assert policy.policy_id  # auto-generated uuid

    def test_with_expiry(self):
        expires = datetime(2026, 12, 31, 23, 59, 59)
        policy = AutoApprovalPolicy(
            customer_id="cust-2",
            action_class=ActionClass.ROLLBACK,
            expires_utc=expires,
        )
        assert policy.expires_utc == expires

    def test_custom_policy_id(self):
        policy = AutoApprovalPolicy(
            policy_id="custom-id",
            customer_id="cust-1",
            action_class=ActionClass.NETWORK_ISOLATION,
        )
        assert policy.policy_id == "custom-id"

    def test_unique_policy_ids(self):
        p1 = AutoApprovalPolicy(customer_id="c", action_class=ActionClass.ROLLBACK)
        p2 = AutoApprovalPolicy(customer_id="c", action_class=ActionClass.ROLLBACK)
        assert p1.policy_id != p2.policy_id


class TestPhaseTransition:
    def test_creation(self):
        pt = PhaseTransition(
            from_phase=TrustPhase.MANUAL,
            to_phase=TrustPhase.SUPERVISED,
            reason="Score threshold met",
            approved_by="admin",
        )
        assert pt.from_phase == TrustPhase.MANUAL
        assert pt.to_phase == TrustPhase.SUPERVISED
        assert pt.reason == "Score threshold met"
        assert pt.approved_by == "admin"
        assert isinstance(pt.transitioned_utc, datetime)


class TestTrustProfile:
    def test_defaults(self):
        profile = TrustProfile(customer_id="cust-1")
        assert profile.customer_id == "cust-1"
        assert profile.trust_phase == TrustPhase.MANUAL
        assert profile.total_recommendations == 0
        assert profile.total_approvals == 0
        assert profile.total_rejections == 0
        assert profile.positive_outcome_rate == 0.0
        assert profile.last_evaluated_utc is None
        assert profile.phase_transition_history == []

    def test_with_data(self):
        transition = PhaseTransition(
            from_phase=TrustPhase.MANUAL,
            to_phase=TrustPhase.SUPERVISED,
            reason="threshold",
            approved_by="admin",
        )
        profile = TrustProfile(
            customer_id="cust-2",
            trust_phase=TrustPhase.SUPERVISED,
            total_recommendations=50,
            total_approvals=45,
            total_rejections=5,
            positive_outcome_rate=0.9,
            last_evaluated_utc=datetime(2026, 1, 1),
            phase_transition_history=[transition],
        )
        assert profile.trust_phase == TrustPhase.SUPERVISED
        assert profile.total_recommendations == 50
        assert profile.positive_outcome_rate == 0.9
        assert len(profile.phase_transition_history) == 1

    def test_outcome_rate_validation(self):
        with pytest.raises(ValidationError):
            TrustProfile(customer_id="c", positive_outcome_rate=1.5)

        with pytest.raises(ValidationError):
            TrustProfile(customer_id="c", positive_outcome_rate=-0.1)


class TestApprovalCheckResult:
    def test_approved(self):
        result = ApprovalCheckResult(
            policy_matched=True,
            policy_id="pol-1",
            auto_approved=True,
            reason="Matched",
        )
        assert result.policy_matched is True
        assert result.policy_id == "pol-1"
        assert result.auto_approved is True
        assert isinstance(result.checked_utc, datetime)

    def test_not_approved(self):
        result = ApprovalCheckResult(
            policy_matched=False,
            auto_approved=False,
            reason="No match",
        )
        assert result.policy_matched is False
        assert result.policy_id is None
        assert result.auto_approved is False
