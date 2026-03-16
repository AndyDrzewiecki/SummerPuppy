from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from summer_puppy.events.models import (
    ActionOutcome,
    ActionRequest,
    ApprovalMethod,
    DryRunResult,
    EventSource,
    EventStatus,
    ExecutionResult,
    ExecutorStatus,
    PredictiveAlert,
    PredictiveAlertType,
    QAStatus,
    Recommendation,
    RollbackRecord,
    SecurityEvent,
    Severity,
)
from summer_puppy.trust.models import (
    ActionClass,
    ApprovalConditions,
    AutoApprovalPolicy,
    PolicyStatus,
)
from summer_puppy.trust.scoring import check_auto_approval

# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_enum_values(self) -> None:
        assert Severity.LOW == "LOW"
        assert Severity.MEDIUM == "MEDIUM"
        assert Severity.HIGH == "HIGH"
        assert Severity.CRITICAL == "CRITICAL"

    def test_member_count(self) -> None:
        assert len(Severity) == 4


class TestEventSource:
    def test_enum_values(self) -> None:
        assert EventSource.SIEM == "SIEM"
        assert EventSource.EDR == "EDR"
        assert EventSource.NDR == "NDR"
        assert EventSource.VULNERABILITY_SCANNER == "VULNERABILITY_SCANNER"
        assert EventSource.THREAT_INTEL == "THREAT_INTEL"
        assert EventSource.MANUAL == "MANUAL"
        assert EventSource.AGENT == "AGENT"

    def test_member_count(self) -> None:
        assert len(EventSource) == 7


class TestEventStatus:
    def test_enum_values(self) -> None:
        assert EventStatus.NEW == "NEW"
        assert EventStatus.TRIAGED == "TRIAGED"
        assert EventStatus.ANALYZING == "ANALYZING"
        assert EventStatus.RECOMMENDATION_PENDING == "RECOMMENDATION_PENDING"
        assert EventStatus.ACTION_PENDING == "ACTION_PENDING"
        assert EventStatus.EXECUTING == "EXECUTING"
        assert EventStatus.COMPLETED == "COMPLETED"
        assert EventStatus.CLOSED == "CLOSED"

    def test_member_count(self) -> None:
        assert len(EventStatus) == 8


class TestQAStatus:
    def test_enum_values(self) -> None:
        assert QAStatus.PENDING == "PENDING"
        assert QAStatus.PASSED == "PASSED"
        assert QAStatus.FAILED == "FAILED"
        assert QAStatus.SKIPPED == "SKIPPED"

    def test_member_count(self) -> None:
        assert len(QAStatus) == 4


class TestApprovalMethod:
    def test_enum_values(self) -> None:
        assert ApprovalMethod.AUTO_APPROVED == "AUTO_APPROVED"
        assert ApprovalMethod.HUMAN_APPROVED == "HUMAN_APPROVED"
        assert ApprovalMethod.MANUAL_OVERRIDE == "MANUAL_OVERRIDE"

    def test_member_count(self) -> None:
        assert len(ApprovalMethod) == 3


# ---------------------------------------------------------------------------
# SecurityEvent tests
# ---------------------------------------------------------------------------


class TestSecurityEvent:
    def test_minimal_creation(self) -> None:
        event = SecurityEvent(
            customer_id="cust-1",
            source=EventSource.SIEM,
            severity=Severity.HIGH,
            title="Suspicious login",
            description="Multiple failed attempts",
        )
        assert event.customer_id == "cust-1"
        assert event.source == EventSource.SIEM
        assert event.severity == Severity.HIGH
        assert event.title == "Suspicious login"
        assert event.description == "Multiple failed attempts"
        # defaults
        assert event.event_id  # auto-generated uuid
        assert event.raw_payload == {}
        assert isinstance(event.detected_utc, datetime)
        assert event.status == EventStatus.NEW
        assert event.affected_assets == []
        assert event.tags == []
        assert event.correlation_id is None

    def test_all_fields_populated(self) -> None:
        now = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)
        event = SecurityEvent(
            event_id="evt-custom",
            customer_id="cust-2",
            source=EventSource.EDR,
            severity=Severity.CRITICAL,
            title="Ransomware detected",
            description="CryptoLocker variant found",
            raw_payload={"hash": "abc123", "path": "/tmp/evil.exe"},
            detected_utc=now,
            status=EventStatus.ANALYZING,
            affected_assets=["server-01", "server-02"],
            tags=["ransomware", "critical"],
            correlation_id="corr-42",
        )
        assert event.event_id == "evt-custom"
        assert event.source == EventSource.EDR
        assert event.raw_payload == {"hash": "abc123", "path": "/tmp/evil.exe"}
        assert event.detected_utc == now
        assert event.status == EventStatus.ANALYZING
        assert event.affected_assets == ["server-01", "server-02"]
        assert event.tags == ["ransomware", "critical"]
        assert event.correlation_id == "corr-42"

    def test_unique_event_ids(self) -> None:
        e1 = SecurityEvent(
            customer_id="c",
            source=EventSource.MANUAL,
            severity=Severity.LOW,
            title="t",
            description="d",
        )
        e2 = SecurityEvent(
            customer_id="c",
            source=EventSource.MANUAL,
            severity=Severity.LOW,
            title="t",
            description="d",
        )
        assert e1.event_id != e2.event_id

    def test_serialization_round_trip(self) -> None:
        event = SecurityEvent(
            customer_id="cust-1",
            source=EventSource.NDR,
            severity=Severity.MEDIUM,
            title="Network anomaly",
            description="Unusual outbound traffic",
        )
        data = event.model_dump()
        restored = SecurityEvent.model_validate(data)
        assert restored.event_id == event.event_id
        assert restored.customer_id == event.customer_id
        assert restored.source == event.source
        assert restored.severity == event.severity


# ---------------------------------------------------------------------------
# Recommendation tests
# ---------------------------------------------------------------------------


class TestRecommendation:
    def test_minimal_creation(self) -> None:
        rec = Recommendation(
            event_id="evt-1",
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            description="Apply patch KB123",
            reasoning="Vulnerability CVE-2026-001 is actively exploited",
            confidence_score=0.92,
            estimated_risk=Severity.LOW,
        )
        assert rec.event_id == "evt-1"
        assert rec.customer_id == "cust-1"
        assert rec.action_class == ActionClass.PATCH_DEPLOYMENT
        assert rec.description == "Apply patch KB123"
        assert rec.reasoning == "Vulnerability CVE-2026-001 is actively exploited"
        assert rec.confidence_score == 0.92
        assert rec.estimated_risk == Severity.LOW
        # defaults
        assert rec.recommendation_id  # auto-generated uuid
        assert rec.affected_asset_classes == []
        assert rec.rollback_plan is None
        assert rec.qa_status == QAStatus.PENDING
        assert isinstance(rec.created_utc, datetime)

    def test_all_fields_populated(self) -> None:
        now = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)
        rec = Recommendation(
            recommendation_id="rec-custom",
            event_id="evt-2",
            customer_id="cust-2",
            action_class=ActionClass.NETWORK_ISOLATION,
            description="Isolate compromised host",
            reasoning="Host is communicating with known C2 server",
            confidence_score=0.85,
            estimated_risk=Severity.HIGH,
            affected_asset_classes=["server", "network"],
            rollback_plan="Re-enable network access via firewall rule X",
            qa_status=QAStatus.PASSED,
            created_utc=now,
        )
        assert rec.recommendation_id == "rec-custom"
        assert rec.affected_asset_classes == ["server", "network"]
        assert rec.rollback_plan == "Re-enable network access via firewall rule X"
        assert rec.qa_status == QAStatus.PASSED
        assert rec.created_utc == now

    def test_confidence_score_too_high(self) -> None:
        with pytest.raises(ValidationError):
            Recommendation(
                event_id="e",
                customer_id="c",
                action_class=ActionClass.ROLLBACK,
                description="d",
                reasoning="r",
                confidence_score=1.1,
                estimated_risk=Severity.LOW,
            )

    def test_confidence_score_too_low(self) -> None:
        with pytest.raises(ValidationError):
            Recommendation(
                event_id="e",
                customer_id="c",
                action_class=ActionClass.ROLLBACK,
                description="d",
                reasoning="r",
                confidence_score=-0.1,
                estimated_risk=Severity.LOW,
            )

    def test_confidence_score_boundary_zero(self) -> None:
        rec = Recommendation(
            event_id="e",
            customer_id="c",
            action_class=ActionClass.ROLLBACK,
            description="d",
            reasoning="r",
            confidence_score=0.0,
            estimated_risk=Severity.LOW,
        )
        assert rec.confidence_score == 0.0

    def test_confidence_score_boundary_one(self) -> None:
        rec = Recommendation(
            event_id="e",
            customer_id="c",
            action_class=ActionClass.ROLLBACK,
            description="d",
            reasoning="r",
            confidence_score=1.0,
            estimated_risk=Severity.LOW,
        )
        assert rec.confidence_score == 1.0

    def test_unique_recommendation_ids(self) -> None:
        kwargs: dict[str, Any] = {
            "event_id": "e",
            "customer_id": "c",
            "action_class": ActionClass.ROLLBACK,
            "description": "d",
            "reasoning": "r",
            "confidence_score": 0.5,
            "estimated_risk": Severity.LOW,
        }
        r1 = Recommendation(**kwargs)
        r2 = Recommendation(**kwargs)
        assert r1.recommendation_id != r2.recommendation_id

    def test_serialization_round_trip(self) -> None:
        rec = Recommendation(
            event_id="evt-1",
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            description="desc",
            reasoning="reason",
            confidence_score=0.9,
            estimated_risk=Severity.MEDIUM,
        )
        data = rec.model_dump()
        restored = Recommendation.model_validate(data)
        assert restored.recommendation_id == rec.recommendation_id
        assert restored.confidence_score == rec.confidence_score

    # --- to_approval_dict tests ---

    def test_to_approval_dict_qa_passed_with_rollback(self) -> None:
        rec = Recommendation(
            event_id="evt-1",
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            description="Apply patch",
            reasoning="reason",
            confidence_score=0.92,
            estimated_risk=Severity.LOW,
            qa_status=QAStatus.PASSED,
            rollback_plan="Uninstall patch",
            affected_asset_classes=["server"],
        )
        d = rec.to_approval_dict()
        assert d["action_class"] == "patch_deployment"
        assert d["severity"] == "LOW"
        assert d["confidence_score"] == 0.92
        assert d["qa_passed"] is True
        assert d["rollback_available"] is True
        assert d["estimated_risk"] == "LOW"
        assert d["asset_classes"] == ["server"]

    def test_to_approval_dict_qa_pending_no_rollback(self) -> None:
        rec = Recommendation(
            event_id="evt-1",
            customer_id="cust-1",
            action_class=ActionClass.NETWORK_ISOLATION,
            description="Isolate host",
            reasoning="reason",
            confidence_score=0.5,
            estimated_risk=Severity.HIGH,
            qa_status=QAStatus.PENDING,
            rollback_plan=None,
        )
        d = rec.to_approval_dict()
        assert d["action_class"] == "network_isolation"
        assert d["severity"] == "HIGH"
        assert d["confidence_score"] == 0.5
        assert d["qa_passed"] is False
        assert d["rollback_available"] is False
        assert d["estimated_risk"] == "HIGH"
        assert d["asset_classes"] == []

    def test_to_approval_dict_qa_failed(self) -> None:
        rec = Recommendation(
            event_id="evt-1",
            customer_id="cust-1",
            action_class=ActionClass.ROLLBACK,
            description="d",
            reasoning="r",
            confidence_score=0.8,
            estimated_risk=Severity.MEDIUM,
            qa_status=QAStatus.FAILED,
            rollback_plan="plan",
        )
        d = rec.to_approval_dict()
        assert d["qa_passed"] is False
        assert d["rollback_available"] is True

    def test_to_approval_dict_works_with_check_auto_approval(self) -> None:
        """Verify that to_approval_dict() output is compatible with check_auto_approval."""
        rec = Recommendation(
            event_id="evt-1",
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            description="Apply patch",
            reasoning="reason",
            confidence_score=0.92,
            estimated_risk=Severity.LOW,
            qa_status=QAStatus.PASSED,
            rollback_plan="Uninstall patch",
            affected_asset_classes=[],
        )
        policy = AutoApprovalPolicy(
            policy_id="pol-1",
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            status=PolicyStatus.ACTIVE,
            max_severity="MEDIUM",
            conditions=ApprovalConditions(),
        )
        result = check_auto_approval(
            rec.to_approval_dict(),
            [policy],
            datetime(2026, 6, 15, 12, 0),
        )
        assert result.policy_matched is True
        assert result.auto_approved is True

    def test_to_approval_dict_rejected_by_check_auto_approval(self) -> None:
        """Verify that a low-confidence recommendation is rejected."""
        rec = Recommendation(
            event_id="evt-1",
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            description="Apply patch",
            reasoning="reason",
            confidence_score=0.5,
            estimated_risk=Severity.LOW,
            qa_status=QAStatus.PENDING,
            rollback_plan=None,
        )
        policy = AutoApprovalPolicy(
            policy_id="pol-1",
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            status=PolicyStatus.ACTIVE,
            max_severity="MEDIUM",
            conditions=ApprovalConditions(),
        )
        result = check_auto_approval(
            rec.to_approval_dict(),
            [policy],
            datetime(2026, 6, 15, 12, 0),
        )
        assert result.policy_matched is False
        assert result.auto_approved is False


# ---------------------------------------------------------------------------
# ActionRequest tests
# ---------------------------------------------------------------------------


class TestActionRequest:
    def test_minimal_creation(self) -> None:
        req = ActionRequest(
            recommendation_id="rec-1",
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            approval_method=ApprovalMethod.AUTO_APPROVED,
            approved_by="system",
        )
        assert req.recommendation_id == "rec-1"
        assert req.customer_id == "cust-1"
        assert req.action_class == ActionClass.PATCH_DEPLOYMENT
        assert req.approval_method == ApprovalMethod.AUTO_APPROVED
        assert req.approved_by == "system"
        # defaults
        assert req.request_id  # auto-generated uuid
        assert isinstance(req.approved_utc, datetime)
        assert req.parameters == {}
        assert req.expires_utc is None

    def test_all_fields_populated(self) -> None:
        now = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)
        expires = datetime(2026, 3, 16, 12, 0, 0, tzinfo=UTC)
        req = ActionRequest(
            request_id="req-custom",
            recommendation_id="rec-2",
            customer_id="cust-2",
            action_class=ActionClass.ACCOUNT_LOCKOUT,
            approval_method=ApprovalMethod.HUMAN_APPROVED,
            approved_by="admin@example.com",
            approved_utc=now,
            parameters={"username": "jdoe", "duration_hours": 24},
            expires_utc=expires,
        )
        assert req.request_id == "req-custom"
        assert req.approval_method == ApprovalMethod.HUMAN_APPROVED
        assert req.approved_by == "admin@example.com"
        assert req.approved_utc == now
        assert req.parameters == {"username": "jdoe", "duration_hours": 24}
        assert req.expires_utc == expires

    def test_unique_request_ids(self) -> None:
        kwargs: dict[str, Any] = {
            "recommendation_id": "rec-1",
            "customer_id": "c",
            "action_class": ActionClass.ROLLBACK,
            "approval_method": ApprovalMethod.MANUAL_OVERRIDE,
            "approved_by": "admin",
        }
        r1 = ActionRequest(**kwargs)
        r2 = ActionRequest(**kwargs)
        assert r1.request_id != r2.request_id

    def test_serialization_round_trip(self) -> None:
        req = ActionRequest(
            recommendation_id="rec-1",
            customer_id="cust-1",
            action_class=ActionClass.PROCESS_TERMINATION,
            approval_method=ApprovalMethod.AUTO_APPROVED,
            approved_by="system",
        )
        data = req.model_dump()
        restored = ActionRequest.model_validate(data)
        assert restored.request_id == req.request_id
        assert restored.action_class == req.action_class


# ---------------------------------------------------------------------------
# ActionOutcome tests
# ---------------------------------------------------------------------------


class TestActionOutcome:
    def test_minimal_creation(self) -> None:
        outcome = ActionOutcome(
            request_id="req-1",
            customer_id="cust-1",
            success=True,
            result_summary="Patch applied successfully",
        )
        assert outcome.request_id == "req-1"
        assert outcome.customer_id == "cust-1"
        assert outcome.success is True
        assert outcome.result_summary == "Patch applied successfully"
        # defaults
        assert outcome.outcome_id  # auto-generated uuid
        assert isinstance(outcome.started_utc, datetime)
        assert outcome.completed_utc is None
        assert outcome.error_detail is None
        assert outcome.rollback_triggered is False
        assert outcome.metrics == {}

    def test_all_fields_populated(self) -> None:
        started = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)
        completed = datetime(2026, 3, 15, 12, 5, 0, tzinfo=UTC)
        outcome = ActionOutcome(
            outcome_id="out-custom",
            request_id="req-2",
            customer_id="cust-2",
            success=False,
            started_utc=started,
            completed_utc=completed,
            result_summary="Patch failed to apply",
            error_detail="Permission denied on /etc/config",
            rollback_triggered=True,
            metrics={"duration_seconds": 300, "retries": 2},
        )
        assert outcome.outcome_id == "out-custom"
        assert outcome.success is False
        assert outcome.started_utc == started
        assert outcome.completed_utc == completed
        assert outcome.error_detail == "Permission denied on /etc/config"
        assert outcome.rollback_triggered is True
        assert outcome.metrics == {"duration_seconds": 300, "retries": 2}

    def test_unique_outcome_ids(self) -> None:
        kwargs: dict[str, Any] = {
            "request_id": "req-1",
            "customer_id": "c",
            "success": True,
            "result_summary": "ok",
        }
        o1 = ActionOutcome(**kwargs)
        o2 = ActionOutcome(**kwargs)
        assert o1.outcome_id != o2.outcome_id

    def test_serialization_round_trip(self) -> None:
        outcome = ActionOutcome(
            request_id="req-1",
            customer_id="cust-1",
            success=True,
            result_summary="Done",
        )
        data = outcome.model_dump()
        restored = ActionOutcome.model_validate(data)
        assert restored.outcome_id == outcome.outcome_id
        assert restored.success == outcome.success
        assert restored.result_summary == outcome.result_summary


# ---------------------------------------------------------------------------
# ExecutorStatus tests
# ---------------------------------------------------------------------------


class TestExecutorStatus:
    def test_enum_values(self) -> None:
        assert ExecutorStatus.PENDING == "PENDING"
        assert ExecutorStatus.DRY_RUN_PASSED == "DRY_RUN_PASSED"
        assert ExecutorStatus.DRY_RUN_FAILED == "DRY_RUN_FAILED"
        assert ExecutorStatus.EXECUTING == "EXECUTING"
        assert ExecutorStatus.COMPLETED == "COMPLETED"
        assert ExecutorStatus.FAILED == "FAILED"
        assert ExecutorStatus.ROLLED_BACK == "ROLLED_BACK"

    def test_member_count(self) -> None:
        assert len(ExecutorStatus) == 7


# ---------------------------------------------------------------------------
# PredictiveAlertType tests
# ---------------------------------------------------------------------------


class TestPredictiveAlertType:
    def test_enum_values(self) -> None:
        assert PredictiveAlertType.UNPATCHED_ASSET == "UNPATCHED_ASSET"
        assert PredictiveAlertType.PRE_BREACH_PATTERN == "PRE_BREACH_PATTERN"
        assert PredictiveAlertType.STALE_DETECTION_RULE == "STALE_DETECTION_RULE"

    def test_member_count(self) -> None:
        assert len(PredictiveAlertType) == 3


# ---------------------------------------------------------------------------
# DryRunResult tests
# ---------------------------------------------------------------------------


class TestDryRunResult:
    def test_minimal_creation(self) -> None:
        result = DryRunResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            is_safe=True,
            reason="All preconditions met",
        )
        assert result.action_class == ActionClass.BLOCK_IP
        assert result.customer_id == "cust-1"
        assert result.is_safe is True
        assert result.reason == "All preconditions met"
        assert result.validated_parameters == {}
        assert isinstance(result.checked_utc, datetime)

    def test_all_fields(self) -> None:
        now = datetime(2026, 3, 16, 12, 0, 0, tzinfo=UTC)
        result = DryRunResult(
            action_class=ActionClass.DISABLE_ACCOUNT,
            customer_id="cust-2",
            is_safe=False,
            reason="Missing account_id",
            validated_parameters={"account_id": "acc-1"},
            checked_utc=now,
        )
        assert result.action_class == ActionClass.DISABLE_ACCOUNT
        assert result.customer_id == "cust-2"
        assert result.is_safe is False
        assert result.validated_parameters == {"account_id": "acc-1"}
        assert result.checked_utc == now

    def test_serialization_round_trip(self) -> None:
        result = DryRunResult(
            action_class=ActionClass.UPDATE_FIREWALL_RULE,
            customer_id="cust-1",
            is_safe=True,
            reason="ok",
        )
        data = result.model_dump()
        restored = DryRunResult.model_validate(data)
        assert restored.action_class == result.action_class
        assert restored.is_safe == result.is_safe


# ---------------------------------------------------------------------------
# ExecutionResult tests
# ---------------------------------------------------------------------------


class TestExecutionResult:
    def test_minimal_creation(self) -> None:
        result = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
        )
        assert result.action_class == ActionClass.BLOCK_IP
        assert result.customer_id == "cust-1"
        assert result.status == ExecutorStatus.COMPLETED
        assert result.execution_id  # auto-generated uuid
        assert result.parameters_applied == {}
        assert result.rollback_parameters == {}
        assert isinstance(result.started_utc, datetime)
        assert result.completed_utc is None
        assert result.error_detail is None

    def test_unique_ids(self) -> None:
        r1 = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
        )
        r2 = ExecutionResult(
            action_class=ActionClass.BLOCK_IP,
            customer_id="cust-1",
            status=ExecutorStatus.COMPLETED,
        )
        assert r1.execution_id != r2.execution_id

    def test_serialization_round_trip(self) -> None:
        result = ExecutionResult(
            action_class=ActionClass.DISABLE_ACCOUNT,
            customer_id="cust-1",
            status=ExecutorStatus.FAILED,
            error_detail="Something went wrong",
            parameters_applied={"account_id": "acc-1"},
        )
        data = result.model_dump()
        restored = ExecutionResult.model_validate(data)
        assert restored.execution_id == result.execution_id
        assert restored.status == result.status
        assert restored.error_detail == result.error_detail


# ---------------------------------------------------------------------------
# RollbackRecord tests
# ---------------------------------------------------------------------------


class TestRollbackRecord:
    def test_minimal_creation(self) -> None:
        record = RollbackRecord(
            execution_id="exec-1",
            customer_id="cust-1",
            action_class=ActionClass.BLOCK_IP,
            reason="Rollback requested",
            success=True,
        )
        assert record.execution_id == "exec-1"
        assert record.customer_id == "cust-1"
        assert record.action_class == ActionClass.BLOCK_IP
        assert record.reason == "Rollback requested"
        assert record.success is True
        assert record.rollback_id  # auto-generated uuid
        assert isinstance(record.rollback_utc, datetime)
        assert record.error_detail is None

    def test_all_fields(self) -> None:
        now = datetime(2026, 3, 16, 12, 0, 0, tzinfo=UTC)
        record = RollbackRecord(
            rollback_id="rb-custom",
            execution_id="exec-2",
            customer_id="cust-2",
            action_class=ActionClass.DISABLE_ACCOUNT,
            reason="Error detected",
            rollback_utc=now,
            success=False,
            error_detail="Rollback failed: timeout",
        )
        assert record.rollback_id == "rb-custom"
        assert record.rollback_utc == now
        assert record.success is False
        assert record.error_detail == "Rollback failed: timeout"

    def test_serialization_round_trip(self) -> None:
        record = RollbackRecord(
            execution_id="exec-1",
            customer_id="cust-1",
            action_class=ActionClass.UPDATE_FIREWALL_RULE,
            reason="test",
            success=True,
        )
        data = record.model_dump()
        restored = RollbackRecord.model_validate(data)
        assert restored.rollback_id == record.rollback_id
        assert restored.success == record.success


# ---------------------------------------------------------------------------
# PredictiveAlert tests
# ---------------------------------------------------------------------------


class TestPredictiveAlert:
    def test_minimal_creation(self) -> None:
        alert = PredictiveAlert(
            customer_id="cust-1",
            alert_type=PredictiveAlertType.UNPATCHED_ASSET,
            risk_score=0.8,
            reasoning="High risk detected",
        )
        assert alert.customer_id == "cust-1"
        assert alert.alert_type == PredictiveAlertType.UNPATCHED_ASSET
        assert alert.risk_score == 0.8
        assert alert.reasoning == "High risk detected"
        assert alert.alert_id  # auto-generated uuid
        assert alert.affected_assets == []
        assert alert.cve_ids == []
        assert alert.recommended_action_class is None
        assert isinstance(alert.generated_utc, datetime)
        assert alert.correlation_id is None

    def test_risk_score_validation_too_high(self) -> None:
        with pytest.raises(ValidationError):
            PredictiveAlert(
                customer_id="cust-1",
                alert_type=PredictiveAlertType.UNPATCHED_ASSET,
                risk_score=1.1,
                reasoning="r",
            )

    def test_risk_score_validation_too_low(self) -> None:
        with pytest.raises(ValidationError):
            PredictiveAlert(
                customer_id="cust-1",
                alert_type=PredictiveAlertType.UNPATCHED_ASSET,
                risk_score=-0.1,
                reasoning="r",
            )

    def test_risk_score_boundary_zero(self) -> None:
        alert = PredictiveAlert(
            customer_id="cust-1",
            alert_type=PredictiveAlertType.PRE_BREACH_PATTERN,
            risk_score=0.0,
            reasoning="r",
        )
        assert alert.risk_score == 0.0

    def test_risk_score_boundary_one(self) -> None:
        alert = PredictiveAlert(
            customer_id="cust-1",
            alert_type=PredictiveAlertType.STALE_DETECTION_RULE,
            risk_score=1.0,
            reasoning="r",
        )
        assert alert.risk_score == 1.0

    def test_serialization_round_trip(self) -> None:
        alert = PredictiveAlert(
            customer_id="cust-1",
            alert_type=PredictiveAlertType.UNPATCHED_ASSET,
            affected_assets=["server-01"],
            cve_ids=["CVE-2026-001"],
            risk_score=0.9,
            reasoning="Unpatched vulnerability",
            recommended_action_class=ActionClass.PATCH_DEPLOYMENT,
            correlation_id="corr-1",
        )
        data = alert.model_dump()
        restored = PredictiveAlert.model_validate(data)
        assert restored.alert_id == alert.alert_id
        assert restored.risk_score == alert.risk_score
        assert restored.recommended_action_class == alert.recommended_action_class
