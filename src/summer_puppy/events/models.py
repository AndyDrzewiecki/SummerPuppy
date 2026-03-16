from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from summer_puppy.trust.models import ActionClass  # noqa: TC001


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventSource(StrEnum):
    SIEM = "SIEM"
    EDR = "EDR"
    NDR = "NDR"
    VULNERABILITY_SCANNER = "VULNERABILITY_SCANNER"
    THREAT_INTEL = "THREAT_INTEL"
    MANUAL = "MANUAL"
    AGENT = "AGENT"


class EventStatus(StrEnum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ANALYZING = "ANALYZING"
    RECOMMENDATION_PENDING = "RECOMMENDATION_PENDING"
    ACTION_PENDING = "ACTION_PENDING"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    CLOSED = "CLOSED"


class QAStatus(StrEnum):
    PENDING = "PENDING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class ApprovalMethod(StrEnum):
    AUTO_APPROVED = "AUTO_APPROVED"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    MANUAL_OVERRIDE = "MANUAL_OVERRIDE"


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str
    source: EventSource
    severity: Severity
    title: str
    description: str
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    detected_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    status: EventStatus = EventStatus.NEW
    affected_assets: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    correlation_id: str | None = None


class Recommendation(BaseModel):
    recommendation_id: str = Field(default_factory=lambda: str(uuid4()))
    event_id: str
    customer_id: str
    action_class: ActionClass
    description: str
    reasoning: str
    confidence_score: float = Field(ge=0, le=1)
    estimated_risk: Severity
    affected_asset_classes: list[str] = Field(default_factory=list)
    rollback_plan: str | None = None
    qa_status: QAStatus = QAStatus.PENDING
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))

    def to_approval_dict(self) -> dict[str, Any]:
        return {
            "action_class": str(self.action_class.value),
            "severity": str(self.estimated_risk.value),
            "confidence_score": self.confidence_score,
            "qa_passed": self.qa_status == QAStatus.PASSED,
            "rollback_available": self.rollback_plan is not None,
            "estimated_risk": str(self.estimated_risk.value),
            "asset_classes": list(self.affected_asset_classes),
        }


class ActionRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    recommendation_id: str
    customer_id: str
    action_class: ActionClass
    approval_method: ApprovalMethod
    approved_by: str
    approved_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    parameters: dict[str, Any] = Field(default_factory=dict)
    expires_utc: datetime | None = None


class AnalysisResult(BaseModel):
    threat_type: str
    attack_vector: str
    affected_systems: list[str] = Field(default_factory=list)
    ioc_indicators: list[str] = Field(default_factory=list)
    severity_assessment: Severity
    confidence: float = Field(ge=0, le=1)
    reasoning: str
    recommended_actions: list[str] = Field(default_factory=list)
    mitre_attack_ids: list[str] = Field(default_factory=list)


class ActionOutcome(BaseModel):
    outcome_id: str = Field(default_factory=lambda: str(uuid4()))
    request_id: str
    customer_id: str
    success: bool
    started_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    completed_utc: datetime | None = None
    result_summary: str
    error_detail: str | None = None
    rollback_triggered: bool = False
    metrics: dict[str, Any] = Field(default_factory=dict)


class ExecutorStatus(StrEnum):
    PENDING = "PENDING"
    DRY_RUN_PASSED = "DRY_RUN_PASSED"
    DRY_RUN_FAILED = "DRY_RUN_FAILED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class DryRunResult(BaseModel):
    action_class: ActionClass
    customer_id: str
    is_safe: bool
    reason: str
    validated_parameters: dict[str, Any] = Field(default_factory=dict)
    checked_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class ExecutionResult(BaseModel):
    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    action_class: ActionClass
    customer_id: str
    status: ExecutorStatus
    parameters_applied: dict[str, Any] = Field(default_factory=dict)
    rollback_parameters: dict[str, Any] = Field(default_factory=dict)
    started_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    completed_utc: datetime | None = None
    error_detail: str | None = None


class RollbackRecord(BaseModel):
    rollback_id: str = Field(default_factory=lambda: str(uuid4()))
    execution_id: str
    customer_id: str
    action_class: ActionClass
    reason: str
    rollback_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    success: bool
    error_detail: str | None = None


class PredictiveAlertType(StrEnum):
    UNPATCHED_ASSET = "UNPATCHED_ASSET"
    PRE_BREACH_PATTERN = "PRE_BREACH_PATTERN"
    STALE_DETECTION_RULE = "STALE_DETECTION_RULE"


class PredictiveAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str
    alert_type: PredictiveAlertType
    affected_assets: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    risk_score: float = Field(ge=0, le=1)
    reasoning: str
    recommended_action_class: ActionClass | None = None
    generated_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    correlation_id: str | None = None
