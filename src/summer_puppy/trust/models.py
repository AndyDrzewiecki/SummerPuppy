from __future__ import annotations

from datetime import datetime, time
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class TrustPhase(StrEnum):
    MANUAL = "manual"
    SUPERVISED = "supervised"
    AUTONOMOUS = "autonomous"
    FULL_AUTONOMY = "full_autonomy"


class ActionClass(StrEnum):
    PATCH_DEPLOYMENT = "patch_deployment"
    CONFIGURATION_CHANGE = "configuration_change"
    NETWORK_ISOLATION = "network_isolation"
    PROCESS_TERMINATION = "process_termination"
    ACCOUNT_LOCKOUT = "account_lockout"
    DETECTION_RULE_UPDATE = "detection_rule_update"
    COMPENSATING_CONTROL = "compensating_control"
    ROLLBACK = "rollback"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    UPDATE_FIREWALL_RULE = "update_firewall_rule"


class PolicyStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ApprovalConditions(BaseModel):
    time_window_start: time | None = None
    time_window_end: time | None = None
    min_confidence_score: float = Field(default=0.8, ge=0, le=1)
    require_qa_passed: bool = True
    require_rollback_available: bool = True
    max_estimated_risk: str = "MEDIUM"
    excluded_asset_classes: list[str] = Field(default_factory=list)


class AutoApprovalPolicy(BaseModel):
    policy_id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str
    action_class: ActionClass
    status: PolicyStatus = PolicyStatus.ACTIVE
    max_severity: str = "MEDIUM"
    conditions: ApprovalConditions = Field(default_factory=ApprovalConditions)
    created_utc: datetime = Field(default_factory=datetime.utcnow)
    expires_utc: datetime | None = None
    created_by: str = "system"


class PhaseTransition(BaseModel):
    from_phase: TrustPhase
    to_phase: TrustPhase
    transitioned_utc: datetime = Field(default_factory=datetime.utcnow)
    reason: str
    approved_by: str


class SevOneAutoTriageConfig(BaseModel):
    """Configuration for automatic SEV-1 (CRITICAL) incident response bypass.

    When enabled, CRITICAL-severity events bypass the human approval gate and execute
    the recommended containment action immediately. A notification is dispatched to
    operators after the action completes.
    """

    enabled: bool = False
    allowed_action_classes: list[ActionClass] = Field(
        default_factory=lambda: [
            ActionClass.NETWORK_ISOLATION,
            ActionClass.PROCESS_TERMINATION,
            ActionClass.ACCOUNT_LOCKOUT,
            ActionClass.BLOCK_IP,
            ActionClass.DISABLE_ACCOUNT,
        ]
    )
    require_rollback_plan: bool = True
    min_confidence_score: float = Field(default=0.7, ge=0, le=1)


class TrustProfile(BaseModel):
    customer_id: str
    trust_phase: TrustPhase = TrustPhase.MANUAL
    total_recommendations: int = 0
    total_approvals: int = 0
    total_rejections: int = 0
    positive_outcome_rate: float = Field(default=0.0, ge=0, le=1)
    last_evaluated_utc: datetime | None = None
    phase_transition_history: list[PhaseTransition] = Field(default_factory=list)
    sev_one_config: SevOneAutoTriageConfig = Field(default_factory=SevOneAutoTriageConfig)


class ApprovalCheckResult(BaseModel):
    policy_matched: bool
    policy_id: str | None = None
    auto_approved: bool
    reason: str
    checked_utc: datetime = Field(default_factory=datetime.utcnow)
