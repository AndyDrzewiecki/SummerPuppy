from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class WorkItemType(StrEnum):
    THREAT_REPORT = "THREAT_REPORT"
    PATCH_REQUEST = "PATCH_REQUEST"
    DETECTION_RULE = "DETECTION_RULE"
    INCIDENT_REPORT = "INCIDENT_REPORT"
    VULNERABILITY_ASSESSMENT = "VULNERABILITY_ASSESSMENT"
    SECURITY_ADVISORY = "SECURITY_ADVISORY"


class WorkItemStatus(StrEnum):
    DRAFT = "DRAFT"
    SUBMITTED = "SUBMITTED"
    ACCEPTED = "ACCEPTED"
    IN_PROGRESS = "IN_PROGRESS"
    REVIEW = "REVIEW"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"


class WorkItemPriority(StrEnum):
    P0_CRITICAL = "P0_CRITICAL"
    P1_HIGH = "P1_HIGH"
    P2_MEDIUM = "P2_MEDIUM"
    P3_LOW = "P3_LOW"


class ArtifactType(StrEnum):
    CODE_PATCH = "CODE_PATCH"
    DETECTION_RULE = "DETECTION_RULE"
    THREAT_REPORT = "THREAT_REPORT"
    INCIDENT_REPORT = "INCIDENT_REPORT"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    RUNBOOK = "RUNBOOK"


class ValidationStatus(StrEnum):
    PENDING = "PENDING"
    VALIDATED = "VALIDATED"
    FAILED = "FAILED"


class DecisionType(StrEnum):
    CREATED = "CREATED"
    PRIORITIZED = "PRIORITIZED"
    ASSIGNED = "ASSIGNED"
    ESCALATED = "ESCALATED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    COMPLETED = "COMPLETED"


class Reasoning(BaseModel):
    evidence: list[str] = Field(default_factory=list)
    alternatives_considered: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1, default=0.5)


class Decision(BaseModel):
    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    work_item_id: str
    pool_id: str
    agent_id: str
    decision_type: DecisionType
    reasoning: Reasoning = Field(default_factory=Reasoning)
    outcome: str = ""
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class Artifact(BaseModel):
    artifact_id: str = Field(default_factory=lambda: str(uuid4()))
    work_item_id: str
    artifact_type: ArtifactType
    content: str = ""
    format: str = "text"
    validation_status: ValidationStatus = ValidationStatus.PENDING
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class WorkItem(BaseModel):
    work_item_id: str = Field(default_factory=lambda: str(uuid4()))
    parent_id: str | None = None
    correlation_id: str | None = None
    item_type: WorkItemType
    status: WorkItemStatus = WorkItemStatus.DRAFT
    priority: WorkItemPriority = WorkItemPriority.P2_MEDIUM
    producer_pool: str = ""
    consumer_pool: str = ""
    title: str
    description: str = ""
    acceptance_criteria: list[str] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    decisions: list[Decision] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    updated_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    due_utc: datetime | None = None
