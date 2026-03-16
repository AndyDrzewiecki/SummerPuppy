"""Pipeline data models for security operations orchestration."""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from summer_puppy.events.models import (  # noqa: TC001
    ActionOutcome,
    ActionRequest,
    Recommendation,
    SecurityEvent,
)
from summer_puppy.trust.models import AutoApprovalPolicy, TrustProfile  # noqa: TC001


class PipelineStage(StrEnum):
    INTAKE = "INTAKE"
    TRIAGE = "TRIAGE"
    ANALYZE = "ANALYZE"
    RECOMMEND = "RECOMMEND"
    APPROVE = "APPROVE"
    EXECUTE = "EXECUTE"
    VERIFY = "VERIFY"
    CLOSE = "CLOSE"
    ERROR = "ERROR"


class PipelineStatus(StrEnum):
    RUNNING = "RUNNING"
    PAUSED_FOR_APPROVAL = "PAUSED_FOR_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class PipelineContext(BaseModel):
    context_id: str = Field(default_factory=lambda: str(uuid4()))
    event: SecurityEvent
    customer_id: str
    correlation_id: str
    current_stage: PipelineStage = PipelineStage.INTAKE
    status: PipelineStatus = PipelineStatus.RUNNING
    recommendation: Recommendation | None = None
    action_request: ActionRequest | None = None
    outcome: ActionOutcome | None = None
    trust_profile: TrustProfile
    policies: list[AutoApprovalPolicy] = Field(default_factory=list)
    audit_entry_ids: list[str] = Field(default_factory=list)
    error_detail: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
