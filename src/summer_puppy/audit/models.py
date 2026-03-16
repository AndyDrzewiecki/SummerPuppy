from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class AuditEntryType(StrEnum):
    EVENT_RECEIVED = "EVENT_RECEIVED"
    RECOMMENDATION_GENERATED = "RECOMMENDATION_GENERATED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    AUTO_APPROVED = "AUTO_APPROVED"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    HUMAN_REJECTED = "HUMAN_REJECTED"
    ACTION_STARTED = "ACTION_STARTED"
    ACTION_COMPLETED = "ACTION_COMPLETED"
    ACTION_FAILED = "ACTION_FAILED"
    ROLLBACK_INITIATED = "ROLLBACK_INITIATED"
    PHASE_TRANSITION = "PHASE_TRANSITION"
    POLICY_CHANGED = "POLICY_CHANGED"


class AuditEntry(BaseModel):
    entry_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    customer_id: str
    entry_type: AuditEntryType
    actor: str
    correlation_id: str | None = None
    resource_id: str | None = None
    resource_type: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    previous_state: str | None = None
    new_state: str | None = None
    checksum: str = ""
