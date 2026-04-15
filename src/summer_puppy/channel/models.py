from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Topic(StrEnum):
    SECURITY_EVENTS = "SECURITY_EVENTS"
    RECOMMENDATIONS = "RECOMMENDATIONS"
    APPROVAL_REQUESTS = "APPROVAL_REQUESTS"
    ACTION_OUTCOMES = "ACTION_OUTCOMES"
    AUDIT_ENTRIES = "AUDIT_ENTRIES"
    PHASE_TRANSITIONS = "PHASE_TRANSITIONS"
    ANALYSIS_RESULTS = "ANALYSIS_RESULTS"
    WORK_ITEMS = "WORK_ITEMS"
    POOL_STATUS = "POOL_STATUS"
    ARTIFACTS = "ARTIFACTS"
    DECISIONS = "DECISIONS"
    DEV_BOT_TRIGGERS = "DEV_BOT_TRIGGERS"
    DEV_BOT_PR_EVENTS = "DEV_BOT_PR_EVENTS"


class Envelope(BaseModel):
    envelope_id: str = Field(default_factory=lambda: str(uuid4()))
    topic: Topic
    customer_id: str
    correlation_id: str | None = None
    payload_type: str
    payload: dict[str, Any]
    published_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    schema_version: str = "1.0"
