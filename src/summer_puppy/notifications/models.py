from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class ChannelType(StrEnum):
    SLACK = "slack"
    EMAIL = "email"
    PAGERDUTY = "pagerduty"


class AlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationChannel(BaseModel):
    channel_id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str
    channel_type: ChannelType
    config: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class AlertEvent(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str
    severity: AlertSeverity
    title: str
    body: str
    correlation_id: str | None = None
    triggered_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
