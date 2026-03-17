from __future__ import annotations

from pydantic import BaseModel, Field

from summer_puppy.notifications.models import AlertSeverity, ChannelType


class ChannelRequest(BaseModel):
    channel_type: ChannelType
    config: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True


class ChannelResponse(BaseModel):
    channel_id: str
    customer_id: str
    channel_type: ChannelType
    enabled: bool


class TestAlertRequest(BaseModel):
    title: str = "Test Alert"
    body: str = "This is a test notification"
    severity: AlertSeverity = AlertSeverity.LOW


class TestAlertResponse(BaseModel):
    dispatched: bool
    sent_count: int
