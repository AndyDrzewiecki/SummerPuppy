"""Pydantic schemas for Event Submission API."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003
from typing import Literal

from pydantic import BaseModel, Field

from summer_puppy.events.models import EventSource, Severity  # noqa: TC001
from summer_puppy.pipeline.models import PipelineStage, PipelineStatus  # noqa: TC001
from summer_puppy.trust.models import ActionClass  # noqa: TC001


class EventSubmitRequest(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1)
    severity: Severity
    source: EventSource
    affected_assets: list[str] = Field(default_factory=list)
    correlation_id: str | None = None


class EventSubmitResponse(BaseModel):
    event_id: str
    correlation_id: str
    status: Literal["INTAKE"] = "INTAKE"
    submitted_utc: datetime


class EventStatusResponse(BaseModel):
    event_id: str
    correlation_id: str
    stage: PipelineStage | None = None
    status: PipelineStatus | None = None
    recommendation_id: str | None = None
    action_class: ActionClass | None = None
    error_detail: str | None = None
