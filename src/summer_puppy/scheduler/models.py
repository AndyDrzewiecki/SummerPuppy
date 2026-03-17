"""Scheduler models: ScheduledJob and JobResult."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003
from uuid import uuid4

from pydantic import BaseModel, Field


class ScheduledJob(BaseModel):
    """Represents a recurring background job."""

    job_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    interval_seconds: int
    enabled: bool = True
    last_run_utc: datetime | None = None
    next_run_utc: datetime | None = None


class JobResult(BaseModel):
    """Records the outcome of a single job execution."""

    job_id: str
    started_utc: datetime
    completed_utc: datetime
    success: bool
    records_affected: int = 0
    error: str | None = None
