from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import uuid4

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from summer_puppy.work.models import WorkItemType


class PoolType(StrEnum):
    THREAT_RESEARCH = "THREAT_RESEARCH"
    ENGINEERING = "ENGINEERING"
    ORCHESTRATION = "ORCHESTRATION"
    QA_VALIDATION = "QA_VALIDATION"


class PoolStatus(StrEnum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    DEGRADED = "DEGRADED"


class AgentPool(BaseModel):
    pool_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    pool_type: PoolType
    can_produce: list[WorkItemType] = Field(default_factory=list)
    can_consume: list[WorkItemType] = Field(default_factory=list)
    status: PoolStatus = PoolStatus.ONLINE
    current_load: int = 0
    max_capacity: int = 10
    sla_response_seconds: int | None = None
    registered_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    last_heartbeat_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
