"""Models for local/on-premise deployment."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class LocalDeploymentConfig(BaseModel):
    """Configuration for customer-local LLM deployment."""

    tenant_id: str
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    offline_mode_enabled: bool = True
    context_cache_max_age_hours: int = 24
    health_check_interval_seconds: int = 30


class TenantContextSlice(BaseModel):
    """Encrypted-at-rest context snapshot for a tenant (local KB cache).

    In production this would be encrypted. In this implementation it is
    a plaintext snapshot of the relevant KB artifacts.
    """

    tenant_id: str
    snapshot_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    playbook_summaries: list[str] = Field(default_factory=list)
    article_summaries: list[str] = Field(default_factory=list)
    max_age_hours: int = 24

    @property
    def is_stale(self) -> bool:
        """True if the snapshot is older than max_age_hours."""
        age = datetime.now(tz=UTC) - self.snapshot_utc
        return age.total_seconds() > self.max_age_hours * 3600


class OfflineTriage(BaseModel):
    """Result of offline (local LLM) emergency triage."""

    triage_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    event_summary: str
    severity_assessment: str
    recommended_action: str
    reasoning: str
    used_cached_context: bool = False
    triage_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    offline_mode: bool = True
