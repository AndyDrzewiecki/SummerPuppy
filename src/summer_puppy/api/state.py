"""AppState singleton for the SummerPuppy FastAPI application."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime  # noqa: TC003
from typing import TYPE_CHECKING, Any

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.skills.registry import InMemorySkillRegistry
from summer_puppy.tenants.store import InMemoryTenantStore

if TYPE_CHECKING:
    from summer_puppy.pipeline.models import PipelineContext
    from summer_puppy.trust.models import TrustProfile


@dataclass
class AppState:
    audit_logger: InMemoryAuditLogger = field(default_factory=InMemoryAuditLogger)
    event_registry: dict[str, PipelineContext | None] = field(default_factory=dict)
    skill_registry: InMemorySkillRegistry = field(default_factory=InMemorySkillRegistry)
    tenant_store: InMemoryTenantStore = field(default_factory=InMemoryTenantStore)
    trust_store: dict[str, TrustProfile] = field(default_factory=dict)
    orchestrator: Any | None = None  # Orchestrator (Any to avoid circular import)
    notification_dispatcher: Any | None = None
    job_runner: Any | None = None
    pool_orchestrator: Any | None = None
    started_utc: datetime | None = None
    version: str = "0.2.0"


_app_state: AppState | None = None


def get_app_state() -> AppState:
    """Return the initialized AppState or raise RuntimeError."""
    if _app_state is None:
        raise RuntimeError("AppState not initialized. Call init_app_state() first.")
    return _app_state


def init_app_state() -> AppState:
    """Initialize and return the AppState singleton (idempotent)."""
    global _app_state
    if _app_state is None:
        _app_state = AppState()
    return _app_state


def reset_app_state() -> None:
    """Reset the AppState singleton (for testing)."""
    global _app_state
    _app_state = None
