"""AppState singleton for the SummerPuppy FastAPI application."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime  # noqa: TC003
from typing import TYPE_CHECKING, Any

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.skills.registry import InMemorySkillRegistry
from summer_puppy.tenants.store import InMemoryTenantStore

if TYPE_CHECKING:
    from summer_puppy.api.settings import Settings
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
    event_bus: Any | None = None
    pool_orchestrator: Any | None = None
    skill_injector: Any | None = None
    dev_bot_handler: Any | None = None
    started_utc: datetime | None = None
    version: str = "0.2.0"


_app_state: AppState | None = None


def get_app_state() -> AppState:
    """Return the initialized AppState or raise RuntimeError."""
    if _app_state is None:
        raise RuntimeError("AppState not initialized. Call init_app_state() first.")
    return _app_state


def init_app_state(settings: Settings | None = None) -> AppState:
    """Initialize and return the AppState singleton (idempotent)."""
    global _app_state
    if _app_state is None:
        _app_state = AppState()
        _wire_app_state(_app_state, settings)
    return _app_state


def _wire_app_state(state: AppState, settings: Settings | None) -> None:
    """Wire all services into state. Called once at first init_app_state()."""
    from summer_puppy.api.settings import get_settings
    from summer_puppy.channel.bus import InMemoryEventBus
    from summer_puppy.notifications.dispatcher import NotificationDispatcher
    from summer_puppy.pipeline.orchestrator import Orchestrator
    from summer_puppy.scheduler.jobs import (
        expire_policies_handler,
        expire_protected_assets_handler,
        run_skill_injection_handler,
    )
    from summer_puppy.scheduler.models import ScheduledJob
    from summer_puppy.scheduler.runner import AsyncJobRunner
    from summer_puppy.skills.prompt_enricher import NullPromptEnricher
    from summer_puppy.trust.models import AutoApprovalPolicy  # noqa: TC001

    _s = settings or get_settings()  # noqa: F841 (may be used in Sprint 8 llm_enabled check)
    event_bus = InMemoryEventBus()
    state.event_bus = event_bus
    state.notification_dispatcher = NotificationDispatcher(mock_mode=True)

    _null_enricher = NullPromptEnricher()
    state.orchestrator = Orchestrator.build_default(
        audit_logger=state.audit_logger,
        event_bus=event_bus,
        notification_dispatcher=state.notification_dispatcher,
        prompt_enricher=_null_enricher,
    )

    runner = AsyncJobRunner()
    job1 = ScheduledJob(name="expire_protected_assets", interval_seconds=60)
    runner.add_job(job1, lambda: expire_protected_assets_handler(state.tenant_store))

    async def _expire_policies() -> int:
        store: dict[str, list[AutoApprovalPolicy]] = {
            p.customer_id: list(p.auto_approval_policies) for p in state.tenant_store.list_all()
        }
        return await expire_policies_handler(store)

    job2 = ScheduledJob(name="expire_policies", interval_seconds=300)
    runner.add_job(job2, _expire_policies)

    async def _run_injection() -> dict[str, Any]:
        customer_ids = [p.customer_id for p in state.tenant_store.list_all()]
        return await run_skill_injection_handler(
            skill_injector=state.skill_injector,
            customer_ids=customer_ids,
        )

    job3 = ScheduledJob(name="skill_injection", interval_seconds=600)
    runner.add_job(job3, _run_injection)
    state.job_runner = runner


def reset_app_state() -> None:
    """Reset the AppState singleton (for testing)."""
    global _app_state
    _app_state = None
