from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query

from summer_puppy.api.middleware.auth_middleware import verify_customer_path
from summer_puppy.api.schemas.reporting import (
    AgentSummary,
    DashboardSummary,
    EventSummary,
    TrustSummary,
)
from summer_puppy.api.state import AppState, get_app_state
from summer_puppy.events.models import Severity
from summer_puppy.pipeline.models import PipelineContext, PipelineStage, PipelineStatus
from summer_puppy.trust.models import TrustProfile

router = APIRouter()


def _get_customer_contexts(state: AppState, customer_id: str) -> list[PipelineContext]:
    """Return all non-None PipelineContexts for this customer."""
    result = []
    for ctx in state.event_registry.values():
        if ctx is not None and ctx.customer_id == customer_id:
            result.append(ctx)
    return result


@router.get(
    "/{customer_id}/dashboard/summary",
    response_model=DashboardSummary,
    dependencies=[Depends(verify_customer_path)],  # noqa: B008
)
async def get_summary(
    customer_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> DashboardSummary:
    now = datetime.now(tz=UTC)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d = now - timedelta(days=7)
    contexts = _get_customer_contexts(state, customer_id)

    events_24h = 0
    events_7d = 0
    open_critical = 0
    remediation_minutes: list[float] = []
    completed_count = 0
    succeeded_count = 0

    for ctx in contexts:
        detected = ctx.event.detected_utc if ctx.event else None
        if detected is not None:
            # Ensure timezone-aware comparison
            if detected.tzinfo is None:
                detected = detected.replace(tzinfo=UTC)
            if detected >= cutoff_24h:
                events_24h += 1
            if detected >= cutoff_7d:
                events_7d += 1

        # Open critical: not at CLOSE stage, not COMPLETED/FAILED status, severity CRITICAL
        is_closed = ctx.current_stage == PipelineStage.CLOSE or ctx.status in (
            PipelineStatus.COMPLETED,
            PipelineStatus.FAILED,
        )
        if not is_closed and ctx.event and ctx.event.severity == Severity.CRITICAL:
            open_critical += 1

        # Avg time to remediate via outcome timestamps
        if ctx.outcome is not None:
            completed_count += 1
            if ctx.outcome.success:
                succeeded_count += 1
            if ctx.outcome.completed_utc is not None and ctx.outcome.started_utc is not None:
                started = ctx.outcome.started_utc
                completed = ctx.outcome.completed_utc
                if started.tzinfo is None:
                    started = started.replace(tzinfo=UTC)
                if completed.tzinfo is None:
                    completed = completed.replace(tzinfo=UTC)
                delta_minutes = (completed - started).total_seconds() / 60.0
                remediation_minutes.append(delta_minutes)

    avg_time = sum(remediation_minutes) / len(remediation_minutes) if remediation_minutes else 0.0
    success_rate = (succeeded_count / completed_count) if completed_count > 0 else 1.0

    trust_profile = state.trust_store.get(customer_id)
    trust_phase = trust_profile.trust_phase if trust_profile else None

    return DashboardSummary(
        events_24h=events_24h,
        events_7d=events_7d,
        open_critical=open_critical,
        avg_time_to_remediate_minutes=avg_time,
        execution_success_rate=success_rate,
        active_agents=len(state.skill_registry.list_agent_profiles()),
        trust_phase=trust_phase,
        orchestrator_ready=state.orchestrator is not None,
    )


@router.get(
    "/{customer_id}/dashboard/events",
    response_model=list[EventSummary],
    dependencies=[Depends(verify_customer_path)],  # noqa: B008
)
async def get_events(
    customer_id: str,
    hours: int = Query(default=24, ge=1),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=500),  # noqa: B008
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> list[EventSummary]:
    cutoff = datetime.now(tz=UTC) - timedelta(hours=hours)
    summaries: list[EventSummary] = []

    for ctx in _get_customer_contexts(state, customer_id):
        event = ctx.event
        detected = event.detected_utc if event else None
        if detected is not None:
            if detected.tzinfo is None:
                detected = detected.replace(tzinfo=UTC)
            if detected < cutoff:
                continue

        action_req = ctx.action_request
        summaries.append(
            EventSummary(
                event_id=event.event_id if event else "",
                correlation_id=ctx.correlation_id,
                severity=str(event.severity) if event else None,
                stage=str(ctx.current_stage),
                status=str(ctx.status),
                action_class=str(action_req.action_class) if action_req else None,
                submitted_utc=detected,
            )
        )

    return summaries[:limit]


@router.get(
    "/{customer_id}/dashboard/agents",
    response_model=list[AgentSummary],
    dependencies=[Depends(verify_customer_path)],  # noqa: B008
)
async def get_agents(
    customer_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> list[AgentSummary]:
    profiles = state.skill_registry.list_agent_profiles()
    return [
        AgentSummary(
            agent_id=p.agent_id,
            customer_id=p.customer_id,
            total_runs=p.total_runs,
            successful_runs=p.successful_runs,
            failed_runs=p.failed_runs,
            qa_pass_rate=p.qa_pass_rate,
        )
        for p in profiles
        if p.customer_id == customer_id
    ]


@router.get(
    "/{customer_id}/dashboard/trust",
    response_model=TrustSummary,
    dependencies=[Depends(verify_customer_path)],  # noqa: B008
)
async def get_trust(
    customer_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> TrustSummary:
    profile = state.trust_store.get(customer_id)
    if profile is None:
        profile = TrustProfile(customer_id=customer_id)
    return TrustSummary(
        customer_id=customer_id,
        trust_phase=profile.trust_phase,
        total_recommendations=profile.total_recommendations,
        total_approvals=profile.total_approvals,
        total_rejections=profile.total_rejections,
        positive_outcome_rate=profile.positive_outcome_rate,
    )
