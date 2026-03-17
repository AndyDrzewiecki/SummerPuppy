"""Event Submission API handlers."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from summer_puppy.api.middleware.auth_middleware import verify_customer_path
from summer_puppy.api.schemas.events import (
    EventStatusResponse,
    EventSubmitRequest,
    EventSubmitResponse,
)
from summer_puppy.api.state import AppState, get_app_state
from summer_puppy.events.models import SecurityEvent
from summer_puppy.trust.models import AutoApprovalPolicy, TrustProfile

router = APIRouter()


async def _process_event_background(event: SecurityEvent, state: AppState) -> None:
    """Run the pipeline for a submitted event and store the resulting context."""
    trust_profile = state.trust_store.get(event.customer_id) or TrustProfile(
        customer_id=event.customer_id
    )
    tenant = state.tenant_store.get(event.customer_id)
    # TenantProfile does not carry AutoApprovalPolicy objects directly;
    # pass an empty list when no external policy store is wired.
    policies: list[AutoApprovalPolicy] = (
        tenant.auto_approval_policies if tenant is not None else []
    )
    if state.orchestrator is not None:
        ctx = await state.orchestrator.process_event(event, trust_profile, policies)
        state.event_registry[event.event_id] = ctx


@router.post(
    "/{customer_id}/events",
    response_model=EventSubmitResponse,
    status_code=202,
    dependencies=[Depends(verify_customer_path)],
)
async def submit_event(
    customer_id: str,
    body: EventSubmitRequest,
    background_tasks: BackgroundTasks,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> EventSubmitResponse:
    """Accept a security event for async pipeline processing."""
    correlation_id = body.correlation_id or str(uuid4())
    event = SecurityEvent(
        customer_id=customer_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        source=body.source,
        affected_assets=body.affected_assets,
        correlation_id=correlation_id,
    )
    # Sentinel: event registered but not yet processed
    state.event_registry[event.event_id] = None
    background_tasks.add_task(_process_event_background, event, state)
    return EventSubmitResponse(
        event_id=event.event_id,
        correlation_id=correlation_id,
        submitted_utc=datetime.now(tz=UTC),
    )


@router.get(
    "/{customer_id}/events/{event_id}",
    response_model=EventStatusResponse,
    dependencies=[Depends(verify_customer_path)],
)
async def get_event_status(
    customer_id: str,
    event_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> EventStatusResponse:
    """Return the current pipeline status for a submitted event."""
    if event_id not in state.event_registry:
        raise HTTPException(status_code=404, detail="Event not found")
    ctx = state.event_registry[event_id]
    if ctx is None:
        # Still processing — return minimal in-progress response
        return EventStatusResponse(event_id=event_id, correlation_id="")
    return EventStatusResponse(
        event_id=event_id,
        correlation_id=str(ctx.correlation_id),
        stage=ctx.current_stage,
        status=ctx.status,
        recommendation_id=(
            str(ctx.recommendation.recommendation_id) if ctx.recommendation else None
        ),
        action_class=ctx.action_request.action_class if ctx.action_request else None,
        error_detail=ctx.error_detail,
    )
