from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from summer_puppy.api.middleware.auth_middleware import verify_customer_path
from summer_puppy.api.state import AppState, get_app_state
from summer_puppy.audit.models import AuditEntry, AuditEntryType
from summer_puppy.events.models import ActionRequest, ApprovalMethod
from summer_puppy.pipeline.models import PipelineStage, PipelineStatus

router = APIRouter()


class ApprovalRequest(BaseModel):
    approved: bool
    actor: str = "human"
    notes: str = ""


class ApprovalResponse(BaseModel):
    event_id: str
    approved: bool
    stage: str
    status: str


@router.post(
    "/{customer_id}/events/{event_id}/approve",
    response_model=ApprovalResponse,
    dependencies=[Depends(verify_customer_path)],
)
async def approve_event(
    customer_id: str,
    event_id: str,
    body: ApprovalRequest,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> ApprovalResponse:
    """Human approval or rejection of a paused pipeline event."""
    if event_id not in state.event_registry:
        raise HTTPException(status_code=404, detail="Event not found")

    ctx = state.event_registry[event_id]
    if ctx is None:
        raise HTTPException(status_code=404, detail="Event still processing")

    if ctx.status != PipelineStatus.PAUSED_FOR_APPROVAL:
        raise HTTPException(status_code=409, detail="Event is not awaiting approval")

    if ctx.customer_id != customer_id:
        raise HTTPException(status_code=403, detail="Event belongs to different customer")

    if body.approved:
        assert ctx.recommendation is not None, "Recommendation must exist for approval"
        action_request = ActionRequest(
            recommendation_id=ctx.recommendation.recommendation_id,
            customer_id=customer_id,
            action_class=ctx.recommendation.action_class,
            approval_method=ApprovalMethod.HUMAN_APPROVED,
            approved_by=body.actor,
        )
        ctx.action_request = action_request
        ctx.current_stage = PipelineStage.EXECUTE
        ctx.status = PipelineStatus.RUNNING

        entry = AuditEntry(
            customer_id=customer_id,
            entry_type=AuditEntryType.HUMAN_APPROVED,
            actor=body.actor,
            correlation_id=str(ctx.correlation_id),
            resource_id=ctx.recommendation.recommendation_id,
        )
        await state.audit_logger.append(entry)

        if state.orchestrator is not None:
            ctx = await state.orchestrator.resume_from_context(ctx)
        state.event_registry[event_id] = ctx
    else:
        assert ctx.recommendation is not None, "Recommendation must exist for rejection"
        entry = AuditEntry(
            customer_id=customer_id,
            entry_type=AuditEntryType.HUMAN_REJECTED,
            actor=body.actor,
            correlation_id=str(ctx.correlation_id),
            resource_id=ctx.recommendation.recommendation_id,
            details={"notes": body.notes},
        )
        await state.audit_logger.append(entry)

        ctx.status = PipelineStatus.FAILED
        ctx.current_stage = PipelineStage.ERROR
        ctx.error_detail = f"Rejected by {body.actor}: {body.notes}"
        state.event_registry[event_id] = ctx

    return ApprovalResponse(
        event_id=event_id,
        approved=body.approved,
        stage=ctx.current_stage.value,
        status=ctx.status.value,
    )
