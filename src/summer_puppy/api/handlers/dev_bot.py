"""Dev bot API endpoints — user stories, patches, PRs, and quality tracking."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from summer_puppy.api.middleware.auth_middleware import verify_customer_path
from summer_puppy.api.state import AppState, get_app_state
from summer_puppy.dev_bot.models import PROutcome

router = APIRouter()


class OutcomeRequest(BaseModel):
    outcome: PROutcome
    merged_without_change: bool = False
    rejection_reason: str = ""


def _get_dev_bot_handler(state: AppState) -> Any:
    handler = getattr(state, "dev_bot_handler", None)
    if handler is None:
        raise HTTPException(status_code=503, detail="Dev bot handler not configured")
    return handler


def _get_quality_tracker(state: AppState) -> Any:
    handler = _get_dev_bot_handler(state)
    qt = getattr(handler, "_quality_tracker", None)
    if qt is None:
        raise HTTPException(status_code=503, detail="Quality tracker not configured")
    return qt


@router.get(
    "/{customer_id}/dev-bot/stories",
    dependencies=[Depends(verify_customer_path)],
)
async def list_stories(
    customer_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> list[dict[str, Any]]:
    """Return recent UserStories for the customer."""
    handler = _get_dev_bot_handler(state)
    stories = handler.get_stories(customer_id=customer_id)
    return [s.model_dump() for s in stories]


@router.get(
    "/{customer_id}/dev-bot/patches",
    dependencies=[Depends(verify_customer_path)],
)
async def list_patches(
    customer_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> list[dict[str, Any]]:
    """Return PatchCandidates for the customer."""
    handler = _get_dev_bot_handler(state)
    patches = handler.get_patches(customer_id=customer_id)
    return [p.model_dump() for p in patches]


@router.get(
    "/{customer_id}/dev-bot/prs",
    dependencies=[Depends(verify_customer_path)],
)
async def list_prs(
    customer_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> list[dict[str, Any]]:
    """Return DevBotPRs for the customer."""
    handler = _get_dev_bot_handler(state)
    prs = handler.get_prs(customer_id=customer_id)
    return [pr.model_dump() for pr in prs]


@router.post(
    "/{customer_id}/dev-bot/prs/{pr_id}/outcome",
    dependencies=[Depends(verify_customer_path)],
)
async def record_pr_outcome(
    customer_id: str,
    pr_id: str,
    body: OutcomeRequest,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> dict[str, Any]:
    """Record the outcome of a PR (approved/rejected/merged) and update quality tracking."""
    handler = _get_dev_bot_handler(state)
    pr = handler.get_pr_by_id(pr_id)
    if pr is None:
        raise HTTPException(status_code=404, detail="PR not found")
    if pr.customer_id != customer_id:
        raise HTTPException(status_code=403, detail="Customer ID mismatch")

    # Find the patch for this PR
    patches = handler.get_patches(customer_id=customer_id)
    patch = next((p for p in patches if p.patch_id == pr.patch_id), None)
    if patch is None:
        raise HTTPException(status_code=404, detail="Patch not found for PR")

    # Update outcome on the PR copy
    updated_pr = pr.model_copy(update={"outcome": body.outcome})
    handler.update_pr(updated_pr)

    qt = _get_quality_tracker(state)
    record = qt.record_outcome(
        pr=updated_pr,
        patch=patch,
        pre_submit_test_passed=True,
        merged_without_change=body.merged_without_change,
        rejection_reason=body.rejection_reason,
    )
    return record.model_dump()


@router.get(
    "/{customer_id}/dev-bot/quality",
    dependencies=[Depends(verify_customer_path)],
)
async def get_quality(
    customer_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> dict[str, Any]:
    """Return quality tracking summary for the customer."""
    qt = _get_quality_tracker(state)
    records = qt.get_records(customer_id=customer_id)
    rate = qt.approval_rate(customer_id=customer_id)
    return {
        "approval_rate": rate,
        "total_records": len(records),
        "records": [r.model_dump() for r in records],
    }
