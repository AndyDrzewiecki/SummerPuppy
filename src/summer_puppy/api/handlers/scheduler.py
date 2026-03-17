from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from summer_puppy.api.auth.dependencies import require_admin
from summer_puppy.api.state import AppState, get_app_state
from summer_puppy.scheduler.models import JobResult  # noqa: TC001

router = APIRouter()


class JobStatusResponse(BaseModel):
    job_id: str
    name: str
    interval_seconds: int
    enabled: bool
    last_results: list[JobResult]


@router.get("/admin/scheduler/jobs", dependencies=[Depends(require_admin)])
async def list_scheduler_jobs(
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> list[JobStatusResponse]:
    if state.job_runner is None:
        return []
    jobs = state.job_runner.get_jobs()
    results = state.job_runner.get_last_results()
    result_map: dict[str, list[JobResult]] = {}
    for r in results:
        result_map.setdefault(r.job_id, []).append(r)
    return [
        JobStatusResponse(
            job_id=j.job_id,
            name=j.name,
            interval_seconds=j.interval_seconds,
            enabled=j.enabled,
            last_results=result_map.get(j.job_id, [])[-5:],
        )
        for j in jobs
    ]
