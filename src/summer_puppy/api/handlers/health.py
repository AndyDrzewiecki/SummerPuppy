"""Health check endpoint handlers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from summer_puppy.api.state import init_app_state

router = APIRouter()


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    uptime_seconds: float
    version: str
    orchestrator_ready: bool
    timestamp_utc: datetime


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Return service health information."""
    state = init_app_state()
    uptime = 0.0
    if state.started_utc is not None:
        uptime = (datetime.now(tz=UTC) - state.started_utc).total_seconds()
    return HealthResponse(
        uptime_seconds=uptime,
        version=state.version,
        orchestrator_ready=state.orchestrator is not None,
        timestamp_utc=datetime.now(tz=UTC),
    )


@router.get("/live")
async def live() -> dict[str, str]:
    """Liveness probe — always returns 200 when the process is alive."""
    return {"status": "ok"}


@router.get("/ready")
async def ready() -> dict[str, str]:
    """Readiness probe — returns 503 until the orchestrator is configured."""
    state = init_app_state()
    if state.orchestrator is None:
        raise HTTPException(status_code=503, detail="not_ready")
    return {"status": "ready"}
