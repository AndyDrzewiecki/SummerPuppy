"""FastAPI application factory for SummerPuppy."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from summer_puppy.api.router import main_router
from summer_puppy.api.state import init_app_state

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage application startup and shutdown."""
    from summer_puppy.api.settings import get_settings

    settings = get_settings()
    state = init_app_state(settings=settings)
    state.started_utc = datetime.now(tz=UTC)
    if state.job_runner is not None:
        await state.job_runner.start()
    yield
    if state.job_runner is not None:
        await state.job_runner.stop()


app = FastAPI(title="SummerPuppy API", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(main_router)
