"""Top-level API router for SummerPuppy."""

from __future__ import annotations

from fastapi import APIRouter

from summer_puppy.api.handlers.approvals import router as approvals_router
from summer_puppy.api.handlers.auth import router as auth_router
from summer_puppy.api.handlers.customers import router as customers_router
from summer_puppy.api.handlers.dev_bot import router as dev_bot_router
from summer_puppy.api.handlers.observability import router as observability_router
from summer_puppy.api.handlers.events import router as events_router
from summer_puppy.api.handlers.health import router as health_router
from summer_puppy.api.handlers.notifications import router as notifications_router
from summer_puppy.api.handlers.policies import router as policies_router
from summer_puppy.api.handlers.reporting import router as reporting_router
from summer_puppy.api.handlers.sandbox import router as sandbox_router
from summer_puppy.api.handlers.scheduler import router as scheduler_router

main_router = APIRouter(prefix="/api/v1")
main_router.include_router(health_router, tags=["health"])
main_router.include_router(auth_router, prefix="/auth", tags=["auth"])
main_router.include_router(customers_router, prefix="/customers", tags=["customers"])
main_router.include_router(events_router, tags=["events"])
main_router.include_router(policies_router, prefix="/customers", tags=["policies"])
main_router.include_router(reporting_router, prefix="/customers", tags=["reporting"])
main_router.include_router(notifications_router, prefix="/customers", tags=["notifications"])
main_router.include_router(scheduler_router, tags=["scheduler"])
main_router.include_router(approvals_router, prefix="/customers", tags=["approvals"])
main_router.include_router(sandbox_router, prefix="/customers", tags=["sandbox"])
main_router.include_router(dev_bot_router, prefix="/customers", tags=["dev-bot"])
main_router.include_router(observability_router, tags=["observability"])
