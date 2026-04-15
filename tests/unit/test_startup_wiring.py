from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from summer_puppy.api.app import app
from summer_puppy.api.state import init_app_state, reset_app_state


@pytest.fixture(autouse=True)
def reset_state():
    reset_app_state()
    yield
    reset_app_state()


def test_orchestrator_is_wired():
    state = init_app_state()
    assert state.orchestrator is not None


def test_job_runner_is_wired():
    state = init_app_state()
    assert state.job_runner is not None


def test_notification_dispatcher_is_wired():
    state = init_app_state()
    assert state.notification_dispatcher is not None


def test_scheduled_jobs_registered():
    state = init_app_state()
    assert state.job_runner is not None
    jobs = state.job_runner.get_jobs()
    names = {j.name for j in jobs}
    assert names == {"expire_protected_assets", "expire_policies", "skill_injection"}


@pytest.mark.asyncio
async def test_ready_endpoint_returns_200_after_wiring():
    init_app_state()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/api/v1/ready")
    assert resp.status_code == 200
