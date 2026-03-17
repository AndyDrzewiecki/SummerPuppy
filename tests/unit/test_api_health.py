"""Tests for FastAPI health endpoints — RED phase (written before implementation)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture(autouse=True)
def _reset_app_state():
    """Reset singleton state before each test."""
    from summer_puppy.api.state import reset_app_state

    reset_app_state()
    yield
    reset_app_state()


@pytest.fixture
def app():
    from summer_puppy.api.app import app as _app

    return _app


async def _get(app, path: str):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.get(path)


# ---------------------------------------------------------------------------
# /api/v1/health
# ---------------------------------------------------------------------------


async def test_health_returns_200(app):
    response = await _get(app, "/api/v1/health")
    assert response.status_code == 200


async def test_health_response_schema(app):
    response = await _get(app, "/api/v1/health")
    data = response.json()
    assert "status" in data
    assert "uptime_seconds" in data
    assert "version" in data
    assert "orchestrator_ready" in data
    assert "timestamp_utc" in data


async def test_health_orchestrator_ready_false_when_none(app):
    from summer_puppy.api.state import init_app_state

    state = init_app_state()
    state.orchestrator = None  # explicitly clear auto-wired orchestrator
    response = await _get(app, "/api/v1/health")
    data = response.json()
    assert data["orchestrator_ready"] is False


async def test_health_orchestrator_ready_true_when_set(app):
    from summer_puppy.api.state import init_app_state

    state = init_app_state()
    state.orchestrator = object()  # any truthy value
    response = await _get(app, "/api/v1/health")
    data = response.json()
    assert data["orchestrator_ready"] is True


async def test_health_version_field(app):
    response = await _get(app, "/api/v1/health")
    data = response.json()
    assert data["version"] == "0.2.0"


async def test_health_status_ok(app):
    response = await _get(app, "/api/v1/health")
    data = response.json()
    assert data["status"] == "ok"


# ---------------------------------------------------------------------------
# /api/v1/live
# ---------------------------------------------------------------------------


async def test_live_always_200(app):
    response = await _get(app, "/api/v1/live")
    assert response.status_code == 200


async def test_live_no_auth_required(app):
    """Live endpoint must be reachable without any auth headers."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# /api/v1/ready
# ---------------------------------------------------------------------------


async def test_ready_503_when_no_orchestrator(app):
    from summer_puppy.api.state import init_app_state

    state = init_app_state()
    state.orchestrator = None  # explicitly clear auto-wired orchestrator
    response = await _get(app, "/api/v1/ready")
    assert response.status_code == 503


async def test_ready_200_when_orchestrator_set(app):
    from summer_puppy.api.state import init_app_state

    state = init_app_state()
    state.orchestrator = object()
    response = await _get(app, "/api/v1/ready")
    assert response.status_code == 200


async def test_ready_response_schema(app):
    from summer_puppy.api.state import init_app_state

    state = init_app_state()
    state.orchestrator = object()
    response = await _get(app, "/api/v1/ready")
    data = response.json()
    assert data == {"status": "ready"}


# ---------------------------------------------------------------------------
# Uptime
# ---------------------------------------------------------------------------


async def test_uptime_seconds_positive(app):
    """After lifespan starts, uptime_seconds should be >= 0."""
    from datetime import UTC, datetime

    from summer_puppy.api.state import init_app_state

    state = init_app_state()
    state.started_utc = datetime.now(tz=UTC)
    response = await _get(app, "/api/v1/health")
    data = response.json()
    assert data["uptime_seconds"] >= 0.0
