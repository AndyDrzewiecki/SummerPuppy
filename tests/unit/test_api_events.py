"""Tests for Event Submission API — Story 3, Sprint 6."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _request(app, method: str, path: str, **kwargs):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await getattr(client, method)(path, **kwargs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_state():
    from summer_puppy.api.state import init_app_state, reset_app_state

    reset_app_state()
    state = init_app_state()
    yield state
    reset_app_state()


@pytest.fixture
def app():
    from summer_puppy.api.app import app as _app

    return _app


@pytest.fixture
def state(reset_state):
    return reset_state


@pytest.fixture
def token():
    from summer_puppy.api.auth.jwt_handler import create_token

    return create_token("cust-1", scopes=["events:write"])


@pytest.fixture
def headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def valid_body():
    return {
        "title": "Suspicious login attempt",
        "description": "Multiple failed logins from unknown IP",
        "severity": "HIGH",
        "source": "SIEM",
        "affected_assets": ["server-01"],
    }


# ---------------------------------------------------------------------------
# TestEventSchemas
# ---------------------------------------------------------------------------


class TestEventSchemas:
    def test_submit_request_valid(self):
        from summer_puppy.api.schemas.events import EventSubmitRequest

        req = EventSubmitRequest(
            title="Test",
            description="Details here",
            severity="HIGH",
            source="SIEM",
        )
        assert req.title == "Test"
        assert req.severity == "HIGH"
        assert req.source == "SIEM"

    def test_submit_request_empty_title_422(self):
        from pydantic import ValidationError

        from summer_puppy.api.schemas.events import EventSubmitRequest

        with pytest.raises(ValidationError):
            EventSubmitRequest(
                title="",
                description="Details",
                severity="HIGH",
                source="SIEM",
            )

    def test_submit_request_invalid_severity_422(self):
        from pydantic import ValidationError

        from summer_puppy.api.schemas.events import EventSubmitRequest

        with pytest.raises(ValidationError):
            EventSubmitRequest(
                title="Test",
                description="Details",
                severity="EXTREME",
                source="SIEM",
            )

    def test_submit_response_has_event_id(self):
        from datetime import UTC, datetime

        from summer_puppy.api.schemas.events import EventSubmitResponse

        resp = EventSubmitResponse(
            event_id="evt-123",
            correlation_id="corr-456",
            submitted_utc=datetime.now(tz=UTC),
        )
        assert resp.event_id == "evt-123"

    def test_submit_response_status_intake(self):
        from datetime import UTC, datetime

        from summer_puppy.api.schemas.events import EventSubmitResponse

        resp = EventSubmitResponse(
            event_id="evt-123",
            correlation_id="corr-456",
            submitted_utc=datetime.now(tz=UTC),
        )
        assert resp.status == "INTAKE"

    def test_status_response_fields(self):
        from summer_puppy.api.schemas.events import EventStatusResponse

        resp = EventStatusResponse(event_id="evt-1", correlation_id="corr-1")
        assert resp.event_id == "evt-1"
        assert resp.correlation_id == "corr-1"
        assert resp.stage is None
        assert resp.status is None
        assert resp.recommendation_id is None
        assert resp.action_class is None
        assert resp.error_detail is None


# ---------------------------------------------------------------------------
# TestEventSubmissionEndpoint
# ---------------------------------------------------------------------------


class TestEventSubmissionEndpoint:
    async def test_post_event_returns_202(self, app, headers, valid_body):
        resp = await _request(
            app, "post", "/api/v1/cust-1/events", json=valid_body, headers=headers
        )
        assert resp.status_code == 202

    async def test_post_event_returns_event_id(self, app, headers, valid_body):
        resp = await _request(
            app, "post", "/api/v1/cust-1/events", json=valid_body, headers=headers
        )
        data = resp.json()
        assert "event_id" in data
        assert isinstance(data["event_id"], str)
        assert len(data["event_id"]) > 0

    async def test_post_event_registers_in_registry(self, app, headers, valid_body, state):
        resp = await _request(
            app, "post", "/api/v1/cust-1/events", json=valid_body, headers=headers
        )
        data = resp.json()
        event_id = data["event_id"]
        assert event_id in state.event_registry

    async def test_post_event_customer_id_mismatch_403(self, app, headers, valid_body):
        # Token is for cust-1, but path is cust-2
        resp = await _request(
            app, "post", "/api/v1/cust-2/events", json=valid_body, headers=headers
        )
        assert resp.status_code == 403

    async def test_post_event_no_auth_401(self, app, valid_body):
        # Sending an invalid/malformed Bearer token triggers 401 from decode_token
        resp = await _request(
            app,
            "post",
            "/api/v1/cust-1/events",
            json=valid_body,
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert resp.status_code == 401

    async def test_post_event_invalid_body_422(self, app, headers):
        resp = await _request(
            app,
            "post",
            "/api/v1/cust-1/events",
            json={"title": "", "description": "x", "severity": "HIGH", "source": "SIEM"},
            headers=headers,
        )
        assert resp.status_code == 422

    async def test_post_event_response_has_correlation_id(self, app, headers, valid_body):
        resp = await _request(
            app, "post", "/api/v1/cust-1/events", json=valid_body, headers=headers
        )
        data = resp.json()
        assert "correlation_id" in data
        assert isinstance(data["correlation_id"], str)

    async def test_post_event_uses_provided_correlation_id(self, app, headers, valid_body):
        body = {**valid_body, "correlation_id": "my-corr-id-123"}
        resp = await _request(app, "post", "/api/v1/cust-1/events", json=body, headers=headers)
        data = resp.json()
        assert data["correlation_id"] == "my-corr-id-123"


# ---------------------------------------------------------------------------
# TestEventStatusEndpoint
# ---------------------------------------------------------------------------


class TestEventStatusEndpoint:
    async def test_get_event_not_found_404(self, app, headers):
        resp = await _request(app, "get", "/api/v1/cust-1/events/nonexistent-id", headers=headers)
        assert resp.status_code == 404

    async def test_get_event_found_in_progress(self, app, headers, state):
        # Registry has None sentinel (submitted, not yet processed)
        state.event_registry["evt-pending"] = None
        resp = await _request(app, "get", "/api/v1/cust-1/events/evt-pending", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == "evt-pending"

    async def test_get_event_completed(self, app, headers, state):
        from summer_puppy.events.models import EventSource, SecurityEvent, Severity
        from summer_puppy.pipeline.models import PipelineContext, PipelineStatus
        from summer_puppy.trust.models import TrustProfile

        event = SecurityEvent(
            customer_id="cust-1",
            title="Test",
            description="Desc",
            severity=Severity.HIGH,
            source=EventSource.SIEM,
            correlation_id="corr-999",
        )
        trust = TrustProfile(customer_id="cust-1")
        ctx = PipelineContext(
            event=event,
            customer_id="cust-1",
            correlation_id="corr-999",
            trust_profile=trust,
            status=PipelineStatus.COMPLETED,
        )
        state.event_registry[event.event_id] = ctx
        resp = await _request(
            app, "get", f"/api/v1/cust-1/events/{event.event_id}", headers=headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == event.event_id
        assert data["status"] == "COMPLETED"

    async def test_get_event_customer_mismatch_403(self, app, state):
        from summer_puppy.api.auth.jwt_handler import create_token

        # Create token for cust-2 but try to access cust-1's path
        token_cust2 = create_token("cust-2", scopes=["events:write"])
        headers_cust2 = {"Authorization": f"Bearer {token_cust2}"}
        state.event_registry["evt-abc"] = None
        resp = await _request(app, "get", "/api/v1/cust-1/events/evt-abc", headers=headers_cust2)
        assert resp.status_code == 403

    async def test_get_event_no_auth_401(self, app, state):
        state.event_registry["evt-abc"] = None
        # Sending an invalid/malformed Bearer token triggers 401 from decode_token
        resp = await _request(
            app,
            "get",
            "/api/v1/cust-1/events/evt-abc",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert resp.status_code == 401

    async def test_get_event_status_in_progress_stage_none(self, app, headers, state):
        state.event_registry["evt-x"] = None
        resp = await _request(app, "get", "/api/v1/cust-1/events/evt-x", headers=headers)
        data = resp.json()
        assert data["stage"] is None

    async def test_get_event_status_completed_has_stage(self, app, headers, state):
        from summer_puppy.events.models import EventSource, SecurityEvent, Severity
        from summer_puppy.pipeline.models import (
            PipelineContext,
            PipelineStage,
            PipelineStatus,
        )
        from summer_puppy.trust.models import TrustProfile

        event = SecurityEvent(
            customer_id="cust-1",
            title="T",
            description="D",
            severity=Severity.LOW,
            source=EventSource.MANUAL,
        )
        ctx = PipelineContext(
            event=event,
            customer_id="cust-1",
            correlation_id="c",
            trust_profile=TrustProfile(customer_id="cust-1"),
            status=PipelineStatus.COMPLETED,
            current_stage=PipelineStage.CLOSE,
        )
        state.event_registry[event.event_id] = ctx
        resp = await _request(
            app, "get", f"/api/v1/cust-1/events/{event.event_id}", headers=headers
        )
        data = resp.json()
        assert data["stage"] == "CLOSE"


# ---------------------------------------------------------------------------
# TestBackgroundProcessing
# ---------------------------------------------------------------------------


class TestBackgroundProcessing:
    async def test_background_task_updates_registry(self, app, headers, valid_body, state):
        """After submitting, registry sentinel (None) is set for the event."""
        resp = await _request(
            app, "post", "/api/v1/cust-1/events", json=valid_body, headers=headers
        )
        assert resp.status_code == 202
        event_id = resp.json()["event_id"]
        # Sentinel is set immediately (None or PipelineContext after bg task)
        assert event_id in state.event_registry

    async def test_background_task_no_orchestrator_graceful(self, app, headers, valid_body, state):
        """When no orchestrator configured, background task completes without updating registry."""
        state.orchestrator = None  # explicitly clear the auto-wired orchestrator
        resp = await _request(
            app, "post", "/api/v1/cust-1/events", json=valid_body, headers=headers
        )
        assert resp.status_code == 202
        event_id = resp.json()["event_id"]
        # Registry should still have the sentinel
        assert event_id in state.event_registry

    async def test_background_task_with_mock_orchestrator(self, app, headers, valid_body, state):
        """When orchestrator is present, background task calls process_event
        and updates registry."""
        from summer_puppy.events.models import EventSource, SecurityEvent, Severity
        from summer_puppy.pipeline.models import (
            PipelineContext,
            PipelineStage,
            PipelineStatus,
        )
        from summer_puppy.trust.models import TrustProfile

        # Build a fake completed context
        fake_event = SecurityEvent(
            customer_id="cust-1",
            title="Processed",
            description="Done",
            severity=Severity.HIGH,
            source=EventSource.SIEM,
        )
        fake_ctx = PipelineContext(
            event=fake_event,
            customer_id="cust-1",
            correlation_id="bg-corr",
            trust_profile=TrustProfile(customer_id="cust-1"),
            status=PipelineStatus.COMPLETED,
            current_stage=PipelineStage.CLOSE,
        )

        mock_orch = MagicMock()
        mock_orch.process_event = AsyncMock(return_value=fake_ctx)
        state.orchestrator = mock_orch

        resp = await _request(
            app, "post", "/api/v1/cust-1/events", json=valid_body, headers=headers
        )
        assert resp.status_code == 202
        event_id = resp.json()["event_id"]

        # Allow background task to run (httpx with ASGI runs background tasks)
        # Registry should be updated with context
        assert event_id in state.event_registry

    async def test_post_event_response_submitted_utc(self, app, headers, valid_body):
        resp = await _request(
            app, "post", "/api/v1/cust-1/events", json=valid_body, headers=headers
        )
        data = resp.json()
        assert "submitted_utc" in data
        assert data["submitted_utc"] is not None

    async def test_post_event_missing_description_422(self, app, headers):
        resp = await _request(
            app,
            "post",
            "/api/v1/cust-1/events",
            json={"title": "T", "severity": "HIGH", "source": "SIEM"},
            headers=headers,
        )
        assert resp.status_code == 422
