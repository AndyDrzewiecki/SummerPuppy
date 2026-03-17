"""Tests for Dashboard & Reporting Endpoints — Story 6, Sprint 6."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _request(app, method: str, path: str, **kwargs):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await getattr(client, method)(path, **kwargs)


def _make_pipeline_context(
    customer_id: str = "cust-1", severity: str = "HIGH", detected_offset_hours: int = 1
):
    """Build a minimal PipelineContext for testing."""
    from summer_puppy.events.models import EventSource, SecurityEvent, Severity
    from summer_puppy.pipeline.models import PipelineContext, PipelineStage, PipelineStatus
    from summer_puppy.trust.models import TrustProfile

    event = SecurityEvent(
        customer_id=customer_id,
        source=EventSource.SIEM,
        severity=Severity(severity),
        title="Test Event",
        description="Test description",
        detected_utc=datetime.now(tz=UTC) - timedelta(hours=detected_offset_hours),
    )
    trust_profile = TrustProfile(customer_id=customer_id)
    return PipelineContext(
        event=event,
        customer_id=customer_id,
        correlation_id="corr-001",
        current_stage=PipelineStage.TRIAGE,
        status=PipelineStatus.RUNNING,
        trust_profile=trust_profile,
    )


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

    return create_token("cust-1", scopes=["reporting:read"])


@pytest.fixture
def headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# TestDashboardSchemas
# ---------------------------------------------------------------------------


class TestDashboardSchemas:
    def test_dashboard_summary_fields(self):
        from summer_puppy.api.schemas.reporting import DashboardSummary
        from summer_puppy.trust.models import TrustPhase

        summary = DashboardSummary(
            events_24h=5,
            events_7d=20,
            open_critical=2,
            avg_time_to_remediate_minutes=15.5,
            execution_success_rate=0.9,
            active_agents=3,
            trust_phase=TrustPhase.SUPERVISED,
            orchestrator_ready=True,
        )
        assert summary.events_24h == 5
        assert summary.events_7d == 20
        assert summary.open_critical == 2
        assert summary.avg_time_to_remediate_minutes == 15.5
        assert summary.execution_success_rate == 0.9
        assert summary.active_agents == 3
        assert summary.trust_phase == TrustPhase.SUPERVISED
        assert summary.orchestrator_ready is True

    def test_event_summary_fields(self):
        from summer_puppy.api.schemas.reporting import EventSummary

        now = datetime.now(tz=UTC)
        es = EventSummary(
            event_id="evt-1",
            correlation_id="corr-1",
            severity="HIGH",
            stage="TRIAGE",
            status="RUNNING",
            action_class=None,
            submitted_utc=now,
        )
        assert es.event_id == "evt-1"
        assert es.correlation_id == "corr-1"
        assert es.severity == "HIGH"
        assert es.stage == "TRIAGE"
        assert es.status == "RUNNING"
        assert es.action_class is None
        assert es.submitted_utc == now

    def test_agent_summary_fields(self):
        from summer_puppy.api.schemas.reporting import AgentSummary

        ag = AgentSummary(
            agent_id="agent-1",
            customer_id="cust-1",
            total_runs=10,
            successful_runs=8,
            failed_runs=2,
            qa_pass_rate=0.85,
        )
        assert ag.agent_id == "agent-1"
        assert ag.customer_id == "cust-1"
        assert ag.total_runs == 10
        assert ag.successful_runs == 8
        assert ag.failed_runs == 2
        assert ag.qa_pass_rate == 0.85

    def test_trust_summary_fields(self):
        from summer_puppy.api.schemas.reporting import TrustSummary
        from summer_puppy.trust.models import TrustPhase

        ts = TrustSummary(
            customer_id="cust-1",
            trust_phase=TrustPhase.MANUAL,
            total_recommendations=10,
            total_approvals=8,
            total_rejections=2,
            positive_outcome_rate=0.8,
        )
        assert ts.customer_id == "cust-1"
        assert ts.trust_phase == TrustPhase.MANUAL
        assert ts.total_recommendations == 10
        assert ts.total_approvals == 8
        assert ts.total_rejections == 2
        assert ts.positive_outcome_rate == 0.8


# ---------------------------------------------------------------------------
# TestDashboardSummaryEndpoint
# ---------------------------------------------------------------------------


class TestDashboardSummaryEndpoint:
    async def test_summary_empty_registry(self, app, state, headers):
        response = await _request(
            app, "get", "/api/v1/customers/cust-1/dashboard/summary", headers=headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["events_24h"] == 0
        assert data["events_7d"] == 0
        assert data["open_critical"] == 0
        assert data["active_agents"] == 0
        assert data["orchestrator_ready"] is False

    async def test_summary_counts_events_24h(self, app, state, headers):
        # Add 2 events within 24h, 1 older
        ctx1 = _make_pipeline_context("cust-1", detected_offset_hours=1)
        ctx2 = _make_pipeline_context("cust-1", detected_offset_hours=12)
        ctx_old = _make_pipeline_context("cust-1", detected_offset_hours=48)
        state.event_registry["e1"] = ctx1
        state.event_registry["e2"] = ctx2
        state.event_registry["e3"] = ctx_old

        response = await _request(
            app, "get", "/api/v1/customers/cust-1/dashboard/summary", headers=headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["events_24h"] == 2
        assert data["events_7d"] == 3

    async def test_summary_orchestrator_ready_reflected(self, app, state, headers):
        from unittest.mock import MagicMock

        state.orchestrator = MagicMock()
        response = await _request(
            app, "get", "/api/v1/customers/cust-1/dashboard/summary", headers=headers
        )
        assert response.status_code == 200
        assert response.json()["orchestrator_ready"] is True

    async def test_summary_requires_auth(self, app):
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/dashboard/summary",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert response.status_code == 401

    async def test_summary_customer_mismatch_403(self, app):
        from summer_puppy.api.auth.jwt_handler import create_token

        other_token = create_token("cust-other", scopes=["reporting:read"])
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/dashboard/summary",
            headers={"Authorization": f"Bearer {other_token}"},
        )
        assert response.status_code == 403


# ---------------------------------------------------------------------------
# TestDashboardEventsEndpoint
# ---------------------------------------------------------------------------


class TestDashboardEventsEndpoint:
    async def test_events_empty(self, app, state, headers):
        response = await _request(
            app, "get", "/api/v1/customers/cust-1/dashboard/events", headers=headers
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_events_returns_list(self, app, state, headers):
        ctx = _make_pipeline_context("cust-1", detected_offset_hours=1)
        state.event_registry["e1"] = ctx

        response = await _request(
            app, "get", "/api/v1/customers/cust-1/dashboard/events", headers=headers
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["severity"] == "HIGH"
        assert data[0]["stage"] == "TRIAGE"

    async def test_events_pagination_limit(self, app, state, headers):
        for i in range(5):
            ctx = _make_pipeline_context("cust-1", detected_offset_hours=1)
            state.event_registry[f"e{i}"] = ctx

        response = await _request(
            app, "get", "/api/v1/customers/cust-1/dashboard/events?limit=2", headers=headers
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    async def test_events_requires_auth(self, app):
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/dashboard/events",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# TestDashboardAgentsEndpoint
# ---------------------------------------------------------------------------


class TestDashboardAgentsEndpoint:
    async def test_agents_empty(self, app, state, headers):
        response = await _request(
            app, "get", "/api/v1/customers/cust-1/dashboard/agents", headers=headers
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_agents_returns_profiles(self, app, state, headers):
        from summer_puppy.skills.models import SkillProfile

        profile = SkillProfile(
            agent_id="agent-abc",
            customer_id="cust-1",
            total_runs=5,
            successful_runs=4,
            failed_runs=1,
            qa_pass_rate=0.8,
        )
        state.skill_registry.update_agent_profile(profile)

        response = await _request(
            app, "get", "/api/v1/customers/cust-1/dashboard/agents", headers=headers
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["agent_id"] == "agent-abc"
        assert data[0]["total_runs"] == 5
        assert data[0]["qa_pass_rate"] == 0.8

    async def test_agents_requires_auth(self, app):
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/dashboard/agents",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# TestDashboardTrustEndpoint
# ---------------------------------------------------------------------------


class TestDashboardTrustEndpoint:
    async def test_trust_not_found_returns_default(self, app, state, headers):
        response = await _request(
            app, "get", "/api/v1/customers/cust-1/dashboard/trust", headers=headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["customer_id"] == "cust-1"
        assert data["trust_phase"] == "manual"
        assert data["total_recommendations"] == 0
        assert data["total_approvals"] == 0
        assert data["total_rejections"] == 0
        assert data["positive_outcome_rate"] == 0.0

    async def test_trust_returns_profile(self, app, state, headers):
        from summer_puppy.trust.models import TrustPhase, TrustProfile

        profile = TrustProfile(
            customer_id="cust-1",
            trust_phase=TrustPhase.SUPERVISED,
            total_recommendations=20,
            total_approvals=15,
            total_rejections=5,
            positive_outcome_rate=0.75,
        )
        state.trust_store["cust-1"] = profile

        response = await _request(
            app, "get", "/api/v1/customers/cust-1/dashboard/trust", headers=headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["trust_phase"] == "supervised"
        assert data["total_recommendations"] == 20
        assert data["total_approvals"] == 15
        assert data["total_rejections"] == 5
        assert data["positive_outcome_rate"] == 0.75

    async def test_trust_requires_auth(self, app):
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/dashboard/trust",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert response.status_code == 401
