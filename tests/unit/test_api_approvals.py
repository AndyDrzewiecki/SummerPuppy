from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from summer_puppy.api.app import app
from summer_puppy.api.auth.jwt_handler import create_token
from summer_puppy.api.state import init_app_state, reset_app_state
from summer_puppy.events.models import QAStatus, Recommendation, SecurityEvent, Severity
from summer_puppy.pipeline.models import PipelineContext, PipelineStage, PipelineStatus
from summer_puppy.trust.models import ActionClass, TrustProfile


def _make_paused_ctx(customer_id: str, event_id: str) -> PipelineContext:
    """Helper: build a paused PipelineContext ready for approval."""
    event = SecurityEvent(
        event_id=event_id,
        customer_id=customer_id,
        title="Test event",
        description="Test",
        severity=Severity.HIGH,
        source="SIEM",
    )
    rec = Recommendation(
        event_id=event_id,
        customer_id=customer_id,
        action_class=ActionClass.PATCH_DEPLOYMENT,
        description="Fix it",
        reasoning="Test",
        confidence_score=0.9,
        estimated_risk=Severity.LOW,
        qa_status=QAStatus.PASSED,
        rollback_plan="Rollback available",
    )
    ctx = PipelineContext(
        event=event,
        customer_id=customer_id,
        correlation_id="test-corr",
        trust_profile=TrustProfile(customer_id=customer_id),
    )
    ctx.recommendation = rec
    ctx.current_stage = PipelineStage.APPROVE
    ctx.status = PipelineStatus.PAUSED_FOR_APPROVAL
    return ctx


@pytest.fixture(autouse=True)
def reset_state():
    reset_app_state()
    init_app_state()
    yield
    reset_app_state()


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


@pytest.mark.asyncio
async def test_approve_paused_event_completes(client):
    state = init_app_state()
    customer_id = "approve-cust"
    event_id = "evt-approve-1"
    ctx = _make_paused_ctx(customer_id, event_id)
    state.event_registry[event_id] = ctx
    token = create_token(customer_id, scopes=["events:write"])
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.post(
        f"/api/v1/customers/{customer_id}/events/{event_id}/approve",
        headers=headers,
        json={"approved": True, "actor": "human"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["approved"] is True
    assert data["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_reject_paused_event_fails(client):
    state = init_app_state()
    customer_id = "reject-cust"
    event_id = "evt-reject-1"
    ctx = _make_paused_ctx(customer_id, event_id)
    state.event_registry[event_id] = ctx
    token = create_token(customer_id, scopes=["events:write"])
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.post(
        f"/api/v1/customers/{customer_id}/events/{event_id}/approve",
        headers=headers,
        json={"approved": False, "actor": "human", "notes": "Not needed"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["approved"] is False
    assert data["status"] == "FAILED"
    updated_ctx = state.event_registry[event_id]
    assert updated_ctx is not None
    assert "Rejected by human" in updated_ctx.error_detail


@pytest.mark.asyncio
async def test_approve_nonexistent_event_returns_404(client):
    customer_id = "notfound-cust"
    token = create_token(customer_id, scopes=["events:write"])
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.post(
        f"/api/v1/customers/{customer_id}/events/nonexistent/approve",
        headers=headers,
        json={"approved": True},
    )
    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_approve_non_paused_event_returns_409(client):
    state = init_app_state()
    customer_id = "running-cust"
    event_id = "evt-running-1"
    ctx = _make_paused_ctx(customer_id, event_id)
    ctx.status = PipelineStatus.RUNNING  # Not paused
    state.event_registry[event_id] = ctx
    token = create_token(customer_id, scopes=["events:write"])
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.post(
        f"/api/v1/customers/{customer_id}/events/{event_id}/approve",
        headers=headers,
        json={"approved": True},
    )
    assert resp.status_code == 409, resp.text


@pytest.mark.asyncio
async def test_approve_wrong_customer_returns_403(client):
    state = init_app_state()
    real_customer = "real-cust-1"
    event_id = "evt-owner-1"
    ctx = _make_paused_ctx(real_customer, event_id)
    state.event_registry[event_id] = ctx
    # Token for a different customer
    token = create_token("other-cust", scopes=["events:write"])
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.post(
        f"/api/v1/customers/other-cust/events/{event_id}/approve",
        headers=headers,
        json={"approved": True},
    )
    assert resp.status_code == 403, resp.text
