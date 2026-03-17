from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from summer_puppy.api.app import app
from summer_puppy.api.state import init_app_state, reset_app_state


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


async def _onboard_and_login(client: AsyncClient, customer_id: str) -> str:
    """Register customer, get API key, exchange for JWT. Returns Bearer token."""
    post = await client.post("/api/v1/customers", json={"customer_id": customer_id})
    assert post.status_code == 201, post.text
    raw_key = post.json()["api_key"]
    tok = await client.post("/api/v1/auth/token", json={"api_key": raw_key})
    assert tok.status_code == 200, tok.text
    return tok.json()["access_token"]


async def _submit_event(client: AsyncClient, customer_id: str, headers: dict[str, str]) -> str:
    """Submit a HIGH-severity event. Returns event_id."""
    resp = await client.post(
        f"/api/v1/{customer_id}/events",
        headers=headers,
        json={
            "title": "Approval lifecycle test",
            "description": "Testing human approval flow",
            "severity": "HIGH",
            "source": "MANUAL",
            "affected_assets": [],
        },
    )
    assert resp.status_code == 202, resp.text
    return resp.json()["event_id"]


async def _poll_status(
    client: AsyncClient,
    customer_id: str,
    event_id: str,
    headers: dict[str, str],
    target_status: str,
    max_wait: float = 5.0,
) -> dict[str, object]:
    """Poll event status until target_status or timeout."""
    interval = 0.1
    elapsed = 0.0
    while elapsed < max_wait:
        await asyncio.sleep(interval)
        elapsed += interval
        resp = await client.get(f"/api/v1/{customer_id}/events/{event_id}", headers=headers)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        if data.get("status") == target_status:
            return data  # type: ignore[return-value]
    return {}


@pytest.mark.asyncio
async def test_approve_lifecycle_completes(client: AsyncClient) -> None:
    """Submit → poll PAUSED → approve → poll COMPLETED."""
    customer_id = "approve-life-cust"
    token = await _onboard_and_login(client, customer_id)
    headers = {"Authorization": f"Bearer {token}"}

    event_id = await _submit_event(client, customer_id, headers)

    # Poll until PAUSED_FOR_APPROVAL
    data = await _poll_status(client, customer_id, event_id, headers, "PAUSED_FOR_APPROVAL")
    assert data.get("status") == "PAUSED_FOR_APPROVAL", (
        f"Did not reach PAUSED_FOR_APPROVAL, got: {data}"
    )

    # Approve
    approve_resp = await client.post(
        f"/api/v1/customers/{customer_id}/events/{event_id}/approve",
        headers=headers,
        json={"approved": True, "actor": "human-test"},
    )
    assert approve_resp.status_code == 200, approve_resp.text
    assert approve_resp.json()["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_reject_lifecycle_fails(client: AsyncClient) -> None:
    """Submit → poll PAUSED → reject → status FAILED."""
    customer_id = "reject-life-cust"
    token = await _onboard_and_login(client, customer_id)
    headers = {"Authorization": f"Bearer {token}"}

    event_id = await _submit_event(client, customer_id, headers)

    # Poll until PAUSED_FOR_APPROVAL
    data = await _poll_status(client, customer_id, event_id, headers, "PAUSED_FOR_APPROVAL")
    assert data.get("status") == "PAUSED_FOR_APPROVAL", (
        f"Did not reach PAUSED_FOR_APPROVAL, got: {data}"
    )

    # Reject
    reject_resp = await client.post(
        f"/api/v1/customers/{customer_id}/events/{event_id}/approve",
        headers=headers,
        json={"approved": False, "actor": "human-test", "notes": "Not necessary"},
    )
    assert reject_resp.status_code == 200, reject_resp.text
    assert reject_resp.json()["status"] == "FAILED"
