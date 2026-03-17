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


@pytest.mark.asyncio
async def test_full_mvp_flow(client):
    """8-step MVP smoke test: onboard → auth → submit → pause → approve → complete → dashboard."""
    customer_id = "smoke-cust-1"

    # Step 1: POST /api/v1/customers — onboard, get raw API key
    resp = await client.post("/api/v1/customers", json={"customer_id": customer_id})
    assert resp.status_code == 201, f"Step 1 failed: {resp.text}"
    raw_key = resp.json()["api_key"]
    assert raw_key

    # Step 2: POST /api/v1/auth/token — exchange key for JWT
    resp = await client.post("/api/v1/auth/token", json={"api_key": raw_key})
    assert resp.status_code == 200, f"Step 2 failed: {resp.text}"
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 3: POST /api/v1/{customer_id}/events (HIGH severity) — get event_id
    resp = await client.post(
        f"/api/v1/{customer_id}/events",
        headers=headers,
        json={
            "title": "E2E smoke test event",
            "description": "Full MVP flow validation",
            "severity": "HIGH",
            "source": "MANUAL",
            "affected_assets": [],
        },
    )
    assert resp.status_code == 202, f"Step 3 failed: {resp.text}"
    event_id = resp.json()["event_id"]
    assert event_id

    # Step 4: Poll until PAUSED_FOR_APPROVAL (max 5s)
    final_status = None
    for _ in range(50):
        await asyncio.sleep(0.1)
        resp = await client.get(
            f"/api/v1/{customer_id}/events/{event_id}",
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        if body.get("status") == "PAUSED_FOR_APPROVAL":
            final_status = "PAUSED_FOR_APPROVAL"
            break
    assert final_status == "PAUSED_FOR_APPROVAL", "Step 4: never reached PAUSED_FOR_APPROVAL"

    # Step 5: POST approve
    resp = await client.post(
        f"/api/v1/customers/{customer_id}/events/{event_id}/approve",
        headers=headers,
        json={"approved": True, "actor": "smoke-test-human"},
    )
    assert resp.status_code == 200, f"Step 5 failed: {resp.text}"

    # Step 6: Poll until COMPLETED (max 5s)
    final_status = None
    for _ in range(50):
        await asyncio.sleep(0.1)
        resp = await client.get(
            f"/api/v1/{customer_id}/events/{event_id}",
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        if body.get("status") == "COMPLETED":
            final_status = "COMPLETED"
            break
    assert final_status == "COMPLETED", f"Step 6: never reached COMPLETED, last status: {body}"

    # Step 7: GET /api/v1/customers/{customer_id}/dashboard/summary — events_24h >= 1
    resp = await client.get(
        f"/api/v1/customers/{customer_id}/dashboard/summary",
        headers=headers,
    )
    assert resp.status_code == 200, f"Step 7 failed: {resp.text}"
    summary = resp.json()
    assert summary.get("events_24h", 0) >= 1, f"Step 7: events_24h should be >= 1, got {summary}"

    # Step 8: GET /api/v1/customers/{customer_id}/dashboard/trust — trust_phase == "manual"
    resp = await client.get(
        f"/api/v1/customers/{customer_id}/dashboard/trust",
        headers=headers,
    )
    assert resp.status_code == 200, f"Step 8 failed: {resp.text}"
    trust_data = resp.json()
    assert trust_data.get("trust_phase") == "manual", (
        f"Step 8: expected trust_phase=manual, got {trust_data}"
    )
