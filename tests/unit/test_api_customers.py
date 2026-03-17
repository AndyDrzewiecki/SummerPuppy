"""Tests for the /api/v1/customers endpoint."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from summer_puppy.api.app import app
from summer_puppy.api.auth.jwt_handler import create_token
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
async def test_post_customers_creates_tenant_and_returns_api_key(client):
    resp = await client.post(
        "/api/v1/customers",
        json={"customer_id": "new-cust-1"},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["customer_id"] == "new-cust-1"
    assert data["trust_phase"] == "manual"
    assert len(data["api_key"]) > 0


@pytest.mark.asyncio
async def test_post_customers_duplicate_returns_409(client):
    await client.post("/api/v1/customers", json={"customer_id": "dup-cust"})
    resp = await client.post("/api/v1/customers", json={"customer_id": "dup-cust"})
    assert resp.status_code == 409, resp.text


@pytest.mark.asyncio
async def test_get_customer_returns_status(client):
    # Register first
    post_resp = await client.post("/api/v1/customers", json={"customer_id": "stat-cust"})
    assert post_resp.status_code == 201
    # Get token for this customer
    token = create_token("stat-cust", scopes=["events:write"])
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.get("/api/v1/customers/stat-cust", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["trust_phase"] == "manual"
    assert data["total_recommendations"] == 0
    assert data["total_approvals"] == 0
    assert data["total_rejections"] == 0


@pytest.mark.asyncio
async def test_get_customer_wrong_token_returns_403(client):
    await client.post("/api/v1/customers", json={"customer_id": "real-cust"})
    token = create_token("other-cust", scopes=["events:write"])
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.get("/api/v1/customers/real-cust", headers=headers)
    assert resp.status_code == 403, resp.text
