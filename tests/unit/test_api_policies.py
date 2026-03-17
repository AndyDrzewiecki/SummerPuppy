"""Tests for Policy Management CRUD API — Story 4, Sprint 6."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_state():
    """Reset AppState singleton before/after each test."""
    from summer_puppy.api.state import init_app_state, reset_app_state

    reset_app_state()
    init_app_state()
    yield
    reset_app_state()


@pytest.fixture
def state():
    from summer_puppy.api.state import get_app_state

    return get_app_state()


@pytest.fixture
def app():
    from summer_puppy.api.app import app as _app

    return _app


@pytest.fixture
def auth_headers():
    from summer_puppy.api.auth.jwt_handler import create_token

    token = create_token("cust-1", scopes=["policies:write"])
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def other_auth_headers():
    from summer_puppy.api.auth.jwt_handler import create_token

    token = create_token("cust-other", scopes=["policies:write"])
    return {"Authorization": f"Bearer {token}"}


async def _request(app, method: str, path: str, **kwargs):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await getattr(client, method)(path, **kwargs)


# ---------------------------------------------------------------------------
# TestPolicySchemas
# ---------------------------------------------------------------------------


class TestPolicySchemas:
    def test_create_policy_request_valid(self):
        from summer_puppy.api.schemas.policies import CreatePolicyRequest
        from summer_puppy.trust.models import ActionClass

        req = CreatePolicyRequest(action_class=ActionClass.PATCH_DEPLOYMENT)
        assert req.action_class == ActionClass.PATCH_DEPLOYMENT
        assert req.max_severity == "MEDIUM"
        assert req.expires_utc is None
        assert req.created_by == "api"

    def test_create_policy_request_missing_action_class_raises(self):
        from pydantic import ValidationError

        from summer_puppy.api.schemas.policies import CreatePolicyRequest

        with pytest.raises(ValidationError):
            CreatePolicyRequest()  # type: ignore[call-arg]

    def test_patch_policy_request_partial(self):
        from summer_puppy.api.schemas.policies import PatchPolicyRequest

        req = PatchPolicyRequest(max_severity="HIGH")
        assert req.max_severity == "HIGH"
        assert req.expires_utc is None
        assert req.status is None

    def test_policy_response_fields(self):
        from summer_puppy.api.schemas.policies import PolicyResponse
        from summer_puppy.trust.models import ActionClass, PolicyStatus

        resp = PolicyResponse(
            policy_id="pid-1",
            customer_id="cust-1",
            action_class=ActionClass.BLOCK_IP,
            status=PolicyStatus.ACTIVE,
            max_severity="LOW",
            expires_utc=None,
        )
        assert resp.policy_id == "pid-1"
        assert resp.customer_id == "cust-1"
        assert resp.status == PolicyStatus.ACTIVE
        assert resp.expires_utc is None

    def test_protected_asset_request_valid(self):
        from summer_puppy.api.schemas.policies import ProtectedAssetRequest

        req = ProtectedAssetRequest(asset_id="asset-abc", reason="critical server")
        assert req.asset_id == "asset-abc"
        assert req.reason == "critical server"
        assert req.protected_until is None

    def test_protected_asset_request_empty_id_raises(self):
        from pydantic import ValidationError

        from summer_puppy.api.schemas.policies import ProtectedAssetRequest

        with pytest.raises(ValidationError):
            ProtectedAssetRequest(asset_id="")


# ---------------------------------------------------------------------------
# TestAutoApprovalPolicyCRUD
# ---------------------------------------------------------------------------


class TestAutoApprovalPolicyCRUD:
    async def test_create_policy_returns_201(self, app, auth_headers):
        response = await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/auto-approval",
            json={"action_class": "patch_deployment"},
            headers=auth_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert "policy_id" in data
        assert data["customer_id"] == "cust-1"
        assert data["action_class"] == "patch_deployment"
        assert data["status"] == "active"

    async def test_create_policy_stored_in_tenant_profile(self, app, auth_headers, state):
        response = await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/auto-approval",
            json={"action_class": "block_ip"},
            headers=auth_headers,
        )
        assert response.status_code == 201
        policy_id = response.json()["policy_id"]

        profile = state.tenant_store.get("cust-1")
        assert profile is not None
        assert any(p.policy_id == policy_id for p in profile.auto_approval_policies)

    async def test_create_policy_audit_logged(self, app, auth_headers, state):
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/auto-approval",
            json={"action_class": "rollback"},
            headers=auth_headers,
        )
        # Allow fire-and-forget task to complete
        import asyncio

        await asyncio.sleep(0.05)
        entries = state.audit_logger._entries
        policy_entries = [e for e in entries if e.entry_type == "POLICY_CHANGED"]
        assert len(policy_entries) >= 1

    async def test_list_policies_empty(self, app, auth_headers):
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/policies/auto-approval",
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_list_policies_returns_created(self, app, auth_headers):
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/auto-approval",
            json={"action_class": "patch_deployment"},
            headers=auth_headers,
        )
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/auto-approval",
            json={"action_class": "block_ip"},
            headers=auth_headers,
        )
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/policies/auto-approval",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        action_classes = {p["action_class"] for p in data}
        assert action_classes == {"patch_deployment", "block_ip"}

    async def test_patch_policy_updates_max_severity(self, app, auth_headers):
        create_resp = await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/auto-approval",
            json={"action_class": "disable_account", "max_severity": "LOW"},
            headers=auth_headers,
        )
        policy_id = create_resp.json()["policy_id"]

        patch_resp = await _request(
            app,
            "patch",
            f"/api/v1/customers/cust-1/policies/auto-approval/{policy_id}",
            json={"max_severity": "CRITICAL"},
            headers=auth_headers,
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["max_severity"] == "CRITICAL"

    async def test_patch_policy_not_found_404(self, app, auth_headers):
        response = await _request(
            app,
            "patch",
            "/api/v1/customers/cust-1/policies/auto-approval/nonexistent-id",
            json={"max_severity": "HIGH"},
            headers=auth_headers,
        )
        assert response.status_code == 404

    async def test_delete_policy_soft_deletes(self, app, auth_headers, state):
        create_resp = await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/auto-approval",
            json={"action_class": "rollback"},
            headers=auth_headers,
        )
        policy_id = create_resp.json()["policy_id"]

        del_resp = await _request(
            app,
            "delete",
            f"/api/v1/customers/cust-1/policies/auto-approval/{policy_id}",
            headers=auth_headers,
        )
        assert del_resp.status_code == 204

        # Confirm soft delete: policy still in store but REVOKED
        profile = state.tenant_store.get("cust-1")
        assert profile is not None
        policy = next(
            (p for p in profile.auto_approval_policies if p.policy_id == policy_id), None
        )
        assert policy is not None
        assert policy.status == "revoked"

    async def test_delete_policy_not_found_404(self, app, auth_headers):
        response = await _request(
            app,
            "delete",
            "/api/v1/customers/cust-1/policies/auto-approval/nonexistent-id",
            headers=auth_headers,
        )
        assert response.status_code == 404

    async def test_delete_policy_audit_logged(self, app, auth_headers, state):
        create_resp = await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/auto-approval",
            json={"action_class": "network_isolation"},
            headers=auth_headers,
        )
        policy_id = create_resp.json()["policy_id"]

        await _request(
            app,
            "delete",
            f"/api/v1/customers/cust-1/policies/auto-approval/{policy_id}",
            headers=auth_headers,
        )
        import asyncio

        await asyncio.sleep(0.05)
        entries = state.audit_logger._entries
        delete_entries = [
            e
            for e in entries
            if e.entry_type == "POLICY_CHANGED" and e.details.get("action") == "delete"
        ]
        assert len(delete_entries) >= 1


# ---------------------------------------------------------------------------
# TestProtectedAssetsCRUD
# ---------------------------------------------------------------------------


class TestProtectedAssetsCRUD:
    async def test_add_protected_asset_returns_201(self, app, auth_headers):
        response = await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/protected-assets",
            json={"asset_id": "server-99", "reason": "prod db"},
            headers=auth_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["asset_id"] == "server-99"
        assert data["reason"] == "prod db"

    async def test_add_protected_asset_stored(self, app, auth_headers, state):
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/protected-assets",
            json={"asset_id": "asset-x", "reason": "critical"},
            headers=auth_headers,
        )
        profile = state.tenant_store.get("cust-1")
        assert profile is not None
        assert any(a.asset_id == "asset-x" for a in profile.protected_assets)

    async def test_remove_protected_asset_204(self, app, auth_headers):
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/protected-assets",
            json={"asset_id": "asset-del", "reason": "test"},
            headers=auth_headers,
        )
        response = await _request(
            app,
            "delete",
            "/api/v1/customers/cust-1/policies/protected-assets/asset-del",
            headers=auth_headers,
        )
        assert response.status_code == 204

    async def test_remove_protected_asset_not_found_404(self, app, auth_headers):
        response = await _request(
            app,
            "delete",
            "/api/v1/customers/cust-1/policies/protected-assets/nonexistent",
            headers=auth_headers,
        )
        assert response.status_code == 404

    async def test_list_protected_assets_endpoint(self, app, auth_headers):
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/protected-assets",
            json={"asset_id": "asset-list-1", "reason": "r1"},
            headers=auth_headers,
        )
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/protected-assets",
            json={"asset_id": "asset-list-2", "reason": "r2"},
            headers=auth_headers,
        )
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/policies/protected-assets",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2


# ---------------------------------------------------------------------------
# TestAuthOnPolicies
# ---------------------------------------------------------------------------


class TestAuthOnPolicies:
    async def test_policy_endpoints_require_auth(self, app):
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/policies/auto-approval",
        )
        assert response.status_code == 422  # Missing Authorization header -> validation error

    async def test_policy_endpoints_reject_invalid_token(self, app):
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/policies/auto-approval",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert response.status_code == 401

    async def test_policy_customer_mismatch_403(self, app, other_auth_headers):
        # other_auth_headers is for cust-other, but path is cust-1
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/policies/auto-approval",
            headers=other_auth_headers,
        )
        assert response.status_code == 403

    async def test_policy_create_mismatch_403(self, app, other_auth_headers):
        response = await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/policies/auto-approval",
            json={"action_class": "rollback"},
            headers=other_auth_headers,
        )
        assert response.status_code == 403

    async def test_policy_delete_mismatch_403(self, app, other_auth_headers):
        response = await _request(
            app,
            "delete",
            "/api/v1/customers/cust-1/policies/auto-approval/some-id",
            headers=other_auth_headers,
        )
        assert response.status_code == 403
