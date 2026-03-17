"""Tests for JWT + API Key Authentication — RED phase (written before implementation)."""

from __future__ import annotations

import hashlib

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
def app():
    from summer_puppy.api.app import app as _app

    return _app


@pytest.fixture
def state():
    from summer_puppy.api.state import get_app_state

    return get_app_state()


@pytest.fixture
def admin_token():
    from summer_puppy.api.auth.jwt_handler import create_token

    return create_token("admin-customer", scopes=["admin"])


@pytest.fixture
def user_token():
    from summer_puppy.api.auth.jwt_handler import create_token

    return create_token("user-123", scopes=["events:write", "policies:write"])


async def _request(app, method: str, path: str, **kwargs):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await getattr(client, method)(path, **kwargs)


# ---------------------------------------------------------------------------
# TestTokenPayload
# ---------------------------------------------------------------------------


class TestTokenPayload:
    def test_token_payload_fields(self):
        from summer_puppy.api.auth.models import TokenPayload

        payload = TokenPayload(customer_id="cust-1", scopes=["read", "write"], exp=9999999999)
        assert payload.customer_id == "cust-1"
        assert payload.scopes == ["read", "write"]
        assert payload.exp == 9999999999

    def test_token_payload_scopes_list(self):
        from summer_puppy.api.auth.models import TokenPayload

        payload = TokenPayload(customer_id="c", scopes=[], exp=1)
        assert isinstance(payload.scopes, list)

    def test_token_payload_scopes_multiple(self):
        from summer_puppy.api.auth.models import TokenPayload

        scopes = ["events:write", "policies:write", "notifications:write", "reporting:read"]
        payload = TokenPayload(customer_id="c", scopes=scopes, exp=1)
        assert len(payload.scopes) == 4


# ---------------------------------------------------------------------------
# TestApiKey
# ---------------------------------------------------------------------------


class TestApiKey:
    def test_api_key_defaults(self):
        from summer_puppy.api.auth.models import ApiKey

        key = ApiKey(customer_id="cust-1", key_hash="abc123")
        assert key.customer_id == "cust-1"
        assert key.key_hash == "abc123"
        assert key.revoked is False
        assert key.description == ""
        assert key.key_id is not None

    def test_api_key_has_key_id(self):
        from summer_puppy.api.auth.models import ApiKey

        key = ApiKey(customer_id="c", key_hash="h")
        assert isinstance(key.key_id, str)
        assert len(key.key_id) > 0

    def test_api_key_revoked_default_false(self):
        from summer_puppy.api.auth.models import ApiKey

        key = ApiKey(customer_id="c", key_hash="h")
        assert key.revoked is False

    def test_api_key_unique_ids(self):
        from summer_puppy.api.auth.models import ApiKey

        k1 = ApiKey(customer_id="c", key_hash="h1")
        k2 = ApiKey(customer_id="c", key_hash="h2")
        assert k1.key_id != k2.key_id

    def test_api_key_description(self):
        from summer_puppy.api.auth.models import ApiKey

        key = ApiKey(customer_id="c", key_hash="h", description="My key")
        assert key.description == "My key"


# ---------------------------------------------------------------------------
# TestJwtHandler
# ---------------------------------------------------------------------------


class TestJwtHandler:
    def test_create_token_returns_string(self):
        from summer_puppy.api.auth.jwt_handler import create_token

        token = create_token("cust-1", scopes=["read"])
        assert isinstance(token, str)
        assert len(token) > 10

    def test_decode_token_returns_payload(self):
        from summer_puppy.api.auth.jwt_handler import create_token, decode_token

        token = create_token("cust-1", scopes=["read"])
        payload = decode_token(token)
        assert payload is not None

    def test_decode_token_customer_id_preserved(self):
        from summer_puppy.api.auth.jwt_handler import create_token, decode_token

        token = create_token("cust-abc", scopes=["read"])
        payload = decode_token(token)
        assert payload.customer_id == "cust-abc"

    def test_decode_token_scopes_preserved(self):
        from summer_puppy.api.auth.jwt_handler import create_token, decode_token

        scopes = ["events:write", "policies:write"]
        token = create_token("cust-1", scopes=scopes)
        payload = decode_token(token)
        assert payload.scopes == scopes

    def test_decode_expired_token_raises_401(self):
        from fastapi import HTTPException

        from summer_puppy.api.auth.jwt_handler import create_token, decode_token

        token = create_token("cust-1", scopes=["read"], ttl_seconds=-1)
        with pytest.raises(HTTPException) as exc:
            decode_token(token)
        assert exc.value.status_code == 401

    def test_decode_invalid_token_raises_401(self):
        from fastapi import HTTPException

        from summer_puppy.api.auth.jwt_handler import decode_token

        with pytest.raises(HTTPException) as exc:
            decode_token("not.a.valid.token")
        assert exc.value.status_code == 401

    def test_create_decode_roundtrip(self):
        from summer_puppy.api.auth.jwt_handler import create_token, decode_token

        token = create_token("roundtrip-cust", scopes=["admin", "read"])
        payload = decode_token(token)
        assert payload.customer_id == "roundtrip-cust"
        assert "admin" in payload.scopes
        assert "read" in payload.scopes


# ---------------------------------------------------------------------------
# TestApiKeyHandler
# ---------------------------------------------------------------------------


class TestApiKeyHandler:
    def test_generate_api_key_returns_tuple(self):
        from summer_puppy.api.auth.api_key_handler import generate_api_key

        result = generate_api_key("cust-1")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_generate_raw_key_not_stored_in_model(self):
        from summer_puppy.api.auth.api_key_handler import generate_api_key

        raw_key, api_key = generate_api_key("cust-1")
        # The raw key itself should not be stored in the model
        assert raw_key != api_key.key_hash
        # Model should not have a raw_key field
        assert not hasattr(api_key, "raw_key")

    def test_verify_api_key_correct(self):
        from summer_puppy.api.auth.api_key_handler import generate_api_key, verify_api_key

        raw_key, api_key = generate_api_key("cust-1")
        assert verify_api_key(raw_key, api_key.key_hash) is True

    def test_verify_api_key_wrong_returns_false(self):
        from summer_puppy.api.auth.api_key_handler import generate_api_key, verify_api_key

        _raw_key, api_key = generate_api_key("cust-1")
        assert verify_api_key("wrong-key", api_key.key_hash) is False

    def test_api_key_hash_is_sha256(self):
        from summer_puppy.api.auth.api_key_handler import generate_api_key

        raw_key, api_key = generate_api_key("cust-1")
        expected_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        assert api_key.key_hash == expected_hash


# ---------------------------------------------------------------------------
# TestInMemoryTenantStoreApiKeys
# ---------------------------------------------------------------------------


class TestInMemoryTenantStoreApiKeys:
    def test_save_api_key(self, state):
        from summer_puppy.api.auth.api_key_handler import generate_api_key

        _raw, api_key = generate_api_key("cust-1")
        state.tenant_store.save_api_key(api_key)
        # No exception raised = success; verify via find
        found = state.tenant_store.find_api_key_by_hash(api_key.key_hash)
        assert found is not None

    def test_find_api_key_by_hash_found(self, state):
        from summer_puppy.api.auth.api_key_handler import generate_api_key

        raw_key, api_key = generate_api_key("cust-1")
        state.tenant_store.save_api_key(api_key)
        found = state.tenant_store.find_api_key_by_hash(api_key.key_hash)
        assert found is not None
        assert found.customer_id == "cust-1"

    def test_find_api_key_by_hash_not_found(self, state):
        result = state.tenant_store.find_api_key_by_hash("nonexistent-hash")
        assert result is None

    def test_revoke_api_key(self, state):
        from summer_puppy.api.auth.api_key_handler import generate_api_key

        _raw, api_key = generate_api_key("cust-1")
        state.tenant_store.save_api_key(api_key)
        result = state.tenant_store.revoke_api_key(api_key.key_id)
        assert result is True

    def test_revoke_returns_false_for_unknown(self, state):
        result = state.tenant_store.revoke_api_key("nonexistent-key-id")
        assert result is False

    def test_revoked_key_not_found_by_hash(self, state):
        from summer_puppy.api.auth.api_key_handler import generate_api_key

        raw_key, api_key = generate_api_key("cust-1")
        state.tenant_store.save_api_key(api_key)
        state.tenant_store.revoke_api_key(api_key.key_id)
        found = state.tenant_store.find_api_key_by_hash(api_key.key_hash)
        assert found is None


# ---------------------------------------------------------------------------
# TestAuthEndpoints
# ---------------------------------------------------------------------------


class TestAuthEndpoints:
    async def test_post_auth_token_returns_jwt(self, app, state):
        from summer_puppy.api.auth.api_key_handler import generate_api_key

        raw_key, api_key = generate_api_key("cust-1")
        state.tenant_store.save_api_key(api_key)

        response = await _request(app, "post", "/api/v1/auth/token", json={"api_key": raw_key})
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert isinstance(data["access_token"], str)
        assert len(data["access_token"]) > 10

    async def test_post_auth_token_invalid_key_returns_401(self, app):
        response = await _request(
            app, "post", "/api/v1/auth/token", json={"api_key": "invalid-key"}
        )
        assert response.status_code == 401

    async def test_post_auth_token_revoked_key_returns_401(self, app, state):
        from summer_puppy.api.auth.api_key_handler import generate_api_key

        raw_key, api_key = generate_api_key("cust-1")
        state.tenant_store.save_api_key(api_key)
        state.tenant_store.revoke_api_key(api_key.key_id)

        response = await _request(app, "post", "/api/v1/auth/token", json={"api_key": raw_key})
        assert response.status_code == 401

    async def test_post_auth_keys_without_admin_returns_403(self, app, user_token):
        response = await _request(
            app,
            "post",
            "/api/v1/auth/keys",
            json={"customer_id": "cust-new"},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    async def test_post_auth_keys_with_admin_returns_raw_key(self, app, admin_token):
        response = await _request(
            app,
            "post",
            "/api/v1/auth/keys",
            json={"customer_id": "cust-new", "description": "test key"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "raw_key" in data
        assert "key_id" in data
        assert data["customer_id"] == "cust-new"
        assert isinstance(data["raw_key"], str)
        assert len(data["raw_key"]) > 10

    async def test_delete_auth_key_returns_204(self, app, admin_token, state):
        from summer_puppy.api.auth.api_key_handler import generate_api_key

        _raw, api_key = generate_api_key("cust-1")
        state.tenant_store.save_api_key(api_key)

        response = await _request(
            app,
            "delete",
            f"/api/v1/auth/keys/{api_key.key_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 204

    async def test_delete_unknown_key_returns_404(self, app, admin_token):
        response = await _request(
            app,
            "delete",
            "/api/v1/auth/keys/nonexistent-key-id",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404
