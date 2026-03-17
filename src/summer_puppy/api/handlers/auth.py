"""Auth endpoints: token exchange and API key management."""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from summer_puppy.api.auth.api_key_handler import generate_api_key
from summer_puppy.api.auth.dependencies import require_admin
from summer_puppy.api.auth.jwt_handler import create_token
from summer_puppy.api.state import AppState, get_app_state

router = APIRouter()


class TokenRequest(BaseModel):
    api_key: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600


class CreateKeyRequest(BaseModel):
    customer_id: str
    description: str = ""


class CreateKeyResponse(BaseModel):
    key_id: str
    raw_key: str
    customer_id: str


@router.post("/token", response_model=TokenResponse)
async def get_token(
    body: TokenRequest,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> TokenResponse:
    """Exchange a raw API key for a JWT access token."""
    key_hash = hashlib.sha256(body.api_key.encode()).hexdigest()
    stored = state.tenant_store.find_api_key_by_hash(key_hash)
    if stored is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    token = create_token(
        stored.customer_id,
        scopes=["events:write", "policies:write", "notifications:write", "reporting:read"],
    )
    return TokenResponse(access_token=token)


@router.post("/keys", response_model=CreateKeyResponse)
async def create_api_key(
    body: CreateKeyRequest,
    _: str = Depends(require_admin),  # noqa: B008
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> CreateKeyResponse:
    """Create a new API key for a customer (admin scope required)."""
    raw_key, api_key = generate_api_key(body.customer_id, body.description)
    state.tenant_store.save_api_key(api_key)
    return CreateKeyResponse(key_id=api_key.key_id, raw_key=raw_key, customer_id=body.customer_id)


@router.delete("/keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: str,
    _: str = Depends(require_admin),  # noqa: B008
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> None:
    """Revoke an API key (admin scope required)."""
    revoked = state.tenant_store.revoke_api_key(key_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="API key not found")
