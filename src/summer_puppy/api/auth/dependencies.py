"""FastAPI dependency functions for authentication and authorization."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Depends, Header, HTTPException  # noqa: TCH002

from summer_puppy.api.auth.jwt_handler import decode_token
from summer_puppy.api.state import AppState, get_app_state

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


async def get_current_customer(
    authorization: str = Header(alias="Authorization"),
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> str:
    """Extract and validate Bearer token; return customer_id."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    payload = decode_token(authorization.removeprefix("Bearer "))
    return payload.customer_id


def require_scope(scope: str) -> Callable[..., Awaitable[str]]:
    """Return a dependency that enforces the given scope."""

    async def _check(
        authorization: str = Header(alias="Authorization"),
        state: AppState = Depends(get_app_state),  # noqa: B008
    ) -> str:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Bearer token required")
        payload = decode_token(authorization.removeprefix("Bearer "))
        if scope not in payload.scopes:
            raise HTTPException(status_code=403, detail=f"Scope '{scope}' required")
        return payload.customer_id

    return _check


require_admin = require_scope("admin")
