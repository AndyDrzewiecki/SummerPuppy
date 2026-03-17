"""JWT token creation and decoding."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import structlog
from fastapi import HTTPException

from summer_puppy.api.auth.models import TokenPayload

logger = structlog.get_logger()
ALGORITHM = "HS256"
_DEFAULT_SECRET = "dev-secret-change-in-prod"


def _get_secret() -> str:
    from summer_puppy.api.settings import get_settings

    secret = get_settings().app_secret_key
    if secret == _DEFAULT_SECRET:
        logger.warning("jwt_using_default_secret")
    return secret


def create_token(customer_id: str, scopes: list[str], ttl_seconds: int = 3600) -> str:
    """Create a signed JWT for the given customer."""
    now = datetime.now(tz=UTC)
    payload = {
        "sub": customer_id,
        "scopes": scopes,
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "iat": int(now.timestamp()),
    }
    return jwt.encode(payload, _get_secret(), algorithm=ALGORITHM)


def decode_token(token: str) -> TokenPayload:
    """Decode and validate a JWT; raises HTTPException on failure."""
    try:
        data = jwt.decode(token, _get_secret(), algorithms=[ALGORITHM])
        return TokenPayload(
            customer_id=data["sub"],
            scopes=data.get("scopes", []),
            exp=data["exp"],
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
