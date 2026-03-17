"""Auth models: TokenPayload and ApiKey."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, Field


class TokenPayload(BaseModel):
    """Payload decoded from a JWT access token."""

    customer_id: str
    scopes: list[str]
    exp: int


class ApiKey(BaseModel):
    """Stored API key record (contains hash, never the raw key)."""

    key_id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str
    key_hash: str
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    revoked: bool = False
    description: str = ""
