"""API authentication utilities."""

from __future__ import annotations

from summer_puppy.api.auth.api_key_handler import generate_api_key, verify_api_key
from summer_puppy.api.auth.dependencies import get_current_customer, require_admin, require_scope
from summer_puppy.api.auth.jwt_handler import create_token, decode_token
from summer_puppy.api.auth.models import ApiKey, TokenPayload

__all__ = [
    "ApiKey",
    "TokenPayload",
    "create_token",
    "decode_token",
    "generate_api_key",
    "verify_api_key",
    "get_current_customer",
    "require_scope",
    "require_admin",
]
