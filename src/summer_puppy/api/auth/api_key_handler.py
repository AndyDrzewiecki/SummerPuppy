"""API key generation and verification."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from summer_puppy.api.auth.models import ApiKey


def generate_api_key(customer_id: str, description: str = "") -> tuple[str, ApiKey]:
    """Generate a new API key; returns (raw_key, ApiKey with hash)."""
    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    api_key = ApiKey(customer_id=customer_id, key_hash=key_hash, description=description)
    return raw_key, api_key


def verify_api_key(raw_key: str, stored_hash: str) -> bool:
    """Return True if the raw key matches the stored SHA-256 hash."""
    candidate = hashlib.sha256(raw_key.encode()).hexdigest()
    return hmac.compare_digest(candidate, stored_hash)
