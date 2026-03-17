"""Tenant store protocol and in-memory implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from summer_puppy.tenants.models import TenantProfile  # noqa: TC001

if TYPE_CHECKING:
    from summer_puppy.api.auth.models import ApiKey


@runtime_checkable
class TenantStore(Protocol):
    """Protocol for tenant profile storage backends."""

    def get(self, customer_id: str) -> TenantProfile | None: ...

    def save(self, profile: TenantProfile) -> None: ...

    def list_all(self) -> list[TenantProfile]: ...


class InMemoryTenantStore:
    """In-memory implementation of TenantStore for testing and development."""

    def __init__(self) -> None:
        self._profiles: dict[str, TenantProfile] = {}
        self._api_keys: dict[str, Any] = {}  # key_id → ApiKey

    def get(self, customer_id: str) -> TenantProfile | None:
        return self._profiles.get(customer_id)

    def save(self, profile: TenantProfile) -> None:
        self._profiles[profile.customer_id] = profile

    def list_all(self) -> list[TenantProfile]:
        return list(self._profiles.values())

    def save_api_key(self, api_key: ApiKey) -> None:
        """Store an API key record."""
        self._api_keys[api_key.key_id] = api_key

    def revoke_api_key(self, key_id: str) -> bool:
        """Mark an API key as revoked; return False if not found."""
        key = self._api_keys.get(key_id)
        if key is None:
            return False
        self._api_keys[key_id] = key.model_copy(update={"revoked": True})
        return True

    def find_api_key_by_hash(self, key_hash: str) -> ApiKey | None:
        """Return the active ApiKey matching key_hash, or None."""
        for key in self._api_keys.values():
            if key.key_hash == key_hash and not key.revoked:
                return cast("ApiKey", key)
        return None

    def get_api_keys(self, customer_id: str) -> list[ApiKey]:
        """Return all API keys for the given customer."""
        return [cast("ApiKey", k) for k in self._api_keys.values() if k.customer_id == customer_id]
