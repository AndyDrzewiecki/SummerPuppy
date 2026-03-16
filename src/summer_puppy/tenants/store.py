"""Tenant store protocol and in-memory implementation."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from summer_puppy.tenants.models import TenantProfile  # noqa: TC001


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

    def get(self, customer_id: str) -> TenantProfile | None:
        return self._profiles.get(customer_id)

    def save(self, profile: TenantProfile) -> None:
        self._profiles[profile.customer_id] = profile

    def list_all(self) -> list[TenantProfile]:
        return list(self._profiles.values())
