"""Local context cache — stores tenant KB snapshots for offline operation."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from summer_puppy.local.models import TenantContextSlice


class LocalContextCache:
    """Maintains per-tenant KB snapshots for offline/edge deployment.

    Tenants are isolated — one tenant cannot read another's cache.
    """

    def __init__(self) -> None:
        self._cache: dict[str, TenantContextSlice] = {}

    def update_snapshot(self, slice: TenantContextSlice) -> None:
        """Store or replace the context snapshot for a tenant."""
        self._cache[slice.tenant_id] = slice

    def get_snapshot(self, tenant_id: str) -> TenantContextSlice | None:
        """Return the current snapshot for a tenant, or None if not cached."""
        return self._cache.get(tenant_id)

    def is_fresh(self, tenant_id: str) -> bool:
        """True if we have a non-stale snapshot for this tenant."""
        snap = self._cache.get(tenant_id)
        if snap is None:
            return False
        return not snap.is_stale

    def invalidate(self, tenant_id: str) -> None:
        """Remove the cached snapshot for a tenant."""
        self._cache.pop(tenant_id, None)

    def build_context_string(self, tenant_id: str) -> str:
        """Return a plain-text context string from the cached snapshot.

        Returns empty string if no valid snapshot exists.
        """
        snap = self._cache.get(tenant_id)
        if snap is None or snap.is_stale:
            return ""

        parts: list[str] = []
        if snap.playbook_summaries:
            parts.append("Playbooks:")
            parts.extend(f"  - {s}" for s in snap.playbook_summaries)
        if snap.article_summaries:
            parts.append("Articles:")
            parts.extend(f"  - {s}" for s in snap.article_summaries)
        return "\n".join(parts)
