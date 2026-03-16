from __future__ import annotations

import hashlib
from typing import Any, Protocol

from summer_puppy.audit.models import AuditEntry, AuditEntryType


class AuditLogger(Protocol):
    async def append(self, entry: AuditEntry) -> None: ...

    async def get_chain(self, correlation_id: str) -> list[AuditEntry]: ...


def compute_checksum(entry: AuditEntry, previous_checksum: str = "") -> str:
    """Compute sha256 hex of (previous_checksum + entry fields)."""
    payload = (
        previous_checksum
        + entry.entry_id
        + entry.timestamp_utc.isoformat()
        + entry.customer_id
        + entry.entry_type.value
        + entry.actor
        + str(entry.details)
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_chain(entries: list[AuditEntry]) -> bool:
    """Walk entries validating each checksum against previous. Empty chain is valid."""
    previous_checksum = ""
    for entry in entries:
        expected = compute_checksum(entry, previous_checksum)
        if entry.checksum != expected:
            return False
        previous_checksum = entry.checksum
    return True


class InMemoryAuditLogger:
    """In-memory implementation of AuditLogger for testing and development."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    async def append(self, entry: AuditEntry) -> None:
        previous_checksum = self._entries[-1].checksum if self._entries else ""
        entry.checksum = compute_checksum(entry, previous_checksum)
        self._entries.append(entry)

    async def get_chain(self, correlation_id: str) -> list[AuditEntry]:
        filtered = [e for e in self._entries if e.correlation_id == correlation_id]
        return sorted(filtered, key=lambda e: e.timestamp_utc)


# ---------------------------------------------------------------------------
# Convenience factory functions
# ---------------------------------------------------------------------------


def log_event_received(
    customer_id: str,
    event_id: str,
    correlation_id: str,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.EVENT_RECEIVED,
        actor="system",
        correlation_id=correlation_id,
        resource_id=event_id,
        details=details or {},
    )


def log_recommendation(
    customer_id: str,
    recommendation_id: str,
    correlation_id: str,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.RECOMMENDATION_GENERATED,
        actor="system",
        correlation_id=correlation_id,
        resource_id=recommendation_id,
        details=details or {},
    )


def log_approval_decision(
    customer_id: str,
    resource_id: str,
    correlation_id: str,
    approved: bool,
    actor: str,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    entry_type = AuditEntryType.HUMAN_APPROVED if approved else AuditEntryType.HUMAN_REJECTED
    return AuditEntry(
        customer_id=customer_id,
        entry_type=entry_type,
        actor=actor,
        correlation_id=correlation_id,
        resource_id=resource_id,
        details=details or {},
    )


def log_action_outcome(
    customer_id: str,
    request_id: str,
    correlation_id: str,
    success: bool,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    entry_type = AuditEntryType.ACTION_COMPLETED if success else AuditEntryType.ACTION_FAILED
    return AuditEntry(
        customer_id=customer_id,
        entry_type=entry_type,
        actor="system",
        correlation_id=correlation_id,
        resource_id=request_id,
        details=details or {},
    )


def log_phase_transition(
    customer_id: str,
    correlation_id: str,
    from_phase: str,
    to_phase: str,
    actor: str,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.PHASE_TRANSITION,
        actor=actor,
        correlation_id=correlation_id,
        previous_state=from_phase,
        new_state=to_phase,
        details=details or {},
    )
