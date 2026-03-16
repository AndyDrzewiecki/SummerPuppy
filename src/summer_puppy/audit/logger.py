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


def log_work_item_routed(
    customer_id: str,
    work_item_id: str,
    correlation_id: str | None = None,
    consumer_pool: str = "",
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    merged = {"consumer_pool": consumer_pool, **(details or {})}
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.WORK_ITEM_ROUTED,
        actor="pool_orchestrator",
        correlation_id=correlation_id,
        resource_id=work_item_id,
        resource_type="work_item",
        details=merged,
    )


def log_work_item_completed(
    customer_id: str,
    work_item_id: str,
    correlation_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.WORK_ITEM_COMPLETED,
        actor="pool_orchestrator",
        correlation_id=correlation_id,
        resource_id=work_item_id,
        resource_type="work_item",
        details=details or {},
    )


def log_work_item_escalated(
    customer_id: str,
    work_item_id: str,
    correlation_id: str | None = None,
    previous_priority: str = "",
    new_priority: str = "",
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    merged = {
        "previous_priority": previous_priority,
        "new_priority": new_priority,
        **(details or {}),
    }
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.WORK_ITEM_ESCALATED,
        actor="pool_orchestrator",
        correlation_id=correlation_id,
        resource_id=work_item_id,
        resource_type="work_item",
        details=merged,
    )


def log_pool_registered(
    customer_id: str,
    pool_id: str,
    pool_name: str = "",
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    merged = {"pool_name": pool_name, **(details or {})}
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.POOL_REGISTERED,
        actor="system",
        resource_id=pool_id,
        resource_type="pool",
        details=merged,
    )


def log_pool_deregistered(
    customer_id: str,
    pool_id: str,
    pool_name: str = "",
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    merged = {"pool_name": pool_name, **(details or {})}
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.POOL_DEREGISTERED,
        actor="system",
        resource_id=pool_id,
        resource_type="pool",
        details=merged,
    )


def log_executor_completed(
    customer_id: str,
    execution_id: str | None = None,
    action_class: str | None = None,
    correlation_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    merged = {"action_class": action_class or "", **(details or {})}
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.EXECUTOR_COMPLETED,
        actor="executor",
        correlation_id=correlation_id,
        resource_id=execution_id,
        resource_type="execution",
        details=merged,
    )


def log_executor_failed(
    customer_id: str,
    execution_id: str | None = None,
    action_class: str | None = None,
    correlation_id: str | None = None,
    error_detail: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    merged = {
        "action_class": action_class or "",
        "error_detail": error_detail or "",
        **(details or {}),
    }
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.EXECUTOR_FAILED,
        actor="executor",
        correlation_id=correlation_id,
        resource_id=execution_id,
        resource_type="execution",
        details=merged,
    )


def log_executor_rolled_back(
    customer_id: str,
    rollback_id: str | None = None,
    execution_id: str | None = None,
    correlation_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    merged = {"execution_id": execution_id or "", **(details or {})}
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.EXECUTOR_ROLLED_BACK,
        actor="executor",
        correlation_id=correlation_id,
        resource_id=rollback_id,
        resource_type="rollback",
        details=merged,
    )


def log_predictive_alert(
    customer_id: str,
    alert_id: str | None = None,
    alert_type: str | None = None,
    risk_score: float | None = None,
    correlation_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    merged = {"alert_type": alert_type or "", "risk_score": risk_score, **(details or {})}
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.PREDICTIVE_ALERT_GENERATED,
        actor="predictive_monitor",
        correlation_id=correlation_id,
        resource_id=alert_id,
        resource_type="predictive_alert",
        details=merged,
    )


def log_known_pattern_auto_resolved(
    customer_id: str,
    event_id: str | None = None,
    pattern_ref_id: str | None = None,
    correlation_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEntry:
    merged = {"pattern_ref_id": pattern_ref_id or "", **(details or {})}
    return AuditEntry(
        customer_id=customer_id,
        entry_type=AuditEntryType.KNOWN_PATTERN_AUTO_RESOLVED,
        actor="pattern_resolver",
        correlation_id=correlation_id,
        resource_id=event_id,
        resource_type="security_event",
        details=merged,
    )
