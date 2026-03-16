"""Audit trail and compliance logging."""

from __future__ import annotations

from summer_puppy.audit.logger import (
    InMemoryAuditLogger,
    compute_checksum,
    log_action_outcome,
    log_approval_decision,
    log_event_received,
    log_phase_transition,
    log_pool_deregistered,
    log_pool_registered,
    log_recommendation,
    log_work_item_completed,
    log_work_item_escalated,
    log_work_item_routed,
    verify_chain,
)
from summer_puppy.audit.models import AuditEntry, AuditEntryType

__all__ = [
    "AuditEntry",
    "AuditEntryType",
    "InMemoryAuditLogger",
    "compute_checksum",
    "log_action_outcome",
    "log_approval_decision",
    "log_event_received",
    "log_phase_transition",
    "log_pool_deregistered",
    "log_pool_registered",
    "log_recommendation",
    "log_work_item_completed",
    "log_work_item_escalated",
    "log_work_item_routed",
    "verify_chain",
]
