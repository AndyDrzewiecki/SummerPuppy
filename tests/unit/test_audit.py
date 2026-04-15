"""Comprehensive tests for the structured audit log (Story 2)."""

from __future__ import annotations

from datetime import UTC, datetime

from summer_puppy.audit.logger import (
    InMemoryAuditLogger,
    compute_checksum,
    log_action_outcome,
    log_approval_decision,
    log_event_received,
    log_executor_completed,
    log_executor_failed,
    log_executor_rolled_back,
    log_known_pattern_auto_resolved,
    log_phase_transition,
    log_pool_deregistered,
    log_pool_registered,
    log_predictive_alert,
    log_recommendation,
    log_work_item_completed,
    log_work_item_escalated,
    log_work_item_routed,
    verify_chain,
)
from summer_puppy.audit.models import AuditEntry, AuditEntryType

# ---------------------------------------------------------------------------
# AuditEntryType enum
# ---------------------------------------------------------------------------


class TestAuditEntryType:
    def test_enum_values(self) -> None:
        assert AuditEntryType.EVENT_RECEIVED == "EVENT_RECEIVED"
        assert AuditEntryType.RECOMMENDATION_GENERATED == "RECOMMENDATION_GENERATED"
        assert AuditEntryType.APPROVAL_REQUESTED == "APPROVAL_REQUESTED"
        assert AuditEntryType.AUTO_APPROVED == "AUTO_APPROVED"
        assert AuditEntryType.HUMAN_APPROVED == "HUMAN_APPROVED"
        assert AuditEntryType.HUMAN_REJECTED == "HUMAN_REJECTED"
        assert AuditEntryType.ACTION_STARTED == "ACTION_STARTED"
        assert AuditEntryType.ACTION_COMPLETED == "ACTION_COMPLETED"
        assert AuditEntryType.ACTION_FAILED == "ACTION_FAILED"
        assert AuditEntryType.ROLLBACK_INITIATED == "ROLLBACK_INITIATED"
        assert AuditEntryType.PHASE_TRANSITION == "PHASE_TRANSITION"
        assert AuditEntryType.POLICY_CHANGED == "POLICY_CHANGED"

    def test_member_count(self) -> None:
        assert len(AuditEntryType) == 29


# ---------------------------------------------------------------------------
# AuditEntry model
# ---------------------------------------------------------------------------


class TestAuditEntry:
    def test_minimal_creation(self) -> None:
        entry = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
        )
        assert entry.customer_id == "cust-1"
        assert entry.entry_type == AuditEntryType.EVENT_RECEIVED
        assert entry.actor == "system"
        assert entry.entry_id  # auto-generated uuid
        assert isinstance(entry.timestamp_utc, datetime)
        assert entry.correlation_id is None
        assert entry.resource_id is None
        assert entry.resource_type is None
        assert entry.details == {}
        assert entry.previous_state is None
        assert entry.new_state is None
        assert entry.checksum == ""

    def test_all_fields(self) -> None:
        ts = datetime(2026, 3, 16, 12, 0, 0, tzinfo=UTC)
        entry = AuditEntry(
            entry_id="entry-42",
            timestamp_utc=ts,
            customer_id="cust-2",
            entry_type=AuditEntryType.PHASE_TRANSITION,
            actor="user:admin@example.com",
            correlation_id="corr-99",
            resource_id="res-1",
            resource_type="trust_profile",
            details={"reason": "threshold met"},
            previous_state="manual",
            new_state="supervised",
            checksum="abc123",
        )
        assert entry.entry_id == "entry-42"
        assert entry.timestamp_utc == ts
        assert entry.customer_id == "cust-2"
        assert entry.entry_type == AuditEntryType.PHASE_TRANSITION
        assert entry.actor == "user:admin@example.com"
        assert entry.correlation_id == "corr-99"
        assert entry.resource_id == "res-1"
        assert entry.resource_type == "trust_profile"
        assert entry.details == {"reason": "threshold met"}
        assert entry.previous_state == "manual"
        assert entry.new_state == "supervised"
        assert entry.checksum == "abc123"

    def test_unique_entry_ids(self) -> None:
        e1 = AuditEntry(customer_id="c", entry_type=AuditEntryType.EVENT_RECEIVED, actor="system")
        e2 = AuditEntry(customer_id="c", entry_type=AuditEntryType.EVENT_RECEIVED, actor="system")
        assert e1.entry_id != e2.entry_id

    def test_serialization_roundtrip(self) -> None:
        entry = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.ACTION_COMPLETED,
            actor="agent:abc",
            details={"duration_ms": 150},
        )
        data = entry.model_dump()
        restored = AuditEntry(**data)
        assert restored.customer_id == entry.customer_id
        assert restored.entry_type == entry.entry_type
        assert restored.actor == entry.actor
        assert restored.details == entry.details

    def test_json_roundtrip(self) -> None:
        entry = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.ROLLBACK_INITIATED,
            actor="system",
        )
        json_str = entry.model_dump_json()
        restored = AuditEntry.model_validate_json(json_str)
        assert restored.entry_id == entry.entry_id
        assert restored.entry_type == entry.entry_type


# ---------------------------------------------------------------------------
# compute_checksum
# ---------------------------------------------------------------------------


class TestComputeChecksum:
    def test_deterministic(self) -> None:
        entry = AuditEntry(
            entry_id="fixed-id",
            timestamp_utc=datetime(2026, 1, 1, tzinfo=UTC),
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
            details={"key": "value"},
        )
        c1 = compute_checksum(entry, "")
        c2 = compute_checksum(entry, "")
        assert c1 == c2
        assert len(c1) == 64  # sha256 hex length

    def test_changes_with_different_previous_checksum(self) -> None:
        entry = AuditEntry(
            entry_id="fixed-id",
            timestamp_utc=datetime(2026, 1, 1, tzinfo=UTC),
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
        )
        c1 = compute_checksum(entry, "")
        c2 = compute_checksum(entry, "prev-hash")
        assert c1 != c2

    def test_changes_with_different_entry_type(self) -> None:
        base_kwargs = {
            "entry_id": "fixed-id",
            "timestamp_utc": datetime(2026, 1, 1, tzinfo=UTC),
            "customer_id": "cust-1",
            "actor": "system",
        }
        e1 = AuditEntry(entry_type=AuditEntryType.EVENT_RECEIVED, **base_kwargs)
        e2 = AuditEntry(entry_type=AuditEntryType.ACTION_COMPLETED, **base_kwargs)
        assert compute_checksum(e1) != compute_checksum(e2)

    def test_changes_with_different_details(self) -> None:
        base_kwargs = {
            "entry_id": "fixed-id",
            "timestamp_utc": datetime(2026, 1, 1, tzinfo=UTC),
            "customer_id": "cust-1",
            "entry_type": AuditEntryType.EVENT_RECEIVED,
            "actor": "system",
        }
        e1 = AuditEntry(details={"a": 1}, **base_kwargs)
        e2 = AuditEntry(details={"a": 2}, **base_kwargs)
        assert compute_checksum(e1) != compute_checksum(e2)

    def test_changes_with_different_actor(self) -> None:
        base_kwargs = {
            "entry_id": "fixed-id",
            "timestamp_utc": datetime(2026, 1, 1, tzinfo=UTC),
            "customer_id": "cust-1",
            "entry_type": AuditEntryType.EVENT_RECEIVED,
        }
        e1 = AuditEntry(actor="system", **base_kwargs)
        e2 = AuditEntry(actor="user:alice@example.com", **base_kwargs)
        assert compute_checksum(e1) != compute_checksum(e2)


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------


class TestVerifyChain:
    def test_empty_chain_is_valid(self) -> None:
        assert verify_chain([]) is True

    def test_valid_single_entry(self) -> None:
        entry = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
        )
        entry.checksum = compute_checksum(entry, "")
        assert verify_chain([entry]) is True

    def test_valid_chain_multiple_entries(self) -> None:
        e1 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
        )
        e1.checksum = compute_checksum(e1, "")

        e2 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.RECOMMENDATION_GENERATED,
            actor="agent:rec",
        )
        e2.checksum = compute_checksum(e2, e1.checksum)

        e3 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.AUTO_APPROVED,
            actor="system",
        )
        e3.checksum = compute_checksum(e3, e2.checksum)

        assert verify_chain([e1, e2, e3]) is True

    def test_tampered_entry_returns_false(self) -> None:
        e1 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
        )
        e1.checksum = compute_checksum(e1, "")

        e2 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.RECOMMENDATION_GENERATED,
            actor="agent:rec",
        )
        e2.checksum = compute_checksum(e2, e1.checksum)

        # Tamper with e1's actor after checksum was computed
        e1.actor = "attacker"
        assert verify_chain([e1, e2]) is False

    def test_wrong_checksum_returns_false(self) -> None:
        e1 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
        )
        e1.checksum = "wrong-checksum"
        assert verify_chain([e1]) is False


# ---------------------------------------------------------------------------
# InMemoryAuditLogger
# ---------------------------------------------------------------------------


class TestInMemoryAuditLogger:
    async def test_append_and_get_chain(self) -> None:
        logger = InMemoryAuditLogger()
        entry = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
            correlation_id="corr-1",
        )
        await logger.append(entry)
        chain = await logger.get_chain("corr-1")
        assert len(chain) == 1
        assert chain[0].entry_id == entry.entry_id
        assert chain[0].checksum != ""  # checksum was computed on append

    async def test_append_computes_chained_checksums(self) -> None:
        logger = InMemoryAuditLogger()
        e1 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
            correlation_id="corr-1",
        )
        e2 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.RECOMMENDATION_GENERATED,
            actor="agent:rec",
            correlation_id="corr-1",
        )
        await logger.append(e1)
        await logger.append(e2)

        chain = await logger.get_chain("corr-1")
        assert len(chain) == 2
        # The second entry's checksum should depend on the first
        assert chain[1].checksum == compute_checksum(chain[1], chain[0].checksum)

    async def test_multiple_correlation_ids_isolated(self) -> None:
        logger = InMemoryAuditLogger()
        e1 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
            correlation_id="corr-A",
        )
        e2 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
            correlation_id="corr-B",
        )
        e3 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.RECOMMENDATION_GENERATED,
            actor="agent:rec",
            correlation_id="corr-A",
        )
        await logger.append(e1)
        await logger.append(e2)
        await logger.append(e3)

        chain_a = await logger.get_chain("corr-A")
        chain_b = await logger.get_chain("corr-B")
        assert len(chain_a) == 2
        assert len(chain_b) == 1
        assert chain_a[0].correlation_id == "corr-A"
        assert chain_a[1].correlation_id == "corr-A"
        assert chain_b[0].correlation_id == "corr-B"

    async def test_get_chain_ordering(self) -> None:
        logger = InMemoryAuditLogger()
        ts1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
        ts2 = datetime(2026, 1, 1, 11, 0, 0, tzinfo=UTC)
        ts3 = datetime(2026, 1, 1, 9, 0, 0, tzinfo=UTC)  # earlier but appended last
        e1 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.EVENT_RECEIVED,
            actor="system",
            correlation_id="corr-1",
            timestamp_utc=ts1,
        )
        e2 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.RECOMMENDATION_GENERATED,
            actor="agent:rec",
            correlation_id="corr-1",
            timestamp_utc=ts2,
        )
        e3 = AuditEntry(
            customer_id="cust-1",
            entry_type=AuditEntryType.AUTO_APPROVED,
            actor="system",
            correlation_id="corr-1",
            timestamp_utc=ts3,
        )
        await logger.append(e1)
        await logger.append(e2)
        await logger.append(e3)

        chain = await logger.get_chain("corr-1")
        # ordered by timestamp
        assert chain[0].timestamp_utc == ts3
        assert chain[1].timestamp_utc == ts1
        assert chain[2].timestamp_utc == ts2

    async def test_get_chain_empty_result(self) -> None:
        logger = InMemoryAuditLogger()
        chain = await logger.get_chain("nonexistent")
        assert chain == []


# ---------------------------------------------------------------------------
# Convenience factory functions
# ---------------------------------------------------------------------------


class TestConvenienceFactories:
    def test_log_event_received(self) -> None:
        entry = log_event_received(
            customer_id="cust-1",
            event_id="evt-1",
            correlation_id="corr-1",
            details={"source": "SIEM"},
        )
        assert entry.entry_type == AuditEntryType.EVENT_RECEIVED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "evt-1"
        assert entry.correlation_id == "corr-1"
        assert entry.details == {"source": "SIEM"}
        assert entry.actor == "system"

    def test_log_recommendation(self) -> None:
        entry = log_recommendation(
            customer_id="cust-1",
            recommendation_id="rec-1",
            correlation_id="corr-1",
            details={"action": "patch"},
        )
        assert entry.entry_type == AuditEntryType.RECOMMENDATION_GENERATED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "rec-1"
        assert entry.correlation_id == "corr-1"
        assert entry.details == {"action": "patch"}
        assert entry.actor == "system"

    def test_log_approval_decision_approved(self) -> None:
        entry = log_approval_decision(
            customer_id="cust-1",
            resource_id="rec-1",
            correlation_id="corr-1",
            approved=True,
            actor="user:admin@example.com",
            details={"policy_id": "pol-1"},
        )
        assert entry.entry_type == AuditEntryType.HUMAN_APPROVED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "rec-1"
        assert entry.actor == "user:admin@example.com"
        assert entry.details == {"policy_id": "pol-1"}

    def test_log_approval_decision_rejected(self) -> None:
        entry = log_approval_decision(
            customer_id="cust-1",
            resource_id="rec-1",
            correlation_id="corr-1",
            approved=False,
            actor="user:admin@example.com",
            details={},
        )
        assert entry.entry_type == AuditEntryType.HUMAN_REJECTED

    def test_log_action_outcome_success(self) -> None:
        entry = log_action_outcome(
            customer_id="cust-1",
            request_id="req-1",
            correlation_id="corr-1",
            success=True,
            details={"duration_ms": 200},
        )
        assert entry.entry_type == AuditEntryType.ACTION_COMPLETED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "req-1"
        assert entry.details == {"duration_ms": 200}

    def test_log_action_outcome_failure(self) -> None:
        entry = log_action_outcome(
            customer_id="cust-1",
            request_id="req-1",
            correlation_id="corr-1",
            success=False,
            details={"error": "timeout"},
        )
        assert entry.entry_type == AuditEntryType.ACTION_FAILED

    def test_log_phase_transition(self) -> None:
        entry = log_phase_transition(
            customer_id="cust-1",
            correlation_id="corr-1",
            from_phase="manual",
            to_phase="supervised",
            actor="user:admin@example.com",
            details={"reason": "threshold met"},
        )
        assert entry.entry_type == AuditEntryType.PHASE_TRANSITION
        assert entry.customer_id == "cust-1"
        assert entry.actor == "user:admin@example.com"
        assert entry.previous_state == "manual"
        assert entry.new_state == "supervised"
        assert entry.details == {"reason": "threshold met"}

    def test_log_work_item_routed(self) -> None:
        entry = log_work_item_routed(
            customer_id="cust-1",
            work_item_id="wi-1",
            correlation_id="corr-1",
            consumer_pool="pool-alpha",
            details={"urgency": "high"},
        )
        assert entry.entry_type == AuditEntryType.WORK_ITEM_ROUTED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "wi-1"
        assert entry.resource_type == "work_item"
        assert entry.correlation_id == "corr-1"
        assert entry.actor == "pool_orchestrator"
        assert entry.details["consumer_pool"] == "pool-alpha"
        assert entry.details["urgency"] == "high"

    def test_log_work_item_routed_includes_consumer_pool_default(self) -> None:
        entry = log_work_item_routed(
            customer_id="cust-1",
            work_item_id="wi-2",
        )
        assert entry.entry_type == AuditEntryType.WORK_ITEM_ROUTED
        assert "consumer_pool" in entry.details
        assert entry.details["consumer_pool"] == ""

    def test_log_work_item_completed(self) -> None:
        entry = log_work_item_completed(
            customer_id="cust-1",
            work_item_id="wi-1",
            correlation_id="corr-1",
            details={"duration_ms": 500},
        )
        assert entry.entry_type == AuditEntryType.WORK_ITEM_COMPLETED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "wi-1"
        assert entry.resource_type == "work_item"
        assert entry.actor == "pool_orchestrator"
        assert entry.details == {"duration_ms": 500}

    def test_log_work_item_escalated(self) -> None:
        entry = log_work_item_escalated(
            customer_id="cust-1",
            work_item_id="wi-1",
            correlation_id="corr-1",
            previous_priority="low",
            new_priority="critical",
            details={"reason": "SLA breach"},
        )
        assert entry.entry_type == AuditEntryType.WORK_ITEM_ESCALATED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "wi-1"
        assert entry.resource_type == "work_item"
        assert entry.actor == "pool_orchestrator"
        assert entry.details["previous_priority"] == "low"
        assert entry.details["new_priority"] == "critical"
        assert entry.details["reason"] == "SLA breach"

    def test_log_work_item_escalated_priority_change_in_details(self) -> None:
        entry = log_work_item_escalated(
            customer_id="cust-1",
            work_item_id="wi-3",
            previous_priority="medium",
            new_priority="high",
        )
        assert "previous_priority" in entry.details
        assert "new_priority" in entry.details
        assert entry.details["previous_priority"] == "medium"
        assert entry.details["new_priority"] == "high"

    def test_log_pool_registered(self) -> None:
        entry = log_pool_registered(
            customer_id="cust-1",
            pool_id="pool-1",
            pool_name="Alpha Pool",
            details={"capacity": 10},
        )
        assert entry.entry_type == AuditEntryType.POOL_REGISTERED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "pool-1"
        assert entry.resource_type == "pool"
        assert entry.actor == "system"
        assert entry.details["pool_name"] == "Alpha Pool"
        assert entry.details["capacity"] == 10

    def test_log_pool_registered_includes_pool_name(self) -> None:
        entry = log_pool_registered(
            customer_id="cust-1",
            pool_id="pool-2",
            pool_name="Beta Pool",
        )
        assert "pool_name" in entry.details
        assert entry.details["pool_name"] == "Beta Pool"

    def test_log_pool_deregistered(self) -> None:
        entry = log_pool_deregistered(
            customer_id="cust-1",
            pool_id="pool-1",
            pool_name="Alpha Pool",
            details={"reason": "maintenance"},
        )
        assert entry.entry_type == AuditEntryType.POOL_DEREGISTERED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "pool-1"
        assert entry.resource_type == "pool"
        assert entry.actor == "system"
        assert entry.details["pool_name"] == "Alpha Pool"
        assert entry.details["reason"] == "maintenance"

    def test_log_executor_completed(self) -> None:
        entry = log_executor_completed(
            customer_id="cust-1",
            execution_id="exec-1",
            action_class="block_ip",
            correlation_id="corr-1",
            details={"duration_ms": 100},
        )
        assert entry.entry_type == AuditEntryType.EXECUTOR_COMPLETED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "exec-1"
        assert entry.resource_type == "execution"
        assert entry.actor == "executor"
        assert entry.correlation_id == "corr-1"
        assert entry.details["action_class"] == "block_ip"
        assert entry.details["duration_ms"] == 100

    def test_log_executor_failed(self) -> None:
        entry = log_executor_failed(
            customer_id="cust-1",
            execution_id="exec-2",
            action_class="disable_account",
            correlation_id="corr-2",
            error_detail="Connection timeout",
            details={"retry_count": 3},
        )
        assert entry.entry_type == AuditEntryType.EXECUTOR_FAILED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "exec-2"
        assert entry.resource_type == "execution"
        assert entry.actor == "executor"
        assert entry.details["action_class"] == "disable_account"
        assert entry.details["error_detail"] == "Connection timeout"
        assert entry.details["retry_count"] == 3

    def test_log_executor_rolled_back(self) -> None:
        entry = log_executor_rolled_back(
            customer_id="cust-1",
            rollback_id="rb-1",
            execution_id="exec-3",
            correlation_id="corr-3",
            details={"reason": "error detected"},
        )
        assert entry.entry_type == AuditEntryType.EXECUTOR_ROLLED_BACK
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "rb-1"
        assert entry.resource_type == "rollback"
        assert entry.actor == "executor"
        assert entry.details["execution_id"] == "exec-3"
        assert entry.details["reason"] == "error detected"

    def test_log_predictive_alert(self) -> None:
        entry = log_predictive_alert(
            customer_id="cust-1",
            alert_id="alert-1",
            alert_type="UNPATCHED_ASSET",
            risk_score=0.85,
            correlation_id="corr-4",
            details={"asset_count": 5},
        )
        assert entry.entry_type == AuditEntryType.PREDICTIVE_ALERT_GENERATED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "alert-1"
        assert entry.resource_type == "predictive_alert"
        assert entry.actor == "predictive_monitor"
        assert entry.details["alert_type"] == "UNPATCHED_ASSET"
        assert entry.details["risk_score"] == 0.85
        assert entry.details["asset_count"] == 5

    def test_log_known_pattern_auto_resolved(self) -> None:
        entry = log_known_pattern_auto_resolved(
            customer_id="cust-1",
            event_id="evt-1",
            pattern_ref_id="pattern-42",
            correlation_id="corr-5",
            details={"resolution": "auto-patched"},
        )
        assert entry.entry_type == AuditEntryType.KNOWN_PATTERN_AUTO_RESOLVED
        assert entry.customer_id == "cust-1"
        assert entry.resource_id == "evt-1"
        assert entry.resource_type == "security_event"
        assert entry.actor == "pattern_resolver"
        assert entry.details["pattern_ref_id"] == "pattern-42"
        assert entry.details["resolution"] == "auto-patched"


# ---------------------------------------------------------------------------
# Integration: full flow through logger with chain verification
# ---------------------------------------------------------------------------


class TestAuditIntegration:
    async def test_append_entries_and_verify_chain(self) -> None:
        logger = InMemoryAuditLogger()

        e1 = log_event_received(
            customer_id="cust-1",
            event_id="evt-1",
            correlation_id="corr-1",
            details={"source": "SIEM"},
        )
        await logger.append(e1)

        e2 = log_recommendation(
            customer_id="cust-1",
            recommendation_id="rec-1",
            correlation_id="corr-1",
            details={"action": "patch"},
        )
        await logger.append(e2)

        e3 = log_approval_decision(
            customer_id="cust-1",
            resource_id="rec-1",
            correlation_id="corr-1",
            approved=True,
            actor="user:admin@example.com",
            details={},
        )
        await logger.append(e3)

        e4 = log_action_outcome(
            customer_id="cust-1",
            request_id="req-1",
            correlation_id="corr-1",
            success=True,
            details={"duration_ms": 200},
        )
        await logger.append(e4)

        # Retrieve chain and verify integrity
        chain = await logger.get_chain("corr-1")
        assert len(chain) == 4
        assert verify_chain(chain) is True

    async def test_tampered_chain_detected(self) -> None:
        logger = InMemoryAuditLogger()

        e1 = log_event_received(
            customer_id="cust-1",
            event_id="evt-1",
            correlation_id="corr-1",
            details={},
        )
        await logger.append(e1)

        e2 = log_recommendation(
            customer_id="cust-1",
            recommendation_id="rec-1",
            correlation_id="corr-1",
            details={},
        )
        await logger.append(e2)

        chain = await logger.get_chain("corr-1")
        assert verify_chain(chain) is True

        # Tamper with the first entry
        chain[0].actor = "evil-actor"
        assert verify_chain(chain) is False

    async def test_pool_operations_chain_verification(self) -> None:
        logger = InMemoryAuditLogger()

        e1 = log_pool_registered(
            customer_id="cust-1",
            pool_id="pool-1",
            pool_name="Alpha Pool",
        )
        await logger.append(e1)

        e2 = log_work_item_routed(
            customer_id="cust-1",
            work_item_id="wi-1",
            correlation_id="corr-pool-1",
            consumer_pool="pool-1",
        )
        await logger.append(e2)

        e3 = log_work_item_escalated(
            customer_id="cust-1",
            work_item_id="wi-1",
            correlation_id="corr-pool-1",
            previous_priority="low",
            new_priority="high",
        )
        await logger.append(e3)

        e4 = log_work_item_completed(
            customer_id="cust-1",
            work_item_id="wi-1",
            correlation_id="corr-pool-1",
        )
        await logger.append(e4)

        e5 = log_pool_deregistered(
            customer_id="cust-1",
            pool_id="pool-1",
            pool_name="Alpha Pool",
        )
        await logger.append(e5)

        # The full chain across all entries should verify
        assert verify_chain(logger._entries) is True
