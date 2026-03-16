"""Integration test: Cross-Pool Work Item Flow.

End-to-end test demonstrating the full Threat Research -> Orchestrator -> Engineering
flow using only in-memory implementations.  No external services required.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from summer_puppy.audit.logger import InMemoryAuditLogger, verify_chain
from summer_puppy.audit.models import AuditEntryType
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.channel.models import Topic
from summer_puppy.memory.store import InMemoryKnowledgeStore
from summer_puppy.pool.models import AgentPool, PoolStatus, PoolType
from summer_puppy.pool.orchestrator import PoolOrchestrator
from summer_puppy.pool.registry import InMemoryPoolRegistry
from summer_puppy.work.models import (
    Artifact,
    ArtifactType,
    WorkItem,
    WorkItemPriority,
    WorkItemStatus,
    WorkItemType,
)
from summer_puppy.work.store import InMemoryWorkItemStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_threat_research_pool() -> AgentPool:
    return AgentPool(
        name="Threat Research",
        pool_type=PoolType.THREAT_RESEARCH,
        can_produce=[WorkItemType.THREAT_REPORT],
        can_consume=[],
        status=PoolStatus.ONLINE,
        max_capacity=5,
    )


def _make_engineering_pool() -> AgentPool:
    return AgentPool(
        name="Engineering",
        pool_type=PoolType.ENGINEERING,
        can_consume=[
            WorkItemType.THREAT_REPORT,
            WorkItemType.PATCH_REQUEST,
            WorkItemType.DETECTION_RULE,
        ],
        can_produce=[WorkItemType.PATCH_REQUEST, WorkItemType.DETECTION_RULE],
        status=PoolStatus.ONLINE,
        max_capacity=10,
    )


def _build_stack() -> tuple[
    InMemoryEventBus,
    InMemoryPoolRegistry,
    InMemoryWorkItemStore,
    InMemoryAuditLogger,
    InMemoryKnowledgeStore,
    PoolOrchestrator,
    AgentPool,
    AgentPool,
]:
    """Wire up the full in-memory stack and return all pieces."""
    event_bus = InMemoryEventBus()
    registry = InMemoryPoolRegistry()
    work_item_store = InMemoryWorkItemStore()
    audit_logger = InMemoryAuditLogger()
    knowledge_store = InMemoryKnowledgeStore()

    threat_pool = _make_threat_research_pool()
    eng_pool = _make_engineering_pool()
    registry.register(threat_pool)
    registry.register(eng_pool)

    orchestrator = PoolOrchestrator(
        event_bus=event_bus,
        pool_registry=registry,
        work_item_store=work_item_store,
        audit_logger=audit_logger,
        knowledge_store=knowledge_store,
    )

    return (
        event_bus,
        registry,
        work_item_store,
        audit_logger,
        knowledge_store,
        orchestrator,
        threat_pool,
        eng_pool,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCrossPoolFlow:
    """Cross-pool work item routing, child items, completion, and audit."""

    async def test_full_cross_pool_work_item_flow(self) -> None:  # noqa: PLR0915
        (
            event_bus,
            _registry,
            work_item_store,
            audit_logger,
            knowledge_store,
            orchestrator,
            threat_pool,
            eng_pool,
        ) = _build_stack()

        # 1. Start the orchestrator
        await orchestrator.start()

        # 2. Create the original work item
        original = WorkItem(
            item_type=WorkItemType.THREAT_REPORT,
            status=WorkItemStatus.SUBMITTED,
            priority=WorkItemPriority.P1_HIGH,
            title="Critical RCE Vulnerability in OpenSSL",
            description="CVE-2026-XXXX allows remote code execution...",
            producer_pool=threat_pool.pool_id,
            context={"customer_id": "customer-1", "cve_id": "CVE-2026-XXXX"},
            acceptance_criteria=[
                "Patch developed",
                "Detection rule created",
                "Advisory published",
            ],
        )

        # 3. Publish the work item
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=original,
            customer_id="customer-1",
            correlation_id=original.correlation_id,
        )

        # 4. Assert: routed to engineering pool
        stored = await work_item_store.get_work_item(original.work_item_id)
        assert stored is not None
        assert stored.status == WorkItemStatus.ACCEPTED
        assert stored.consumer_pool == eng_pool.pool_id

        # 5. Simulate engineering pool creating child items
        child1 = WorkItem(
            item_type=WorkItemType.PATCH_REQUEST,
            parent_id=original.work_item_id,
            title="Patch for CVE-2026-XXXX",
            status=WorkItemStatus.SUBMITTED,
            context={"customer_id": "customer-1"},
        )
        child2 = WorkItem(
            item_type=WorkItemType.DETECTION_RULE,
            parent_id=original.work_item_id,
            title="Sigma rule for CVE-2026-XXXX",
            status=WorkItemStatus.SUBMITTED,
            context={"customer_id": "customer-1"},
        )

        await work_item_store.store_work_item(child1)
        await work_item_store.store_work_item(child2)

        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=child1,
            customer_id="customer-1",
            correlation_id=child1.correlation_id,
        )
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=child2,
            customer_id="customer-1",
            correlation_id=child2.correlation_id,
        )

        # 6. Assert: both children routed to engineering pool
        stored_child1 = await work_item_store.get_work_item(child1.work_item_id)
        stored_child2 = await work_item_store.get_work_item(child2.work_item_id)
        assert stored_child1 is not None
        assert stored_child1.status == WorkItemStatus.ACCEPTED
        assert stored_child1.consumer_pool == eng_pool.pool_id

        assert stored_child2 is not None
        assert stored_child2.status == WorkItemStatus.ACCEPTED
        assert stored_child2.consumer_pool == eng_pool.pool_id

        # 7. Simulate engineering completing with artifacts
        patch_artifact = Artifact(
            artifact_type=ArtifactType.CODE_PATCH,
            content="--- a/ssl.c\n+++ b/ssl.c\n...",
            format="diff",
            work_item_id=child1.work_item_id,
        )
        sigma_artifact = Artifact(
            artifact_type=ArtifactType.DETECTION_RULE,
            content="title: CVE-2026-XXXX\nlogsource:...",
            format="sigma",
            work_item_id=child2.work_item_id,
        )

        # Update child1 in the store, then publish a COMPLETED snapshot
        await work_item_store.add_artifact(child1.work_item_id, patch_artifact)
        await work_item_store.update_status(child1.work_item_id, WorkItemStatus.COMPLETED)
        updated_child1 = await work_item_store.get_work_item(child1.work_item_id)
        assert updated_child1 is not None

        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=updated_child1,
            customer_id="customer-1",
            correlation_id=updated_child1.correlation_id,
        )

        # Update child2 in the store, then publish a COMPLETED snapshot
        await work_item_store.add_artifact(child2.work_item_id, sigma_artifact)
        await work_item_store.update_status(child2.work_item_id, WorkItemStatus.COMPLETED)
        updated_child2 = await work_item_store.get_work_item(child2.work_item_id)
        assert updated_child2 is not None

        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=updated_child2,
            customer_id="customer-1",
            correlation_id=updated_child2.correlation_id,
        )

        # 8. Assert: knowledge store has artifacts and summaries
        assert patch_artifact.artifact_id in knowledge_store._artifacts_store
        assert sigma_artifact.artifact_id in knowledge_store._artifacts_store

        summaries = await knowledge_store.get_work_item_summaries("customer-1")
        summary_ids = [s["work_item_id"] for s in summaries]
        assert child1.work_item_id in summary_ids
        assert child2.work_item_id in summary_ids

        # 9. Verify decisions trail
        orig_stored = await work_item_store.get_work_item(original.work_item_id)
        assert orig_stored is not None
        assigned_decisions = [
            d for d in orig_stored.decisions if d.decision_type.value == "ASSIGNED"
        ]
        assert len(assigned_decisions) >= 1

        c1_stored = await work_item_store.get_work_item(child1.work_item_id)
        c2_stored = await work_item_store.get_work_item(child2.work_item_id)
        assert c1_stored is not None
        assert c2_stored is not None
        assert any(d.decision_type.value == "ASSIGNED" for d in c1_stored.decisions)
        assert any(d.decision_type.value == "ASSIGNED" for d in c2_stored.decisions)

        # 10. Verify audit chain
        all_entries = audit_logger._entries
        assert verify_chain(all_entries) is True

        routed_entries = [
            e for e in all_entries if e.entry_type == AuditEntryType.WORK_ITEM_ROUTED
        ]
        completed_entries = [
            e for e in all_entries if e.entry_type == AuditEntryType.WORK_ITEM_COMPLETED
        ]
        assert len(routed_entries) >= 3  # original + child1 + child2
        assert len(completed_entries) >= 2  # child1 + child2

        # 11. Stop the orchestrator
        await orchestrator.stop()

    async def test_stall_detection_in_flow(self) -> None:
        (
            event_bus,
            _registry,
            work_item_store,
            audit_logger,
            _knowledge_store,
            orchestrator,
            threat_pool,
            eng_pool,
        ) = _build_stack()

        # 1. Start orchestrator
        await orchestrator.start()

        # 2. Create and submit a work item
        item = WorkItem(
            item_type=WorkItemType.THREAT_REPORT,
            status=WorkItemStatus.SUBMITTED,
            priority=WorkItemPriority.P1_HIGH,
            title="Stale Threat Report",
            description="Should trigger stall detection.",
            producer_pool=threat_pool.pool_id,
            context={"customer_id": "customer-1"},
        )

        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="customer-1",
            correlation_id=item.correlation_id,
        )

        # 3. Verify it got routed (ACCEPTED)
        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is not None
        assert stored.status == WorkItemStatus.ACCEPTED
        assert stored.consumer_pool == eng_pool.pool_id

        # 4. Manually set updated_utc to 10 minutes ago
        stored.updated_utc = datetime.now(tz=UTC) - timedelta(minutes=10)

        # 5. Call detect_stalled with a 60-second threshold
        escalated = await orchestrator.detect_stalled(stall_threshold_seconds=60)

        # 6. Assert: item was escalated
        assert len(escalated) >= 1
        escalated_item = next(e for e in escalated if e.work_item_id == item.work_item_id)
        assert escalated_item.priority == WorkItemPriority.P0_CRITICAL
        assert escalated_item.status == WorkItemStatus.SUBMITTED

        # Verify escalation audit entry
        escalated_audit = [
            e for e in audit_logger._entries if e.entry_type == AuditEntryType.WORK_ITEM_ESCALATED
        ]
        assert len(escalated_audit) >= 1

        # 7. Stop orchestrator
        await orchestrator.stop()
