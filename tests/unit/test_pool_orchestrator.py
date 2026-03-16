"""Tests for PoolOrchestrator routing and lifecycle management."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.audit.models import AuditEntryType
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.channel.models import Topic
from summer_puppy.memory.store import InMemoryKnowledgeStore
from summer_puppy.pool.models import AgentPool, PoolType
from summer_puppy.pool.orchestrator import PoolOrchestrator
from summer_puppy.pool.registry import InMemoryPoolRegistry
from summer_puppy.work.models import (
    Artifact,
    ArtifactType,
    DecisionType,
    WorkItem,
    WorkItemPriority,
    WorkItemStatus,
    WorkItemType,
)
from summer_puppy.work.store import InMemoryWorkItemStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def event_bus() -> InMemoryEventBus:
    return InMemoryEventBus()


@pytest.fixture()
def pool_registry() -> InMemoryPoolRegistry:
    registry = InMemoryPoolRegistry()

    # THREAT_RESEARCH pool that produces THREAT_REPORT
    threat_pool = AgentPool(
        pool_id="threat-pool-1",
        name="Threat Research",
        pool_type=PoolType.THREAT_RESEARCH,
        can_produce=[WorkItemType.THREAT_REPORT],
        can_consume=[],
        current_load=0,
        max_capacity=10,
    )
    registry.register(threat_pool)

    # ENGINEERING pool that consumes THREAT_REPORT, PATCH_REQUEST
    eng_pool = AgentPool(
        pool_id="eng-pool-1",
        name="Engineering",
        pool_type=PoolType.ENGINEERING,
        can_produce=[],
        can_consume=[WorkItemType.THREAT_REPORT, WorkItemType.PATCH_REQUEST],
        current_load=2,
        max_capacity=10,
    )
    registry.register(eng_pool)

    return registry


@pytest.fixture()
def work_item_store() -> InMemoryWorkItemStore:
    return InMemoryWorkItemStore()


@pytest.fixture()
def audit_logger() -> InMemoryAuditLogger:
    return InMemoryAuditLogger()


@pytest.fixture()
def knowledge_store() -> InMemoryKnowledgeStore:
    return InMemoryKnowledgeStore()


@pytest.fixture()
def orchestrator(
    event_bus: InMemoryEventBus,
    pool_registry: InMemoryPoolRegistry,
    work_item_store: InMemoryWorkItemStore,
    audit_logger: InMemoryAuditLogger,
    knowledge_store: InMemoryKnowledgeStore,
) -> PoolOrchestrator:
    return PoolOrchestrator(
        event_bus=event_bus,
        pool_registry=pool_registry,
        work_item_store=work_item_store,
        audit_logger=audit_logger,
        knowledge_store=knowledge_store,
    )


def _make_work_item(
    *,
    item_type: WorkItemType = WorkItemType.THREAT_REPORT,
    status: WorkItemStatus = WorkItemStatus.SUBMITTED,
    priority: WorkItemPriority = WorkItemPriority.P2_MEDIUM,
    title: str = "Test Work Item",
    customer_id: str = "cust-1",
    artifacts: list[Artifact] | None = None,
    context: dict[str, str] | None = None,
) -> WorkItem:
    return WorkItem(
        item_type=item_type,
        status=status,
        priority=priority,
        title=title,
        context={"customer_id": customer_id, **(context or {})},
        artifacts=artifacts or [],
    )


# ---------------------------------------------------------------------------
# Routing tests
# ---------------------------------------------------------------------------


class TestRoutesSubmittedWorkItem:
    @pytest.mark.asyncio()
    async def test_routes_submitted_work_item(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        work_item_store: InMemoryWorkItemStore,
    ) -> None:
        """Submit THREAT_REPORT -> routed to ENGINEERING pool."""
        await orchestrator.start()

        item = _make_work_item()
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is not None
        assert stored.status == WorkItemStatus.ACCEPTED
        assert stored.consumer_pool == "eng-pool-1"

        await orchestrator.stop()


class TestRoutesToLowestLoadPool:
    @pytest.mark.asyncio()
    async def test_routes_to_lowest_load_pool(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        pool_registry: InMemoryPoolRegistry,
        work_item_store: InMemoryWorkItemStore,
    ) -> None:
        """Two engineering pools, one at 8/10, one at 2/10 -> routes to 2/10."""
        # Add a second engineering pool with higher load
        heavy_pool = AgentPool(
            pool_id="eng-pool-heavy",
            name="Engineering Heavy",
            pool_type=PoolType.ENGINEERING,
            can_consume=[WorkItemType.THREAT_REPORT],
            current_load=8,
            max_capacity=10,
        )
        pool_registry.register(heavy_pool)

        await orchestrator.start()

        item = _make_work_item()
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is not None
        # eng-pool-1 has load 2/10 = 0.2, eng-pool-heavy has 8/10 = 0.8
        assert stored.consumer_pool == "eng-pool-1"

        await orchestrator.stop()


class TestNoAvailableConsumers:
    @pytest.mark.asyncio()
    async def test_no_available_consumers(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        work_item_store: InMemoryWorkItemStore,
    ) -> None:
        """Submit item with type no pool can consume -> stays SUBMITTED, no crash."""
        await orchestrator.start()

        item = _make_work_item(item_type=WorkItemType.DETECTION_RULE)
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        # Item was never stored (stays SUBMITTED, not routed)
        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is None

        await orchestrator.stop()


class TestCreatesRoutingDecision:
    @pytest.mark.asyncio()
    async def test_creates_routing_decision(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        work_item_store: InMemoryWorkItemStore,
    ) -> None:
        """Verify Decision with ASSIGNED type is added to work item."""
        await orchestrator.start()

        item = _make_work_item()
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is not None
        assigned_decisions = [
            d for d in stored.decisions if d.decision_type == DecisionType.ASSIGNED
        ]
        assert len(assigned_decisions) == 1
        assert assigned_decisions[0].pool_id == "eng-pool-1"
        assert assigned_decisions[0].agent_id == "pool_orchestrator"

        await orchestrator.stop()


class TestCreatesRoutingAuditEntry:
    @pytest.mark.asyncio()
    async def test_creates_routing_audit_entry(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        audit_logger: InMemoryAuditLogger,
    ) -> None:
        """Verify audit entry with WORK_ITEM_ROUTED type."""
        await orchestrator.start()

        item = _make_work_item()
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        routed_entries = [
            e for e in audit_logger._entries if e.entry_type == AuditEntryType.WORK_ITEM_ROUTED
        ]
        assert len(routed_entries) == 1
        assert routed_entries[0].resource_id == item.work_item_id

        await orchestrator.stop()


class TestPublishesUpdatedWorkItem:
    @pytest.mark.asyncio()
    async def test_publishes_updated_work_item(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
    ) -> None:
        """Verify event bus receives updated item on WORK_ITEMS topic."""
        await orchestrator.start()

        item = _make_work_item()
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        # The original publish + the re-publish from routing
        history = event_bus.get_history(Topic.WORK_ITEMS)
        assert len(history) >= 2
        # Due to InMemoryEventBus synchronous dispatch, the nested publish
        # (ACCEPTED) is appended to history before the outer publish (SUBMITTED).
        accepted_envelopes = [
            env for env in history if env.payload["status"] == WorkItemStatus.ACCEPTED.value
        ]
        assert len(accepted_envelopes) == 1

        await orchestrator.stop()


# ---------------------------------------------------------------------------
# Completion tests
# ---------------------------------------------------------------------------


class TestCompletesWorkItem:
    @pytest.mark.asyncio()
    async def test_completes_work_item(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        knowledge_store: InMemoryKnowledgeStore,
    ) -> None:
        """Submit COMPLETED item -> artifacts stored in knowledge store."""
        await orchestrator.start()

        artifact = Artifact(
            artifact_id="art-1",
            work_item_id="wi-1",
            artifact_type=ArtifactType.THREAT_REPORT,
            content="Threat report content",
        )
        item = _make_work_item(
            status=WorkItemStatus.COMPLETED,
            artifacts=[artifact],
        )
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        assert "art-1" in knowledge_store._artifacts_store

        await orchestrator.stop()


class TestStoresWorkItemSummaryOnCompletion:
    @pytest.mark.asyncio()
    async def test_stores_work_item_summary_on_completion(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        knowledge_store: InMemoryKnowledgeStore,
    ) -> None:
        """Verify knowledge store has summary after completion."""
        await orchestrator.start()

        item = _make_work_item(status=WorkItemStatus.COMPLETED)
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        summaries = await knowledge_store.get_work_item_summaries("cust-1")
        assert len(summaries) == 1
        assert summaries[0]["work_item_id"] == item.work_item_id
        assert summaries[0]["title"] == "Test Work Item"

        await orchestrator.stop()


class TestCreatesCompletionDecision:
    @pytest.mark.asyncio()
    async def test_creates_completion_decision(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        work_item_store: InMemoryWorkItemStore,
    ) -> None:
        """Verify Decision with COMPLETED type."""
        await orchestrator.start()

        item = _make_work_item(status=WorkItemStatus.COMPLETED)
        # Pre-store so the decision can be added
        await work_item_store.store_work_item(item)
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is not None
        completed_decisions = [
            d for d in stored.decisions if d.decision_type == DecisionType.COMPLETED
        ]
        assert len(completed_decisions) == 1

        await orchestrator.stop()


class TestCreatesCompletionAuditEntry:
    @pytest.mark.asyncio()
    async def test_creates_completion_audit_entry(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        audit_logger: InMemoryAuditLogger,
    ) -> None:
        """Verify WORK_ITEM_COMPLETED audit entry."""
        await orchestrator.start()

        item = _make_work_item(status=WorkItemStatus.COMPLETED)
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        completed_entries = [
            e for e in audit_logger._entries if e.entry_type == AuditEntryType.WORK_ITEM_COMPLETED
        ]
        assert len(completed_entries) == 1
        assert completed_entries[0].resource_id == item.work_item_id

        await orchestrator.stop()


# ---------------------------------------------------------------------------
# Anti-recursion tests
# ---------------------------------------------------------------------------


class TestIgnoresAcceptedStatus:
    @pytest.mark.asyncio()
    async def test_ignores_accepted_status(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        work_item_store: InMemoryWorkItemStore,
        audit_logger: InMemoryAuditLogger,
    ) -> None:
        """Publish item with ACCEPTED status -> handler does nothing."""
        await orchestrator.start()

        item = _make_work_item(status=WorkItemStatus.ACCEPTED)
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        # No work item stored, no audit entries
        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is None
        assert len(audit_logger._entries) == 0

        await orchestrator.stop()


class TestIgnoresInProgressStatus:
    @pytest.mark.asyncio()
    async def test_ignores_in_progress_status(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        work_item_store: InMemoryWorkItemStore,
        audit_logger: InMemoryAuditLogger,
    ) -> None:
        """Publish item with IN_PROGRESS status -> handler does nothing."""
        await orchestrator.start()

        item = _make_work_item(status=WorkItemStatus.IN_PROGRESS)
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is None
        assert len(audit_logger._entries) == 0

        await orchestrator.stop()


# ---------------------------------------------------------------------------
# Start/stop tests
# ---------------------------------------------------------------------------


class TestStartSubscribes:
    @pytest.mark.asyncio()
    async def test_start_subscribes(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        work_item_store: InMemoryWorkItemStore,
    ) -> None:
        """After start(), handler receives published items."""
        await orchestrator.start()

        item = _make_work_item()
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is not None
        assert stored.status == WorkItemStatus.ACCEPTED

        await orchestrator.stop()


class TestStopUnsubscribes:
    @pytest.mark.asyncio()
    async def test_stop_unsubscribes(
        self,
        orchestrator: PoolOrchestrator,
        event_bus: InMemoryEventBus,
        work_item_store: InMemoryWorkItemStore,
    ) -> None:
        """After stop(), handler no longer receives items."""
        await orchestrator.start()
        await orchestrator.stop()

        item = _make_work_item()
        await event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id="cust-1",
        )

        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is None


# ---------------------------------------------------------------------------
# Stall detection tests
# ---------------------------------------------------------------------------


class TestDetectStalled:
    @pytest.mark.asyncio()
    async def test_detect_stalled(
        self,
        orchestrator: PoolOrchestrator,
        work_item_store: InMemoryWorkItemStore,
    ) -> None:
        """Item with old updated_utc in ACCEPTED status -> escalated."""
        item = _make_work_item(status=WorkItemStatus.ACCEPTED)
        item.updated_utc = datetime.now(tz=UTC) - timedelta(seconds=600)
        await work_item_store.store_work_item(item)

        stalled = await orchestrator.detect_stalled(stall_threshold_seconds=300)
        assert len(stalled) == 1
        assert stalled[0].work_item_id == item.work_item_id


class TestEscalateIncreasesPriority:
    @pytest.mark.asyncio()
    async def test_escalate_increases_priority(
        self,
        orchestrator: PoolOrchestrator,
        work_item_store: InMemoryWorkItemStore,
    ) -> None:
        """P3 -> P2, P2 -> P1, etc."""
        for old_prio, expected_prio in [
            (WorkItemPriority.P3_LOW, WorkItemPriority.P2_MEDIUM),
            (WorkItemPriority.P2_MEDIUM, WorkItemPriority.P1_HIGH),
            (WorkItemPriority.P1_HIGH, WorkItemPriority.P0_CRITICAL),
            (WorkItemPriority.P0_CRITICAL, WorkItemPriority.P0_CRITICAL),
        ]:
            store = InMemoryWorkItemStore()
            orch = PoolOrchestrator(
                event_bus=InMemoryEventBus(),
                pool_registry=InMemoryPoolRegistry(),
                work_item_store=store,
                audit_logger=InMemoryAuditLogger(),
                knowledge_store=InMemoryKnowledgeStore(),
            )
            item = _make_work_item(
                status=WorkItemStatus.ACCEPTED,
                priority=old_prio,
            )
            item.updated_utc = datetime.now(tz=UTC) - timedelta(seconds=600)
            await store.store_work_item(item)

            stalled = await orch.detect_stalled(stall_threshold_seconds=300)
            assert len(stalled) == 1
            assert stalled[0].priority == expected_prio


class TestStalledItemResubmitted:
    @pytest.mark.asyncio()
    async def test_stalled_item_resubmitted(
        self,
        orchestrator: PoolOrchestrator,
        work_item_store: InMemoryWorkItemStore,
    ) -> None:
        """Status changed to SUBMITTED after escalation."""
        item = _make_work_item(status=WorkItemStatus.ACCEPTED)
        item.updated_utc = datetime.now(tz=UTC) - timedelta(seconds=600)
        await work_item_store.store_work_item(item)

        stalled = await orchestrator.detect_stalled(stall_threshold_seconds=300)
        assert len(stalled) == 1

        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is not None
        assert stored.status == WorkItemStatus.SUBMITTED


class TestStalledCreatesEscalationDecision:
    @pytest.mark.asyncio()
    async def test_stalled_creates_escalation_decision(
        self,
        orchestrator: PoolOrchestrator,
        work_item_store: InMemoryWorkItemStore,
    ) -> None:
        """Decision with ESCALATED type."""
        item = _make_work_item(status=WorkItemStatus.ACCEPTED)
        item.updated_utc = datetime.now(tz=UTC) - timedelta(seconds=600)
        await work_item_store.store_work_item(item)

        await orchestrator.detect_stalled(stall_threshold_seconds=300)

        stored = await work_item_store.get_work_item(item.work_item_id)
        assert stored is not None
        escalated_decisions = [
            d for d in stored.decisions if d.decision_type == DecisionType.ESCALATED
        ]
        assert len(escalated_decisions) == 1
        assert "stalled" in escalated_decisions[0].reasoning.evidence[0].lower()


class TestStalledCreatesAuditEntry:
    @pytest.mark.asyncio()
    async def test_stalled_creates_audit_entry(
        self,
        orchestrator: PoolOrchestrator,
        work_item_store: InMemoryWorkItemStore,
        audit_logger: InMemoryAuditLogger,
    ) -> None:
        """Escalation creates WORK_ITEM_ESCALATED audit entry."""
        item = _make_work_item(status=WorkItemStatus.ACCEPTED)
        item.updated_utc = datetime.now(tz=UTC) - timedelta(seconds=600)
        await work_item_store.store_work_item(item)

        await orchestrator.detect_stalled(stall_threshold_seconds=300)

        escalated_entries = [
            e for e in audit_logger._entries if e.entry_type == AuditEntryType.WORK_ITEM_ESCALATED
        ]
        assert len(escalated_entries) == 1
        assert escalated_entries[0].resource_id == item.work_item_id


class TestStalledPublishesResubmittedItem:
    @pytest.mark.asyncio()
    async def test_stalled_publishes_resubmitted_item(
        self,
        orchestrator: PoolOrchestrator,
        work_item_store: InMemoryWorkItemStore,
        event_bus: InMemoryEventBus,
    ) -> None:
        """Escalated item is published back to WORK_ITEMS topic."""
        item = _make_work_item(status=WorkItemStatus.ACCEPTED)
        item.updated_utc = datetime.now(tz=UTC) - timedelta(seconds=600)
        await work_item_store.store_work_item(item)

        await orchestrator.detect_stalled(stall_threshold_seconds=300)

        history = event_bus.get_history(Topic.WORK_ITEMS)
        assert len(history) >= 1
        # The published item should be SUBMITTED
        assert history[0].payload["status"] == WorkItemStatus.SUBMITTED.value
