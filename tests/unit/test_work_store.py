"""Tests for WorkItemStore protocol and InMemoryWorkItemStore (Story 3.4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from summer_puppy.work.models import (
    Artifact,
    ArtifactType,
    Decision,
    DecisionType,
    WorkItem,
    WorkItemPriority,
    WorkItemStatus,
    WorkItemType,
)
from summer_puppy.work.store import InMemoryWorkItemStore, WorkItemStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_item(
    *,
    work_item_id: str = "wi-1",
    title: str = "Test item",
    item_type: WorkItemType = WorkItemType.THREAT_REPORT,
    status: WorkItemStatus = WorkItemStatus.DRAFT,
    priority: WorkItemPriority = WorkItemPriority.P2_MEDIUM,
    consumer_pool: str = "pool-a",
    parent_id: str | None = None,
    updated_utc: datetime | None = None,
) -> WorkItem:
    kwargs: dict[str, object] = {
        "work_item_id": work_item_id,
        "title": title,
        "item_type": item_type,
        "status": status,
        "priority": priority,
        "consumer_pool": consumer_pool,
    }
    if parent_id is not None:
        kwargs["parent_id"] = parent_id
    if updated_utc is not None:
        kwargs["updated_utc"] = updated_utc
    return WorkItem(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Store + Get round-trip
# ---------------------------------------------------------------------------


class TestStoreAndGet:
    async def test_store_and_get_round_trip(self) -> None:
        store = InMemoryWorkItemStore()
        item = _make_item(work_item_id="wi-100", title="Round-trip test")
        await store.store_work_item(item)

        retrieved = await store.get_work_item("wi-100")
        assert retrieved is not None
        assert retrieved.work_item_id == "wi-100"
        assert retrieved.title == "Round-trip test"

    async def test_get_returns_none_for_missing(self) -> None:
        store = InMemoryWorkItemStore()
        result = await store.get_work_item("nonexistent")
        assert result is None


# ---------------------------------------------------------------------------
# list_work_items
# ---------------------------------------------------------------------------


class TestListWorkItems:
    async def test_no_filters_returns_all(self) -> None:
        store = InMemoryWorkItemStore()
        for i in range(3):
            await store.store_work_item(_make_item(work_item_id=f"wi-{i}"))
        items = await store.list_work_items()
        assert len(items) == 3

    async def test_filter_by_consumer_pool(self) -> None:
        store = InMemoryWorkItemStore()
        await store.store_work_item(_make_item(work_item_id="wi-1", consumer_pool="alpha"))
        await store.store_work_item(_make_item(work_item_id="wi-2", consumer_pool="beta"))
        await store.store_work_item(_make_item(work_item_id="wi-3", consumer_pool="alpha"))

        items = await store.list_work_items(consumer_pool="alpha")
        assert len(items) == 2
        assert all(i.consumer_pool == "alpha" for i in items)

    async def test_filter_by_status(self) -> None:
        store = InMemoryWorkItemStore()
        await store.store_work_item(_make_item(work_item_id="wi-1", status=WorkItemStatus.DRAFT))
        await store.store_work_item(
            _make_item(work_item_id="wi-2", status=WorkItemStatus.IN_PROGRESS)
        )
        await store.store_work_item(_make_item(work_item_id="wi-3", status=WorkItemStatus.DRAFT))

        items = await store.list_work_items(status=WorkItemStatus.DRAFT)
        assert len(items) == 2
        assert all(i.status == WorkItemStatus.DRAFT for i in items)

    async def test_filter_by_priority(self) -> None:
        store = InMemoryWorkItemStore()
        await store.store_work_item(
            _make_item(work_item_id="wi-1", priority=WorkItemPriority.P0_CRITICAL)
        )
        await store.store_work_item(
            _make_item(work_item_id="wi-2", priority=WorkItemPriority.P3_LOW)
        )

        items = await store.list_work_items(priority=WorkItemPriority.P0_CRITICAL)
        assert len(items) == 1
        assert items[0].priority == WorkItemPriority.P0_CRITICAL

    async def test_respects_limit(self) -> None:
        store = InMemoryWorkItemStore()
        for i in range(10):
            await store.store_work_item(_make_item(work_item_id=f"wi-{i}"))

        items = await store.list_work_items(limit=3)
        assert len(items) == 3

    async def test_multiple_filters_combined(self) -> None:
        store = InMemoryWorkItemStore()
        await store.store_work_item(
            _make_item(
                work_item_id="wi-1",
                consumer_pool="alpha",
                status=WorkItemStatus.IN_PROGRESS,
                priority=WorkItemPriority.P1_HIGH,
            )
        )
        await store.store_work_item(
            _make_item(
                work_item_id="wi-2",
                consumer_pool="alpha",
                status=WorkItemStatus.IN_PROGRESS,
                priority=WorkItemPriority.P3_LOW,
            )
        )
        await store.store_work_item(
            _make_item(
                work_item_id="wi-3",
                consumer_pool="beta",
                status=WorkItemStatus.IN_PROGRESS,
                priority=WorkItemPriority.P1_HIGH,
            )
        )

        items = await store.list_work_items(
            consumer_pool="alpha",
            status=WorkItemStatus.IN_PROGRESS,
            priority=WorkItemPriority.P1_HIGH,
        )
        assert len(items) == 1
        assert items[0].work_item_id == "wi-1"


# ---------------------------------------------------------------------------
# update_status
# ---------------------------------------------------------------------------


class TestUpdateStatus:
    async def test_changes_status_and_updates_updated_utc(self) -> None:
        store = InMemoryWorkItemStore()
        item = _make_item(work_item_id="wi-1", status=WorkItemStatus.DRAFT)
        await store.store_work_item(item)
        original_updated = item.updated_utc

        await store.update_status("wi-1", WorkItemStatus.IN_PROGRESS)

        updated = await store.get_work_item("wi-1")
        assert updated is not None
        assert updated.status == WorkItemStatus.IN_PROGRESS
        assert updated.updated_utc >= original_updated

    async def test_missing_item_does_nothing(self) -> None:
        store = InMemoryWorkItemStore()
        # Should not raise
        await store.update_status("nonexistent", WorkItemStatus.COMPLETED)


# ---------------------------------------------------------------------------
# add_artifact
# ---------------------------------------------------------------------------


class TestAddArtifact:
    async def test_appends_to_item_artifacts(self) -> None:
        store = InMemoryWorkItemStore()
        item = _make_item(work_item_id="wi-1")
        await store.store_work_item(item)

        artifact = Artifact(
            work_item_id="wi-1",
            artifact_type=ArtifactType.CODE_PATCH,
            content="diff --git ...",
        )
        await store.add_artifact("wi-1", artifact)

        retrieved = await store.get_work_item("wi-1")
        assert retrieved is not None
        assert len(retrieved.artifacts) == 1
        assert retrieved.artifacts[0].artifact_type == ArtifactType.CODE_PATCH
        assert retrieved.artifacts[0].content == "diff --git ..."


# ---------------------------------------------------------------------------
# add_decision
# ---------------------------------------------------------------------------


class TestAddDecision:
    async def test_appends_to_item_decisions(self) -> None:
        store = InMemoryWorkItemStore()
        item = _make_item(work_item_id="wi-1")
        await store.store_work_item(item)

        decision = Decision(
            work_item_id="wi-1",
            pool_id="pool-a",
            agent_id="agent-1",
            decision_type=DecisionType.APPROVED,
            outcome="Looks good",
        )
        await store.add_decision("wi-1", decision)

        retrieved = await store.get_work_item("wi-1")
        assert retrieved is not None
        assert len(retrieved.decisions) == 1
        assert retrieved.decisions[0].decision_type == DecisionType.APPROVED
        assert retrieved.decisions[0].outcome == "Looks good"


# ---------------------------------------------------------------------------
# get_children
# ---------------------------------------------------------------------------


class TestGetChildren:
    async def test_returns_children_matching_parent_id(self) -> None:
        store = InMemoryWorkItemStore()
        parent = _make_item(work_item_id="parent-1")
        child1 = _make_item(work_item_id="child-1", parent_id="parent-1")
        child2 = _make_item(work_item_id="child-2", parent_id="parent-1")
        unrelated = _make_item(work_item_id="other-1", parent_id="parent-99")

        await store.store_work_item(parent)
        await store.store_work_item(child1)
        await store.store_work_item(child2)
        await store.store_work_item(unrelated)

        children = await store.get_children("parent-1")
        assert len(children) == 2
        child_ids = {c.work_item_id for c in children}
        assert child_ids == {"child-1", "child-2"}

    async def test_empty_list_for_no_children(self) -> None:
        store = InMemoryWorkItemStore()
        parent = _make_item(work_item_id="parent-1")
        await store.store_work_item(parent)

        children = await store.get_children("parent-1")
        assert children == []


# ---------------------------------------------------------------------------
# get_stalled_items
# ---------------------------------------------------------------------------


class TestGetStalledItems:
    async def test_returns_stale_accepted_items(self) -> None:
        store = InMemoryWorkItemStore()
        old_time = datetime.now(tz=UTC) - timedelta(seconds=600)
        item = _make_item(
            work_item_id="wi-stale",
            status=WorkItemStatus.ACCEPTED,
            updated_utc=old_time,
        )
        await store.store_work_item(item)

        stalled = await store.get_stalled_items(stall_threshold_seconds=300)
        assert len(stalled) == 1
        assert stalled[0].work_item_id == "wi-stale"

    async def test_returns_stale_in_progress_items(self) -> None:
        store = InMemoryWorkItemStore()
        old_time = datetime.now(tz=UTC) - timedelta(seconds=600)
        item = _make_item(
            work_item_id="wi-stale-ip",
            status=WorkItemStatus.IN_PROGRESS,
            updated_utc=old_time,
        )
        await store.store_work_item(item)

        stalled = await store.get_stalled_items(stall_threshold_seconds=300)
        assert len(stalled) == 1
        assert stalled[0].work_item_id == "wi-stale-ip"

    async def test_does_not_return_completed_or_draft_even_if_old(self) -> None:
        store = InMemoryWorkItemStore()
        old_time = datetime.now(tz=UTC) - timedelta(seconds=600)
        completed = _make_item(
            work_item_id="wi-done",
            status=WorkItemStatus.COMPLETED,
            updated_utc=old_time,
        )
        draft = _make_item(
            work_item_id="wi-draft",
            status=WorkItemStatus.DRAFT,
            updated_utc=old_time,
        )
        await store.store_work_item(completed)
        await store.store_work_item(draft)

        stalled = await store.get_stalled_items(stall_threshold_seconds=300)
        assert len(stalled) == 0


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    async def test_isinstance_check(self) -> None:
        store = InMemoryWorkItemStore()
        assert isinstance(store, WorkItemStore)
