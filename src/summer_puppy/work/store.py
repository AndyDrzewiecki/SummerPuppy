"""Work item store protocol and in-memory implementation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from summer_puppy.work.models import (
    Artifact,
    Decision,
    WorkItem,
    WorkItemPriority,
    WorkItemStatus,
)

_STALL_STATUSES = frozenset({WorkItemStatus.ACCEPTED, WorkItemStatus.IN_PROGRESS})


@runtime_checkable
class WorkItemStore(Protocol):
    """Protocol for work item storage backends."""

    async def store_work_item(self, item: WorkItem) -> None: ...

    async def get_work_item(self, work_item_id: str) -> WorkItem | None: ...

    async def list_work_items(
        self,
        consumer_pool: str | None = None,
        status: WorkItemStatus | None = None,
        priority: WorkItemPriority | None = None,
        limit: int = 50,
    ) -> list[WorkItem]: ...

    async def update_status(self, work_item_id: str, new_status: WorkItemStatus) -> None: ...

    async def add_artifact(self, work_item_id: str, artifact: Artifact) -> None: ...

    async def add_decision(self, work_item_id: str, decision: Decision) -> None: ...

    async def get_children(self, parent_id: str) -> list[WorkItem]: ...

    async def get_stalled_items(self, stall_threshold_seconds: int) -> list[WorkItem]: ...


class InMemoryWorkItemStore:
    """In-memory implementation of WorkItemStore for testing and development."""

    def __init__(self) -> None:
        self._items: dict[str, WorkItem] = {}

    async def store_work_item(self, item: WorkItem) -> None:
        self._items[item.work_item_id] = item

    async def get_work_item(self, work_item_id: str) -> WorkItem | None:
        return self._items.get(work_item_id)

    async def list_work_items(
        self,
        consumer_pool: str | None = None,
        status: WorkItemStatus | None = None,
        priority: WorkItemPriority | None = None,
        limit: int = 50,
    ) -> list[WorkItem]:
        results = list(self._items.values())

        if consumer_pool is not None:
            results = [i for i in results if i.consumer_pool == consumer_pool]
        if status is not None:
            results = [i for i in results if i.status == status]
        if priority is not None:
            results = [i for i in results if i.priority == priority]

        return results[:limit]

    async def update_status(self, work_item_id: str, new_status: WorkItemStatus) -> None:
        item = self._items.get(work_item_id)
        if item is None:
            return
        item.status = new_status
        item.updated_utc = datetime.now(tz=UTC)

    async def add_artifact(self, work_item_id: str, artifact: Artifact) -> None:
        item = self._items.get(work_item_id)
        if item is None:
            return
        item.artifacts.append(artifact)

    async def add_decision(self, work_item_id: str, decision: Decision) -> None:
        item = self._items.get(work_item_id)
        if item is None:
            return
        item.decisions.append(decision)

    async def get_children(self, parent_id: str) -> list[WorkItem]:
        return [i for i in self._items.values() if i.parent_id == parent_id]

    async def get_stalled_items(self, stall_threshold_seconds: int) -> list[WorkItem]:
        now = datetime.now(tz=UTC)
        stalled: list[WorkItem] = []
        for item in self._items.values():
            if item.status not in _STALL_STATUSES:
                continue
            elapsed = (now - item.updated_utc).total_seconds()
            if elapsed > stall_threshold_seconds:
                stalled.append(item)
        return stalled
