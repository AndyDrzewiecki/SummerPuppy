from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from summer_puppy.pool.models import AgentPool, PoolStatus

if TYPE_CHECKING:
    from summer_puppy.work.models import WorkItemType

_ACTIVE_STATUSES = {PoolStatus.ONLINE, PoolStatus.DEGRADED}


@runtime_checkable
class PoolRegistry(Protocol):
    def register(self, pool: AgentPool) -> None: ...

    def unregister(self, pool_id: str) -> None: ...

    def get_pool(self, pool_id: str) -> AgentPool | None: ...

    def find_consumers(self, item_type: WorkItemType) -> list[AgentPool]: ...

    def find_producers(self, item_type: WorkItemType) -> list[AgentPool]: ...

    def heartbeat(self, pool_id: str) -> None: ...

    def all_pools(self) -> list[AgentPool]: ...


class InMemoryPoolRegistry:
    def __init__(self) -> None:
        self._pools: dict[str, AgentPool] = {}

    def register(self, pool: AgentPool) -> None:
        self._pools[pool.pool_id] = pool

    def unregister(self, pool_id: str) -> None:
        self._pools.pop(pool_id, None)

    def get_pool(self, pool_id: str) -> AgentPool | None:
        return self._pools.get(pool_id)

    def find_consumers(self, item_type: WorkItemType) -> list[AgentPool]:
        return [
            pool
            for pool in self._pools.values()
            if item_type in pool.can_consume
            and pool.status in _ACTIVE_STATUSES
            and pool.current_load < pool.max_capacity
        ]

    def find_producers(self, item_type: WorkItemType) -> list[AgentPool]:
        return [
            pool
            for pool in self._pools.values()
            if item_type in pool.can_produce and pool.status in _ACTIVE_STATUSES
        ]

    def heartbeat(self, pool_id: str) -> None:
        pool = self._pools.get(pool_id)
        if pool is not None:
            pool.last_heartbeat_utc = datetime.now(tz=UTC)

    def all_pools(self) -> list[AgentPool]:
        return list(self._pools.values())
