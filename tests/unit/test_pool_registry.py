from __future__ import annotations

from datetime import UTC, datetime

from summer_puppy.pool.models import AgentPool, PoolStatus, PoolType
from summer_puppy.pool.registry import InMemoryPoolRegistry, PoolRegistry
from summer_puppy.work.models import WorkItemType

# ---------------------------------------------------------------------------
# InMemoryPoolRegistry tests
# ---------------------------------------------------------------------------


class TestInMemoryPoolRegistryBasic:
    def test_register_and_get_pool_round_trip(self) -> None:
        registry = InMemoryPoolRegistry()
        pool = AgentPool(name="Threat Pool", pool_type=PoolType.THREAT_RESEARCH)
        registry.register(pool)
        retrieved = registry.get_pool(pool.pool_id)
        assert retrieved is not None
        assert retrieved.pool_id == pool.pool_id
        assert retrieved.name == "Threat Pool"

    def test_unregister_removes_pool(self) -> None:
        registry = InMemoryPoolRegistry()
        pool = AgentPool(name="Temp Pool", pool_type=PoolType.ENGINEERING)
        registry.register(pool)
        registry.unregister(pool.pool_id)
        assert registry.get_pool(pool.pool_id) is None

    def test_get_pool_returns_none_for_missing(self) -> None:
        registry = InMemoryPoolRegistry()
        assert registry.get_pool("nonexistent-id") is None


class TestInMemoryPoolRegistryFindConsumers:
    def test_returns_pools_with_matching_can_consume_and_online_and_capacity(self) -> None:
        registry = InMemoryPoolRegistry()
        pool = AgentPool(
            name="Consumer Pool",
            pool_type=PoolType.ENGINEERING,
            can_consume=[WorkItemType.THREAT_REPORT],
            status=PoolStatus.ONLINE,
            current_load=3,
            max_capacity=10,
        )
        registry.register(pool)
        consumers = registry.find_consumers(WorkItemType.THREAT_REPORT)
        assert len(consumers) == 1
        assert consumers[0].pool_id == pool.pool_id

    def test_excludes_offline_pools(self) -> None:
        registry = InMemoryPoolRegistry()
        pool = AgentPool(
            name="Offline Pool",
            pool_type=PoolType.ENGINEERING,
            can_consume=[WorkItemType.THREAT_REPORT],
            status=PoolStatus.OFFLINE,
            current_load=0,
            max_capacity=10,
        )
        registry.register(pool)
        consumers = registry.find_consumers(WorkItemType.THREAT_REPORT)
        assert len(consumers) == 0

    def test_excludes_pools_at_max_capacity(self) -> None:
        registry = InMemoryPoolRegistry()
        pool = AgentPool(
            name="Full Pool",
            pool_type=PoolType.ENGINEERING,
            can_consume=[WorkItemType.THREAT_REPORT],
            status=PoolStatus.ONLINE,
            current_load=10,
            max_capacity=10,
        )
        registry.register(pool)
        consumers = registry.find_consumers(WorkItemType.THREAT_REPORT)
        assert len(consumers) == 0

    def test_includes_degraded_pools(self) -> None:
        registry = InMemoryPoolRegistry()
        pool = AgentPool(
            name="Degraded Pool",
            pool_type=PoolType.ENGINEERING,
            can_consume=[WorkItemType.PATCH_REQUEST],
            status=PoolStatus.DEGRADED,
            current_load=2,
            max_capacity=10,
        )
        registry.register(pool)
        consumers = registry.find_consumers(WorkItemType.PATCH_REQUEST)
        assert len(consumers) == 1
        assert consumers[0].pool_id == pool.pool_id


class TestInMemoryPoolRegistryFindProducers:
    def test_returns_pools_with_matching_can_produce(self) -> None:
        registry = InMemoryPoolRegistry()
        pool = AgentPool(
            name="Producer Pool",
            pool_type=PoolType.THREAT_RESEARCH,
            can_produce=[WorkItemType.THREAT_REPORT, WorkItemType.INCIDENT_REPORT],
            status=PoolStatus.ONLINE,
        )
        registry.register(pool)
        producers = registry.find_producers(WorkItemType.THREAT_REPORT)
        assert len(producers) == 1
        assert producers[0].pool_id == pool.pool_id

    def test_excludes_offline_producers(self) -> None:
        registry = InMemoryPoolRegistry()
        pool = AgentPool(
            name="Offline Producer",
            pool_type=PoolType.THREAT_RESEARCH,
            can_produce=[WorkItemType.THREAT_REPORT],
            status=PoolStatus.OFFLINE,
        )
        registry.register(pool)
        producers = registry.find_producers(WorkItemType.THREAT_REPORT)
        assert len(producers) == 0

    def test_includes_degraded_producers(self) -> None:
        registry = InMemoryPoolRegistry()
        pool = AgentPool(
            name="Degraded Producer",
            pool_type=PoolType.THREAT_RESEARCH,
            can_produce=[WorkItemType.DETECTION_RULE],
            status=PoolStatus.DEGRADED,
        )
        registry.register(pool)
        producers = registry.find_producers(WorkItemType.DETECTION_RULE)
        assert len(producers) == 1


class TestInMemoryPoolRegistryHeartbeat:
    def test_heartbeat_updates_last_heartbeat_utc(self) -> None:
        registry = InMemoryPoolRegistry()
        old_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        pool = AgentPool(
            name="Heartbeat Pool",
            pool_type=PoolType.ORCHESTRATION,
            last_heartbeat_utc=old_time,
        )
        registry.register(pool)
        registry.heartbeat(pool.pool_id)
        updated = registry.get_pool(pool.pool_id)
        assert updated is not None
        assert updated.last_heartbeat_utc > old_time


class TestInMemoryPoolRegistryAllPools:
    def test_all_pools_returns_all_registered(self) -> None:
        registry = InMemoryPoolRegistry()
        p1 = AgentPool(name="Pool A", pool_type=PoolType.THREAT_RESEARCH)
        p2 = AgentPool(name="Pool B", pool_type=PoolType.ENGINEERING)
        p3 = AgentPool(name="Pool C", pool_type=PoolType.QA_VALIDATION)
        registry.register(p1)
        registry.register(p2)
        registry.register(p3)
        all_pools = registry.all_pools()
        assert len(all_pools) == 3
        pool_ids = {p.pool_id for p in all_pools}
        assert p1.pool_id in pool_ids
        assert p2.pool_id in pool_ids
        assert p3.pool_id in pool_ids


class TestPoolRegistryProtocolConformance:
    def test_isinstance_check(self) -> None:
        registry = InMemoryPoolRegistry()
        assert isinstance(registry, PoolRegistry)
