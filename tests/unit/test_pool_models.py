from __future__ import annotations

from datetime import UTC, datetime

from summer_puppy.pool.models import AgentPool, PoolStatus, PoolType
from summer_puppy.work.models import WorkItemType

# ---------------------------------------------------------------------------
# PoolType enum tests
# ---------------------------------------------------------------------------


class TestPoolType:
    def test_enum_values(self) -> None:
        assert PoolType.THREAT_RESEARCH == "THREAT_RESEARCH"
        assert PoolType.ENGINEERING == "ENGINEERING"
        assert PoolType.ORCHESTRATION == "ORCHESTRATION"
        assert PoolType.QA_VALIDATION == "QA_VALIDATION"

    def test_member_count(self) -> None:
        assert len(PoolType) == 4


# ---------------------------------------------------------------------------
# PoolStatus enum tests
# ---------------------------------------------------------------------------


class TestPoolStatus:
    def test_enum_values(self) -> None:
        assert PoolStatus.ONLINE == "ONLINE"
        assert PoolStatus.OFFLINE == "OFFLINE"
        assert PoolStatus.DEGRADED == "DEGRADED"

    def test_member_count(self) -> None:
        assert len(PoolStatus) == 3


# ---------------------------------------------------------------------------
# AgentPool model tests
# ---------------------------------------------------------------------------


class TestAgentPool:
    def test_minimal_creation(self) -> None:
        pool = AgentPool(name="Threat Research Pool", pool_type=PoolType.THREAT_RESEARCH)
        assert pool.name == "Threat Research Pool"
        assert pool.pool_type == PoolType.THREAT_RESEARCH
        # defaults
        assert pool.pool_id  # auto-generated uuid
        assert pool.can_produce == []
        assert pool.can_consume == []
        assert pool.status == PoolStatus.ONLINE
        assert pool.current_load == 0
        assert pool.max_capacity == 10
        assert pool.sla_response_seconds is None
        assert isinstance(pool.registered_utc, datetime)
        assert isinstance(pool.last_heartbeat_utc, datetime)

    def test_all_fields(self) -> None:
        now = datetime(2026, 3, 16, 10, 0, 0, tzinfo=UTC)
        pool = AgentPool(
            pool_id="pool-custom",
            name="Engineering Pool",
            pool_type=PoolType.ENGINEERING,
            can_produce=[WorkItemType.PATCH_REQUEST, WorkItemType.DETECTION_RULE],
            can_consume=[WorkItemType.THREAT_REPORT],
            status=PoolStatus.DEGRADED,
            current_load=5,
            max_capacity=20,
            sla_response_seconds=300,
            registered_utc=now,
            last_heartbeat_utc=now,
        )
        assert pool.pool_id == "pool-custom"
        assert pool.name == "Engineering Pool"
        assert pool.pool_type == PoolType.ENGINEERING
        assert pool.can_produce == [WorkItemType.PATCH_REQUEST, WorkItemType.DETECTION_RULE]
        assert pool.can_consume == [WorkItemType.THREAT_REPORT]
        assert pool.status == PoolStatus.DEGRADED
        assert pool.current_load == 5
        assert pool.max_capacity == 20
        assert pool.sla_response_seconds == 300
        assert pool.registered_utc == now
        assert pool.last_heartbeat_utc == now

    def test_default_status_is_online(self) -> None:
        pool = AgentPool(name="Test", pool_type=PoolType.QA_VALIDATION)
        assert pool.status == PoolStatus.ONLINE

    def test_unique_pool_ids(self) -> None:
        p1 = AgentPool(name="Pool A", pool_type=PoolType.ORCHESTRATION)
        p2 = AgentPool(name="Pool B", pool_type=PoolType.ORCHESTRATION)
        assert p1.pool_id != p2.pool_id

    def test_serialization_round_trip(self) -> None:
        pool = AgentPool(
            name="Round-trip Pool",
            pool_type=PoolType.THREAT_RESEARCH,
            can_produce=[WorkItemType.THREAT_REPORT],
            can_consume=[WorkItemType.INCIDENT_REPORT],
            status=PoolStatus.ONLINE,
            current_load=3,
            max_capacity=15,
            sla_response_seconds=120,
        )
        data = pool.model_dump()
        restored = AgentPool.model_validate(data)
        assert restored.pool_id == pool.pool_id
        assert restored.name == pool.name
        assert restored.pool_type == pool.pool_type
        assert restored.can_produce == pool.can_produce
        assert restored.can_consume == pool.can_consume
        assert restored.status == pool.status
        assert restored.current_load == pool.current_load
        assert restored.max_capacity == pool.max_capacity
        assert restored.sla_response_seconds == pool.sla_response_seconds
