"""Unit tests for failover controller (Phase 12)."""

from __future__ import annotations

import pytest

from summer_puppy.recovery.failover import (
    FailoverConfig,
    FailoverController,
    FailoverStatus,
    ServiceEndpoint,
    ServiceRole,
)


def _make_config(
    auto_failover: bool = True,
    failure_threshold: int = 3,
) -> FailoverConfig:
    primary = ServiceEndpoint("primary-host", 7687)
    replica = ServiceEndpoint("replica-host", 7687, role=ServiceRole.REPLICA, is_healthy=True)
    return FailoverConfig(
        neo4j_primary=primary,
        neo4j_replicas=[replica],
        redis_primary=ServiceEndpoint("redis-primary", 6379),
        redis_replicas=[ServiceEndpoint("redis-replica", 6379, role=ServiceRole.REPLICA)],
        failure_threshold=failure_threshold,
        auto_failover=auto_failover,
    )


class TestServiceEndpoint:
    def test_address(self) -> None:
        ep = ServiceEndpoint("localhost", 7687)
        assert ep.address == "localhost:7687"

    def test_default_role_is_primary(self) -> None:
        ep = ServiceEndpoint("localhost", 7687)
        assert ep.role == ServiceRole.PRIMARY

    def test_replica_role(self) -> None:
        ep = ServiceEndpoint("replica", 6379, role=ServiceRole.REPLICA)
        assert ep.role == ServiceRole.REPLICA


class TestFailoverConfig:
    def test_defaults(self) -> None:
        cfg = FailoverConfig()
        assert cfg.failure_threshold == 3
        assert cfg.health_check_interval_seconds == 10.0
        assert cfg.auto_failover is False
        assert cfg.neo4j_primary.port == 7687
        assert cfg.redis_primary.port == 6379

    def test_custom_values(self) -> None:
        cfg = FailoverConfig(
            failure_threshold=5,
            auto_failover=True,
        )
        assert cfg.failure_threshold == 5
        assert cfg.auto_failover is True


class TestFailoverControllerInit:
    def test_initial_status_is_idle(self) -> None:
        ctrl = FailoverController(_make_config())
        assert ctrl.status == FailoverStatus.IDLE

    def test_failure_counts_start_at_zero(self) -> None:
        ctrl = FailoverController(_make_config())
        assert ctrl.get_failure_count("neo4j") == 0
        assert ctrl.get_failure_count("redis") == 0

    def test_active_neo4j_starts_as_primary(self) -> None:
        cfg = _make_config()
        ctrl = FailoverController(cfg)
        assert ctrl.active_neo4j_endpoint.host == "primary-host"

    def test_no_events_initially(self) -> None:
        ctrl = FailoverController(_make_config())
        assert ctrl.get_events() == []


class TestFailoverControllerHealthTracking:
    def test_healthy_result_resets_counter(self) -> None:
        ctrl = FailoverController(_make_config())
        ctrl._failure_counts["neo4j"] = 2
        ctrl.record_health_result("neo4j", is_healthy=True)
        assert ctrl.get_failure_count("neo4j") == 0

    def test_unhealthy_increments_counter(self) -> None:
        ctrl = FailoverController(_make_config(auto_failover=False))
        ctrl.record_health_result("neo4j", is_healthy=False)
        assert ctrl.get_failure_count("neo4j") == 1

    def test_threshold_not_reached_no_failover(self) -> None:
        ctrl = FailoverController(_make_config(auto_failover=True, failure_threshold=3))
        ctrl.record_health_result("neo4j", is_healthy=False)
        ctrl.record_health_result("neo4j", is_healthy=False)
        # Only 2 failures, threshold is 3
        assert ctrl.status == FailoverStatus.IDLE
        assert len(ctrl.get_events()) == 0

    def test_threshold_reached_with_auto_failover_triggers(self) -> None:
        ctrl = FailoverController(_make_config(auto_failover=True, failure_threshold=3))
        for _ in range(3):
            ctrl.record_health_result("neo4j", is_healthy=False)

        assert ctrl.status == FailoverStatus.FAILED_OVER
        assert len(ctrl.get_events()) == 1
        event = ctrl.get_events()[0]
        assert event.service == "neo4j"
        assert event.to_endpoint == "replica-host:7687"

    def test_threshold_reached_without_auto_failover_no_failover(self) -> None:
        ctrl = FailoverController(_make_config(auto_failover=False, failure_threshold=3))
        for _ in range(3):
            ctrl.record_health_result("neo4j", is_healthy=False)

        # No failover triggered, but count should still be at threshold
        assert len(ctrl.get_events()) == 0

    def test_active_endpoint_updated_after_failover(self) -> None:
        ctrl = FailoverController(_make_config(auto_failover=True, failure_threshold=2))
        ctrl.record_health_result("neo4j", is_healthy=False)
        ctrl.record_health_result("neo4j", is_healthy=False)

        assert ctrl.active_neo4j_endpoint.host == "replica-host"

    def test_failure_count_reset_after_failover(self) -> None:
        ctrl = FailoverController(_make_config(auto_failover=True, failure_threshold=2))
        ctrl.record_health_result("neo4j", is_healthy=False)
        ctrl.record_health_result("neo4j", is_healthy=False)

        assert ctrl.get_failure_count("neo4j") == 0

    def test_redis_failover(self) -> None:
        ctrl = FailoverController(_make_config(auto_failover=True, failure_threshold=2))
        ctrl.record_health_result("redis", is_healthy=False)
        ctrl.record_health_result("redis", is_healthy=False)

        assert ctrl.active_redis_endpoint.host == "redis-replica"
        event = ctrl.get_events()[0]
        assert event.service == "redis"

    def test_no_failover_when_no_healthy_replicas(self) -> None:
        cfg = FailoverConfig(
            neo4j_primary=ServiceEndpoint("primary", 7687),
            neo4j_replicas=[],  # no replicas
            failure_threshold=1,
            auto_failover=True,
        )
        ctrl = FailoverController(cfg)
        ctrl.record_health_result("neo4j", is_healthy=False)

        # Status stays IDLE when there are no replicas
        assert len(ctrl.get_events()) == 0


class TestFailoverControllerReset:
    def test_reset_failure_count(self) -> None:
        ctrl = FailoverController(_make_config())
        ctrl._failure_counts["neo4j"] = 5
        ctrl.reset_failure_count("neo4j")
        assert ctrl.get_failure_count("neo4j") == 0

    def test_reset_all_sets_recovered(self) -> None:
        ctrl = FailoverController(_make_config())
        ctrl._failure_counts = {"neo4j": 0, "redis": 0}
        ctrl.reset_failure_count("neo4j")
        # After all counts are 0 → status becomes RECOVERED
        assert ctrl.status == FailoverStatus.RECOVERED
