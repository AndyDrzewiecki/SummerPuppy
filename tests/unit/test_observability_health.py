"""Unit tests for health aggregator and component health (Phase 12)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from summer_puppy.observability.health import (
    ComponentHealth,
    HealthAggregator,
    HealthReport,
    HealthStatus,
    _aggregate_status,
    make_neo4j_checker,
    make_redis_checker,
)


# ---------------------------------------------------------------------------
# HealthStatus
# ---------------------------------------------------------------------------


class TestHealthStatus:
    def test_values(self) -> None:
        assert HealthStatus.HEALTHY == "healthy"
        assert HealthStatus.DEGRADED == "degraded"
        assert HealthStatus.UNHEALTHY == "unhealthy"
        assert HealthStatus.UNKNOWN == "unknown"


# ---------------------------------------------------------------------------
# ComponentHealth
# ---------------------------------------------------------------------------


class TestComponentHealth:
    def test_defaults(self) -> None:
        ch = ComponentHealth(name="neo4j")
        assert ch.status == HealthStatus.UNKNOWN
        assert ch.latency_ms == 0.0
        assert ch.error is None
        assert ch.details == {}

    def test_healthy_component(self) -> None:
        ch = ComponentHealth(name="redis", status=HealthStatus.HEALTHY, latency_ms=1.5)
        assert ch.status == HealthStatus.HEALTHY
        assert ch.latency_ms == 1.5

    def test_unhealthy_component(self) -> None:
        ch = ComponentHealth(
            name="kafka",
            status=HealthStatus.UNHEALTHY,
            error="connection_refused",
        )
        assert ch.status == HealthStatus.UNHEALTHY
        assert ch.error == "connection_refused"


# ---------------------------------------------------------------------------
# HealthReport
# ---------------------------------------------------------------------------


class TestHealthReport:
    def test_is_healthy_true(self) -> None:
        report = HealthReport(overall_status=HealthStatus.HEALTHY)
        assert report.is_healthy is True

    def test_is_healthy_false(self) -> None:
        report = HealthReport(overall_status=HealthStatus.UNHEALTHY)
        assert report.is_healthy is False

    def test_unhealthy_components_filtered(self) -> None:
        report = HealthReport(
            overall_status=HealthStatus.UNHEALTHY,
            components=[
                ComponentHealth(name="neo4j", status=HealthStatus.HEALTHY),
                ComponentHealth(name="redis", status=HealthStatus.UNHEALTHY),
                ComponentHealth(name="kafka", status=HealthStatus.UNHEALTHY),
            ],
        )
        unhealthy = report.unhealthy_components
        assert len(unhealthy) == 2
        assert {c.name for c in unhealthy} == {"redis", "kafka"}

    def test_degraded_components_filtered(self) -> None:
        report = HealthReport(
            overall_status=HealthStatus.DEGRADED,
            components=[
                ComponentHealth(name="neo4j", status=HealthStatus.HEALTHY),
                ComponentHealth(name="redis", status=HealthStatus.DEGRADED),
            ],
        )
        degraded = report.degraded_components
        assert len(degraded) == 1
        assert degraded[0].name == "redis"

    def test_uptime_seconds(self) -> None:
        report = HealthReport(overall_status=HealthStatus.HEALTHY, uptime_seconds=3600.0)
        assert report.uptime_seconds == 3600.0


# ---------------------------------------------------------------------------
# _aggregate_status
# ---------------------------------------------------------------------------


class TestAggregateStatus:
    def test_all_healthy(self) -> None:
        components = [
            ComponentHealth(name="a", status=HealthStatus.HEALTHY),
            ComponentHealth(name="b", status=HealthStatus.HEALTHY),
        ]
        assert _aggregate_status(components) == HealthStatus.HEALTHY

    def test_one_unhealthy_makes_overall_unhealthy(self) -> None:
        components = [
            ComponentHealth(name="a", status=HealthStatus.HEALTHY),
            ComponentHealth(name="b", status=HealthStatus.UNHEALTHY),
        ]
        assert _aggregate_status(components) == HealthStatus.UNHEALTHY

    def test_degraded_without_unhealthy_is_degraded(self) -> None:
        components = [
            ComponentHealth(name="a", status=HealthStatus.HEALTHY),
            ComponentHealth(name="b", status=HealthStatus.DEGRADED),
        ]
        assert _aggregate_status(components) == HealthStatus.DEGRADED

    def test_unknown_makes_degraded(self) -> None:
        components = [
            ComponentHealth(name="a", status=HealthStatus.HEALTHY),
            ComponentHealth(name="b", status=HealthStatus.UNKNOWN),
        ]
        assert _aggregate_status(components) == HealthStatus.DEGRADED

    def test_empty_list_is_healthy(self) -> None:
        assert _aggregate_status([]) == HealthStatus.HEALTHY

    def test_unhealthy_beats_degraded(self) -> None:
        components = [
            ComponentHealth(name="a", status=HealthStatus.DEGRADED),
            ComponentHealth(name="b", status=HealthStatus.UNHEALTHY),
        ]
        assert _aggregate_status(components) == HealthStatus.UNHEALTHY


# ---------------------------------------------------------------------------
# HealthAggregator — register / unregister
# ---------------------------------------------------------------------------


class TestHealthAggregatorRegister:
    def test_register_adds_checker(self) -> None:
        agg = HealthAggregator()
        agg.register("neo4j", AsyncMock())
        assert "neo4j" in agg.registered_components

    def test_unregister_removes_checker(self) -> None:
        agg = HealthAggregator()
        agg.register("redis", AsyncMock())
        agg.unregister("redis")
        assert "redis" not in agg.registered_components

    def test_unregister_unknown_is_noop(self) -> None:
        agg = HealthAggregator()
        agg.unregister("nonexistent")  # Should not raise

    def test_registered_components_lists_all(self) -> None:
        agg = HealthAggregator()
        agg.register("a", AsyncMock())
        agg.register("b", AsyncMock())
        agg.register("c", AsyncMock())
        assert set(agg.registered_components) == {"a", "b", "c"}


# ---------------------------------------------------------------------------
# HealthAggregator — check_component
# ---------------------------------------------------------------------------


class TestHealthAggregatorCheckComponent:
    async def test_check_returns_component_health_from_checker(self) -> None:
        agg = HealthAggregator()
        expected = ComponentHealth(name="neo4j", status=HealthStatus.HEALTHY, latency_ms=2.5)

        async def checker() -> ComponentHealth:
            return expected

        agg.register("neo4j", checker)
        result = await agg.check_component("neo4j")

        assert result.name == "neo4j"
        assert result.status == HealthStatus.HEALTHY

    async def test_check_returns_unhealthy_on_exception(self) -> None:
        agg = HealthAggregator()

        async def failing_checker() -> ComponentHealth:
            raise ConnectionError("refused")

        agg.register("kafka", failing_checker)
        result = await agg.check_component("kafka")

        assert result.status == HealthStatus.UNHEALTHY
        assert "refused" in (result.error or "")

    async def test_check_unknown_component_returns_unknown(self) -> None:
        agg = HealthAggregator()
        result = await agg.check_component("nonexistent")
        assert result.status == HealthStatus.UNKNOWN
        assert result.error == "checker_not_registered"

    async def test_check_wraps_bool_true_as_healthy(self) -> None:
        agg = HealthAggregator()

        async def bool_checker() -> bool:
            return True

        agg.register("simple", bool_checker)
        result = await agg.check_component("simple")
        assert result.status == HealthStatus.HEALTHY

    async def test_check_wraps_bool_false_as_unhealthy(self) -> None:
        agg = HealthAggregator()

        async def bool_checker() -> bool:
            return False

        agg.register("simple", bool_checker)
        result = await agg.check_component("simple")
        assert result.status == HealthStatus.UNHEALTHY


# ---------------------------------------------------------------------------
# HealthAggregator — run_checks
# ---------------------------------------------------------------------------


class TestHealthAggregatorRunChecks:
    async def test_run_checks_all_healthy(self) -> None:
        agg = HealthAggregator()

        for name in ["neo4j", "redis", "kafka"]:
            n = name

            async def make_checker(nm: str = n) -> ComponentHealth:
                return ComponentHealth(name=nm, status=HealthStatus.HEALTHY)

            agg.register(name, make_checker)

        report = await agg.run_checks()

        assert report.overall_status == HealthStatus.HEALTHY
        assert len(report.components) == 3

    async def test_run_checks_one_unhealthy(self) -> None:
        agg = HealthAggregator()

        async def healthy() -> ComponentHealth:
            return ComponentHealth(name="neo4j", status=HealthStatus.HEALTHY)

        async def unhealthy() -> ComponentHealth:
            return ComponentHealth(name="redis", status=HealthStatus.UNHEALTHY)

        agg.register("neo4j", healthy)
        agg.register("redis", unhealthy)

        report = await agg.run_checks()

        assert report.overall_status == HealthStatus.UNHEALTHY

    async def test_run_checks_empty_is_healthy(self) -> None:
        agg = HealthAggregator()
        report = await agg.run_checks()
        assert report.overall_status == HealthStatus.HEALTHY
        assert report.components == []

    async def test_run_checks_includes_version(self) -> None:
        agg = HealthAggregator(service_version="1.2.3")
        report = await agg.run_checks()
        assert report.version == "1.2.3"

    async def test_run_checks_calculates_uptime(self) -> None:
        agg = HealthAggregator()
        agg.set_started_utc(datetime.now(tz=UTC))
        report = await agg.run_checks()
        assert report.uptime_seconds >= 0.0

    async def test_run_checks_handles_timeout(self) -> None:
        agg = HealthAggregator()
        import asyncio

        async def slow_checker() -> ComponentHealth:
            await asyncio.sleep(10)  # Much longer than timeout
            return ComponentHealth(name="slow", status=HealthStatus.HEALTHY)

        agg.register("slow", slow_checker)
        report = await agg.run_checks(timeout_seconds=0.05)

        assert any(c.name == "slow" for c in report.components)
        slow = next(c for c in report.components if c.name == "slow")
        assert slow.status == HealthStatus.UNHEALTHY
        assert "timed_out" in (slow.error or "")


# ---------------------------------------------------------------------------
# Checker factories
# ---------------------------------------------------------------------------


class TestCheckerFactories:
    async def test_make_neo4j_checker_healthy(self) -> None:
        from summer_puppy.memory.connection import ConnectionHealth

        mock_mgr = AsyncMock()
        mock_mgr.health_check = AsyncMock(
            return_value=ConnectionHealth(is_healthy=True, latency_ms=5.0)
        )

        checker = make_neo4j_checker(mock_mgr)
        result = await checker()

        assert result.name == "neo4j"
        assert result.status == HealthStatus.HEALTHY

    async def test_make_neo4j_checker_unhealthy(self) -> None:
        from summer_puppy.memory.connection import ConnectionHealth

        mock_mgr = AsyncMock()
        mock_mgr.health_check = AsyncMock(
            return_value=ConnectionHealth(
                is_healthy=False, latency_ms=0.0, error="timeout"
            )
        )

        checker = make_neo4j_checker(mock_mgr)
        result = await checker()

        assert result.status == HealthStatus.UNHEALTHY
        assert result.error == "timeout"

    async def test_make_redis_checker_healthy(self) -> None:
        mock_store = AsyncMock()
        mock_store.health_check = AsyncMock(return_value=True)

        checker = make_redis_checker(mock_store)
        result = await checker()

        assert result.name == "redis"
        assert result.status == HealthStatus.HEALTHY

    async def test_make_redis_checker_unhealthy(self) -> None:
        mock_store = AsyncMock()
        mock_store.health_check = AsyncMock(return_value=False)

        checker = make_redis_checker(mock_store)
        result = await checker()

        assert result.status == HealthStatus.UNHEALTHY
