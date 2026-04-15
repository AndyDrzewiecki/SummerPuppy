"""Aggregated health checking for all production components (Phase 12).

Provides ``HealthAggregator`` which polls each registered component and
surfaces a structured ``HealthReport`` consumable by the ``/health/detailed``
endpoint and alerting rules.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Callable

from pydantic import BaseModel, Field

from summer_puppy.logging.config import get_logger

logger = get_logger(__name__)


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ComponentHealth(BaseModel):
    """Health status of a single infrastructure component."""

    name: str
    status: HealthStatus = HealthStatus.UNKNOWN
    latency_ms: float = 0.0
    error: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    checked_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class HealthReport(BaseModel):
    """Aggregated health report for the entire service."""

    overall_status: HealthStatus
    components: list[ComponentHealth] = Field(default_factory=list)
    version: str = "0.2.0"
    uptime_seconds: float = 0.0
    checked_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))

    @property
    def is_healthy(self) -> bool:
        return self.overall_status == HealthStatus.HEALTHY

    @property
    def unhealthy_components(self) -> list[ComponentHealth]:
        return [c for c in self.components if c.status == HealthStatus.UNHEALTHY]

    @property
    def degraded_components(self) -> list[ComponentHealth]:
        return [c for c in self.components if c.status == HealthStatus.DEGRADED]


# ---------------------------------------------------------------------------
# Health aggregator
# ---------------------------------------------------------------------------


CheckerFn = Callable[[], Any]  # async callable -> ComponentHealth


class HealthAggregator:
    """Runs all registered component health checks and aggregates the results.

    Usage::

        agg = HealthAggregator()
        agg.register("neo4j", check_neo4j)
        agg.register("redis", check_redis)
        agg.register("kafka", check_kafka)

        report = await agg.run_checks()
    """

    def __init__(self, service_version: str = "0.2.0") -> None:
        self._checkers: dict[str, CheckerFn] = {}
        self._version = service_version
        self._started_utc: datetime | None = None

    def set_started_utc(self, started: datetime) -> None:
        self._started_utc = started

    def register(self, name: str, checker: CheckerFn) -> None:
        """Register an async component health checker by name."""
        self._checkers[name] = checker
        logger.debug("health_checker_registered", component=name)

    def unregister(self, name: str) -> None:
        """Remove a registered checker."""
        self._checkers.pop(name, None)

    async def check_component(self, name: str) -> ComponentHealth:
        """Run a single named checker and return its ComponentHealth."""
        checker = self._checkers.get(name)
        if checker is None:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNKNOWN,
                error="checker_not_registered",
            )
        try:
            result = await checker()
            if isinstance(result, ComponentHealth):
                return result
            # If the checker returned a plain bool
            return ComponentHealth(
                name=name,
                status=HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("health_check_raised", component=name, error=str(exc))
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                error=str(exc),
            )

    async def run_checks(self, timeout_seconds: float = 5.0) -> HealthReport:
        """Run all registered checks concurrently and return a HealthReport."""
        import time

        start = time.monotonic()

        tasks = {
            name: asyncio.create_task(self.check_component(name))
            for name in self._checkers
        }

        results: list[ComponentHealth] = []
        for name, task in tasks.items():
            try:
                component = await asyncio.wait_for(task, timeout=timeout_seconds)
            except asyncio.TimeoutError:
                component = ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    error=f"health_check_timed_out_after_{timeout_seconds}s",
                )
            results.append(component)

        overall = _aggregate_status(results)
        uptime = 0.0
        if self._started_utc is not None:
            uptime = (datetime.now(tz=UTC) - self._started_utc).total_seconds()

        elapsed_ms = (time.monotonic() - start) * 1000
        logger.info(
            "health_check_complete",
            overall=overall.value,
            components=len(results),
            duration_ms=round(elapsed_ms, 1),
        )
        return HealthReport(
            overall_status=overall,
            components=results,
            version=self._version,
            uptime_seconds=uptime,
        )

    @property
    def registered_components(self) -> list[str]:
        return list(self._checkers.keys())


def _aggregate_status(components: list[ComponentHealth]) -> HealthStatus:
    """Derive overall status from component statuses."""
    if not components:
        return HealthStatus.HEALTHY

    statuses = {c.status for c in components}
    if HealthStatus.UNHEALTHY in statuses:
        return HealthStatus.UNHEALTHY
    if HealthStatus.DEGRADED in statuses or HealthStatus.UNKNOWN in statuses:
        return HealthStatus.DEGRADED
    return HealthStatus.HEALTHY


# ---------------------------------------------------------------------------
# Pre-built checker factories
# ---------------------------------------------------------------------------


def make_neo4j_checker(connection_manager: Any) -> CheckerFn:
    """Return a health checker for a Neo4jConnectionManager."""

    async def check() -> ComponentHealth:
        import time

        start = time.monotonic()
        health = await connection_manager.health_check()
        latency = (time.monotonic() - start) * 1000
        return ComponentHealth(
            name="neo4j",
            status=HealthStatus.HEALTHY if health.is_healthy else HealthStatus.UNHEALTHY,
            latency_ms=round(latency, 2),
            error=health.error,
        )

    return check


def make_redis_checker(state_store: Any) -> CheckerFn:
    """Return a health checker for a RedisStateStore."""

    async def check() -> ComponentHealth:
        import time

        start = time.monotonic()
        healthy = await state_store.health_check()
        latency = (time.monotonic() - start) * 1000
        return ComponentHealth(
            name="redis",
            status=HealthStatus.HEALTHY if healthy else HealthStatus.UNHEALTHY,
            latency_ms=round(latency, 2),
        )

    return check


def make_kafka_checker(bootstrap_servers: str) -> CheckerFn:
    """Return a health checker that verifies Kafka broker connectivity."""

    async def check() -> ComponentHealth:
        import time

        start = time.monotonic()
        try:
            from kafka.admin import KafkaAdminClient  # type: ignore[import-untyped]

            client = KafkaAdminClient(bootstrap_servers=bootstrap_servers)
            client.list_topics()
            client.close()
            latency = (time.monotonic() - start) * 1000
            return ComponentHealth(
                name="kafka",
                status=HealthStatus.HEALTHY,
                latency_ms=round(latency, 2),
            )
        except Exception as exc:  # noqa: BLE001
            latency = (time.monotonic() - start) * 1000
            return ComponentHealth(
                name="kafka",
                status=HealthStatus.UNHEALTHY,
                latency_ms=round(latency, 2),
                error=str(exc),
            )

    return check
