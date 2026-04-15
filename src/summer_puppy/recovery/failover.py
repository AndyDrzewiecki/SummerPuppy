"""Failover configuration and controller for SummerPuppy (Phase 12).

Supports primary/replica topology for Neo4j and Redis.  The controller
detects unhealthy primaries and promotes replicas automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from summer_puppy.logging.config import get_logger

logger = get_logger(__name__)


class FailoverStatus(StrEnum):
    IDLE = "idle"
    DETECTING = "detecting"
    FAILING_OVER = "failing_over"
    FAILED_OVER = "failed_over"
    RECOVERED = "recovered"


class ServiceRole(StrEnum):
    PRIMARY = "primary"
    REPLICA = "replica"


@dataclass
class ServiceEndpoint:
    """A single service endpoint (primary or replica)."""

    host: str
    port: int
    role: ServiceRole = ServiceRole.PRIMARY
    is_healthy: bool = True
    last_checked_utc: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class FailoverConfig:
    """Configuration for the FailoverController."""

    # Neo4j endpoints
    neo4j_primary: ServiceEndpoint = field(
        default_factory=lambda: ServiceEndpoint("localhost", 7687)
    )
    neo4j_replicas: list[ServiceEndpoint] = field(default_factory=list)
    # Redis endpoints
    redis_primary: ServiceEndpoint = field(
        default_factory=lambda: ServiceEndpoint("localhost", 6379)
    )
    redis_replicas: list[ServiceEndpoint] = field(default_factory=list)
    # Kafka bootstrap servers (comma-separated)
    kafka_bootstrap_servers: str = "localhost:9092"
    # How many consecutive health-check failures before triggering failover
    failure_threshold: int = 3
    # Seconds between health checks
    health_check_interval_seconds: float = 10.0
    # Whether to auto-failover or just alert
    auto_failover: bool = False


class FailoverEvent(BaseModel):
    """Record of a failover event."""

    event_id: str = Field(default_factory=lambda: __import__("uuid").uuid4().__str__())
    service: str  # "neo4j" | "redis"
    from_endpoint: str
    to_endpoint: str
    reason: str
    triggered_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    status: FailoverStatus = FailoverStatus.FAILING_OVER


class FailoverController:
    """Monitors service endpoints and manages failover promotion.

    In auto_failover mode the controller automatically promotes the first
    healthy replica when the primary fails enough consecutive checks.
    Otherwise it logs and records the failure for human action.
    """

    def __init__(self, config: FailoverConfig) -> None:
        self._config = config
        self._failure_counts: dict[str, int] = {
            "neo4j": 0,
            "redis": 0,
        }
        self._status = FailoverStatus.IDLE
        self._events: list[FailoverEvent] = []
        # Track the currently active endpoints
        self._active_neo4j = config.neo4j_primary
        self._active_redis = config.redis_primary

    # ------------------------------------------------------------------
    # Health tracking
    # ------------------------------------------------------------------

    def record_health_result(self, service: str, is_healthy: bool) -> None:
        """Update failure counter for the service; trigger failover if threshold exceeded."""
        if is_healthy:
            self._failure_counts[service] = 0
            logger.debug("failover_health_ok", service=service)
        else:
            self._failure_counts[service] += 1
            count = self._failure_counts[service]
            logger.warning(
                "failover_health_failure",
                service=service,
                consecutive_failures=count,
                threshold=self._config.failure_threshold,
            )
            if count >= self._config.failure_threshold:
                self._maybe_failover(service)

    def _maybe_failover(self, service: str) -> None:
        if not self._config.auto_failover:
            logger.error(
                "failover_threshold_reached_manual_action_required",
                service=service,
                failures=self._failure_counts[service],
            )
            return

        if service == "neo4j":
            self._do_failover_neo4j()
        elif service == "redis":
            self._do_failover_redis()

    def _do_failover_neo4j(self) -> None:
        replicas = [r for r in self._config.neo4j_replicas if r.is_healthy]
        if not replicas:
            logger.error("failover_no_healthy_neo4j_replicas")
            return

        new_primary = replicas[0]
        event = FailoverEvent(
            service="neo4j",
            from_endpoint=self._active_neo4j.address,
            to_endpoint=new_primary.address,
            reason=f"primary_failed_{self._failure_counts['neo4j']}_consecutive_checks",
        )
        self._active_neo4j = new_primary
        self._failure_counts["neo4j"] = 0
        self._status = FailoverStatus.FAILED_OVER
        self._events.append(event)
        logger.warning(
            "neo4j_failover_complete",
            from_endpoint=event.from_endpoint,
            to_endpoint=event.to_endpoint,
        )

    def _do_failover_redis(self) -> None:
        replicas = [r for r in self._config.redis_replicas if r.is_healthy]
        if not replicas:
            logger.error("failover_no_healthy_redis_replicas")
            return

        new_primary = replicas[0]
        event = FailoverEvent(
            service="redis",
            from_endpoint=self._active_redis.address,
            to_endpoint=new_primary.address,
            reason=f"primary_failed_{self._failure_counts['redis']}_consecutive_checks",
        )
        self._active_redis = new_primary
        self._failure_counts["redis"] = 0
        self._status = FailoverStatus.FAILED_OVER
        self._events.append(event)
        logger.warning(
            "redis_failover_complete",
            from_endpoint=event.from_endpoint,
            to_endpoint=event.to_endpoint,
        )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def active_neo4j_endpoint(self) -> ServiceEndpoint:
        return self._active_neo4j

    @property
    def active_redis_endpoint(self) -> ServiceEndpoint:
        return self._active_redis

    @property
    def status(self) -> FailoverStatus:
        return self._status

    def get_failure_count(self, service: str) -> int:
        return self._failure_counts.get(service, 0)

    def get_events(self) -> list[FailoverEvent]:
        return list(self._events)

    def reset_failure_count(self, service: str) -> None:
        """Reset after successful recovery."""
        self._failure_counts[service] = 0
        if not any(v > 0 for v in self._failure_counts.values()):
            self._status = FailoverStatus.RECOVERED
