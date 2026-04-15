"""Neo4j connection management with pooling, retry, and health checking."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from summer_puppy.logging.config import get_logger

logger = get_logger(__name__)


@dataclass
class Neo4jConnectionConfig:
    """Configuration for the Neo4j driver connection pool."""

    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: str = "password"
    max_connection_pool_size: int = 50
    connection_timeout_seconds: float = 30.0
    max_transaction_retry_time_seconds: float = 30.0
    # Retry settings for transient errors
    max_retry_attempts: int = 3
    retry_base_delay_seconds: float = 0.5
    retry_max_delay_seconds: float = 5.0


@dataclass
class ConnectionHealth:
    """Result of a connectivity check."""

    is_healthy: bool
    latency_ms: float
    error: str | None = None
    server_info: dict[str, Any] = field(default_factory=dict)


class Neo4jConnectionManager:
    """Manages a Neo4j AsyncDriver with connection pooling and health checks."""

    def __init__(self, config: Neo4jConnectionConfig) -> None:
        self._config = config
        self._driver: Any = None

    async def connect(self) -> None:
        """Create the AsyncDriver.  Idempotent."""
        if self._driver is not None:
            return

        import neo4j  # type: ignore[import-untyped]

        self._driver = neo4j.AsyncGraphDatabase.driver(
            self._config.uri,
            auth=(self._config.username, self._config.password),
            max_connection_pool_size=self._config.max_connection_pool_size,
            connection_timeout=self._config.connection_timeout_seconds,
        )
        logger.info(
            "neo4j_connected",
            uri=self._config.uri,
            pool_size=self._config.max_connection_pool_size,
        )

    async def close(self) -> None:
        """Close the driver and release all connections."""
        if self._driver is not None:
            await self._driver.close()
            self._driver = None
            logger.info("neo4j_driver_closed")

    async def health_check(self) -> ConnectionHealth:
        """Ping the database and return latency + server info."""
        import time

        if self._driver is None:
            return ConnectionHealth(is_healthy=False, latency_ms=0, error="driver_not_initialized")

        start = time.monotonic()
        try:
            async with self._driver.session() as session:
                result = await session.run("RETURN 1 AS ping")
                await result.consume()
            latency_ms = (time.monotonic() - start) * 1000
            return ConnectionHealth(
                is_healthy=True,
                latency_ms=round(latency_ms, 2),
            )
        except Exception as exc:  # noqa: BLE001
            latency_ms = (time.monotonic() - start) * 1000
            logger.warning("neo4j_health_check_failed", error=str(exc))
            return ConnectionHealth(
                is_healthy=False,
                latency_ms=round(latency_ms, 2),
                error=str(exc),
            )

    @property
    def driver(self) -> Any:
        if self._driver is None:
            raise RuntimeError("Neo4jConnectionManager: call connect() first.")
        return self._driver

    async def run_with_retry(
        self,
        cypher: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a read query with exponential-backoff retry on transient errors."""
        import neo4j.exceptions  # type: ignore[import-untyped]

        delay = self._config.retry_base_delay_seconds
        last_exc: Exception | None = None

        for attempt in range(1, self._config.max_retry_attempts + 1):
            try:
                async with self.driver.session() as session:
                    result = await session.run(cypher, **(parameters or {}))
                    records = await result.data()
                    return [dict(r) for r in records]
            except neo4j.exceptions.TransientError as exc:
                last_exc = exc
                if attempt < self._config.max_retry_attempts:
                    logger.warning(
                        "neo4j_transient_error_retry",
                        attempt=attempt,
                        delay=delay,
                        error=str(exc),
                    )
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, self._config.retry_max_delay_seconds)
            except Exception as exc:  # noqa: BLE001
                raise exc from None

        raise RuntimeError(
            f"Neo4j query failed after {self._config.max_retry_attempts} attempts"
        ) from last_exc
