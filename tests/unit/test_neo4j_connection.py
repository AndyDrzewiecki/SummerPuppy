"""Unit tests for Neo4j connection management (Phase 12)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from summer_puppy.memory.connection import (
    ConnectionHealth,
    Neo4jConnectionConfig,
    Neo4jConnectionManager,
)


class TestNeo4jConnectionConfig:
    def test_defaults(self) -> None:
        cfg = Neo4jConnectionConfig()
        assert cfg.uri == "bolt://localhost:7687"
        assert cfg.username == "neo4j"
        assert cfg.password == "password"
        assert cfg.max_connection_pool_size == 50
        assert cfg.max_retry_attempts == 3
        assert cfg.retry_base_delay_seconds == 0.5

    def test_custom_values(self) -> None:
        cfg = Neo4jConnectionConfig(
            uri="bolt://prod:7687",
            username="admin",
            password="secret",
            max_connection_pool_size=100,
        )
        assert cfg.uri == "bolt://prod:7687"
        assert cfg.username == "admin"
        assert cfg.password == "secret"
        assert cfg.max_connection_pool_size == 100

    def test_retry_config(self) -> None:
        cfg = Neo4jConnectionConfig(
            max_retry_attempts=5,
            retry_base_delay_seconds=1.0,
            retry_max_delay_seconds=10.0,
        )
        assert cfg.max_retry_attempts == 5
        assert cfg.retry_base_delay_seconds == 1.0
        assert cfg.retry_max_delay_seconds == 10.0


class TestConnectionHealth:
    def test_healthy(self) -> None:
        h = ConnectionHealth(is_healthy=True, latency_ms=5.2)
        assert h.is_healthy is True
        assert h.latency_ms == 5.2
        assert h.error is None

    def test_unhealthy(self) -> None:
        h = ConnectionHealth(is_healthy=False, latency_ms=0.0, error="connection_refused")
        assert h.is_healthy is False
        assert h.error == "connection_refused"

    def test_server_info_defaults_empty(self) -> None:
        h = ConnectionHealth(is_healthy=True, latency_ms=1.0)
        assert h.server_info == {}


class TestNeo4jConnectionManager:
    def _make_mock_driver(self) -> tuple[MagicMock, AsyncMock]:
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_result = AsyncMock()
        mock_result.consume = AsyncMock()
        mock_session.run = AsyncMock(return_value=mock_result)

        mock_driver = MagicMock()
        mock_driver.session = MagicMock(return_value=mock_session)
        mock_driver.close = AsyncMock()
        return mock_driver, mock_session

    def test_init_driver_is_none(self) -> None:
        mgr = Neo4jConnectionManager(Neo4jConnectionConfig())
        assert mgr._driver is None

    async def test_connect_creates_driver(self) -> None:
        cfg = Neo4jConnectionConfig()
        mgr = Neo4jConnectionManager(cfg)

        mock_driver, _ = self._make_mock_driver()

        with patch("neo4j.AsyncGraphDatabase") as mock_gdb:
            mock_gdb.driver.return_value = mock_driver
            await mgr.connect()

        assert mgr._driver is not None

    async def test_connect_is_idempotent(self) -> None:
        cfg = Neo4jConnectionConfig()
        mgr = Neo4jConnectionManager(cfg)
        mock_driver, _ = self._make_mock_driver()

        with patch("neo4j.AsyncGraphDatabase") as mock_gdb:
            mock_gdb.driver.return_value = mock_driver
            await mgr.connect()
            await mgr.connect()  # second call should be a no-op

        # driver.driver() should only have been called once
        assert mock_gdb.driver.call_count == 1

    async def test_close_clears_driver(self) -> None:
        cfg = Neo4jConnectionConfig()
        mgr = Neo4jConnectionManager(cfg)
        mock_driver, _ = self._make_mock_driver()
        mgr._driver = mock_driver

        await mgr.close()

        mock_driver.close.assert_called_once()
        assert mgr._driver is None

    async def test_close_when_not_connected_is_noop(self) -> None:
        mgr = Neo4jConnectionManager(Neo4jConnectionConfig())
        # Should not raise
        await mgr.close()

    async def test_health_check_returns_healthy(self) -> None:
        mgr = Neo4jConnectionManager(Neo4jConnectionConfig())
        mock_driver, _ = self._make_mock_driver()
        mgr._driver = mock_driver

        health = await mgr.health_check()

        assert health.is_healthy is True
        assert health.latency_ms >= 0

    async def test_health_check_returns_unhealthy_on_exception(self) -> None:
        mgr = Neo4jConnectionManager(Neo4jConnectionConfig())
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session.run = AsyncMock(side_effect=Exception("connection_refused"))

        mock_driver = MagicMock()
        mock_driver.session = MagicMock(return_value=mock_session)
        mgr._driver = mock_driver

        health = await mgr.health_check()

        assert health.is_healthy is False
        assert health.error is not None
        assert "connection_refused" in health.error

    async def test_health_check_without_driver_is_unhealthy(self) -> None:
        mgr = Neo4jConnectionManager(Neo4jConnectionConfig())
        health = await mgr.health_check()
        assert health.is_healthy is False
        assert health.error == "driver_not_initialized"

    def test_driver_property_raises_when_not_connected(self) -> None:
        mgr = Neo4jConnectionManager(Neo4jConnectionConfig())
        with pytest.raises(RuntimeError, match="connect()"):
            _ = mgr.driver

    def test_driver_property_returns_driver_when_connected(self) -> None:
        mgr = Neo4jConnectionManager(Neo4jConnectionConfig())
        mock_driver = MagicMock()
        mgr._driver = mock_driver
        assert mgr.driver is mock_driver

    async def test_run_with_retry_succeeds_on_first_attempt(self) -> None:
        mgr = Neo4jConnectionManager(Neo4jConnectionConfig())
        mock_driver, mock_session = self._make_mock_driver()
        mgr._driver = mock_driver

        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=[{"x": 1}])
        mock_session.run = AsyncMock(return_value=mock_result)

        rows = await mgr.run_with_retry("RETURN 1 AS x")
        assert rows == [{"x": 1}]

    async def test_run_with_retry_raises_on_non_transient_error(self) -> None:
        mgr = Neo4jConnectionManager(Neo4jConnectionConfig())
        mock_driver, mock_session = self._make_mock_driver()
        mock_session.run = AsyncMock(side_effect=ValueError("bad_query"))
        mgr._driver = mock_driver

        with pytest.raises(ValueError, match="bad_query"):
            await mgr.run_with_retry("BAD CYPHER")
