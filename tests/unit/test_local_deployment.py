"""Tests for local deployment module (Phase 10)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from summer_puppy.local.context_cache import LocalContextCache
from summer_puppy.local.emergency_triage import OfflineTriageEngine
from summer_puppy.local.health import OllamaHealthMonitor
from summer_puppy.local.models import (
    HealthStatus,
    LocalDeploymentConfig,
    OfflineTriage,
    TenantContextSlice,
)


# ---------------------------------------------------------------------------
# TestTenantContextSlice
# ---------------------------------------------------------------------------


class TestTenantContextSlice:
    def test_fresh_snapshot_not_stale(self) -> None:
        snap = TenantContextSlice(tenant_id="t1", max_age_hours=24)
        assert snap.is_stale is False

    def test_old_snapshot_is_stale(self) -> None:
        old_time = datetime.now(tz=UTC) - timedelta(hours=25)
        snap = TenantContextSlice(tenant_id="t1", snapshot_utc=old_time, max_age_hours=24)
        assert snap.is_stale is True


# ---------------------------------------------------------------------------
# TestLocalContextCache
# ---------------------------------------------------------------------------


class TestLocalContextCache:
    def test_get_returns_none_before_update(self) -> None:
        cache = LocalContextCache()
        assert cache.get_snapshot("tenant-1") is None

    def test_update_and_get_snapshot(self) -> None:
        cache = LocalContextCache()
        snap = TenantContextSlice(tenant_id="tenant-1", playbook_summaries=["PB1"])
        cache.update_snapshot(snap)
        result = cache.get_snapshot("tenant-1")
        assert result is not None
        assert result.tenant_id == "tenant-1"
        assert result.playbook_summaries == ["PB1"]

    def test_is_fresh_false_before_update(self) -> None:
        cache = LocalContextCache()
        assert cache.is_fresh("tenant-1") is False

    def test_is_fresh_true_after_update(self) -> None:
        cache = LocalContextCache()
        snap = TenantContextSlice(tenant_id="tenant-1")
        cache.update_snapshot(snap)
        assert cache.is_fresh("tenant-1") is True

    def test_invalidate_clears_snapshot(self) -> None:
        cache = LocalContextCache()
        snap = TenantContextSlice(tenant_id="tenant-1")
        cache.update_snapshot(snap)
        cache.invalidate("tenant-1")
        assert cache.get_snapshot("tenant-1") is None

    def test_build_context_string_empty_when_no_snapshot(self) -> None:
        cache = LocalContextCache()
        result = cache.build_context_string("no-such-tenant")
        assert result == ""

    def test_build_context_string_includes_playbooks(self) -> None:
        cache = LocalContextCache()
        snap = TenantContextSlice(
            tenant_id="t1",
            playbook_summaries=["Playbook A: do X", "Playbook B: do Y"],
            article_summaries=["Article 1 summary"],
        )
        cache.update_snapshot(snap)
        ctx = cache.build_context_string("t1")
        assert "Playbook A: do X" in ctx
        assert "Playbook B: do Y" in ctx

    def test_tenant_isolation(self) -> None:
        cache = LocalContextCache()
        snap1 = TenantContextSlice(tenant_id="cust-1", playbook_summaries=["secret-pb"])
        cache.update_snapshot(snap1)
        # cust-2 should not see cust-1's data
        assert cache.get_snapshot("cust-2") is None
        assert cache.build_context_string("cust-2") == ""


# ---------------------------------------------------------------------------
# TestOfflineTriageEngine
# ---------------------------------------------------------------------------


class TestOfflineTriageEngine:
    def _make_llm_response(self, content: str) -> Any:
        from summer_puppy.llm.models import LLMResponse, LLMUsage

        return LLMResponse(
            content=content,
            usage=LLMUsage(input_tokens=0, output_tokens=0, model="llama3", latency_ms=1.0),
        )

    async def test_triage_returns_offline_triage(self) -> None:
        llm = AsyncMock()
        llm.analyze = AsyncMock(
            return_value=self._make_llm_response(
                "severity_assessment: HIGH\nrecommended_action: isolate host\nreasoning: suspicious"
            )
        )
        cache = LocalContextCache()
        engine = OfflineTriageEngine(llm_client=llm, context_cache=cache)

        result = await engine.triage_event("tenant-1", "Suspicious login from unknown IP")

        assert isinstance(result, OfflineTriage)
        assert result.tenant_id == "tenant-1"
        assert result.event_summary == "Suspicious login from unknown IP"
        assert result.offline_mode is True

    async def test_triage_uses_cached_context(self) -> None:
        llm = AsyncMock()
        llm.analyze = AsyncMock(return_value=self._make_llm_response("HIGH risk"))
        cache = LocalContextCache()
        snap = TenantContextSlice(
            tenant_id="tenant-1", playbook_summaries=["Block suspicious IPs"]
        )
        cache.update_snapshot(snap)
        engine = OfflineTriageEngine(llm_client=llm, context_cache=cache)

        result = await engine.triage_event("tenant-1", "Port scan detected")

        assert result.used_cached_context is True

    async def test_triage_works_without_context(self) -> None:
        llm = AsyncMock()
        llm.analyze = AsyncMock(return_value=self._make_llm_response("LOW risk"))
        cache = LocalContextCache()
        engine = OfflineTriageEngine(llm_client=llm, context_cache=cache)

        result = await engine.triage_event("tenant-no-context", "Minor alert")

        assert result.used_cached_context is False
        assert isinstance(result, OfflineTriage)

    async def test_is_available_true_when_llm_works(self) -> None:
        llm = AsyncMock()
        llm.analyze = AsyncMock(return_value=self._make_llm_response("pong"))
        cache = LocalContextCache()
        engine = OfflineTriageEngine(llm_client=llm, context_cache=cache)

        assert await engine.is_available() is True

    async def test_is_available_false_when_llm_fails(self) -> None:
        llm = AsyncMock()
        llm.analyze = AsyncMock(side_effect=RuntimeError("connection refused"))
        cache = LocalContextCache()
        engine = OfflineTriageEngine(llm_client=llm, context_cache=cache)

        assert await engine.is_available() is False


# ---------------------------------------------------------------------------
# TestOllamaHealthMonitor
# ---------------------------------------------------------------------------


class TestOllamaHealthMonitor:
    async def test_check_once_healthy_on_200(self) -> None:
        monitor = OllamaHealthMonitor(base_url="http://localhost:11434")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_class:
            mock_http = AsyncMock()
            mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_class.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_http.get = AsyncMock(return_value=mock_response)

            status = await monitor.check_once()

        assert status == HealthStatus.HEALTHY

    async def test_check_once_offline_on_error(self) -> None:
        import httpx

        monitor = OllamaHealthMonitor(base_url="http://localhost:11434")

        with patch("httpx.AsyncClient") as mock_class:
            mock_http = AsyncMock()
            mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_class.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_http.get = AsyncMock(side_effect=httpx.ConnectError("refused"))

            status = await monitor.check_once()

        assert status == HealthStatus.OFFLINE

    def test_initial_status_is_unknown(self) -> None:
        monitor = OllamaHealthMonitor()
        assert monitor.current_status == HealthStatus.UNKNOWN

    async def test_health_history_populated_after_check(self) -> None:
        monitor = OllamaHealthMonitor()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_class:
            mock_http = AsyncMock()
            mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_class.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_http.get = AsyncMock(return_value=mock_response)

            await monitor.check_once()

        history = monitor.get_health_history()
        assert len(history) >= 1
        assert "status" in history[0]
        assert "checked_utc" in history[0]
