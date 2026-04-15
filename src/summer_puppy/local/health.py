"""Health monitoring for the local Ollama LLM instance."""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from typing import Any

import httpx

from summer_puppy.local.models import HealthStatus


class OllamaHealthMonitor:
    """Polls Ollama /api/tags endpoint to track health status.

    Runs a background polling loop; provides current health status
    and history of health checks.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        check_interval_seconds: int = 30,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._check_interval = check_interval_seconds
        self._timeout = httpx.Timeout(timeout_seconds)
        self._status: HealthStatus = HealthStatus.UNKNOWN
        self._last_check_utc: datetime | None = None
        self._history: list[dict[str, Any]] = []
        self._poll_task: asyncio.Task[None] | None = None

    async def check_once(self) -> HealthStatus:
        """Perform a single health check. Returns HEALTHY or OFFLINE."""
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(f"{self._base_url}/api/tags")
                response.raise_for_status()
            status = HealthStatus.HEALTHY
        except Exception:
            status = HealthStatus.OFFLINE

        now = datetime.now(tz=UTC)
        self._status = status
        self._last_check_utc = now
        self._history.append({"status": status, "checked_utc": now})
        return status

    async def start_polling(self) -> None:
        """Start background polling loop. Non-blocking (creates asyncio task)."""
        self._poll_task = asyncio.create_task(self._poll_loop())

    async def stop_polling(self) -> None:
        """Stop background polling loop."""
        if self._poll_task is not None:
            self._poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._poll_task
            self._poll_task = None

    async def _poll_loop(self) -> None:
        while True:
            await self.check_once()
            await asyncio.sleep(self._check_interval)

    @property
    def current_status(self) -> HealthStatus:
        """Current health status (last known)."""
        return self._status

    @property
    def last_check_utc(self) -> datetime | None:
        """When the last health check was performed."""
        return self._last_check_utc

    def get_health_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent health check history."""
        return self._history[-limit:]
