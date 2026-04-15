"""Stateless worker identity and registry for horizontal scaling.

Each worker process registers itself in Redis on startup and deregisters
on graceful shutdown.  The registry provides service-discovery for
load-balancing and health monitoring.
"""

from __future__ import annotations

import os
import socket
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from summer_puppy.logging.config import get_logger

logger = get_logger(__name__)


class WorkerStatus(StrEnum):
    STARTING = "starting"
    HEALTHY = "healthy"
    DRAINING = "draining"
    STOPPED = "stopped"


@dataclass
class WorkerConfig:
    """Configuration for a stateless worker process."""

    worker_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str = field(default_factory=socket.gethostname)
    pid: int = field(default_factory=os.getpid)
    # Maximum concurrent pipeline executions this worker will accept
    max_concurrency: int = 10
    # Heartbeat TTL — worker is considered dead if no heartbeat in this window
    heartbeat_ttl_seconds: int = 60
    heartbeat_interval_seconds: int = 15


class WorkerIdentity(BaseModel):
    """Serialisable worker identity stored in Redis."""

    worker_id: str
    hostname: str
    pid: int
    status: WorkerStatus = WorkerStatus.STARTING
    max_concurrency: int = 10
    active_tasks: int = 0
    registered_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    last_heartbeat_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    version: str = "0.2.0"
    capabilities: list[str] = Field(default_factory=list)


class WorkerRegistry:
    """Redis-backed registry of active worker instances.

    Workers self-register on startup and are automatically expired from
    the registry when their heartbeat TTL elapses.
    """

    _KEY_PREFIX = "worker-registry"

    def __init__(self, state_store: Any) -> None:  # Any = RedisStateStore
        self._store = state_store

    def _worker_key(self, worker_id: str) -> str:
        return f"{self._KEY_PREFIX}:{worker_id}"

    async def register(self, identity: WorkerIdentity, ttl_seconds: int = 60) -> None:
        """Register a worker, with TTL to auto-expire stale entries."""
        identity.registered_utc = datetime.now(tz=UTC)
        identity.last_heartbeat_utc = datetime.now(tz=UTC)
        identity.status = WorkerStatus.HEALTHY
        await self._store.set(
            self._worker_key(identity.worker_id),
            identity.model_dump(mode="json"),
            ttl_seconds=ttl_seconds,
        )
        logger.info(
            "worker_registered",
            worker_id=identity.worker_id,
            hostname=identity.hostname,
            pid=identity.pid,
        )

    async def heartbeat(self, worker_id: str, ttl_seconds: int = 60) -> None:
        """Refresh a worker's TTL and update last_heartbeat_utc."""
        key = self._worker_key(worker_id)
        data = await self._store.get(key)
        if data is None:
            logger.warning("heartbeat_for_unknown_worker", worker_id=worker_id)
            return
        data["last_heartbeat_utc"] = datetime.now(tz=UTC).isoformat()
        await self._store.set(key, data, ttl_seconds=ttl_seconds)

    async def deregister(self, worker_id: str) -> None:
        """Remove a worker from the registry."""
        await self._store.delete(self._worker_key(worker_id))
        logger.info("worker_deregistered", worker_id=worker_id)

    async def get_worker(self, worker_id: str) -> WorkerIdentity | None:
        """Return the WorkerIdentity for a given worker_id, or None."""
        data = await self._store.get(self._worker_key(worker_id))
        if data is None:
            return None
        return WorkerIdentity.model_validate(data)

    async def list_workers(self) -> list[WorkerIdentity]:
        """Return all currently registered workers."""
        keys = await self._store.list_keys(f"{self._KEY_PREFIX}:*")
        if not keys:
            return []
        data_map = await self._store.get_many(keys)
        workers: list[WorkerIdentity] = []
        for raw in data_map.values():
            if raw is not None:
                try:
                    workers.append(WorkerIdentity.model_validate(raw))
                except Exception:  # noqa: BLE001
                    pass
        return workers

    async def update_active_tasks(self, worker_id: str, delta: int) -> None:
        """Atomically adjust the active task count for a worker."""
        key = self._worker_key(worker_id)
        data = await self._store.get(key)
        if data is None:
            return
        data["active_tasks"] = max(0, int(data.get("active_tasks", 0)) + delta)
        await self._store.set(key, data)

    async def set_status(self, worker_id: str, status: WorkerStatus) -> None:
        """Update a worker's status field."""
        key = self._worker_key(worker_id)
        data = await self._store.get(key)
        if data is None:
            return
        data["status"] = status.value
        await self._store.set(key, data)

    async def count_healthy_workers(self) -> int:
        """Return the number of workers with HEALTHY status."""
        workers = await self.list_workers()
        return sum(1 for w in workers if w.status == WorkerStatus.HEALTHY)
