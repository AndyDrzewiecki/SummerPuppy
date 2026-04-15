"""Unit tests for stateless worker registry (Phase 12)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from summer_puppy.scaling.worker import (
    WorkerConfig,
    WorkerIdentity,
    WorkerRegistry,
    WorkerStatus,
)


# ---------------------------------------------------------------------------
# WorkerConfig
# ---------------------------------------------------------------------------


class TestWorkerConfig:
    def test_defaults_auto_generate_worker_id(self) -> None:
        c1 = WorkerConfig()
        c2 = WorkerConfig()
        assert c1.worker_id != c2.worker_id

    def test_hostname_is_set(self) -> None:
        cfg = WorkerConfig()
        assert cfg.hostname  # non-empty

    def test_pid_is_positive(self) -> None:
        cfg = WorkerConfig()
        assert cfg.pid > 0

    def test_custom_concurrency(self) -> None:
        cfg = WorkerConfig(max_concurrency=20)
        assert cfg.max_concurrency == 20


# ---------------------------------------------------------------------------
# WorkerIdentity
# ---------------------------------------------------------------------------


class TestWorkerIdentity:
    def test_defaults(self) -> None:
        wi = WorkerIdentity(worker_id="w1", hostname="host1", pid=1234)
        assert wi.status == WorkerStatus.STARTING
        assert wi.max_concurrency == 10
        assert wi.active_tasks == 0
        assert wi.capabilities == []

    def test_model_dump_and_validate_roundtrip(self) -> None:
        wi = WorkerIdentity(
            worker_id="w1",
            hostname="host1",
            pid=1234,
            status=WorkerStatus.HEALTHY,
            capabilities=["pipeline", "sandbox"],
        )
        data = wi.model_dump(mode="json")
        restored = WorkerIdentity.model_validate(data)
        assert restored.worker_id == "w1"
        assert restored.status == WorkerStatus.HEALTHY
        assert "pipeline" in restored.capabilities

    def test_status_is_string_enum(self) -> None:
        assert WorkerStatus.HEALTHY == "healthy"
        assert WorkerStatus.DRAINING == "draining"
        assert WorkerStatus.STOPPED == "stopped"


# ---------------------------------------------------------------------------
# WorkerRegistry — register
# ---------------------------------------------------------------------------


def _make_mock_store(
    get_returns: dict | None = None,
    list_keys_returns: list | None = None,
    get_many_returns: dict | None = None,
) -> AsyncMock:
    store = AsyncMock()
    store.set = AsyncMock(return_value=None)
    store.get = AsyncMock(return_value=get_returns)
    store.delete = AsyncMock(return_value=True)
    store.list_keys = AsyncMock(return_value=list_keys_returns or [])
    store.get_many = AsyncMock(return_value=get_many_returns or {})
    return store


class TestWorkerRegistryRegister:
    async def test_register_calls_store_set(self) -> None:
        store = _make_mock_store()
        registry = WorkerRegistry(store)
        identity = WorkerIdentity(worker_id="w-1", hostname="h1", pid=100)

        await registry.register(identity)

        store.set.assert_called_once()
        key_used = store.set.call_args[0][0]
        assert "worker-registry" in key_used
        assert "w-1" in key_used

    async def test_register_sets_status_to_healthy(self) -> None:
        store = _make_mock_store()
        registry = WorkerRegistry(store)
        identity = WorkerIdentity(worker_id="w-1", hostname="h1", pid=100)

        await registry.register(identity)

        stored_data = store.set.call_args[0][1]
        assert stored_data["status"] == WorkerStatus.HEALTHY.value

    async def test_register_passes_custom_ttl(self) -> None:
        store = _make_mock_store()
        registry = WorkerRegistry(store)
        identity = WorkerIdentity(worker_id="w-1", hostname="h1", pid=100)

        await registry.register(identity, ttl_seconds=120)

        call_kwargs = store.set.call_args[1]
        assert call_kwargs.get("ttl_seconds") == 120


# ---------------------------------------------------------------------------
# WorkerRegistry — heartbeat
# ---------------------------------------------------------------------------


class TestWorkerRegistryHeartbeat:
    async def test_heartbeat_updates_last_heartbeat(self) -> None:
        existing = WorkerIdentity(
            worker_id="w-1", hostname="h1", pid=100
        ).model_dump(mode="json")
        store = _make_mock_store(get_returns=existing)
        registry = WorkerRegistry(store)

        await registry.heartbeat("w-1")

        store.set.assert_called_once()
        updated = store.set.call_args[0][1]
        assert "last_heartbeat_utc" in updated

    async def test_heartbeat_unknown_worker_is_noop(self) -> None:
        store = _make_mock_store(get_returns=None)
        registry = WorkerRegistry(store)

        # Should not raise
        await registry.heartbeat("nonexistent")
        store.set.assert_not_called()


# ---------------------------------------------------------------------------
# WorkerRegistry — deregister
# ---------------------------------------------------------------------------


class TestWorkerRegistryDeregister:
    async def test_deregister_calls_delete(self) -> None:
        store = _make_mock_store()
        registry = WorkerRegistry(store)

        await registry.deregister("w-1")

        store.delete.assert_called_once()
        key = store.delete.call_args[0][0]
        assert "w-1" in key


# ---------------------------------------------------------------------------
# WorkerRegistry — get_worker
# ---------------------------------------------------------------------------


class TestWorkerRegistryGetWorker:
    async def test_get_worker_returns_none_when_missing(self) -> None:
        store = _make_mock_store(get_returns=None)
        registry = WorkerRegistry(store)

        result = await registry.get_worker("w-1")

        assert result is None

    async def test_get_worker_returns_identity(self) -> None:
        identity = WorkerIdentity(worker_id="w-1", hostname="h1", pid=100)
        store = _make_mock_store(get_returns=identity.model_dump(mode="json"))
        registry = WorkerRegistry(store)

        result = await registry.get_worker("w-1")

        assert result is not None
        assert result.worker_id == "w-1"
        assert result.hostname == "h1"


# ---------------------------------------------------------------------------
# WorkerRegistry — list_workers
# ---------------------------------------------------------------------------


class TestWorkerRegistryListWorkers:
    async def test_list_workers_empty(self) -> None:
        store = _make_mock_store(list_keys_returns=[])
        registry = WorkerRegistry(store)

        result = await registry.list_workers()

        assert result == []

    async def test_list_workers_returns_all(self) -> None:
        w1 = WorkerIdentity(worker_id="w1", hostname="h1", pid=1)
        w2 = WorkerIdentity(worker_id="w2", hostname="h2", pid=2)
        store = _make_mock_store(
            list_keys_returns=["worker-registry:w1", "worker-registry:w2"],
            get_many_returns={
                "worker-registry:w1": w1.model_dump(mode="json"),
                "worker-registry:w2": w2.model_dump(mode="json"),
            },
        )
        registry = WorkerRegistry(store)

        result = await registry.list_workers()

        assert len(result) == 2
        ids = {w.worker_id for w in result}
        assert "w1" in ids
        assert "w2" in ids

    async def test_count_healthy_workers(self) -> None:
        w1 = WorkerIdentity(worker_id="w1", hostname="h1", pid=1, status=WorkerStatus.HEALTHY)
        w2 = WorkerIdentity(worker_id="w2", hostname="h2", pid=2, status=WorkerStatus.DRAINING)
        w3 = WorkerIdentity(worker_id="w3", hostname="h3", pid=3, status=WorkerStatus.HEALTHY)
        store = _make_mock_store(
            list_keys_returns=["k1", "k2", "k3"],
            get_many_returns={
                "k1": w1.model_dump(mode="json"),
                "k2": w2.model_dump(mode="json"),
                "k3": w3.model_dump(mode="json"),
            },
        )
        registry = WorkerRegistry(store)

        count = await registry.count_healthy_workers()

        assert count == 2


# ---------------------------------------------------------------------------
# WorkerRegistry — update_active_tasks / set_status
# ---------------------------------------------------------------------------


class TestWorkerRegistryUpdates:
    async def test_update_active_tasks_increments(self) -> None:
        identity = WorkerIdentity(
            worker_id="w1", hostname="h1", pid=1, active_tasks=3
        ).model_dump(mode="json")
        store = _make_mock_store(get_returns=identity)
        registry = WorkerRegistry(store)

        await registry.update_active_tasks("w1", delta=2)

        stored = store.set.call_args[0][1]
        assert stored["active_tasks"] == 5

    async def test_update_active_tasks_clamps_to_zero(self) -> None:
        identity = WorkerIdentity(
            worker_id="w1", hostname="h1", pid=1, active_tasks=1
        ).model_dump(mode="json")
        store = _make_mock_store(get_returns=identity)
        registry = WorkerRegistry(store)

        await registry.update_active_tasks("w1", delta=-5)

        stored = store.set.call_args[0][1]
        assert stored["active_tasks"] == 0

    async def test_set_status_updates_status(self) -> None:
        identity = WorkerIdentity(
            worker_id="w1", hostname="h1", pid=1, status=WorkerStatus.HEALTHY
        ).model_dump(mode="json")
        store = _make_mock_store(get_returns=identity)
        registry = WorkerRegistry(store)

        await registry.set_status("w1", WorkerStatus.DRAINING)

        stored = store.set.call_args[0][1]
        assert stored["status"] == WorkerStatus.DRAINING.value
