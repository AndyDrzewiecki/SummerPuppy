"""Unit tests for Redis-backed shared state and distributed locking (Phase 12)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from summer_puppy.scaling.redis_state import DistributedLock, RedisConfig, RedisStateStore


# ---------------------------------------------------------------------------
# RedisConfig
# ---------------------------------------------------------------------------


class TestRedisConfig:
    def test_defaults(self) -> None:
        cfg = RedisConfig()
        assert cfg.host == "localhost"
        assert cfg.port == 6379
        assert cfg.db == 0
        assert cfg.password is None
        assert cfg.ssl is False
        assert cfg.max_connections == 20
        assert cfg.default_ttl_seconds == 3600
        assert cfg.lock_ttl_seconds == 30

    def test_custom_values(self) -> None:
        cfg = RedisConfig(
            host="redis-prod",
            port=6380,
            password="secret",
            ssl=True,
            max_connections=50,
        )
        assert cfg.host == "redis-prod"
        assert cfg.port == 6380
        assert cfg.password == "secret"
        assert cfg.ssl is True


# ---------------------------------------------------------------------------
# RedisStateStore — init / connect / close
# ---------------------------------------------------------------------------


def _make_mock_redis() -> AsyncMock:
    mock = AsyncMock()
    mock.ping = AsyncMock(return_value=True)
    mock.set = AsyncMock(return_value=True)
    mock.get = AsyncMock(return_value=None)
    mock.delete = AsyncMock(return_value=1)
    mock.exists = AsyncMock(return_value=0)
    mock.incrby = AsyncMock(return_value=1)
    mock.mget = AsyncMock(return_value=[])
    mock.hset = AsyncMock(return_value=1)
    mock.hgetall = AsyncMock(return_value={})
    mock.keys = AsyncMock(return_value=[])
    mock.expire = AsyncMock(return_value=True)
    mock.aclose = AsyncMock()
    return mock


class TestRedisStateStoreInit:
    def test_init_no_client(self) -> None:
        store = RedisStateStore(RedisConfig())
        assert store._client is None
        assert store._namespace == "global"

    def test_custom_namespace(self) -> None:
        store = RedisStateStore(RedisConfig(), namespace="my-service")
        assert store._namespace == "my-service"

    async def test_connect_creates_client(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis_class = MagicMock(return_value=mock_redis)

        with patch("redis.asyncio.Redis", mock_redis_class):
            await store.connect()

        assert store._client is not None

    async def test_connect_is_idempotent(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis_class = MagicMock(return_value=mock_redis)

        with patch("redis.asyncio.Redis", mock_redis_class):
            await store.connect()
            await store.connect()

        assert mock_redis_class.call_count == 1

    async def test_close_clears_client(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        store._client = mock_redis

        await store.close()

        mock_redis.aclose.assert_called_once()
        assert store._client is None

    async def test_close_when_not_connected_is_noop(self) -> None:
        store = RedisStateStore(RedisConfig())
        # Should not raise
        await store.close()


# ---------------------------------------------------------------------------
# RedisStateStore — health_check
# ---------------------------------------------------------------------------


class TestRedisStateStoreHealth:
    async def test_health_check_returns_true_when_ping_ok(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        store._client = mock_redis

        result = await store.health_check()

        assert result is True
        mock_redis.ping.assert_called_once()

    async def test_health_check_returns_false_when_no_client(self) -> None:
        store = RedisStateStore(RedisConfig())
        result = await store.health_check()
        assert result is False

    async def test_health_check_returns_false_on_exception(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis.ping = AsyncMock(side_effect=Exception("connection_refused"))
        store._client = mock_redis

        result = await store.health_check()

        assert result is False


# ---------------------------------------------------------------------------
# RedisStateStore — set / get
# ---------------------------------------------------------------------------


class TestRedisStateStoreSetGet:
    async def test_set_stores_json_encoded_value(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        store._client = mock_redis

        await store.set("my-key", {"x": 1, "y": [2, 3]})

        mock_redis.set.assert_called_once()
        call_args = mock_redis.set.call_args
        # First arg is key, second is JSON-encoded value
        assert "summer-puppy:global:my-key" == call_args[0][0]
        raw = call_args[0][1]
        parsed = json.loads(raw)
        assert parsed == {"x": 1, "y": [2, 3]}

    async def test_set_uses_default_ttl(self) -> None:
        cfg = RedisConfig(default_ttl_seconds=600)
        store = RedisStateStore(cfg)
        mock_redis = _make_mock_redis()
        store._client = mock_redis

        await store.set("k", "v")

        call_kwargs = mock_redis.set.call_args[1]
        assert call_kwargs.get("ex") == 600

    async def test_set_uses_custom_ttl(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        store._client = mock_redis

        await store.set("k", "v", ttl_seconds=120)

        call_kwargs = mock_redis.set.call_args[1]
        assert call_kwargs.get("ex") == 120

    async def test_get_returns_none_when_key_missing(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis.get = AsyncMock(return_value=None)
        store._client = mock_redis

        result = await store.get("missing")

        assert result is None

    async def test_get_returns_deserialized_value(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis.get = AsyncMock(return_value=json.dumps({"a": 1}))
        store._client = mock_redis

        result = await store.get("key")

        assert result == {"a": 1}

    async def test_key_is_namespaced(self) -> None:
        store = RedisStateStore(RedisConfig(), namespace="tenant-1")
        mock_redis = _make_mock_redis()
        store._client = mock_redis

        await store.set("foo", "bar")

        key_used = mock_redis.set.call_args[0][0]
        assert key_used == "summer-puppy:tenant-1:foo"


# ---------------------------------------------------------------------------
# RedisStateStore — delete / exists / increment
# ---------------------------------------------------------------------------


class TestRedisStateStoreOps:
    async def test_delete_returns_true_when_key_existed(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis.delete = AsyncMock(return_value=1)
        store._client = mock_redis

        result = await store.delete("key")

        assert result is True

    async def test_delete_returns_false_when_key_missing(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis.delete = AsyncMock(return_value=0)
        store._client = mock_redis

        result = await store.delete("key")

        assert result is False

    async def test_exists_returns_true(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis.exists = AsyncMock(return_value=1)
        store._client = mock_redis

        result = await store.exists("k")

        assert result is True

    async def test_exists_returns_false(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis.exists = AsyncMock(return_value=0)
        store._client = mock_redis

        result = await store.exists("k")

        assert result is False

    async def test_increment_returns_new_value(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis.incrby = AsyncMock(return_value=5)
        store._client = mock_redis

        result = await store.increment("counter", amount=3)

        assert result == 5
        mock_redis.incrby.assert_called_once()

    async def test_get_many_returns_mapping(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis.mget = AsyncMock(
            return_value=[json.dumps({"val": "a"}), json.dumps({"val": "b"})]
        )
        store._client = mock_redis

        result = await store.get_many(["k1", "k2"])

        assert result["k1"] == {"val": "a"}
        assert result["k2"] == {"val": "b"}

    async def test_get_many_empty_keys(self) -> None:
        store = RedisStateStore(RedisConfig())
        result = await store.get_many([])
        assert result == {}


# ---------------------------------------------------------------------------
# RedisStateStore — hash operations
# ---------------------------------------------------------------------------


class TestRedisStateStoreHash:
    async def test_set_hash_stores_mapping(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        store._client = mock_redis

        await store.set_hash("my-hash", {"field1": "value1", "field2": 42})

        mock_redis.hset.assert_called_once()

    async def test_get_hash_deserializes(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis.hgetall = AsyncMock(
            return_value={
                "field1": json.dumps("value1"),
                "field2": json.dumps(42),
            }
        )
        store._client = mock_redis

        result = await store.get_hash("my-hash")

        assert result["field1"] == "value1"
        assert result["field2"] == 42

    async def test_get_hash_empty(self) -> None:
        store = RedisStateStore(RedisConfig())
        mock_redis = _make_mock_redis()
        mock_redis.hgetall = AsyncMock(return_value={})
        store._client = mock_redis

        result = await store.get_hash("empty")

        assert result == {}


# ---------------------------------------------------------------------------
# DistributedLock
# ---------------------------------------------------------------------------


class TestDistributedLock:
    async def test_acquire_returns_true_on_success(self) -> None:
        mock_redis = _make_mock_redis()
        mock_redis.set = AsyncMock(return_value=True)

        lock = DistributedLock(mock_redis, "my-resource", ttl_seconds=10)
        acquired = await lock.acquire()

        assert acquired is True
        assert lock.is_held is True

    async def test_acquire_returns_false_after_max_retries(self) -> None:
        mock_redis = _make_mock_redis()
        mock_redis.set = AsyncMock(return_value=None)  # always fails

        lock = DistributedLock(
            mock_redis,
            "contested",
            ttl_seconds=10,
            retry_interval_seconds=0.0,
            max_retries=3,
        )
        acquired = await lock.acquire()

        assert acquired is False
        assert lock.is_held is False

    async def test_release_runs_lua_script(self) -> None:
        mock_redis = _make_mock_redis()
        mock_redis.set = AsyncMock(return_value=True)
        mock_redis.eval = AsyncMock(return_value=1)

        lock = DistributedLock(mock_redis, "my-resource")
        await lock.acquire()
        await lock.release()

        mock_redis.eval.assert_called_once()
        assert lock.is_held is False

    async def test_release_is_noop_when_not_held(self) -> None:
        mock_redis = _make_mock_redis()
        mock_redis.eval = AsyncMock()

        lock = DistributedLock(mock_redis, "my-resource")
        # Don't acquire — just release
        await lock.release()

        mock_redis.eval.assert_not_called()

    async def test_context_manager_acquires_and_releases(self) -> None:
        mock_redis = _make_mock_redis()
        mock_redis.set = AsyncMock(return_value=True)
        mock_redis.eval = AsyncMock(return_value=1)

        lock = DistributedLock(mock_redis, "ctx-resource")
        async with lock:
            assert lock.is_held is True
        assert lock.is_held is False

    async def test_context_manager_raises_on_failed_acquire(self) -> None:
        mock_redis = _make_mock_redis()
        mock_redis.set = AsyncMock(return_value=None)

        lock = DistributedLock(
            mock_redis, "busy", retry_interval_seconds=0.0, max_retries=1
        )
        with pytest.raises(TimeoutError):
            async with lock:
                pass

    async def test_lock_key_is_namespaced(self) -> None:
        mock_redis = _make_mock_redis()
        mock_redis.set = AsyncMock(return_value=True)

        lock = DistributedLock(mock_redis, "evt-123")
        await lock.acquire()

        key_used = mock_redis.set.call_args[0][0]
        assert "summer-puppy:lock:" in key_used
        assert "evt-123" in key_used

    async def test_is_held_false_initially(self) -> None:
        mock_redis = _make_mock_redis()
        lock = DistributedLock(mock_redis, "r")
        assert lock.is_held is False
