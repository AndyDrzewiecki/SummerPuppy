"""Redis-backed shared state and distributed locking for stateless workers.

Enables horizontal scaling by moving mutable state out of worker processes
into a shared Redis cluster, so any worker can handle any request.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from summer_puppy.logging.config import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class RedisConfig:
    """Connection configuration for the Redis cluster."""

    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: str | None = None
    ssl: bool = False
    max_connections: int = 20
    socket_timeout_seconds: float = 5.0
    socket_connect_timeout_seconds: float = 5.0
    # Key TTL defaults (seconds)
    default_ttl_seconds: int = 3600  # 1 hour
    lock_ttl_seconds: int = 30


# ---------------------------------------------------------------------------
# State store
# ---------------------------------------------------------------------------


class RedisStateStore:
    """Async Redis-backed key-value state store for shared worker state.

    Wraps redis-py's async client with a typed, JSON-serialised interface.
    All keys are namespaced as ``summer-puppy:{namespace}:{key}``.
    """

    def __init__(self, config: RedisConfig, namespace: str = "global") -> None:
        self._config = config
        self._namespace = namespace
        self._client: Any = None

    async def connect(self) -> None:
        """Initialise the async Redis client (idempotent)."""
        if self._client is not None:
            return

        import redis.asyncio as redis  # type: ignore[import-untyped]

        self._client = redis.Redis(
            host=self._config.host,
            port=self._config.port,
            db=self._config.db,
            password=self._config.password,
            ssl=self._config.ssl,
            max_connections=self._config.max_connections,
            socket_timeout=self._config.socket_timeout_seconds,
            socket_connect_timeout=self._config.socket_connect_timeout_seconds,
            decode_responses=True,
        )
        logger.info(
            "redis_connected",
            host=self._config.host,
            port=self._config.port,
            namespace=self._namespace,
        )

    async def close(self) -> None:
        """Close the Redis connection pool."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            logger.info("redis_connection_closed")

    async def health_check(self) -> bool:
        """Ping Redis; return True if healthy."""
        if self._client is None:
            return False
        try:
            await self._client.ping()
            return True
        except Exception:  # noqa: BLE001
            return False

    def _key(self, key: str) -> str:
        return f"summer-puppy:{self._namespace}:{key}"

    async def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: int | None = None,
    ) -> None:
        """Serialise value to JSON and store under key."""
        raw = json.dumps(value, default=str)
        ttl = ttl_seconds if ttl_seconds is not None else self._config.default_ttl_seconds
        await self._client.set(self._key(key), raw, ex=ttl)

    async def get(self, key: str) -> Any | None:
        """Retrieve and deserialise the value for key; return None if missing."""
        raw = await self._client.get(self._key(key))
        if raw is None:
            return None
        return json.loads(raw)

    async def delete(self, key: str) -> bool:
        """Delete key; return True if it existed."""
        deleted = await self._client.delete(self._key(key))
        return bool(deleted)

    async def exists(self, key: str) -> bool:
        """Return True if key exists."""
        count = await self._client.exists(self._key(key))
        return bool(count)

    async def increment(self, key: str, amount: int = 1) -> int:
        """Atomically increment an integer counter; returns new value."""
        return await self._client.incrby(self._key(key), amount)  # type: ignore[no-any-return]

    async def get_many(self, keys: list[str]) -> dict[str, Any]:
        """Retrieve multiple keys in one round-trip."""
        if not keys:
            return {}
        prefixed = [self._key(k) for k in keys]
        values = await self._client.mget(prefixed)
        result: dict[str, Any] = {}
        for k, raw in zip(keys, values):
            if raw is not None:
                result[k] = json.loads(raw)
        return result

    async def set_hash(self, key: str, mapping: dict[str, Any]) -> None:
        """Store a dict as a Redis hash."""
        serialised = {k: json.dumps(v, default=str) for k, v in mapping.items()}
        await self._client.hset(self._key(key), mapping=serialised)
        if self._config.default_ttl_seconds:
            await self._client.expire(self._key(key), self._config.default_ttl_seconds)

    async def get_hash(self, key: str) -> dict[str, Any]:
        """Retrieve a Redis hash as a dict."""
        raw = await self._client.hgetall(self._key(key))
        return {k: json.loads(v) for k, v in raw.items()}

    async def list_keys(self, pattern: str = "*") -> list[str]:
        """Return keys matching pattern (strips namespace prefix)."""
        prefix = self._key("")
        raw_keys = await self._client.keys(self._key(pattern))
        return [k[len(prefix):] for k in raw_keys]


# ---------------------------------------------------------------------------
# Distributed lock
# ---------------------------------------------------------------------------


class DistributedLock:
    """Redis-backed distributed lock using SET NX PX (Redlock-lite pattern).

    Usage::

        lock = DistributedLock(redis_client, "process-event-evt-123")
        async with lock:
            # only one worker processes this event at a time
            ...

    The lock is automatically released on context manager exit.  A unique
    owner token prevents another holder from releasing our lock.
    """

    def __init__(
        self,
        client: Any,  # redis.asyncio.Redis
        resource: str,
        ttl_seconds: int = 30,
        retry_interval_seconds: float = 0.1,
        max_retries: int = 50,
    ) -> None:
        self._client = client
        self._resource = f"summer-puppy:lock:{resource}"
        self._ttl_ms = ttl_seconds * 1000
        self._retry_interval = retry_interval_seconds
        self._max_retries = max_retries
        self._token: str | None = None

    async def acquire(self) -> bool:
        """Try to acquire the lock.  Returns True on success."""
        token = str(uuid.uuid4())
        for _ in range(self._max_retries):
            acquired = await self._client.set(
                self._resource,
                token,
                px=self._ttl_ms,
                nx=True,
            )
            if acquired:
                self._token = token
                logger.debug("distributed_lock_acquired", resource=self._resource)
                return True
            await asyncio.sleep(self._retry_interval)
        logger.warning("distributed_lock_timeout", resource=self._resource)
        return False

    async def release(self) -> None:
        """Release the lock only if we still hold it."""
        if self._token is None:
            return
        # Lua script for compare-and-delete (atomic)
        lua = (
            "if redis.call('get', KEYS[1]) == ARGV[1] then "
            "   return redis.call('del', KEYS[1]) "
            "else return 0 end"
        )
        await self._client.eval(lua, 1, self._resource, self._token)
        self._token = None
        logger.debug("distributed_lock_released", resource=self._resource)

    async def __aenter__(self) -> "DistributedLock":
        acquired = await self.acquire()
        if not acquired:
            raise TimeoutError(f"Could not acquire lock for {self._resource!r}")
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.release()

    @property
    def is_held(self) -> bool:
        return self._token is not None
