"""Kafka-backed EventBus for production workloads.

Uses kafka-python with asyncio.to_thread() for non-blocking publish,
and background consumer threads per subscription.  Serialises every
Envelope as UTF-8 JSON keyed by customer_id so that messages for the
same customer always land on the same partition.
"""

from __future__ import annotations

import asyncio
import json
import threading
import uuid
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from summer_puppy.channel.models import Envelope, Topic
from summer_puppy.logging.config import get_logger

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from pydantic import BaseModel

logger = get_logger(__name__)

_SENTINEL = object()  # signals consumer threads to stop


class KafkaTopicManager:
    """Creates and deletes Kafka topics via the AdminClient."""

    def __init__(self, bootstrap_servers: str) -> None:
        self._bootstrap = bootstrap_servers

    def ensure_topics(
        self,
        topics: list[Topic],
        num_partitions: int = 3,
        replication_factor: int = 1,
    ) -> dict[str, bool]:
        """Create missing topics; return {topic_name: created} mapping."""
        from kafka.admin import KafkaAdminClient, NewTopic  # type: ignore[import-untyped]
        from kafka.errors import TopicAlreadyExistsError  # type: ignore[import-untyped]

        client = KafkaAdminClient(bootstrap_servers=self._bootstrap)
        try:
            existing: set[str] = set(client.list_topics())
            new_topics = [
                NewTopic(
                    name=t.value,
                    num_partitions=num_partitions,
                    replication_factor=replication_factor,
                )
                for t in topics
                if t.value not in existing
            ]
            results: dict[str, bool] = {}
            if new_topics:
                try:
                    client.create_topics(new_topics, validate_only=False)
                    for nt in new_topics:
                        results[nt.name] = True
                        logger.info("kafka_topic_created", topic=nt.name)
                except TopicAlreadyExistsError:
                    for nt in new_topics:
                        results[nt.name] = False
            for t in topics:
                if t.value not in results:
                    results[t.value] = False  # already existed
            return results
        finally:
            client.close()

    def delete_topics(self, topics: list[Topic]) -> None:
        """Delete the given topics (best-effort, ignores missing)."""
        from kafka.admin import KafkaAdminClient  # type: ignore[import-untyped]

        client = KafkaAdminClient(bootstrap_servers=self._bootstrap)
        try:
            client.delete_topics([t.value for t in topics])
            logger.info("kafka_topics_deleted", count=len(topics))
        finally:
            client.close()


class _ConsumerThread(threading.Thread):
    """Background thread that polls a Kafka topic and dispatches envelopes."""

    def __init__(
        self,
        subscription_id: str,
        bootstrap_servers: str,
        topic: Topic,
        group_id: str,
        handler: Callable[[Envelope], Awaitable[None]],
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        super().__init__(daemon=True, name=f"kafka-consumer-{subscription_id[:8]}")
        self.subscription_id = subscription_id
        self._bootstrap = bootstrap_servers
        self._topic = topic
        self._group_id = group_id
        self._handler = handler
        self._loop = loop
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        from kafka import KafkaConsumer  # type: ignore[import-untyped]

        consumer = KafkaConsumer(
            self._topic.value,
            bootstrap_servers=self._bootstrap,
            group_id=self._group_id,
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            consumer_timeout_ms=200,  # raises StopIteration after timeout → poll loop
        )
        try:
            while not self._stop_event.is_set():
                try:
                    for message in consumer:
                        if self._stop_event.is_set():
                            break
                        try:
                            raw = json.loads(message.value.decode("utf-8"))
                            envelope = Envelope.model_validate(raw)
                            future = asyncio.run_coroutine_threadsafe(
                                self._handler(envelope), self._loop
                            )
                            future.result(timeout=30)
                        except Exception:  # noqa: BLE001
                            logger.exception(
                                "kafka_consumer_dispatch_error",
                                subscription_id=self.subscription_id,
                                topic=self._topic.value,
                            )
                except StopIteration:
                    pass  # consumer_timeout_ms elapsed — loop again
        finally:
            consumer.close()
            logger.info(
                "kafka_consumer_stopped",
                subscription_id=self.subscription_id,
                topic=self._topic.value,
            )


class KafkaEventBus:
    """Production EventBus backed by Apache Kafka.

    Each ``subscribe()`` call spawns a dedicated consumer thread in its own
    consumer group so that every subscriber receives every message (fan-out).
    ``publish()`` serialises the Envelope to JSON and sends it via a shared
    KafkaProducer, keyed by customer_id for ordered per-customer delivery.
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        consumer_group_prefix: str = "summer-puppy",
    ) -> None:
        self._bootstrap = bootstrap_servers
        self._group_prefix = consumer_group_prefix
        self._producer: Any = None
        self._producer_lock = threading.Lock()
        self._consumers: dict[str, _ConsumerThread] = {}
        self._subscriptions: dict[str, Topic] = {}  # sub_id -> topic
        self._loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------------
    # EventBus protocol
    # ------------------------------------------------------------------

    async def publish(
        self,
        topic: Topic,
        message: BaseModel,
        customer_id: str,
        correlation_id: str | None = None,
    ) -> Envelope:
        payload_type = f"{type(message).__module__}.{type(message).__qualname__}"
        envelope = Envelope(
            topic=topic,
            customer_id=customer_id,
            correlation_id=correlation_id,
            payload_type=payload_type,
            payload=message.model_dump(),
        )
        raw = envelope.model_dump_json().encode("utf-8")
        key = customer_id.encode("utf-8")

        producer = self._get_producer()
        await asyncio.to_thread(
            lambda: producer.send(topic.value, value=raw, key=key).get(timeout=10)
        )
        logger.debug(
            "kafka_message_published",
            topic=topic.value,
            customer_id=customer_id,
            envelope_id=envelope.envelope_id,
        )
        return envelope

    async def subscribe(
        self,
        topic: Topic,
        handler: Callable[[Envelope], Awaitable[None]],
    ) -> str:
        subscription_id = str(uuid.uuid4())
        loop = asyncio.get_event_loop()
        group_id = f"{self._group_prefix}-{subscription_id[:8]}"

        consumer_thread = _ConsumerThread(
            subscription_id=subscription_id,
            bootstrap_servers=self._bootstrap,
            topic=topic,
            group_id=group_id,
            handler=handler,
            loop=loop,
        )
        self._consumers[subscription_id] = consumer_thread
        self._subscriptions[subscription_id] = topic
        consumer_thread.start()

        logger.info(
            "kafka_subscription_created",
            subscription_id=subscription_id,
            topic=topic.value,
            group_id=group_id,
        )
        return subscription_id

    async def unsubscribe(self, subscription_id: str) -> None:
        thread = self._consumers.pop(subscription_id, None)
        self._subscriptions.pop(subscription_id, None)
        if thread is not None:
            thread.stop()
            await asyncio.to_thread(thread.join, 5.0)
            logger.info("kafka_subscription_removed", subscription_id=subscription_id)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Gracefully stop all consumer threads and flush/close the producer."""
        sub_ids = list(self._consumers.keys())
        for sid in sub_ids:
            await self.unsubscribe(sid)

        with self._producer_lock:
            if self._producer is not None:
                await asyncio.to_thread(self._producer.flush)
                await asyncio.to_thread(self._producer.close)
                self._producer = None
                logger.info("kafka_producer_closed")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_producer(self) -> Any:
        """Lazily create and cache the KafkaProducer (thread-safe)."""
        if self._producer is not None:
            return self._producer
        with self._producer_lock:
            if self._producer is None:
                from kafka import KafkaProducer  # type: ignore[import-untyped]

                self._producer = KafkaProducer(
                    bootstrap_servers=self._bootstrap,
                    acks="all",
                    retries=3,
                    max_block_ms=5000,
                )
                logger.info("kafka_producer_created", bootstrap=self._bootstrap)
        return self._producer

    def active_subscription_count(self) -> int:
        return len(self._consumers)

    def subscriptions_for_topic(self, topic: Topic) -> list[str]:
        return [sid for sid, t in self._subscriptions.items() if t == topic]


# ---------------------------------------------------------------------------
# Consumer group coordinator — tracks offsets and lag per group
# ---------------------------------------------------------------------------


class ConsumerGroupCoordinator:
    """Queries Kafka for consumer group lag metrics."""

    def __init__(self, bootstrap_servers: str) -> None:
        self._bootstrap = bootstrap_servers

    def get_consumer_lag(self, group_id: str) -> dict[str, int]:
        """Return {topic-partition: lag} for the given consumer group."""
        from kafka.admin import KafkaAdminClient  # type: ignore[import-untyped]

        client = KafkaAdminClient(bootstrap_servers=self._bootstrap)
        try:
            offsets = client.list_consumer_group_offsets(group_id)
            lag: dict[str, int] = {}
            for tp, offset_meta in offsets.items():
                key = f"{tp.topic}:{tp.partition}"
                lag[key] = offset_meta.offset
            return lag
        finally:
            client.close()

    def list_consumer_groups(self) -> list[str]:
        """Return all consumer group IDs visible to the broker."""
        from kafka.admin import KafkaAdminClient  # type: ignore[import-untyped]

        client = KafkaAdminClient(bootstrap_servers=self._bootstrap)
        try:
            groups = client.list_consumer_groups()
            return [g[0] for g in groups]
        finally:
            client.close()


# ---------------------------------------------------------------------------
# Topic configuration registry
# ---------------------------------------------------------------------------

#: Recommended partition counts per topic (based on expected throughput)
TOPIC_PARTITION_CONFIG: dict[Topic, int] = {
    Topic.SECURITY_EVENTS: 6,
    Topic.RECOMMENDATIONS: 3,
    Topic.APPROVAL_REQUESTS: 3,
    Topic.ACTION_OUTCOMES: 3,
    Topic.AUDIT_ENTRIES: 6,
    Topic.PHASE_TRANSITIONS: 3,
    Topic.ANALYSIS_RESULTS: 3,
    Topic.WORK_ITEMS: 3,
    Topic.POOL_STATUS: 1,
    Topic.ARTIFACTS: 3,
    Topic.DECISIONS: 3,
    Topic.DEV_BOT_TRIGGERS: 1,
    Topic.DEV_BOT_PR_EVENTS: 1,
}


def get_topic_partition_count(topic: Topic) -> int:
    return TOPIC_PARTITION_CONFIG.get(topic, 3)


# Keep a defaultdict variant handy for callers that enumerate all topics
def all_topic_configs() -> dict[str, int]:
    """Return {topic_name: partition_count} for every Topic enum member."""
    return {t.value: get_topic_partition_count(t) for t in Topic}
