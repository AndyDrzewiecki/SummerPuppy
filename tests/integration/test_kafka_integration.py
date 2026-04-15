"""Integration tests for the Kafka-backed EventBus (Phase 12).

Requires Docker + testcontainers[kafka].  Tests are skipped automatically
when Docker is unavailable.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Any

import pytest

try:
    from testcontainers.kafka import KafkaContainer  # type: ignore[import-untyped]

    HAS_KAFKA_TESTCONTAINER = True
except ImportError:
    HAS_KAFKA_TESTCONTAINER = False

pytestmark = [
    pytest.mark.skipif(
        not shutil.which("docker"),
        reason="Docker not available — skipping Kafka integration tests",
    ),
    pytest.mark.skipif(
        not HAS_KAFKA_TESTCONTAINER,
        reason="testcontainers[kafka] not installed",
    ),
]


@pytest.fixture()
async def kafka_bootstrap() -> Any:
    """Start a Kafka container and yield its bootstrap server address."""
    try:
        container = KafkaContainer("confluentinc/cp-kafka:7.6.0")
        container.start()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Could not start Kafka container: {exc}")

    bootstrap = container.get_bootstrap_server()
    try:
        yield bootstrap
    finally:
        container.stop()


class TestKafkaIntegration:
    async def test_publish_subscribe_roundtrip(self, kafka_bootstrap: str) -> None:
        from pydantic import BaseModel

        from summer_puppy.channel.kafka_bus import KafkaEventBus, KafkaTopicManager
        from summer_puppy.channel.models import Envelope, Topic

        # Ensure topic exists
        mgr = KafkaTopicManager(kafka_bootstrap)
        mgr.ensure_topics([Topic.SECURITY_EVENTS], num_partitions=1, replication_factor=1)

        bus = KafkaEventBus(bootstrap_servers=kafka_bootstrap)
        received: list[Envelope] = []
        event = asyncio.Event()

        async def handler(env: Envelope) -> None:
            received.append(env)
            event.set()

        await bus.subscribe(Topic.SECURITY_EVENTS, handler)
        # Allow consumer to connect
        await asyncio.sleep(2)

        class TestMsg(BaseModel):
            data: str

        envelope = await bus.publish(
            Topic.SECURITY_EVENTS, TestMsg(data="hello"), customer_id="cust-int"
        )

        # Wait up to 15 s for delivery
        try:
            await asyncio.wait_for(event.wait(), timeout=15)
        except asyncio.TimeoutError:
            pytest.fail("Message not received within 15 seconds")

        assert len(received) == 1
        assert received[0].envelope_id == envelope.envelope_id
        await bus.close()

    async def test_topic_manager_creates_topics(self, kafka_bootstrap: str) -> None:
        from summer_puppy.channel.kafka_bus import KafkaTopicManager
        from summer_puppy.channel.models import Topic

        mgr = KafkaTopicManager(kafka_bootstrap)
        results = mgr.ensure_topics(
            [Topic.RECOMMENDATIONS, Topic.AUDIT_ENTRIES],
            num_partitions=1,
            replication_factor=1,
        )
        assert Topic.RECOMMENDATIONS.value in results
        assert Topic.AUDIT_ENTRIES.value in results
