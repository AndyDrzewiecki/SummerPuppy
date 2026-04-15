from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel

from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.channel.models import Envelope, Topic
from summer_puppy.events.models import EventSource, SecurityEvent, Severity
from summer_puppy.trust.models import TrustPhase, TrustProfile

# ---------------------------------------------------------------------------
# Topic enum
# ---------------------------------------------------------------------------


class TestTopic:
    def test_enum_values(self) -> None:
        assert Topic.SECURITY_EVENTS == "SECURITY_EVENTS"
        assert Topic.RECOMMENDATIONS == "RECOMMENDATIONS"
        assert Topic.APPROVAL_REQUESTS == "APPROVAL_REQUESTS"
        assert Topic.ACTION_OUTCOMES == "ACTION_OUTCOMES"
        assert Topic.AUDIT_ENTRIES == "AUDIT_ENTRIES"
        assert Topic.PHASE_TRANSITIONS == "PHASE_TRANSITIONS"

    def test_member_count(self) -> None:
        assert len(Topic) == 13

    def test_cross_pool_topic_values(self) -> None:
        assert Topic.WORK_ITEMS == "WORK_ITEMS"
        assert Topic.POOL_STATUS == "POOL_STATUS"
        assert Topic.ARTIFACTS == "ARTIFACTS"
        assert Topic.DECISIONS == "DECISIONS"


# ---------------------------------------------------------------------------
# Envelope model
# ---------------------------------------------------------------------------


class TestEnvelope:
    def test_minimal_creation(self) -> None:
        env = Envelope(
            topic=Topic.SECURITY_EVENTS,
            customer_id="cust-1",
            payload_type="some.module.Model",
            payload={"key": "value"},
        )
        assert env.envelope_id  # auto-generated uuid
        assert env.topic == Topic.SECURITY_EVENTS
        assert env.customer_id == "cust-1"
        assert env.correlation_id is None
        assert env.payload_type == "some.module.Model"
        assert env.payload == {"key": "value"}
        assert isinstance(env.published_utc, datetime)
        assert env.schema_version == "1.0"

    def test_all_fields(self) -> None:
        ts = datetime(2026, 3, 16, 12, 0, 0, tzinfo=UTC)
        env = Envelope(
            envelope_id="env-123",
            topic=Topic.RECOMMENDATIONS,
            customer_id="cust-2",
            correlation_id="corr-456",
            payload_type="summer_puppy.events.models.Recommendation",
            payload={"recommendation_id": "rec-1"},
            published_utc=ts,
            schema_version="2.0",
        )
        assert env.envelope_id == "env-123"
        assert env.topic == Topic.RECOMMENDATIONS
        assert env.correlation_id == "corr-456"
        assert env.published_utc == ts
        assert env.schema_version == "2.0"

    def test_serialization_round_trip(self) -> None:
        env = Envelope(
            topic=Topic.AUDIT_ENTRIES,
            customer_id="cust-rt",
            payload_type="some.Model",
            payload={"a": 1, "b": [2, 3]},
        )
        data = env.model_dump()
        restored = Envelope.model_validate(data)
        assert restored == env

    def test_unique_envelope_ids(self) -> None:
        e1 = Envelope(
            topic=Topic.SECURITY_EVENTS,
            customer_id="c",
            payload_type="M",
            payload={},
        )
        e2 = Envelope(
            topic=Topic.SECURITY_EVENTS,
            customer_id="c",
            payload_type="M",
            payload={},
        )
        assert e1.envelope_id != e2.envelope_id


# ---------------------------------------------------------------------------
# InMemoryEventBus — publish
# ---------------------------------------------------------------------------


class TestInMemoryEventBusPublish:
    async def test_publish_returns_envelope_with_correct_fields(self) -> None:
        bus = InMemoryEventBus()
        event = SecurityEvent(
            customer_id="cust-pub",
            source=EventSource.SIEM,
            severity=Severity.HIGH,
            title="Test Alert",
            description="Something happened",
        )
        envelope = await bus.publish(Topic.SECURITY_EVENTS, event, customer_id="cust-pub")
        assert isinstance(envelope, Envelope)
        assert envelope.topic == Topic.SECURITY_EVENTS
        assert envelope.customer_id == "cust-pub"
        assert envelope.payload_type == "summer_puppy.events.models.SecurityEvent"
        assert envelope.payload == event.model_dump()
        assert envelope.correlation_id is None
        assert envelope.schema_version == "1.0"


# ---------------------------------------------------------------------------
# InMemoryEventBus — subscribe + publish delivery
# ---------------------------------------------------------------------------


class TestInMemoryEventBusSubscribe:
    async def test_handler_receives_envelope(self) -> None:
        bus = InMemoryEventBus()
        received: list[Envelope] = []

        async def handler(env: Envelope) -> None:
            received.append(env)

        await bus.subscribe(Topic.SECURITY_EVENTS, handler)

        event = SecurityEvent(
            customer_id="cust-sub",
            source=EventSource.EDR,
            severity=Severity.LOW,
            title="Minor",
            description="low severity",
        )
        envelope = await bus.publish(Topic.SECURITY_EVENTS, event, customer_id="cust-sub")

        assert len(received) == 1
        assert received[0] is envelope

    async def test_multiple_subscribers_same_topic(self) -> None:
        bus = InMemoryEventBus()
        received_a: list[Envelope] = []
        received_b: list[Envelope] = []

        async def handler_a(env: Envelope) -> None:
            received_a.append(env)

        async def handler_b(env: Envelope) -> None:
            received_b.append(env)

        await bus.subscribe(Topic.RECOMMENDATIONS, handler_a)
        await bus.subscribe(Topic.RECOMMENDATIONS, handler_b)

        event = SecurityEvent(
            customer_id="cust-multi",
            source=EventSource.NDR,
            severity=Severity.MEDIUM,
            title="Multi",
            description="multi sub",
        )
        await bus.publish(Topic.RECOMMENDATIONS, event, customer_id="cust-multi")

        assert len(received_a) == 1
        assert len(received_b) == 1

    async def test_subscribers_different_topics_isolated(self) -> None:
        bus = InMemoryEventBus()
        received_sec: list[Envelope] = []
        received_audit: list[Envelope] = []

        async def handler_sec(env: Envelope) -> None:
            received_sec.append(env)

        async def handler_audit(env: Envelope) -> None:
            received_audit.append(env)

        await bus.subscribe(Topic.SECURITY_EVENTS, handler_sec)
        await bus.subscribe(Topic.AUDIT_ENTRIES, handler_audit)

        event = SecurityEvent(
            customer_id="cust-iso",
            source=EventSource.SIEM,
            severity=Severity.CRITICAL,
            title="Critical",
            description="critical event",
        )
        await bus.publish(Topic.SECURITY_EVENTS, event, customer_id="cust-iso")

        assert len(received_sec) == 1
        assert len(received_audit) == 0


# ---------------------------------------------------------------------------
# InMemoryEventBus — unsubscribe
# ---------------------------------------------------------------------------


class TestInMemoryEventBusUnsubscribe:
    async def test_unsubscribe_stops_delivery(self) -> None:
        bus = InMemoryEventBus()
        received: list[Envelope] = []

        async def handler(env: Envelope) -> None:
            received.append(env)

        sub_id = await bus.subscribe(Topic.ACTION_OUTCOMES, handler)

        event = SecurityEvent(
            customer_id="cust-unsub",
            source=EventSource.AGENT,
            severity=Severity.LOW,
            title="Pre-unsub",
            description="before unsub",
        )
        await bus.publish(Topic.ACTION_OUTCOMES, event, customer_id="cust-unsub")
        assert len(received) == 1

        await bus.unsubscribe(sub_id)

        await bus.publish(Topic.ACTION_OUTCOMES, event, customer_id="cust-unsub")
        assert len(received) == 1  # no new delivery


# ---------------------------------------------------------------------------
# InMemoryEventBus — get_history
# ---------------------------------------------------------------------------


class TestInMemoryEventBusHistory:
    async def test_get_history_returns_all(self) -> None:
        bus = InMemoryEventBus()
        event = SecurityEvent(
            customer_id="cust-hist",
            source=EventSource.SIEM,
            severity=Severity.LOW,
            title="H1",
            description="hist1",
        )
        await bus.publish(Topic.SECURITY_EVENTS, event, customer_id="cust-hist")
        await bus.publish(Topic.RECOMMENDATIONS, event, customer_id="cust-hist")

        history = bus.get_history()
        assert len(history) == 2

    async def test_get_history_filtered_by_topic(self) -> None:
        bus = InMemoryEventBus()
        event = SecurityEvent(
            customer_id="cust-filt",
            source=EventSource.SIEM,
            severity=Severity.LOW,
            title="F1",
            description="filt1",
        )
        await bus.publish(Topic.SECURITY_EVENTS, event, customer_id="cust-filt")
        await bus.publish(Topic.RECOMMENDATIONS, event, customer_id="cust-filt")
        await bus.publish(Topic.SECURITY_EVENTS, event, customer_id="cust-filt")

        sec_history = bus.get_history(topic=Topic.SECURITY_EVENTS)
        rec_history = bus.get_history(topic=Topic.RECOMMENDATIONS)
        assert len(sec_history) == 2
        assert len(rec_history) == 1


# ---------------------------------------------------------------------------
# InMemoryEventBus — publishes any Pydantic model
# ---------------------------------------------------------------------------


class TestInMemoryEventBusAnyModel:
    async def test_publishes_security_event(self) -> None:
        bus = InMemoryEventBus()
        event = SecurityEvent(
            customer_id="cust-any-se",
            source=EventSource.THREAT_INTEL,
            severity=Severity.HIGH,
            title="Threat",
            description="threat intel",
        )
        envelope = await bus.publish(Topic.SECURITY_EVENTS, event, customer_id="cust-any-se")
        assert envelope.payload_type == "summer_puppy.events.models.SecurityEvent"
        assert envelope.payload["title"] == "Threat"

    async def test_publishes_trust_profile(self) -> None:
        bus = InMemoryEventBus()
        profile = TrustProfile(customer_id="cust-any-tp")
        envelope = await bus.publish(Topic.PHASE_TRANSITIONS, profile, customer_id="cust-any-tp")
        assert envelope.payload_type == "summer_puppy.trust.models.TrustProfile"
        assert envelope.payload["customer_id"] == "cust-any-tp"
        assert envelope.payload["trust_phase"] == TrustPhase.MANUAL


# ---------------------------------------------------------------------------
# InMemoryEventBus — publish to cross-pool topics
# ---------------------------------------------------------------------------


class TestInMemoryEventBusCrossPoolTopics:
    async def test_publish_work_item_to_work_items_topic(self) -> None:
        class WorkItem(BaseModel):
            item_id: str
            description: str

        bus = InMemoryEventBus()
        work_item = WorkItem(item_id="wi-1", description="Investigate alert")
        envelope = await bus.publish(Topic.WORK_ITEMS, work_item, customer_id="cust-cross")
        assert isinstance(envelope, Envelope)
        assert envelope.topic == Topic.WORK_ITEMS
        assert envelope.payload["item_id"] == "wi-1"
        assert envelope.payload["description"] == "Investigate alert"


# ---------------------------------------------------------------------------
# InMemoryEventBus — correlation_id propagation
# ---------------------------------------------------------------------------


class TestInMemoryEventBusCorrelation:
    async def test_correlation_id_propagates(self) -> None:
        bus = InMemoryEventBus()
        event = SecurityEvent(
            customer_id="cust-corr",
            source=EventSource.MANUAL,
            severity=Severity.MEDIUM,
            title="Corr",
            description="correlation test",
        )
        envelope = await bus.publish(
            Topic.SECURITY_EVENTS,
            event,
            customer_id="cust-corr",
            correlation_id="corr-xyz-789",
        )
        assert envelope.correlation_id == "corr-xyz-789"
