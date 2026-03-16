from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from uuid import uuid4

from summer_puppy.channel.models import Envelope, Topic

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from pydantic import BaseModel


@runtime_checkable
class EventBus(Protocol):
    async def publish(
        self,
        topic: Topic,
        message: BaseModel,
        customer_id: str,
        correlation_id: str | None = None,
    ) -> Envelope: ...

    async def subscribe(
        self,
        topic: Topic,
        handler: Callable[[Envelope], Awaitable[None]],
    ) -> str: ...

    async def unsubscribe(self, subscription_id: str) -> None: ...


class InMemoryEventBus:
    def __init__(self) -> None:
        self._subscribers: dict[Topic, list[tuple[str, Callable[[Envelope], Awaitable[None]]]]] = (
            defaultdict(list)
        )
        self._history: list[Envelope] = []

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
        for _sub_id, handler in self._subscribers[topic]:
            await handler(envelope)
        self._history.append(envelope)
        return envelope

    async def subscribe(
        self,
        topic: Topic,
        handler: Callable[[Envelope], Awaitable[None]],
    ) -> str:
        subscription_id = str(uuid4())
        self._subscribers[topic].append((subscription_id, handler))
        return subscription_id

    async def unsubscribe(self, subscription_id: str) -> None:
        for topic in self._subscribers:
            self._subscribers[topic] = [
                (sid, h) for sid, h in self._subscribers[topic] if sid != subscription_id
            ]

    async def drain(self) -> None:
        """No-op for InMemoryEventBus since publish is eager."""

    def get_history(self, topic: Topic | None = None) -> list[Envelope]:
        if topic is None:
            return list(self._history)
        return [env for env in self._history if env.topic == topic]
