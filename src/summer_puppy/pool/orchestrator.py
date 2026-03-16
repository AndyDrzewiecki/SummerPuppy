"""Pool orchestrator: routing and lifecycle management for work items."""

from __future__ import annotations

from datetime import UTC, datetime

from summer_puppy.audit.logger import (
    AuditLogger,  # noqa: TC001
    log_work_item_completed,
    log_work_item_escalated,
    log_work_item_routed,
)
from summer_puppy.channel.bus import EventBus  # noqa: TC001
from summer_puppy.channel.models import Envelope, Topic
from summer_puppy.logging.config import get_logger
from summer_puppy.memory.store import KnowledgeStore  # noqa: TC001
from summer_puppy.pool.registry import PoolRegistry  # noqa: TC001
from summer_puppy.work.models import (
    Decision,
    DecisionType,
    Reasoning,
    WorkItem,
    WorkItemPriority,
    WorkItemStatus,
)
from summer_puppy.work.store import WorkItemStore  # noqa: TC001

logger = get_logger("pool_orchestrator")

_PRIORITY_ESCALATION: dict[WorkItemPriority, WorkItemPriority] = {
    WorkItemPriority.P3_LOW: WorkItemPriority.P2_MEDIUM,
    WorkItemPriority.P2_MEDIUM: WorkItemPriority.P1_HIGH,
    WorkItemPriority.P1_HIGH: WorkItemPriority.P0_CRITICAL,
    WorkItemPriority.P0_CRITICAL: WorkItemPriority.P0_CRITICAL,
}


class PoolOrchestrator:
    """Routes work items to agent pools and manages their lifecycle."""

    def __init__(
        self,
        event_bus: EventBus,
        pool_registry: PoolRegistry,
        work_item_store: WorkItemStore,
        audit_logger: AuditLogger,
        knowledge_store: KnowledgeStore,
    ) -> None:
        self._event_bus = event_bus
        self._pool_registry = pool_registry
        self._work_item_store = work_item_store
        self._audit_logger = audit_logger
        self._knowledge_store = knowledge_store
        self._subscription_ids: list[str] = []

    async def start(self) -> None:
        """Subscribe to relevant topics on the event bus."""
        work_item_sub = await self._event_bus.subscribe(
            Topic.WORK_ITEMS, self._handle_work_item_event
        )
        pool_status_sub = await self._event_bus.subscribe(
            Topic.POOL_STATUS, self._handle_pool_status_event
        )
        self._subscription_ids.extend([work_item_sub, pool_status_sub])

    async def stop(self) -> None:
        """Unsubscribe all stored subscription IDs."""
        for sub_id in self._subscription_ids:
            await self._event_bus.unsubscribe(sub_id)
        self._subscription_ids.clear()

    async def _handle_work_item_event(self, envelope: Envelope) -> None:
        """Dispatch work item events based on status."""
        item = WorkItem.model_validate(envelope.payload)

        if item.status == WorkItemStatus.SUBMITTED:
            await self._route_work_item(item)
        elif item.status == WorkItemStatus.COMPLETED:
            await self._complete_work_item(item)
        # Ignore all other statuses (ANTI-RECURSION)

    async def _route_work_item(self, item: WorkItem) -> None:
        """Find the best consumer pool and route the work item to it."""
        consumers = self._pool_registry.find_consumers(item.item_type)

        if not consumers:
            logger.warning(
                "no_consumers_available",
                work_item_id=item.work_item_id,
                item_type=item.item_type.value,
            )
            return

        # Select best pool: sort by load ratio (current_load / max_capacity), pick lowest
        best_pool = min(consumers, key=lambda p: p.current_load / p.max_capacity)

        item.consumer_pool = best_pool.pool_id
        item.status = WorkItemStatus.ACCEPTED
        item.updated_utc = datetime.now(tz=UTC)

        await self._work_item_store.store_work_item(item)

        decision = Decision(
            decision_type=DecisionType.ASSIGNED,
            work_item_id=item.work_item_id,
            pool_id=best_pool.pool_id,
            agent_id="pool_orchestrator",
            reasoning=Reasoning(
                evidence=[
                    f"Selected pool {best_pool.name} with load"
                    f" {best_pool.current_load}/{best_pool.max_capacity}"
                ],
                confidence=0.9,
            ),
            outcome=f"Routed to {best_pool.name}",
        )
        await self._work_item_store.add_decision(item.work_item_id, decision)

        customer_id = item.context.get("customer_id", "")
        audit_entry = log_work_item_routed(
            customer_id=customer_id,
            work_item_id=item.work_item_id,
            correlation_id=item.correlation_id,
            consumer_pool=best_pool.pool_id,
        )
        await self._audit_logger.append(audit_entry)

        await self._event_bus.publish(
            topic=Topic.WORK_ITEMS,
            message=item,
            customer_id=customer_id,
            correlation_id=item.correlation_id,
        )

    async def _complete_work_item(self, item: WorkItem) -> None:
        """Store artifacts and summary in knowledge store, record decision and audit."""
        for artifact in item.artifacts:
            await self._knowledge_store.store_artifact(artifact.artifact_id, artifact.model_dump())

        customer_id = item.context.get("customer_id", "")
        await self._knowledge_store.store_work_item_summary(
            item.work_item_id,
            {
                "customer_id": customer_id,
                "title": item.title,
                "item_type": item.item_type.value,
                "status": item.status.value,
                "artifacts_count": len(item.artifacts),
            },
        )

        decision = Decision(
            decision_type=DecisionType.COMPLETED,
            work_item_id=item.work_item_id,
            pool_id=item.consumer_pool,
            agent_id="pool_orchestrator",
            reasoning=Reasoning(
                evidence=[f"Work item {item.work_item_id} completed"],
                confidence=1.0,
            ),
            outcome="Completed",
        )
        await self._work_item_store.add_decision(item.work_item_id, decision)

        audit_entry = log_work_item_completed(
            customer_id=customer_id,
            work_item_id=item.work_item_id,
            correlation_id=item.correlation_id,
        )
        await self._audit_logger.append(audit_entry)

    async def _handle_pool_status_event(self, envelope: Envelope) -> None:
        """Handle pool status updates (currently just logs)."""
        logger.info(
            "pool_status_update",
            pool_payload=envelope.payload,
            customer_id=envelope.customer_id,
        )

    async def detect_stalled(self, stall_threshold_seconds: int = 300) -> list[WorkItem]:
        """Detect and escalate stalled work items."""
        stalled = await self._work_item_store.get_stalled_items(stall_threshold_seconds)
        escalated: list[WorkItem] = []

        for item in stalled:
            old_priority = item.priority
            new_priority = _PRIORITY_ESCALATION[old_priority]

            item.priority = new_priority
            item.status = WorkItemStatus.SUBMITTED
            item.updated_utc = datetime.now(tz=UTC)

            await self._work_item_store.store_work_item(item)

            decision = Decision(
                decision_type=DecisionType.ESCALATED,
                work_item_id=item.work_item_id,
                pool_id=item.consumer_pool,
                agent_id="pool_orchestrator",
                reasoning=Reasoning(
                    evidence=[f"Work item stalled for >{stall_threshold_seconds}s"],
                    confidence=1.0,
                ),
                outcome=f"Escalated from {old_priority} to {new_priority}",
            )
            await self._work_item_store.add_decision(item.work_item_id, decision)

            customer_id = item.context.get("customer_id", "")
            audit_entry = log_work_item_escalated(
                customer_id=customer_id,
                work_item_id=item.work_item_id,
                correlation_id=item.correlation_id,
                previous_priority=old_priority.value,
                new_priority=new_priority.value,
            )
            await self._audit_logger.append(audit_entry)

            await self._event_bus.publish(
                topic=Topic.WORK_ITEMS,
                message=item,
                customer_id=customer_id,
                correlation_id=item.correlation_id,
            )

            escalated.append(item)

        return escalated
