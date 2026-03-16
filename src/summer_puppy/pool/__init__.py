"""Agent pool model and registry protocol."""

from __future__ import annotations

from summer_puppy.pool.models import AgentPool, PoolStatus, PoolType
from summer_puppy.pool.orchestrator import PoolOrchestrator
from summer_puppy.pool.registry import InMemoryPoolRegistry, PoolRegistry
from summer_puppy.work.models import WorkItemType as _WorkItemType

# Resolve deferred WorkItemType annotation used by AgentPool fields.
AgentPool.model_rebuild(_types_namespace={"WorkItemType": _WorkItemType})

__all__ = [
    "AgentPool",
    "InMemoryPoolRegistry",
    "PoolOrchestrator",
    "PoolRegistry",
    "PoolStatus",
    "PoolType",
]
