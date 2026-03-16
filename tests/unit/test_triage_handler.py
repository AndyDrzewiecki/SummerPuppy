"""Tests for TriageHandler and build_default with knowledge_store (Story 6)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.events.models import EventSource, SecurityEvent, Severity
from summer_puppy.llm.client import InMemoryLLMClient
from summer_puppy.memory.models import AssetNode
from summer_puppy.memory.store import InMemoryKnowledgeStore, KnowledgeStore
from summer_puppy.pipeline.handlers import (
    LLMAnalyzeHandler,
    PassthroughTriageHandler,
    TriageHandler,
)
from summer_puppy.pipeline.models import PipelineContext, PipelineStage
from summer_puppy.pipeline.orchestrator import Orchestrator
from summer_puppy.trust.models import TrustPhase, TrustProfile

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**overrides: Any) -> SecurityEvent:
    defaults: dict[str, Any] = {
        "customer_id": "cust-test",
        "source": EventSource.SIEM,
        "severity": Severity.HIGH,
        "title": "Suspicious Login Activity",
        "description": "Multiple failed login attempts detected from unusual IP",
        "affected_assets": ["server-01", "server-02"],
        "raw_payload": {"ip": "10.0.0.99", "attempts": 50},
        "correlation_id": "corr-triage-001",
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


def _make_trust_profile(**overrides: Any) -> TrustProfile:
    defaults: dict[str, Any] = {
        "customer_id": "cust-test",
        "trust_phase": TrustPhase.MANUAL,
    }
    defaults.update(overrides)
    return TrustProfile(**defaults)


def _make_context(
    event: SecurityEvent | None = None,
    trust_profile: TrustProfile | None = None,
    **overrides: Any,
) -> PipelineContext:
    ev = event or _make_event()
    tp = trust_profile or _make_trust_profile()
    defaults: dict[str, Any] = {
        "event": ev,
        "customer_id": ev.customer_id,
        "correlation_id": ev.correlation_id or "corr-triage-001",
        "trust_profile": tp,
        "current_stage": PipelineStage.TRIAGE,
    }
    defaults.update(overrides)
    return PipelineContext(**defaults)


def _make_asset(asset_id: str, name: str = "test-server") -> AssetNode:
    return AssetNode(
        id=asset_id,
        name=name,
        type="server",
        customer_id="cust-test",
        criticality="HIGH",
    )


# ===========================================================================
# TriageHandler tests
# ===========================================================================


class TestTriageHandler:
    async def test_happy_path_stores_knowledge_context(self) -> None:
        """InMemoryKnowledgeStore with stored asset -> ctx.metadata has asset data."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        store = InMemoryKnowledgeStore()
        await store.store_asset(_make_asset("server-01", "Web Server 01"))

        handler = TriageHandler(
            knowledge_store=store, audit_logger=audit_logger, event_bus=event_bus
        )
        ctx = _make_context(event=_make_event(affected_assets=["server-01"]))
        result = await handler.handle(ctx)

        assert "knowledge_context" in result.metadata
        kc = result.metadata["knowledge_context"]
        assert "assets" in kc
        assert len(kc["assets"]) == 1
        assert kc["assets"][0]["asset"]["name"] == "Web Server 01"

    async def test_multiple_affected_assets(self) -> None:
        """Two assets stored, both returned in context."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        store = InMemoryKnowledgeStore()
        await store.store_asset(_make_asset("server-01", "Web Server 01"))
        await store.store_asset(_make_asset("server-02", "DB Server 02"))

        handler = TriageHandler(
            knowledge_store=store, audit_logger=audit_logger, event_bus=event_bus
        )
        ctx = _make_context(event=_make_event(affected_assets=["server-01", "server-02"]))
        result = await handler.handle(ctx)

        kc = result.metadata["knowledge_context"]
        assert len(kc["assets"]) == 2
        asset_names = {a["asset"]["name"] for a in kc["assets"]}
        assert asset_names == {"Web Server 01", "DB Server 02"}

    async def test_no_matching_assets(self) -> None:
        """affected_assets has IDs not in store -> empty assets list."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        store = InMemoryKnowledgeStore()

        handler = TriageHandler(
            knowledge_store=store, audit_logger=audit_logger, event_bus=event_bus
        )
        ctx = _make_context(event=_make_event(affected_assets=["unknown-99"]))
        result = await handler.handle(ctx)

        kc = result.metadata["knowledge_context"]
        assert kc["assets"] == []

    async def test_knowledge_store_failure_graceful_degradation(self) -> None:
        """Mock store that raises Exception -> graceful degradation."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        mock_store = AsyncMock(spec=KnowledgeStore)
        mock_store.get_asset_context.side_effect = Exception("Store unavailable")

        handler = TriageHandler(
            knowledge_store=mock_store, audit_logger=audit_logger, event_bus=event_bus
        )
        ctx = _make_context(event=_make_event(affected_assets=["server-01"]))
        result = await handler.handle(ctx)

        kc = result.metadata["knowledge_context"]
        assert kc["assets"] == []
        assert kc["error"] == "Knowledge store unavailable"

    async def test_advances_to_analyze_stage(self) -> None:
        """Verify stage advances to ANALYZE."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        store = InMemoryKnowledgeStore()

        handler = TriageHandler(
            knowledge_store=store, audit_logger=audit_logger, event_bus=event_bus
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.ANALYZE

    async def test_advances_to_analyze_on_store_failure(self) -> None:
        """Stage advances to ANALYZE even when store fails."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        mock_store = AsyncMock(spec=KnowledgeStore)
        mock_store.get_asset_context.side_effect = RuntimeError("Connection refused")

        handler = TriageHandler(
            knowledge_store=mock_store, audit_logger=audit_logger, event_bus=event_bus
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.ANALYZE

    async def test_knowledge_context_structure(self) -> None:
        """Verify knowledge_context is a dict with 'assets' key."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        store = InMemoryKnowledgeStore()

        handler = TriageHandler(
            knowledge_store=store, audit_logger=audit_logger, event_bus=event_bus
        )
        ctx = _make_context(event=_make_event(affected_assets=[]))
        result = await handler.handle(ctx)

        kc = result.metadata["knowledge_context"]
        assert isinstance(kc, dict)
        assert "assets" in kc
        assert isinstance(kc["assets"], list)

    async def test_partial_asset_match(self) -> None:
        """Some assets exist, some don't — only found assets returned."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        store = InMemoryKnowledgeStore()
        await store.store_asset(_make_asset("server-01", "Web Server 01"))

        handler = TriageHandler(
            knowledge_store=store, audit_logger=audit_logger, event_bus=event_bus
        )
        ctx = _make_context(event=_make_event(affected_assets=["server-01", "unknown-99"]))
        result = await handler.handle(ctx)

        kc = result.metadata["knowledge_context"]
        assert len(kc["assets"]) == 1
        assert kc["assets"][0]["asset"]["id"] == "server-01"

    async def test_empty_affected_assets(self) -> None:
        """No affected assets -> empty context."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        store = InMemoryKnowledgeStore()

        handler = TriageHandler(
            knowledge_store=store, audit_logger=audit_logger, event_bus=event_bus
        )
        ctx = _make_context(event=_make_event(affected_assets=[]))
        result = await handler.handle(ctx)

        kc = result.metadata["knowledge_context"]
        assert kc["assets"] == []

    async def test_asset_context_includes_model_dump(self) -> None:
        """Verify asset contexts are serialized via model_dump()."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        store = InMemoryKnowledgeStore()
        await store.store_asset(_make_asset("server-01", "Web Server 01"))

        handler = TriageHandler(
            knowledge_store=store, audit_logger=audit_logger, event_bus=event_bus
        )
        ctx = _make_context(event=_make_event(affected_assets=["server-01"]))
        result = await handler.handle(ctx)

        kc = result.metadata["knowledge_context"]
        # Should be a plain dict (serialized), not an AssetContext instance
        assert isinstance(kc["assets"][0], dict)
        assert "asset" in kc["assets"][0]
        assert "vulnerabilities" in kc["assets"][0]
        assert "recent_events" in kc["assets"][0]
        assert "historical_outcomes" in kc["assets"][0]


# ===========================================================================
# Orchestrator.build_default with knowledge_store tests
# ===========================================================================


class TestBuildDefaultWithKnowledgeStore:
    async def test_with_knowledge_store_uses_triage_handler(self) -> None:
        """With knowledge_store: TRIAGE uses TriageHandler."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        store = InMemoryKnowledgeStore()

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            knowledge_store=store,
        )

        handler = orch._handlers[PipelineStage.TRIAGE]
        assert isinstance(handler, TriageHandler)

    async def test_without_knowledge_store_uses_passthrough(self) -> None:
        """Without knowledge_store: TRIAGE uses PassthroughTriageHandler."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
        )

        handler = orch._handlers[PipelineStage.TRIAGE]
        assert isinstance(handler, PassthroughTriageHandler)

    async def test_with_both_llm_and_knowledge_store(self) -> None:
        """With both llm_client and knowledge_store: both TRIAGE and ANALYZE use real handlers."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        store = InMemoryKnowledgeStore()
        llm_client = InMemoryLLMClient(
            default_structured={
                "threat_type": "Brute Force",
                "attack_vector": "SSH",
                "severity_assessment": "HIGH",
                "confidence": 0.85,
                "reasoning": "Test reasoning",
            }
        )

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            llm_client=llm_client,
            knowledge_store=store,
        )

        triage_handler = orch._handlers[PipelineStage.TRIAGE]
        analyze_handler = orch._handlers[PipelineStage.ANALYZE]
        assert isinstance(triage_handler, TriageHandler)
        assert isinstance(analyze_handler, LLMAnalyzeHandler)
