"""Tests for the PredictiveMonitorHandler."""

from __future__ import annotations

from typing import Any

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.events.models import EventSource, SecurityEvent, Severity
from summer_puppy.memory.models import AssetNode, VulnerabilityNode
from summer_puppy.memory.store import InMemoryKnowledgeStore
from summer_puppy.pipeline.handlers import PredictiveMonitorHandler
from summer_puppy.pipeline.models import PipelineContext, PipelineStage
from summer_puppy.trust.models import TrustPhase, TrustProfile

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**overrides: Any) -> SecurityEvent:
    defaults: dict[str, Any] = {
        "customer_id": "cust-test",
        "source": EventSource.SIEM,
        "severity": Severity.MEDIUM,
        "title": "Test Security Event",
        "description": "A test event for predictive monitor testing",
        "correlation_id": "corr-001",
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


def _make_context(
    event: SecurityEvent | None = None,
    **overrides: Any,
) -> PipelineContext:
    ev = event or _make_event()
    defaults: dict[str, Any] = {
        "event": ev,
        "customer_id": ev.customer_id,
        "correlation_id": ev.correlation_id or "corr-001",
        "trust_profile": TrustProfile(
            customer_id=ev.customer_id,
            trust_phase=TrustPhase.MANUAL,
        ),
    }
    defaults.update(overrides)
    return PipelineContext(**defaults)


# ===========================================================================
# PredictiveMonitorHandler tests
# ===========================================================================


class TestPredictiveMonitorHandler:
    async def test_handle_populates_predictive_alerts(self) -> None:
        audit_logger = InMemoryAuditLogger()
        knowledge_store = InMemoryKnowledgeStore()

        # Set up asset with vulnerabilities
        asset = AssetNode(
            id="server-01", name="Web Server", type="server", customer_id="cust-test"
        )
        await knowledge_store.store_asset(asset)
        vuln1 = VulnerabilityNode(cve_id="CVE-2026-001", severity="HIGH", cvss_score=8.5)
        vuln2 = VulnerabilityNode(cve_id="CVE-2026-002", severity="CRITICAL", cvss_score=9.8)
        vuln3 = VulnerabilityNode(cve_id="CVE-2026-003", severity="MEDIUM", cvss_score=5.0)
        knowledge_store.add_vulnerability(vuln1)
        knowledge_store.add_vulnerability(vuln2)
        knowledge_store.add_vulnerability(vuln3)
        knowledge_store.link_asset_vulnerability("server-01", "CVE-2026-001")
        knowledge_store.link_asset_vulnerability("server-01", "CVE-2026-002")
        knowledge_store.link_asset_vulnerability("server-01", "CVE-2026-003")

        event = _make_event(affected_assets=["server-01"])
        ctx = _make_context(event=event)

        handler = PredictiveMonitorHandler(
            audit_logger=audit_logger,
            knowledge_store=knowledge_store,
        )
        result = await handler.handle(ctx)

        alerts = result.metadata["predictive_alerts"]
        assert len(alerts) > 0
        assert alerts[0]["customer_id"] == "cust-test"
        assert alerts[0]["alert_type"] == "UNPATCHED_ASSET"

    async def test_handle_does_not_change_stage(self) -> None:
        audit_logger = InMemoryAuditLogger()
        knowledge_store = InMemoryKnowledgeStore()

        asset = AssetNode(
            id="server-01", name="Web Server", type="server", customer_id="cust-test"
        )
        await knowledge_store.store_asset(asset)
        vuln = VulnerabilityNode(cve_id="CVE-2026-001", severity="HIGH", cvss_score=8.5)
        knowledge_store.add_vulnerability(vuln)
        knowledge_store.link_asset_vulnerability("server-01", "CVE-2026-001")
        knowledge_store.link_asset_vulnerability("server-01", "CVE-2026-001")  # dup safe
        # Add more vulns to exceed threshold
        vuln2 = VulnerabilityNode(cve_id="CVE-2026-002", severity="HIGH", cvss_score=7.0)
        knowledge_store.add_vulnerability(vuln2)
        knowledge_store.link_asset_vulnerability("server-01", "CVE-2026-002")

        event = _make_event(affected_assets=["server-01"])
        ctx = _make_context(event=event, current_stage=PipelineStage.ANALYZE)

        handler = PredictiveMonitorHandler(
            audit_logger=audit_logger,
            knowledge_store=knowledge_store,
        )
        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.ANALYZE

    async def test_no_alerts_for_assets_without_vulnerabilities(self) -> None:
        audit_logger = InMemoryAuditLogger()
        knowledge_store = InMemoryKnowledgeStore()

        asset = AssetNode(
            id="server-02", name="Clean Server", type="server", customer_id="cust-test"
        )
        await knowledge_store.store_asset(asset)

        event = _make_event(affected_assets=["server-02"])
        ctx = _make_context(event=event)

        handler = PredictiveMonitorHandler(
            audit_logger=audit_logger,
            knowledge_store=knowledge_store,
        )
        result = await handler.handle(ctx)

        alerts = result.metadata["predictive_alerts"]
        assert alerts == []

    async def test_no_alerts_for_empty_affected_assets(self) -> None:
        audit_logger = InMemoryAuditLogger()
        knowledge_store = InMemoryKnowledgeStore()

        event = _make_event(affected_assets=[])
        ctx = _make_context(event=event)

        handler = PredictiveMonitorHandler(
            audit_logger=audit_logger,
            knowledge_store=knowledge_store,
        )
        result = await handler.handle(ctx)

        alerts = result.metadata["predictive_alerts"]
        assert alerts == []

    async def test_audit_entries_created_for_alerts(self) -> None:
        audit_logger = InMemoryAuditLogger()
        knowledge_store = InMemoryKnowledgeStore()

        # Create two assets, each with enough vulns to trigger alerts
        for asset_id in ("server-01", "server-02"):
            asset = AssetNode(
                id=asset_id,
                name=f"Server {asset_id}",
                type="server",
                customer_id="cust-test",
            )
            await knowledge_store.store_asset(asset)
            for i in range(3):
                cve_id = f"CVE-2026-{asset_id}-{i}"
                vuln = VulnerabilityNode(cve_id=cve_id, severity="HIGH", cvss_score=8.0)
                knowledge_store.add_vulnerability(vuln)
                knowledge_store.link_asset_vulnerability(asset_id, cve_id)

        event = _make_event(affected_assets=["server-01", "server-02"])
        ctx = _make_context(event=event)

        handler = PredictiveMonitorHandler(
            audit_logger=audit_logger,
            knowledge_store=knowledge_store,
        )
        await handler.handle(ctx)

        # One audit entry per alert
        assert len(audit_logger._entries) == 2
