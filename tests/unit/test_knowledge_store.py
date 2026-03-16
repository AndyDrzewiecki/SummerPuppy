"""Comprehensive tests for the Neo4j Knowledge Graph Schema and Client (Story 5)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from summer_puppy.memory.models import AssetContext, AssetNode, VulnerabilityNode
from summer_puppy.memory.schema import CYPHER_CONSTRAINTS, init_schema
from summer_puppy.memory.store import (
    InMemoryKnowledgeStore,
    KnowledgeStore,
    Neo4jKnowledgeStore,
)

# ---------------------------------------------------------------------------
# AssetNode model
# ---------------------------------------------------------------------------


class TestAssetNode:
    def test_minimal_creation(self) -> None:
        node = AssetNode(name="web-server-1", type="server", customer_id="cust-1")
        assert node.name == "web-server-1"
        assert node.type == "server"
        assert node.customer_id == "cust-1"
        assert node.criticality == "MEDIUM"
        assert node.metadata == {}
        assert node.id  # auto-generated uuid

    def test_all_fields(self) -> None:
        node = AssetNode(
            id="asset-42",
            name="api-gateway",
            type="endpoint",
            customer_id="cust-2",
            criticality="CRITICAL",
            metadata={"region": "us-east-1", "env": "production"},
        )
        assert node.id == "asset-42"
        assert node.name == "api-gateway"
        assert node.type == "endpoint"
        assert node.customer_id == "cust-2"
        assert node.criticality == "CRITICAL"
        assert node.metadata == {"region": "us-east-1", "env": "production"}

    def test_unique_ids(self) -> None:
        n1 = AssetNode(name="a", type="server", customer_id="c")
        n2 = AssetNode(name="a", type="server", customer_id="c")
        assert n1.id != n2.id


# ---------------------------------------------------------------------------
# VulnerabilityNode model
# ---------------------------------------------------------------------------


class TestVulnerabilityNode:
    def test_creation(self) -> None:
        vuln = VulnerabilityNode(cve_id="CVE-2024-1234")
        assert vuln.cve_id == "CVE-2024-1234"
        assert vuln.severity == "MEDIUM"
        assert vuln.description == ""
        assert vuln.cvss_score == 0.0
        assert vuln.affected_assets == []

    def test_all_fields(self) -> None:
        vuln = VulnerabilityNode(
            cve_id="CVE-2024-5678",
            severity="CRITICAL",
            description="Remote code execution in libfoo",
            cvss_score=9.8,
            affected_assets=["asset-1", "asset-2"],
        )
        assert vuln.cve_id == "CVE-2024-5678"
        assert vuln.severity == "CRITICAL"
        assert vuln.description == "Remote code execution in libfoo"
        assert vuln.cvss_score == 9.8
        assert vuln.affected_assets == ["asset-1", "asset-2"]

    def test_cvss_score_validation_min(self) -> None:
        with pytest.raises(ValidationError):
            VulnerabilityNode(cve_id="CVE-2024-0001", cvss_score=-0.1)

    def test_cvss_score_validation_max(self) -> None:
        with pytest.raises(ValidationError):
            VulnerabilityNode(cve_id="CVE-2024-0001", cvss_score=10.1)

    def test_cvss_score_boundary_values(self) -> None:
        vuln_low = VulnerabilityNode(cve_id="CVE-2024-0001", cvss_score=0.0)
        assert vuln_low.cvss_score == 0.0
        vuln_high = VulnerabilityNode(cve_id="CVE-2024-0002", cvss_score=10.0)
        assert vuln_high.cvss_score == 10.0


# ---------------------------------------------------------------------------
# AssetContext model
# ---------------------------------------------------------------------------


class TestAssetContext:
    def test_creation_with_asset(self) -> None:
        asset = AssetNode(name="db-1", type="server", customer_id="cust-1")
        ctx = AssetContext(asset=asset)
        assert ctx.asset == asset
        assert ctx.vulnerabilities == []
        assert ctx.recent_events == []
        assert ctx.historical_outcomes == []

    def test_creation_with_vulnerabilities(self) -> None:
        asset = AssetNode(name="db-1", type="server", customer_id="cust-1")
        vuln = VulnerabilityNode(cve_id="CVE-2024-1234", severity="HIGH", cvss_score=7.5)
        ctx = AssetContext(
            asset=asset,
            vulnerabilities=[vuln],
            recent_events=[{"event_id": "evt-1", "type": "alert"}],
            historical_outcomes=[{"outcome": "patched", "success": True}],
        )
        assert len(ctx.vulnerabilities) == 1
        assert ctx.vulnerabilities[0].cve_id == "CVE-2024-1234"
        assert len(ctx.recent_events) == 1
        assert len(ctx.historical_outcomes) == 1


# ---------------------------------------------------------------------------
# InMemoryKnowledgeStore
# ---------------------------------------------------------------------------


class TestInMemoryKnowledgeStore:
    async def test_protocol_conformance(self) -> None:
        store = InMemoryKnowledgeStore()
        assert isinstance(store, KnowledgeStore)

    async def test_store_asset_and_get_context(self) -> None:
        store = InMemoryKnowledgeStore()
        asset = AssetNode(id="a-1", name="web-1", type="server", customer_id="cust-1")
        await store.store_asset(asset)
        ctx = await store.get_asset_context("a-1")
        assert ctx is not None
        assert ctx.asset.id == "a-1"
        assert ctx.asset.name == "web-1"

    async def test_get_asset_context_nonexistent_returns_none(self) -> None:
        store = InMemoryKnowledgeStore()
        ctx = await store.get_asset_context("nonexistent")
        assert ctx is None

    async def test_store_event_outcome_and_get_historical(self) -> None:
        store = InMemoryKnowledgeStore()
        asset = AssetNode(id="a-1", name="web-1", type="server", customer_id="cust-1")
        await store.store_asset(asset)
        await store.store_event_outcome(
            "evt-1", {"customer_id": "cust-1", "result": "success", "timestamp": "2026-03-16"}
        )
        outcomes = await store.get_historical_outcomes("cust-1")
        assert len(outcomes) == 1
        assert outcomes[0]["result"] == "success"

    async def test_get_historical_outcomes_respects_limit(self) -> None:
        store = InMemoryKnowledgeStore()
        for i in range(10):
            await store.store_event_outcome(f"evt-{i}", {"customer_id": "cust-1", "index": i})
        outcomes = await store.get_historical_outcomes("cust-1", limit=3)
        assert len(outcomes) == 3

    async def test_get_historical_outcomes_filters_by_customer(self) -> None:
        store = InMemoryKnowledgeStore()
        await store.store_event_outcome("evt-1", {"customer_id": "cust-1", "val": "a"})
        await store.store_event_outcome("evt-2", {"customer_id": "cust-2", "val": "b"})
        await store.store_event_outcome("evt-3", {"customer_id": "cust-1", "val": "c"})

        outcomes_1 = await store.get_historical_outcomes("cust-1")
        outcomes_2 = await store.get_historical_outcomes("cust-2")
        assert len(outcomes_1) == 2
        assert len(outcomes_2) == 1
        assert outcomes_2[0]["val"] == "b"

    async def test_link_event_to_assets(self) -> None:
        store = InMemoryKnowledgeStore()
        asset1 = AssetNode(id="a-1", name="web-1", type="server", customer_id="cust-1")
        asset2 = AssetNode(id="a-2", name="web-2", type="server", customer_id="cust-1")
        await store.store_asset(asset1)
        await store.store_asset(asset2)

        await store.link_event_to_assets("evt-1", ["a-1", "a-2"])

        ctx1 = await store.get_asset_context("a-1")
        assert ctx1 is not None
        assert any(e["event_id"] == "evt-1" for e in ctx1.recent_events)

        ctx2 = await store.get_asset_context("a-2")
        assert ctx2 is not None
        assert any(e["event_id"] == "evt-1" for e in ctx2.recent_events)

    async def test_add_vulnerability_and_link(self) -> None:
        store = InMemoryKnowledgeStore()
        asset = AssetNode(id="a-1", name="web-1", type="server", customer_id="cust-1")
        await store.store_asset(asset)

        vuln = VulnerabilityNode(cve_id="CVE-2024-1234", severity="HIGH", cvss_score=8.1)
        store.add_vulnerability(vuln)
        store.link_asset_vulnerability("a-1", "CVE-2024-1234")

        ctx = await store.get_asset_context("a-1")
        assert ctx is not None
        assert len(ctx.vulnerabilities) == 1
        assert ctx.vulnerabilities[0].cve_id == "CVE-2024-1234"

    async def test_asset_context_includes_customer_outcomes(self) -> None:
        store = InMemoryKnowledgeStore()
        asset = AssetNode(id="a-1", name="web-1", type="server", customer_id="cust-1")
        await store.store_asset(asset)
        await store.store_event_outcome("evt-1", {"customer_id": "cust-1", "result": "patched"})
        ctx = await store.get_asset_context("a-1")
        assert ctx is not None
        assert len(ctx.historical_outcomes) >= 1
        assert ctx.historical_outcomes[0]["result"] == "patched"

    async def test_store_asset_overwrites_existing(self) -> None:
        store = InMemoryKnowledgeStore()
        asset1 = AssetNode(id="a-1", name="old-name", type="server", customer_id="cust-1")
        await store.store_asset(asset1)
        asset2 = AssetNode(id="a-1", name="new-name", type="server", customer_id="cust-1")
        await store.store_asset(asset2)
        ctx = await store.get_asset_context("a-1")
        assert ctx is not None
        assert ctx.asset.name == "new-name"

    async def test_store_and_get_work_item_summaries_round_trip(self) -> None:
        store = InMemoryKnowledgeStore()
        summary = {"customer_id": "cust-1", "title": "Patch CVE-2024-001", "status": "open"}
        await store.store_work_item_summary("wi-1", summary)

        results = await store.get_work_item_summaries("cust-1")
        assert len(results) == 1
        assert results[0]["work_item_id"] == "wi-1"
        assert results[0]["title"] == "Patch CVE-2024-001"
        assert results[0]["customer_id"] == "cust-1"

    async def test_get_work_item_summaries_filters_by_customer(self) -> None:
        store = InMemoryKnowledgeStore()
        await store.store_work_item_summary("wi-1", {"customer_id": "cust-1", "title": "Task A"})
        await store.store_work_item_summary("wi-2", {"customer_id": "cust-2", "title": "Task B"})
        await store.store_work_item_summary("wi-3", {"customer_id": "cust-1", "title": "Task C"})

        results_1 = await store.get_work_item_summaries("cust-1")
        results_2 = await store.get_work_item_summaries("cust-2")
        assert len(results_1) == 2
        assert len(results_2) == 1
        assert results_2[0]["title"] == "Task B"

    async def test_get_work_item_summaries_respects_limit(self) -> None:
        store = InMemoryKnowledgeStore()
        for i in range(10):
            await store.store_work_item_summary(f"wi-{i}", {"customer_id": "cust-1", "index": i})
        results = await store.get_work_item_summaries("cust-1", limit=3)
        assert len(results) == 3

    async def test_store_artifact_stores_and_retrievable(self) -> None:
        store = InMemoryKnowledgeStore()
        artifact_data = {
            "type": "report",
            "work_item_id": "wi-1",
            "content": "Analysis complete",
        }
        await store.store_artifact("art-1", artifact_data)

        # Verify via internal state
        assert "art-1" in store._artifacts_store
        stored = store._artifacts_store["art-1"]
        assert stored["artifact_id"] == "art-1"
        assert stored["type"] == "report"
        assert stored["work_item_id"] == "wi-1"
        assert stored["content"] == "Analysis complete"

    async def test_store_artifact_overwrites_existing(self) -> None:
        store = InMemoryKnowledgeStore()
        await store.store_artifact("art-1", {"type": "draft", "version": 1})
        await store.store_artifact("art-1", {"type": "final", "version": 2})

        stored = store._artifacts_store["art-1"]
        assert stored["type"] == "final"
        assert stored["version"] == 2


# ---------------------------------------------------------------------------
# Schema (CYPHER_CONSTRAINTS + init_schema)
# ---------------------------------------------------------------------------


class TestSchema:
    def test_cypher_constraints_is_nonempty_list(self) -> None:
        assert isinstance(CYPHER_CONSTRAINTS, list)
        assert len(CYPHER_CONSTRAINTS) >= 3  # at least 3 constraints + indexes

    def test_constraints_contain_asset_id(self) -> None:
        assert any("asset_id" in c.lower() or "Asset" in c for c in CYPHER_CONSTRAINTS)

    def test_constraints_contain_vuln_cve(self) -> None:
        assert any("vuln_cve" in c.lower() or "Vulnerability" in c for c in CYPHER_CONSTRAINTS)

    def test_constraints_contain_event_id(self) -> None:
        assert any("event_id" in c.lower() or "SecurityEvent" in c for c in CYPHER_CONSTRAINTS)

    def test_constraints_contain_work_item_id(self) -> None:
        assert any("work_item_id" in c.lower() or "WorkItem" in c for c in CYPHER_CONSTRAINTS)

    def test_constraints_contain_artifact_id(self) -> None:
        assert any("artifact_id" in c.lower() or "Artifact" in c for c in CYPHER_CONSTRAINTS)

    async def test_init_schema_executes_all_constraints(self) -> None:
        mock_session = AsyncMock()
        mock_session.run = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        mock_driver = AsyncMock()
        mock_driver.session = MagicMock(return_value=mock_session)

        await init_schema(mock_driver)
        assert mock_session.run.call_count == len(CYPHER_CONSTRAINTS)


# ---------------------------------------------------------------------------
# Neo4jKnowledgeStore (mocked driver)
# ---------------------------------------------------------------------------


class TestNeo4jKnowledgeStore:
    def _make_mock_driver(self) -> tuple[Any, AsyncMock]:
        """Create a mock Neo4j driver + session with proper async context manager."""
        mock_session = AsyncMock()
        mock_session.run = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        mock_driver = MagicMock()
        mock_driver.session = MagicMock(return_value=mock_session)
        return mock_driver, mock_session

    async def test_store_asset_runs_merge_cypher(self) -> None:
        driver, session = self._make_mock_driver()
        store = Neo4jKnowledgeStore(driver)
        asset = AssetNode(id="a-1", name="web-1", type="server", customer_id="cust-1")
        await store.store_asset(asset)

        session.run.assert_called_once()
        cypher = session.run.call_args[0][0]
        assert "MERGE" in cypher
        assert "Asset" in cypher

    async def test_get_asset_context_runs_match_cypher(self) -> None:
        driver, session = self._make_mock_driver()
        # Mock result with no records (asset not found)
        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=None)
        session.run.return_value = mock_result

        store = Neo4jKnowledgeStore(driver)
        ctx = await store.get_asset_context("a-1")

        session.run.assert_called()
        cypher = session.run.call_args[0][0]
        assert "MATCH" in cypher
        assert ctx is None

    async def test_store_event_outcome_runs_cypher(self) -> None:
        driver, session = self._make_mock_driver()
        store = Neo4jKnowledgeStore(driver)
        await store.store_event_outcome("evt-1", {"result": "success"})

        session.run.assert_called_once()
        cypher = session.run.call_args[0][0]
        assert "MERGE" in cypher or "CREATE" in cypher

    async def test_link_event_to_assets_runs_cypher(self) -> None:
        driver, session = self._make_mock_driver()
        store = Neo4jKnowledgeStore(driver)
        await store.link_event_to_assets("evt-1", ["a-1", "a-2"])

        # Should run at least one Cypher query
        assert session.run.call_count >= 1

    async def test_get_historical_outcomes_runs_cypher(self) -> None:
        driver, session = self._make_mock_driver()
        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=[])
        session.run.return_value = mock_result

        store = Neo4jKnowledgeStore(driver)
        outcomes = await store.get_historical_outcomes("cust-1", limit=10)

        session.run.assert_called_once()
        cypher = session.run.call_args[0][0]
        assert "MATCH" in cypher
        assert isinstance(outcomes, list)

    async def test_store_work_item_summary_runs_merge_cypher(self) -> None:
        driver, session = self._make_mock_driver()
        store = Neo4jKnowledgeStore(driver)
        await store.store_work_item_summary(
            "wi-1", {"customer_id": "cust-1", "title": "Fix issue"}
        )

        session.run.assert_called_once()
        cypher = session.run.call_args[0][0]
        assert "MERGE" in cypher
        assert "WorkItem" in cypher

    async def test_get_work_item_summaries_runs_match_cypher(self) -> None:
        driver, session = self._make_mock_driver()
        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=[])
        session.run.return_value = mock_result

        store = Neo4jKnowledgeStore(driver)
        results = await store.get_work_item_summaries("cust-1", limit=10)

        session.run.assert_called_once()
        cypher = session.run.call_args[0][0]
        assert "MATCH" in cypher
        assert "WorkItem" in cypher
        assert isinstance(results, list)

    async def test_store_artifact_runs_merge_cypher(self) -> None:
        driver, session = self._make_mock_driver()
        store = Neo4jKnowledgeStore(driver)
        await store.store_artifact("art-1", {"type": "report", "work_item_id": "wi-1"})

        session.run.assert_called_once()
        cypher = session.run.call_args[0][0]
        assert "MERGE" in cypher
        assert "Artifact" in cypher
