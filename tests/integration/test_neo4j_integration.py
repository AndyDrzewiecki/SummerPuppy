"""Integration tests for Neo4j Knowledge Store (Story 5).

Requires Docker for testcontainers. Tests are automatically skipped
when Docker is not available or testcontainers is not installed.
"""

from __future__ import annotations

import shutil
from typing import Any

import pytest

try:
    from testcontainers.neo4j import Neo4jContainer

    HAS_TESTCONTAINERS = True
except ImportError:
    HAS_TESTCONTAINERS = False

pytestmark = [
    pytest.mark.skipif(
        not shutil.which("docker"),
        reason="Docker not available — skipping Neo4j integration tests",
    ),
    pytest.mark.skipif(
        not HAS_TESTCONTAINERS,
        reason="testcontainers[neo4j] not installed",
    ),
]


@pytest.fixture()
async def neo4j_driver() -> Any:
    """Spin up a Neo4j container and yield an AsyncDriver.

    Skips if Docker is unavailable or container fails to start.
    """
    pytest.importorskip("neo4j")
    try:
        container = Neo4jContainer("neo4j:5")
        container.start()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Could not start Neo4j container: {exc}")

    import neo4j

    uri = container.get_connection_url()
    driver = neo4j.AsyncGraphDatabase.driver(
        uri,
        auth=("neo4j", container.NEO4J_ADMIN_PASSWORD),
    )
    try:
        yield driver
    finally:
        await driver.close()
        container.stop()


class TestNeo4jIntegration:
    async def test_init_schema_creates_constraints(self, neo4j_driver: Any) -> None:
        from summer_puppy.memory.schema import init_schema

        await init_schema(neo4j_driver)

        # Verify constraints exist by querying Neo4j
        async with neo4j_driver.session() as session:
            result = await session.run("SHOW CONSTRAINTS")
            constraints = await result.data()
            assert len(constraints) >= 3

    async def test_store_asset_and_get_context_roundtrip(self, neo4j_driver: Any) -> None:
        from summer_puppy.memory.models import AssetNode
        from summer_puppy.memory.schema import init_schema
        from summer_puppy.memory.store import Neo4jKnowledgeStore

        await init_schema(neo4j_driver)
        store = Neo4jKnowledgeStore(neo4j_driver)

        asset = AssetNode(
            id="int-a-1",
            name="prod-web-1",
            type="server",
            customer_id="cust-int",
            criticality="HIGH",
        )
        await store.store_asset(asset)

        ctx = await store.get_asset_context("int-a-1")
        assert ctx is not None
        assert ctx.asset.id == "int-a-1"
        assert ctx.asset.name == "prod-web-1"
        assert ctx.asset.criticality == "HIGH"

    async def test_store_event_outcome_and_get_historical(self, neo4j_driver: Any) -> None:
        from summer_puppy.memory.schema import init_schema
        from summer_puppy.memory.store import Neo4jKnowledgeStore

        await init_schema(neo4j_driver)
        store = Neo4jKnowledgeStore(neo4j_driver)

        await store.store_event_outcome(
            "evt-int-1",
            {"customer_id": "cust-int", "result": "patched", "timestamp": "2026-03-16"},
        )
        outcomes = await store.get_historical_outcomes("cust-int", limit=10)
        assert len(outcomes) >= 1
        assert any(o.get("result") == "patched" for o in outcomes)

    async def test_link_event_to_assets_creates_relationships(self, neo4j_driver: Any) -> None:
        from summer_puppy.memory.models import AssetNode
        from summer_puppy.memory.schema import init_schema
        from summer_puppy.memory.store import Neo4jKnowledgeStore

        await init_schema(neo4j_driver)
        store = Neo4jKnowledgeStore(neo4j_driver)

        asset1 = AssetNode(id="int-a-10", name="db-1", type="server", customer_id="cust-int")
        asset2 = AssetNode(id="int-a-11", name="db-2", type="server", customer_id="cust-int")
        await store.store_asset(asset1)
        await store.store_asset(asset2)

        await store.link_event_to_assets("evt-int-10", ["int-a-10", "int-a-11"])

        # Verify the relationship exists
        async with neo4j_driver.session() as session:
            result = await session.run(
                "MATCH (e:SecurityEvent {event_id: $eid})-[:AFFECTS]->(a:Asset) "
                "RETURN a.id AS asset_id",
                eid="evt-int-10",
            )
            records = await result.data()
            asset_ids = {r["asset_id"] for r in records}
            assert "int-a-10" in asset_ids
            assert "int-a-11" in asset_ids

    async def test_get_asset_context_nonexistent_returns_none(self, neo4j_driver: Any) -> None:
        from summer_puppy.memory.schema import init_schema
        from summer_puppy.memory.store import Neo4jKnowledgeStore

        await init_schema(neo4j_driver)
        store = Neo4jKnowledgeStore(neo4j_driver)

        ctx = await store.get_asset_context("nonexistent-id")
        assert ctx is None
