"""Cypher schema constraints and indexes for the Neo4j knowledge graph."""

from __future__ import annotations

from typing import Any

CYPHER_CONSTRAINTS: list[str] = [
    # Uniqueness constraints
    "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT vuln_cve IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE",
    (
        "CREATE CONSTRAINT event_id IF NOT EXISTS "
        "FOR (e:SecurityEvent) REQUIRE e.event_id IS UNIQUE"
    ),
    # Work item and artifact uniqueness constraints
    (
        "CREATE CONSTRAINT work_item_id IF NOT EXISTS "
        "FOR (w:WorkItem) REQUIRE w.work_item_id IS UNIQUE"
    ),
    (
        "CREATE CONSTRAINT artifact_id IF NOT EXISTS "
        "FOR (a:Artifact) REQUIRE a.artifact_id IS UNIQUE"
    ),
    # Indexes for customer_id lookups
    "CREATE INDEX asset_customer IF NOT EXISTS FOR (a:Asset) ON (a.customer_id)",
    ("CREATE INDEX event_customer IF NOT EXISTS FOR (e:SecurityEvent) ON (e.customer_id)"),
]


async def init_schema(driver: Any) -> None:
    """Run all CYPHER_CONSTRAINTS against the given Neo4j AsyncDriver."""
    async with driver.session() as session:
        for cypher in CYPHER_CONSTRAINTS:
            await session.run(cypher)
