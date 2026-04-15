"""Knowledge store protocol and implementations (in-memory + Neo4j)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Protocol, runtime_checkable

from summer_puppy.memory.models import AssetContext, AssetNode, VulnerabilityNode


@runtime_checkable
class KnowledgeStore(Protocol):
    """Protocol for knowledge graph storage backends."""

    async def get_asset_context(self, asset_id: str) -> AssetContext | None: ...

    async def store_event_outcome(self, event_id: str, outcome: dict[str, Any]) -> None: ...

    async def get_historical_outcomes(
        self, customer_id: str, limit: int = 50
    ) -> list[dict[str, Any]]: ...

    async def store_asset(self, asset: AssetNode) -> None: ...

    async def link_event_to_assets(self, event_id: str, asset_ids: list[str]) -> None: ...

    async def store_work_item_summary(
        self, work_item_id: str, summary: dict[str, Any]
    ) -> None: ...

    async def get_work_item_summaries(
        self, customer_id: str, limit: int = 50
    ) -> list[dict[str, Any]]: ...

    async def store_artifact(self, artifact_id: str, artifact_data: dict[str, Any]) -> None: ...


class InMemoryKnowledgeStore:
    """In-memory implementation of KnowledgeStore for testing and development."""

    def __init__(self) -> None:
        self._assets: dict[str, AssetNode] = {}
        self._vulnerabilities: dict[str, VulnerabilityNode] = {}
        self._event_outcomes: list[dict[str, Any]] = []
        self._asset_events: dict[str, list[str]] = defaultdict(list)  # event_id -> [asset_id]
        self._asset_vulns: dict[str, list[str]] = defaultdict(list)  # asset_id -> [cve_id]
        self._work_item_summaries: list[dict[str, Any]] = []
        self._artifacts_store: dict[str, dict[str, Any]] = {}

    async def store_asset(self, asset: AssetNode) -> None:
        self._assets[asset.id] = asset

    async def get_asset_context(self, asset_id: str) -> AssetContext | None:
        asset = self._assets.get(asset_id)
        if asset is None:
            return None

        # Collect vulnerabilities linked to this asset
        cve_ids = self._asset_vulns.get(asset_id, [])
        vulns = [
            self._vulnerabilities[cve_id] for cve_id in cve_ids if cve_id in self._vulnerabilities
        ]

        # Collect recent events linked to this asset
        recent_events: list[dict[str, Any]] = []
        for event_id, linked_asset_ids in self._asset_events.items():
            if asset_id in linked_asset_ids:
                recent_events.append({"event_id": event_id})

        # Collect historical outcomes for the customer
        historical = [o for o in self._event_outcomes if o.get("customer_id") == asset.customer_id]

        return AssetContext(
            asset=asset,
            vulnerabilities=vulns,
            recent_events=recent_events,
            historical_outcomes=historical,
        )

    async def store_event_outcome(self, event_id: str, outcome: dict[str, Any]) -> None:
        outcome_with_id = {**outcome, "event_id": event_id}
        self._event_outcomes.append(outcome_with_id)

    async def get_historical_outcomes(
        self, customer_id: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        filtered = [o for o in self._event_outcomes if o.get("customer_id") == customer_id]
        return filtered[:limit]

    async def link_event_to_assets(self, event_id: str, asset_ids: list[str]) -> None:
        self._asset_events[event_id] = asset_ids

    async def store_work_item_summary(self, work_item_id: str, summary: dict[str, Any]) -> None:
        summary_with_id = {**summary, "work_item_id": work_item_id}
        self._work_item_summaries.append(summary_with_id)

    async def get_work_item_summaries(
        self, customer_id: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        filtered = [s for s in self._work_item_summaries if s.get("customer_id") == customer_id]
        # Also include artifacts (playbooks, KB articles) stored via store_artifact
        artifact_summaries = [
            v
            for v in self._artifacts_store.values()
            if v.get("customer_id") == customer_id
        ]
        combined = filtered + artifact_summaries
        return combined[:limit]

    async def store_artifact(self, artifact_id: str, artifact_data: dict[str, Any]) -> None:
        self._artifacts_store[artifact_id] = {**artifact_data, "artifact_id": artifact_id}

    def add_vulnerability(self, vuln: VulnerabilityNode) -> None:
        """Helper: register a vulnerability in the store."""
        self._vulnerabilities[vuln.cve_id] = vuln

    def link_asset_vulnerability(self, asset_id: str, cve_id: str) -> None:
        """Helper: link an asset to a vulnerability."""
        if cve_id not in self._asset_vulns[asset_id]:
            self._asset_vulns[asset_id].append(cve_id)


class Neo4jKnowledgeStore:
    """Neo4j-backed implementation of KnowledgeStore using Cypher queries."""

    def __init__(self, driver: Any) -> None:
        self._driver = driver

    async def store_asset(self, asset: AssetNode) -> None:
        async with self._driver.session() as session:
            await session.run(
                "MERGE (a:Asset {id: $id}) "
                "SET a.name = $name, a.type = $type, "
                "a.customer_id = $customer_id, a.criticality = $criticality, "
                "a.metadata = $metadata",
                id=asset.id,
                name=asset.name,
                type=asset.type,
                customer_id=asset.customer_id,
                criticality=asset.criticality,
                metadata=str(asset.metadata),
            )

    async def get_asset_context(self, asset_id: str) -> AssetContext | None:
        async with self._driver.session() as session:
            result = await session.run(
                "MATCH (a:Asset {id: $id}) "
                "OPTIONAL MATCH (a)<-[:AFFECTS_ASSET]-(v:Vulnerability) "
                "OPTIONAL MATCH (e:SecurityEvent)-[:AFFECTS]->(a) "
                "RETURN a, collect(DISTINCT v) AS vulns, "
                "collect(DISTINCT e) AS events",
                id=asset_id,
            )
            record = await result.single()
            if record is None or record["a"] is None:
                return None

            a = record["a"]
            asset = AssetNode(
                id=a["id"],
                name=a["name"],
                type=a["type"],
                customer_id=a["customer_id"],
                criticality=a.get("criticality", "MEDIUM"),
                metadata={},
            )

            vulns = [
                VulnerabilityNode(
                    cve_id=v["cve_id"],
                    severity=v.get("severity", "MEDIUM"),
                    description=v.get("description", ""),
                    cvss_score=v.get("cvss_score", 0.0),
                )
                for v in record["vulns"]
                if v is not None
            ]

            events = [
                {"event_id": e["event_id"], **{k: e[k] for k in e if k != "event_id"}}
                for e in record["events"]
                if e is not None
            ]

            # Get historical outcomes for the customer
            outcome_result = await session.run(
                "MATCH (e:SecurityEvent {customer_id: $cid}) "
                "WHERE e.outcome IS NOT NULL "
                "RETURN e.event_id AS event_id, e.outcome AS outcome, "
                "e.timestamp AS timestamp "
                "ORDER BY e.timestamp DESC LIMIT 50",
                cid=asset.customer_id,
            )
            outcome_records = await outcome_result.data()
            historical: list[dict[str, Any]] = [dict(r) for r in outcome_records]

            return AssetContext(
                asset=asset,
                vulnerabilities=vulns,
                recent_events=events,
                historical_outcomes=historical,
            )

    async def store_event_outcome(self, event_id: str, outcome: dict[str, Any]) -> None:
        customer_id = outcome.get("customer_id", "")
        timestamp = outcome.get("timestamp", "")
        async with self._driver.session() as session:
            await session.run(
                "MERGE (e:SecurityEvent {event_id: $event_id}) "
                "SET e.outcome = $outcome, e.customer_id = $customer_id, "
                "e.timestamp = $timestamp",
                event_id=event_id,
                outcome=str(outcome),
                customer_id=customer_id,
                timestamp=timestamp,
            )

    async def get_historical_outcomes(
        self, customer_id: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        async with self._driver.session() as session:
            result = await session.run(
                "MATCH (e:SecurityEvent {customer_id: $cid}) "
                "WHERE e.outcome IS NOT NULL "
                "RETURN e.event_id AS event_id, e.outcome AS outcome, "
                "e.timestamp AS timestamp "
                "ORDER BY e.timestamp DESC LIMIT $limit",
                cid=customer_id,
                limit=limit,
            )
            records = await result.data()
            return [dict(r) for r in records]

    async def link_event_to_assets(self, event_id: str, asset_ids: list[str]) -> None:
        async with self._driver.session() as session:
            for aid in asset_ids:
                await session.run(
                    "MERGE (e:SecurityEvent {event_id: $event_id}) "
                    "WITH e "
                    "MATCH (a:Asset {id: $asset_id}) "
                    "MERGE (e)-[:AFFECTS]->(a)",
                    event_id=event_id,
                    asset_id=aid,
                )

    async def store_work_item_summary(self, work_item_id: str, summary: dict[str, Any]) -> None:
        customer_id = summary.get("customer_id", "")
        title = summary.get("title", "")
        status = summary.get("status", "")
        async with self._driver.session() as session:
            await session.run(
                "MERGE (w:WorkItem {work_item_id: $id}) "
                "SET w.customer_id = $customer_id, w.title = $title, "
                "w.status = $status, w.summary = $summary",
                id=work_item_id,
                customer_id=customer_id,
                title=title,
                status=status,
                summary=str(summary),
            )

    async def get_work_item_summaries(
        self, customer_id: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        async with self._driver.session() as session:
            result = await session.run(
                "MATCH (w:WorkItem {customer_id: $customer_id}) RETURN w LIMIT $limit",
                customer_id=customer_id,
                limit=limit,
            )
            records = await result.data()
            return [dict(r["w"]) for r in records]

    async def store_artifact(self, artifact_id: str, artifact_data: dict[str, Any]) -> None:
        artifact_type = artifact_data.get("type", "")
        work_item_id = artifact_data.get("work_item_id", "")
        async with self._driver.session() as session:
            await session.run(
                "MERGE (a:Artifact {artifact_id: $id}) "
                "SET a.type = $type, a.work_item_id = $work_item_id, "
                "a.data = $data",
                id=artifact_id,
                type=artifact_type,
                work_item_id=work_item_id,
                data=str(artifact_data),
            )
