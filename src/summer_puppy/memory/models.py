"""Domain models for the knowledge graph memory layer."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class AssetNode(BaseModel):
    """Represents an infrastructure asset tracked in the knowledge graph."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    type: str  # e.g. "server", "endpoint", "user", "service"
    customer_id: str
    criticality: str = "MEDIUM"  # LOW / MEDIUM / HIGH / CRITICAL
    metadata: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityNode(BaseModel):
    """Represents a known vulnerability (CVE) in the knowledge graph."""

    cve_id: str
    severity: str = "MEDIUM"
    description: str = ""
    cvss_score: float = Field(ge=0, le=10, default=0.0)
    affected_assets: list[str] = Field(default_factory=list)


class AssetContext(BaseModel):
    """Aggregated context for an asset including vulnerabilities and history."""

    asset: AssetNode
    vulnerabilities: list[VulnerabilityNode] = Field(default_factory=list)
    recent_events: list[dict[str, Any]] = Field(default_factory=list)
    historical_outcomes: list[dict[str, Any]] = Field(default_factory=list)
