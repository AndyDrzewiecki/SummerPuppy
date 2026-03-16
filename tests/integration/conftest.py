"""Integration test configuration.

Provides shared fixtures for integration tests. Neo4j-specific tests
that require Docker handle their own skip logic via pytestmark in their
test modules.
"""

from __future__ import annotations

import pytest

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.events.models import EventSource, SecurityEvent, Severity
from summer_puppy.llm.client import InMemoryLLMClient
from summer_puppy.llm.models import LLMResponse, LLMUsage
from summer_puppy.memory.models import AssetNode
from summer_puppy.memory.store import InMemoryKnowledgeStore
from summer_puppy.trust.models import (
    ActionClass,
    ApprovalConditions,
    AutoApprovalPolicy,
    TrustPhase,
    TrustProfile,
)

_MOCK_USAGE = LLMUsage(
    input_tokens=100,
    output_tokens=200,
    model="in-memory",
    latency_ms=50.0,
)


@pytest.fixture()
def mock_llm_client() -> InMemoryLLMClient:
    """Return an InMemoryLLMClient with realistic canned responses for analyze and recommend."""
    client = InMemoryLLMClient()

    analyze_response = LLMResponse(
        content="Analysis complete",
        structured_output={
            "threat_type": "Unauthorized Access",
            "attack_vector": "Credential Stuffing",
            "affected_systems": ["auth-server-01"],
            "ioc_indicators": ["multiple_failed_logins"],
            "severity_assessment": "HIGH",
            "confidence": 0.85,
            "reasoning": "Pattern matches credential stuffing attack...",
            "recommended_actions": ["Block source IPs", "Force password reset"],
            "mitre_attack_ids": ["T1110"],
        },
        usage=_MOCK_USAGE,
    )

    recommend_response = LLMResponse(
        content="Recommendation generated",
        structured_output={
            "action_class": "account_lockout",
            "description": "Lock affected accounts and force password reset",
            "reasoning": "Credential stuffing detected with high confidence...",
            "confidence_score": 0.82,
            "estimated_risk": "MEDIUM",
            "rollback_plan": "Unlock accounts and restore previous credentials",
            "affected_asset_classes": ["authentication"],
        },
        usage=_MOCK_USAGE,
    )

    client.set_responses([analyze_response, recommend_response])
    return client


@pytest.fixture()
def memory_store() -> InMemoryKnowledgeStore:
    """Return an InMemoryKnowledgeStore pre-populated with a sample AssetNode."""
    store = InMemoryKnowledgeStore()
    asset = AssetNode(
        id="auth-server-01",
        name="Auth Server",
        type="server",
        customer_id="customer-1",
        criticality="HIGH",
    )
    # Directly set the asset in the store (sync helper for tests).
    store._assets[asset.id] = asset
    return store


@pytest.fixture()
def sample_event() -> SecurityEvent:
    """Return a sample HIGH-severity SecurityEvent."""
    return SecurityEvent(
        source=EventSource.SIEM,
        severity=Severity.HIGH,
        title="Multiple Failed Login Attempts",
        description="Over 1000 failed login attempts from multiple source IPs "
        "detected against the primary authentication server in the last hour.",
        affected_assets=["auth-server-01"],
        customer_id="customer-1",
    )


@pytest.fixture()
def sample_trust_profile() -> TrustProfile:
    """Return a TrustProfile at AUTONOMOUS phase with high success rate."""
    return TrustProfile(
        customer_id="customer-1",
        trust_phase=TrustPhase.AUTONOMOUS,
        total_recommendations=60,
        positive_outcome_rate=0.93,
    )


@pytest.fixture()
def sample_policies() -> list[AutoApprovalPolicy]:
    """Return a list with one AutoApprovalPolicy matching ACCOUNT_LOCKOUT."""
    return [
        AutoApprovalPolicy(
            customer_id="customer-1",
            action_class=ActionClass.ACCOUNT_LOCKOUT,
            max_severity="HIGH",
            conditions=ApprovalConditions(
                min_confidence_score=0.7,
                require_qa_passed=False,
                require_rollback_available=False,
                max_estimated_risk="MEDIUM",
            ),
        ),
    ]


@pytest.fixture()
def audit_logger() -> InMemoryAuditLogger:
    """Return a fresh InMemoryAuditLogger."""
    return InMemoryAuditLogger()


@pytest.fixture()
def event_bus() -> InMemoryEventBus:
    """Return a fresh InMemoryEventBus."""
    return InMemoryEventBus()
