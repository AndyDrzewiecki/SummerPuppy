"""LangGraph agent end-to-end integration tests.

These tests exercise the SecurityAnalysisGraph and LangGraphStepHandler
with InMemoryLLMClient — no Docker or external services required.
"""

from __future__ import annotations

from summer_puppy.agents.adapter import LangGraphStepHandler
from summer_puppy.agents.graph import SecurityAnalysisGraph
from summer_puppy.audit.logger import InMemoryAuditLogger  # noqa: TC001
from summer_puppy.channel.bus import InMemoryEventBus  # noqa: TC001
from summer_puppy.events.models import EventSource, SecurityEvent, Severity
from summer_puppy.llm.client import InMemoryLLMClient
from summer_puppy.llm.models import LLMResponse, LLMUsage
from summer_puppy.memory.store import InMemoryKnowledgeStore  # noqa: TC001
from summer_puppy.pipeline.models import PipelineStage, PipelineStatus
from summer_puppy.pipeline.orchestrator import Orchestrator
from summer_puppy.trust.models import TrustPhase, TrustProfile

_MOCK_USAGE = LLMUsage(
    input_tokens=100,
    output_tokens=200,
    model="in-memory",
    latency_ms=50.0,
)


def _make_agent_llm_client() -> InMemoryLLMClient:
    """Create an LLM client with responses suitable for the agent graph.

    The agent graph calls: triage (no LLM), analyze (generate_structured),
    recommend (generate_structured). We queue two structured responses.
    """
    client = InMemoryLLMClient()
    analyze_response = LLMResponse(
        content="",
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
        content="",
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


class TestAgentHighSeverityPath:
    async def test_agent_high_severity_path(self) -> None:
        """HIGH severity event should go through analyze + recommend nodes."""
        client = _make_agent_llm_client()
        graph = SecurityAnalysisGraph(llm_client=client)

        event = SecurityEvent(
            source=EventSource.SIEM,
            severity=Severity.HIGH,
            title="Multiple Failed Login Attempts",
            description="Over 1000 failed login attempts detected.",
            affected_assets=["auth-server-01"],
            customer_id="customer-1",
        )
        trust_profile = TrustProfile(
            customer_id="customer-1",
            trust_phase=TrustPhase.AUTONOMOUS,
            total_recommendations=60,
            positive_outcome_rate=0.93,
        )

        result = await graph.run(event, trust_profile)

        assert result.analysis is not None
        assert result.recommendation is not None


class TestAgentLowSeverityPath:
    async def test_agent_low_severity_path(self) -> None:
        """LOW severity event should go through simple_recommend (no full analysis)."""
        # For low severity, graph does triage -> simple_recommend (no LLM calls).
        client = InMemoryLLMClient()
        graph = SecurityAnalysisGraph(llm_client=client)

        event = SecurityEvent(
            source=EventSource.SIEM,
            severity=Severity.LOW,
            title="Low Priority Alert",
            description="Minor configuration drift detected.",
            affected_assets=["web-server-02"],
            customer_id="customer-1",
        )
        trust_profile = TrustProfile(
            customer_id="customer-1",
            trust_phase=TrustPhase.SUPERVISED,
        )

        result = await graph.run(event, trust_profile)

        assert result.recommendation is not None
        # Low severity takes simple_recommend path — no full LLM analysis
        assert result.analysis is None


class TestAgentAdapterInPipeline:
    async def test_agent_adapter_in_pipeline(
        self,
        memory_store: InMemoryKnowledgeStore,
        sample_event: SecurityEvent,
        audit_logger: InMemoryAuditLogger,
        event_bus: InMemoryEventBus,
    ) -> None:
        """LangGraphStepHandler registered as ANALYZE handler should complete pipeline."""
        client = _make_agent_llm_client()
        graph = SecurityAnalysisGraph(llm_client=client)

        adapter = LangGraphStepHandler(
            graph=graph,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )

        trust_profile = TrustProfile(
            customer_id="customer-1",
            trust_phase=TrustPhase.AUTONOMOUS,
            total_recommendations=60,
            positive_outcome_rate=0.93,
        )

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            knowledge_store=memory_store,
        )
        # Replace ANALYZE handler with the LangGraph adapter.
        # The adapter handles both analyze and recommend, advancing to APPROVE.
        orch.register_handler(PipelineStage.ANALYZE, adapter)

        ctx = await orch.process_event(
            event=sample_event,
            trust_profile=trust_profile,
        )

        assert ctx.status == PipelineStatus.COMPLETED
