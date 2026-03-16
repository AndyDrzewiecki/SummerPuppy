"""Tests for LangGraph-based security analysis agent (Story 4)."""

from __future__ import annotations

from typing import Any

from summer_puppy.agents.adapter import LangGraphStepHandler
from summer_puppy.agents.graph import AgentResult, AgentState, SecurityAnalysisGraph
from summer_puppy.agents.nodes import (
    analyze_node,
    recommend_node,
    simple_recommend_node,
    triage_node,
)
from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.events.models import EventSource, SecurityEvent, Severity
from summer_puppy.llm.client import InMemoryLLMClient
from summer_puppy.llm.models import LLMResponse, LLMUsage
from summer_puppy.pipeline.handlers import StepHandler
from summer_puppy.pipeline.models import PipelineContext, PipelineStage
from summer_puppy.trust.models import TrustPhase, TrustProfile

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**overrides: Any) -> SecurityEvent:
    defaults: dict[str, Any] = {
        "customer_id": "cust-agent",
        "source": EventSource.SIEM,
        "severity": Severity.HIGH,
        "title": "Suspicious Login Activity",
        "description": "Multiple failed login attempts detected from unusual IP",
        "affected_assets": ["server-01", "server-02"],
        "raw_payload": {"ip": "10.0.0.99", "attempts": 50},
        "correlation_id": "corr-agent-001",
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


def _make_trust_profile(**overrides: Any) -> TrustProfile:
    defaults: dict[str, Any] = {
        "customer_id": "cust-agent",
        "trust_phase": TrustPhase.MANUAL,
    }
    defaults.update(overrides)
    return TrustProfile(**defaults)


def _make_agent_state(**overrides: Any) -> AgentState:
    defaults: AgentState = {
        "event": {
            "event_id": "evt-001",
            "customer_id": "cust-agent",
            "source": "SIEM",
            "severity": "HIGH",
            "title": "Suspicious Login Activity",
            "description": "Multiple failed logins",
            "affected_assets": ["server-01"],
            "raw_payload": {"ip": "10.0.0.99"},
        },
        "customer_id": "cust-agent",
        "trust_profile": {
            "customer_id": "cust-agent",
            "trust_phase": "manual",
        },
        "knowledge_context": {},
        "analysis": None,
        "recommendation": None,
        "severity_route": "",
        "reasoning_trace": [],
        "error": None,
    }
    defaults.update(overrides)
    return defaults


def _valid_analysis_output() -> dict[str, Any]:
    return {
        "threat_type": "Brute Force",
        "attack_vector": "SSH",
        "affected_systems": ["server-01"],
        "ioc_indicators": ["10.0.0.99"],
        "severity_assessment": "HIGH",
        "confidence": 0.85,
        "reasoning": "Multiple failed SSH login attempts",
        "recommended_actions": ["Block IP"],
        "mitre_attack_ids": ["T1110"],
    }


def _valid_recommendation_output() -> dict[str, Any]:
    return {
        "action_class": "compensating_control",
        "description": "Block source IP and update detection rules",
        "reasoning": "Brute force attack requires immediate compensating control",
        "confidence_score": 0.8,
        "estimated_risk": "MEDIUM",
        "rollback_plan": "Remove IP block",
        "affected_asset_classes": ["server"],
    }


def _make_llm_response(
    structured: dict[str, Any] | None = None,
) -> LLMResponse:
    return LLMResponse(
        content="Test response",
        structured_output=structured,
        usage=LLMUsage(
            input_tokens=100,
            output_tokens=200,
            model="test-model",
            latency_ms=50.0,
        ),
    )


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
        "correlation_id": ev.correlation_id or "corr-agent-001",
        "trust_profile": tp,
        "current_stage": PipelineStage.ANALYZE,
    }
    defaults.update(overrides)
    return PipelineContext(**defaults)


# ===========================================================================
# AgentResult model tests
# ===========================================================================


class TestAgentResult:
    def test_creation_with_defaults(self) -> None:
        result = AgentResult()
        assert result.analysis is None
        assert result.recommendation is None
        assert result.reasoning_trace == []
        assert result.error is None

    def test_creation_with_all_fields(self) -> None:
        result = AgentResult(
            analysis={"threat_type": "Brute Force"},
            recommendation={"action_class": "compensating_control"},
            reasoning_trace=["Step 1", "Step 2"],
            error="Some error",
        )
        assert result.analysis == {"threat_type": "Brute Force"}
        assert result.recommendation == {"action_class": "compensating_control"}
        assert result.reasoning_trace == ["Step 1", "Step 2"]
        assert result.error == "Some error"


# ===========================================================================
# Node function tests
# ===========================================================================


class TestTriageNode:
    async def test_high_severity_routes_high(self) -> None:
        llm_client = InMemoryLLMClient()
        state = _make_agent_state(event={"severity": "HIGH", "title": "Test"})
        result = await triage_node(state, llm_client=llm_client)
        assert result["severity_route"] == "high"
        assert any("high" in entry.lower() for entry in result["reasoning_trace"])

    async def test_critical_severity_routes_high(self) -> None:
        llm_client = InMemoryLLMClient()
        state = _make_agent_state(event={"severity": "CRITICAL", "title": "Test"})
        result = await triage_node(state, llm_client=llm_client)
        assert result["severity_route"] == "high"

    async def test_low_severity_routes_low(self) -> None:
        llm_client = InMemoryLLMClient()
        state = _make_agent_state(event={"severity": "LOW", "title": "Test"})
        result = await triage_node(state, llm_client=llm_client)
        assert result["severity_route"] == "low"
        assert any("low" in entry.lower() for entry in result["reasoning_trace"])

    async def test_medium_severity_routes_low(self) -> None:
        llm_client = InMemoryLLMClient()
        state = _make_agent_state(event={"severity": "MEDIUM", "title": "Test"})
        result = await triage_node(state, llm_client=llm_client)
        assert result["severity_route"] == "low"


class TestAnalyzeNode:
    async def test_returns_analysis_from_llm(self) -> None:
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())
        state = _make_agent_state()
        result = await analyze_node(state, llm_client=llm_client)
        assert result["analysis"] is not None
        assert result["analysis"]["threat_type"] == "Brute Force"
        assert len(result["reasoning_trace"]) > 0

    async def test_llm_failure_returns_fallback_with_error(self) -> None:
        llm_client = InMemoryLLMClient()
        llm_client.set_error(RuntimeError("LLM service unavailable"))
        state = _make_agent_state()
        result = await analyze_node(state, llm_client=llm_client)
        assert result["analysis"] is not None
        assert result["error"] is not None
        assert "LLM service unavailable" in result["error"]
        assert len(result["reasoning_trace"]) > 0


class TestRecommendNode:
    async def test_returns_recommendation_from_llm(self) -> None:
        llm_client = InMemoryLLMClient(default_structured=_valid_recommendation_output())
        state = _make_agent_state(
            analysis=_valid_analysis_output(),
        )
        result = await recommend_node(state, llm_client=llm_client)
        assert result["recommendation"] is not None
        assert result["recommendation"]["action_class"] == "compensating_control"
        assert len(result["reasoning_trace"]) > 0

    async def test_llm_failure_returns_fallback(self) -> None:
        llm_client = InMemoryLLMClient()
        llm_client.set_error(RuntimeError("LLM down"))
        state = _make_agent_state(analysis=_valid_analysis_output())
        result = await recommend_node(state, llm_client=llm_client)
        assert result["recommendation"] is not None
        assert result["error"] is not None


class TestSimpleRecommendNode:
    async def test_low_severity_detection_rule_update(self) -> None:
        llm_client = InMemoryLLMClient()
        state = _make_agent_state(
            event={"severity": "LOW", "title": "Low sev event", "description": "Minor"},
        )
        result = await simple_recommend_node(state, llm_client=llm_client)
        assert result["recommendation"] is not None
        assert result["recommendation"]["action_class"] == "detection_rule_update"
        assert len(result["reasoning_trace"]) > 0

    async def test_medium_severity_compensating_control(self) -> None:
        llm_client = InMemoryLLMClient()
        state = _make_agent_state(
            event={"severity": "MEDIUM", "title": "Med sev event", "description": "Moderate"},
        )
        result = await simple_recommend_node(state, llm_client=llm_client)
        assert result["recommendation"] is not None
        assert result["recommendation"]["action_class"] == "compensating_control"


# ===========================================================================
# SecurityAnalysisGraph tests
# ===========================================================================


class TestSecurityAnalysisGraph:
    async def test_high_severity_traverses_analyze_recommend(self) -> None:
        llm_client = InMemoryLLMClient()
        llm_client.set_responses(
            [
                _make_llm_response(structured=_valid_analysis_output()),
                _make_llm_response(structured=_valid_recommendation_output()),
            ]
        )
        graph = SecurityAnalysisGraph(llm_client)
        event = _make_event(severity=Severity.HIGH)
        trust = _make_trust_profile()
        result = await graph.run(event, trust)
        assert result.analysis is not None
        assert result.recommendation is not None

    async def test_low_severity_traverses_simple_recommend(self) -> None:
        llm_client = InMemoryLLMClient()
        graph = SecurityAnalysisGraph(llm_client)
        event = _make_event(severity=Severity.LOW)
        trust = _make_trust_profile()
        result = await graph.run(event, trust)
        # Should NOT call LLM for analysis — simple path
        assert result.recommendation is not None
        # Simple path should not have full analysis
        assert result.analysis is None

    async def test_high_severity_result_has_analysis(self) -> None:
        llm_client = InMemoryLLMClient()
        llm_client.set_responses(
            [
                _make_llm_response(structured=_valid_analysis_output()),
                _make_llm_response(structured=_valid_recommendation_output()),
            ]
        )
        graph = SecurityAnalysisGraph(llm_client)
        event = _make_event(severity=Severity.CRITICAL)
        trust = _make_trust_profile()
        result = await graph.run(event, trust)
        assert result.analysis is not None
        assert result.analysis["threat_type"] == "Brute Force"

    async def test_both_paths_have_recommendation(self) -> None:
        # HIGH path
        llm_high = InMemoryLLMClient()
        llm_high.set_responses(
            [
                _make_llm_response(structured=_valid_analysis_output()),
                _make_llm_response(structured=_valid_recommendation_output()),
            ]
        )
        graph_high = SecurityAnalysisGraph(llm_high)
        result_high = await graph_high.run(
            _make_event(severity=Severity.HIGH),
            _make_trust_profile(),
        )
        assert result_high.recommendation is not None

        # LOW path
        llm_low = InMemoryLLMClient()
        graph_low = SecurityAnalysisGraph(llm_low)
        result_low = await graph_low.run(
            _make_event(severity=Severity.LOW),
            _make_trust_profile(),
        )
        assert result_low.recommendation is not None

    async def test_reasoning_trace_accumulates(self) -> None:
        llm_client = InMemoryLLMClient()
        llm_client.set_responses(
            [
                _make_llm_response(structured=_valid_analysis_output()),
                _make_llm_response(structured=_valid_recommendation_output()),
            ]
        )
        graph = SecurityAnalysisGraph(llm_client)
        event = _make_event(severity=Severity.HIGH)
        trust = _make_trust_profile()
        result = await graph.run(event, trust)
        # Should have entries from triage + analyze + recommend
        assert len(result.reasoning_trace) >= 3

    async def test_knowledge_context_passed_to_graph(self) -> None:
        llm_client = InMemoryLLMClient()
        llm_client.set_responses(
            [
                _make_llm_response(structured=_valid_analysis_output()),
                _make_llm_response(structured=_valid_recommendation_output()),
            ]
        )
        graph = SecurityAnalysisGraph(llm_client)
        event = _make_event(severity=Severity.HIGH)
        trust = _make_trust_profile()
        kc = {"previous_events": ["evt-prior-001"]}
        result = await graph.run(event, trust, knowledge_context=kc)
        assert result.analysis is not None


# ===========================================================================
# LangGraphStepHandler tests
# ===========================================================================


class TestLangGraphStepHandler:
    def test_implements_step_handler_protocol(self) -> None:
        llm_client = InMemoryLLMClient()
        graph = SecurityAnalysisGraph(llm_client)
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = LangGraphStepHandler(
            graph=graph,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        assert isinstance(handler, StepHandler)

    async def test_sets_analysis_in_metadata(self) -> None:
        llm_client = InMemoryLLMClient()
        llm_client.set_responses(
            [
                _make_llm_response(structured=_valid_analysis_output()),
                _make_llm_response(structured=_valid_recommendation_output()),
            ]
        )
        graph = SecurityAnalysisGraph(llm_client)
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = LangGraphStepHandler(
            graph=graph,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )

        ctx = _make_context(event=_make_event(severity=Severity.HIGH))
        result = await handler.handle(ctx)
        assert "analysis" in result.metadata

    async def test_sets_recommendation(self) -> None:
        llm_client = InMemoryLLMClient()
        llm_client.set_responses(
            [
                _make_llm_response(structured=_valid_analysis_output()),
                _make_llm_response(structured=_valid_recommendation_output()),
            ]
        )
        graph = SecurityAnalysisGraph(llm_client)
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = LangGraphStepHandler(
            graph=graph,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )

        ctx = _make_context(event=_make_event(severity=Severity.HIGH))
        result = await handler.handle(ctx)
        assert result.recommendation is not None

    async def test_advances_to_approve_stage(self) -> None:
        llm_client = InMemoryLLMClient()
        llm_client.set_responses(
            [
                _make_llm_response(structured=_valid_analysis_output()),
                _make_llm_response(structured=_valid_recommendation_output()),
            ]
        )
        graph = SecurityAnalysisGraph(llm_client)
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        handler = LangGraphStepHandler(
            graph=graph,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )

        ctx = _make_context(event=_make_event(severity=Severity.HIGH))
        result = await handler.handle(ctx)
        assert result.current_stage == PipelineStage.APPROVE
