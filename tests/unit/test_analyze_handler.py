"""Tests for AnalysisResult model and LLMAnalyzeHandler (Story 2)."""

from __future__ import annotations

from typing import Any

import pytest

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.audit.models import AuditEntryType
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.channel.models import Topic
from summer_puppy.events.models import AnalysisResult, EventSource, SecurityEvent, Severity
from summer_puppy.llm.client import InMemoryLLMClient
from summer_puppy.llm.models import LLMResponse, LLMUsage
from summer_puppy.pipeline.handlers import LLMAnalyzeHandler, PassthroughAnalyzeHandler
from summer_puppy.pipeline.models import PipelineContext, PipelineStage, PipelineStatus
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
        "correlation_id": "corr-analysis-001",
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
        "correlation_id": ev.correlation_id or "corr-analysis-001",
        "trust_profile": tp,
        "current_stage": PipelineStage.ANALYZE,
    }
    defaults.update(overrides)
    return PipelineContext(**defaults)


def _valid_analysis_output() -> dict[str, Any]:
    """Return a valid structured output dict matching AnalysisResult schema."""
    return {
        "threat_type": "Brute Force",
        "attack_vector": "SSH",
        "affected_systems": ["server-01", "server-02"],
        "ioc_indicators": ["10.0.0.99"],
        "severity_assessment": "HIGH",
        "confidence": 0.85,
        "reasoning": "Multiple failed SSH login attempts from single IP",
        "recommended_actions": ["Block IP 10.0.0.99", "Reset credentials"],
        "mitre_attack_ids": ["T1110"],
    }


def _make_llm_response(structured: dict[str, Any] | None = None) -> LLMResponse:
    return LLMResponse(
        content="Analysis complete",
        structured_output=structured or _valid_analysis_output(),
        usage=LLMUsage(
            input_tokens=100,
            output_tokens=200,
            model="test-model",
            latency_ms=50.0,
        ),
    )


# ===========================================================================
# AnalysisResult model tests
# ===========================================================================


class TestAnalysisResult:
    def test_minimal_creation(self) -> None:
        result = AnalysisResult(
            threat_type="Malware",
            attack_vector="Email",
            severity_assessment=Severity.HIGH,
            confidence=0.9,
            reasoning="Detected known malware signature",
        )
        assert result.threat_type == "Malware"
        assert result.attack_vector == "Email"
        assert result.severity_assessment == Severity.HIGH
        assert result.confidence == 0.9
        assert result.reasoning == "Detected known malware signature"
        assert result.affected_systems == []
        assert result.ioc_indicators == []
        assert result.recommended_actions == []
        assert result.mitre_attack_ids == []

    def test_all_fields_populated(self) -> None:
        result = AnalysisResult(
            threat_type="Brute Force",
            attack_vector="SSH",
            affected_systems=["server-01", "server-02"],
            ioc_indicators=["10.0.0.99", "hash:abc123"],
            severity_assessment=Severity.CRITICAL,
            confidence=0.95,
            reasoning="Massive brute force campaign detected",
            recommended_actions=["Block IP", "Reset creds"],
            mitre_attack_ids=["T1110", "T1078"],
        )
        assert result.threat_type == "Brute Force"
        assert result.attack_vector == "SSH"
        assert result.affected_systems == ["server-01", "server-02"]
        assert result.ioc_indicators == ["10.0.0.99", "hash:abc123"]
        assert result.severity_assessment == Severity.CRITICAL
        assert result.confidence == 0.95
        assert result.reasoning == "Massive brute force campaign detected"
        assert result.recommended_actions == ["Block IP", "Reset creds"]
        assert result.mitre_attack_ids == ["T1110", "T1078"]

    def test_confidence_minimum_zero(self) -> None:
        result = AnalysisResult(
            threat_type="Unknown",
            attack_vector="Unknown",
            severity_assessment=Severity.LOW,
            confidence=0.0,
            reasoning="No confidence",
        )
        assert result.confidence == 0.0

    def test_confidence_maximum_one(self) -> None:
        result = AnalysisResult(
            threat_type="Unknown",
            attack_vector="Unknown",
            severity_assessment=Severity.LOW,
            confidence=1.0,
            reasoning="Full confidence",
        )
        assert result.confidence == 1.0

    def test_confidence_below_zero_rejected(self) -> None:
        with pytest.raises(ValueError):  # noqa: PT011
            AnalysisResult(
                threat_type="X",
                attack_vector="X",
                severity_assessment=Severity.LOW,
                confidence=-0.1,
                reasoning="Bad",
            )

    def test_confidence_above_one_rejected(self) -> None:
        with pytest.raises(ValueError):  # noqa: PT011
            AnalysisResult(
                threat_type="X",
                attack_vector="X",
                severity_assessment=Severity.LOW,
                confidence=1.1,
                reasoning="Bad",
            )

    def test_serialization_round_trip(self) -> None:
        original = AnalysisResult(
            threat_type="DDoS",
            attack_vector="Network Flood",
            affected_systems=["web-01"],
            ioc_indicators=["192.168.1.100"],
            severity_assessment=Severity.CRITICAL,
            confidence=0.88,
            reasoning="High volume traffic detected",
            recommended_actions=["Enable rate limiting"],
            mitre_attack_ids=["T1498"],
        )
        dumped = original.model_dump()
        restored = AnalysisResult.model_validate(dumped)
        assert restored == original

    def test_json_serialization_round_trip(self) -> None:
        original = AnalysisResult(
            threat_type="Phishing",
            attack_vector="Email",
            severity_assessment=Severity.MEDIUM,
            confidence=0.75,
            reasoning="Suspicious email headers",
        )
        json_str = original.model_dump_json()
        restored = AnalysisResult.model_validate_json(json_str)
        assert restored == original


# ===========================================================================
# LLMAnalyzeHandler tests
# ===========================================================================


class TestLLMAnalyzeHandler:
    async def test_happy_path_stores_analysis_in_metadata(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert "analysis" in result.metadata
        analysis = AnalysisResult.model_validate(result.metadata["analysis"])
        assert analysis.threat_type == "Brute Force"
        assert analysis.confidence == 0.85

    async def test_happy_path_advances_to_recommend(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.RECOMMEND

    async def test_creates_audit_entry_analysis_completed(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        entries = await audit_logger.get_chain(result.correlation_id)
        entry_types = [e.entry_type for e in entries]
        assert AuditEntryType.ANALYSIS_COMPLETED in entry_types

    async def test_publishes_to_analysis_results_topic(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        await handler.handle(ctx)

        messages = event_bus.get_history(Topic.ANALYSIS_RESULTS)
        assert len(messages) == 1
        assert messages[0].customer_id == "cust-test"

    async def test_calls_generate_structured(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        await handler.handle(ctx)

        assert len(llm_client.calls) == 1
        assert llm_client.calls[0]["method"] == "generate_structured"

    async def test_prompt_includes_event_title(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        await handler.handle(ctx)

        prompt = llm_client.calls[0]["prompt"]
        assert "Suspicious Login Activity" in prompt

    async def test_prompt_includes_severity(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        await handler.handle(ctx)

        prompt = llm_client.calls[0]["prompt"]
        assert "HIGH" in prompt

    async def test_prompt_includes_description(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        await handler.handle(ctx)

        prompt = llm_client.calls[0]["prompt"]
        assert "Multiple failed login attempts" in prompt

    async def test_prompt_includes_knowledge_context_from_metadata(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context(metadata={"knowledge_context": "Previous brute force from same IP"})
        await handler.handle(ctx)

        prompt = llm_client.calls[0]["prompt"]
        assert "Previous brute force from same IP" in prompt

    async def test_prompt_uses_default_knowledge_context_when_absent(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        await handler.handle(ctx)

        prompt = llm_client.calls[0]["prompt"]
        assert "No historical context available" in prompt

    async def test_llm_failure_fallback_still_advances(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient()
        llm_client.set_error(Exception("LLM service unavailable"))

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert result.current_stage == PipelineStage.RECOMMEND

    async def test_llm_failure_fallback_stores_basic_analysis(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient()
        llm_client.set_error(Exception("LLM timeout"))

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert "analysis" in result.metadata
        analysis = AnalysisResult.model_validate(result.metadata["analysis"])
        # Fallback should use the event's severity
        assert analysis.severity_assessment == Severity.HIGH

    async def test_llm_failure_fallback_has_low_confidence(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient()
        llm_client.set_error(RuntimeError("Connection refused"))

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        analysis = AnalysisResult.model_validate(result.metadata["analysis"])
        # Fallback confidence should be low since LLM failed
        assert analysis.confidence <= 0.3

    async def test_audit_entry_includes_event_id_as_resource(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        entries = await audit_logger.get_chain(result.correlation_id)
        analysis_entries = [
            e for e in entries if e.entry_type == AuditEntryType.ANALYSIS_COMPLETED
        ]
        assert len(analysis_entries) == 1
        assert analysis_entries[0].resource_id == ctx.event.event_id

    async def test_audit_entry_id_tracked_in_context(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        assert len(result.audit_entry_ids) >= 1

    async def test_with_queued_response(self) -> None:
        """Verify handler works with explicit queued LLM responses."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient()
        llm_client.set_responses([_make_llm_response()])

        handler = LLMAnalyzeHandler(
            llm_client=llm_client,
            audit_logger=audit_logger,
            event_bus=event_bus,
        )
        ctx = _make_context()
        result = await handler.handle(ctx)

        analysis = AnalysisResult.model_validate(result.metadata["analysis"])
        assert analysis.threat_type == "Brute Force"
        assert analysis.attack_vector == "SSH"


# ===========================================================================
# Orchestrator.build_default with llm_client tests
# ===========================================================================


class TestBuildDefaultWithLLMClient:
    async def test_with_llm_client_uses_llm_analyze_handler(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            llm_client=llm_client,
        )

        handler = orch._handlers[PipelineStage.ANALYZE]
        assert isinstance(handler, LLMAnalyzeHandler)

    async def test_without_llm_client_uses_passthrough(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
        )

        handler = orch._handlers[PipelineStage.ANALYZE]
        assert isinstance(handler, PassthroughAnalyzeHandler)

    async def test_build_default_none_llm_client_backward_compatible(self) -> None:
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            llm_client=None,
        )

        handler = orch._handlers[PipelineStage.ANALYZE]
        assert isinstance(handler, PassthroughAnalyzeHandler)

    async def test_full_pipeline_with_llm_analyze(self) -> None:
        """End-to-end: event flows through pipeline with LLM analysis."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()
        llm_client = InMemoryLLMClient(default_structured=_valid_analysis_output())

        orch = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
            llm_client=llm_client,
        )

        event = _make_event()
        profile = _make_trust_profile(trust_phase=TrustPhase.AUTONOMOUS)
        result = await orch.process_event(event, profile)

        assert result.status == PipelineStatus.COMPLETED
        assert "analysis" in result.metadata
