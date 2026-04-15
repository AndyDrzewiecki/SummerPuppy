"""Integration test for the full enrichment pipeline (Phase 9A)."""

from __future__ import annotations

from typing import Any

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.events.models import EventSource, SecurityEvent, Severity
from summer_puppy.llm.client import InMemoryLLMClient
from summer_puppy.llm.models import LLMResponse, LLMUsage
from summer_puppy.memory.store import InMemoryKnowledgeStore
from summer_puppy.pipeline.handlers import LLMAnalyzeHandler
from summer_puppy.pipeline.models import PipelineContext, PipelineStage
from summer_puppy.skills.injector import SkillInjector
from summer_puppy.skills.kb import InMemorySkillKnowledgeBase
from summer_puppy.skills.models import PlaybookTemplate, PromotionLevel
from summer_puppy.skills.prompt_enricher import PromptEnricher
from summer_puppy.trust.models import ActionClass, TrustPhase, TrustProfile


def _make_event(**overrides: Any) -> SecurityEvent:
    defaults: dict[str, Any] = {
        "customer_id": "cust-integration",
        "source": EventSource.SIEM,
        "severity": Severity.HIGH,
        "title": "Enrichment Integration Test Event",
        "description": "End-to-end enrichment test",
        "affected_assets": ["server-alpha"],
        "raw_payload": {},
        "tags": ["patch", "deployment"],
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


def _make_trust_profile(**overrides: Any) -> TrustProfile:
    return TrustProfile(
        customer_id=overrides.get("customer_id", "cust-integration"),
        trust_phase=overrides.get("trust_phase", TrustPhase.MANUAL),
    )


def _make_analyze_response() -> LLMResponse:
    return LLMResponse(
        content="",
        structured_output={
            "threat_type": "Exploitation",
            "attack_vector": "Remote",
            "severity_assessment": "HIGH",
            "confidence": 0.92,
            "reasoning": "Integration test analysis",
        },
        usage=LLMUsage(input_tokens=0, output_tokens=0, model="in-memory", latency_ms=0.0),
    )


async def test_enrichment_pipeline_end_to_end() -> None:
    """
    Prove the full enrichment pipeline works:
    1. Store a playbook in SkillKnowledgeBase at PLAYBOOK_TEMPLATE level
    2. Run SkillInjector.run_injection_cycle → writes to InMemoryKnowledgeStore
    3. Create PromptEnricher with that store
    4. Call build_context → get back a context string containing the playbook
    5. Feed that context into LLMAnalyzeHandler → verify LLM receives enriched prompt
    """
    customer_id = "cust-integration"

    # Step 1: Create KB with a playbook
    skill_kb = InMemorySkillKnowledgeBase()
    playbook = PlaybookTemplate(
        customer_id=customer_id,
        action_class=ActionClass.PATCH_DEPLOYMENT,
        name="Patch Critical Servers",
        steps=[
            "Identify affected servers",
            "Apply patch via deployment pipeline",
            "Verify patch applied and services healthy",
        ],
    )
    skill_kb.store_playbook(playbook)

    # Step 2: Inject into KnowledgeStore
    knowledge_store = InMemoryKnowledgeStore()
    injector = SkillInjector(knowledge_base=skill_kb, knowledge_store=knowledge_store)
    injection_result = await injector.run_injection_cycle(customer_id)
    assert injection_result["playbooks_injected"] >= 1, (
        f"Expected at least 1 playbook injected, got {injection_result}"
    )

    # Step 3 & 4: Build context from PromptEnricher
    enricher = PromptEnricher(knowledge_store=knowledge_store)
    context_str = await enricher.build_context(
        customer_id=customer_id,
        event_tags=["patch", "deployment"],
        action_class=None,
    )
    assert "Patch Critical Servers" in context_str, (
        f"Expected playbook name in context, got: {context_str[:500]}"
    )
    assert "Identify affected servers" in context_str, (
        f"Expected playbook steps in context, got: {context_str[:500]}"
    )

    # Step 5: Feed into LLMAnalyzeHandler and check LLM receives enriched prompt
    llm = InMemoryLLMClient()
    llm.set_responses([_make_analyze_response()])

    handler = LLMAnalyzeHandler(
        llm_client=llm,
        audit_logger=InMemoryAuditLogger(),
        event_bus=InMemoryEventBus(),
        prompt_enricher=enricher,
    )

    event = _make_event(customer_id=customer_id)
    trust_profile = _make_trust_profile(customer_id=customer_id)
    ctx = PipelineContext(
        event=event,
        customer_id=customer_id,
        correlation_id="corr-integration-e2e",
        trust_profile=trust_profile,
        policies=[],
    )
    ctx.current_stage = PipelineStage.ANALYZE

    result = await handler.handle(ctx)

    # Verify the handler completed successfully
    assert result.current_stage == PipelineStage.RECOMMEND

    # Verify the enriched context was in the LLM prompt
    assert llm.calls, "LLM should have been called"
    prompt_sent = llm.calls[0]["prompt"]
    assert "Patch Critical Servers" in prompt_sent, (
        f"Expected playbook name in LLM prompt.\nPrompt received:\n{prompt_sent[:600]}"
    )


async def test_enrichment_context_appended_to_existing_metadata() -> None:
    """When knowledge_context already exists in metadata, enriched context is appended."""
    customer_id = "cust-append"

    skill_kb = InMemorySkillKnowledgeBase()
    playbook = PlaybookTemplate(
        customer_id=customer_id,
        action_class=ActionClass.NETWORK_ISOLATION,
        name="Isolate Compromised Host",
        steps=["Quarantine host", "Block network access"],
    )
    skill_kb.store_playbook(playbook)

    knowledge_store = InMemoryKnowledgeStore()
    injector = SkillInjector(knowledge_base=skill_kb, knowledge_store=knowledge_store)
    await injector.run_injection_cycle(customer_id)

    enricher = PromptEnricher(knowledge_store=knowledge_store)

    llm = InMemoryLLMClient(
        default_structured={
            "threat_type": "Intrusion",
            "attack_vector": "Network",
            "severity_assessment": "HIGH",
            "confidence": 0.88,
            "reasoning": "append test",
        }
    )

    handler = LLMAnalyzeHandler(
        llm_client=llm,
        audit_logger=InMemoryAuditLogger(),
        event_bus=InMemoryEventBus(),
        prompt_enricher=enricher,
    )

    event = _make_event(customer_id=customer_id)
    trust_profile = _make_trust_profile(customer_id=customer_id)
    ctx = PipelineContext(
        event=event,
        customer_id=customer_id,
        correlation_id="corr-append-001",
        trust_profile=trust_profile,
        policies=[],
    )
    ctx.current_stage = PipelineStage.ANALYZE
    ctx.metadata["knowledge_context"] = {"assets": [{"id": "server-x", "type": "vm"}]}

    await handler.handle(ctx)

    prompt_sent = llm.calls[0]["prompt"]
    # Both existing context and enriched playbook should be in prompt
    assert "server-x" in prompt_sent or "assets" in prompt_sent, (
        "Existing knowledge context should appear in prompt"
    )
    assert "Isolate Compromised Host" in prompt_sent, (
        "Enriched playbook name should appear in prompt"
    )
