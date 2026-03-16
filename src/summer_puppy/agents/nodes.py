"""Node functions for the LangGraph security analysis pipeline."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from summer_puppy.llm.prompts import ANALYZE_EVENT, GENERATE_RECOMMENDATION

if TYPE_CHECKING:
    from summer_puppy.llm.client import LLMClient


async def triage_node(state: dict[str, Any], *, llm_client: LLMClient) -> dict[str, Any]:
    """Check event severity and set severity_route."""
    event = state["event"]
    severity = str(event.get("severity", "")).upper()
    severity_route = "high" if severity in ("HIGH", "CRITICAL") else "low"

    existing_trace: list[str] = list(state.get("reasoning_trace") or [])
    existing_trace.append(f"Triaged as {severity_route} severity")

    return {"severity_route": severity_route, "reasoning_trace": existing_trace}


async def analyze_node(state: dict[str, Any], *, llm_client: LLMClient) -> dict[str, Any]:
    """Analyze the security event using LLM structured generation."""
    event = state["event"]
    existing_trace: list[str] = list(state.get("reasoning_trace") or [])

    try:
        knowledge_context = state.get("knowledge_context", {})
        prompt = ANALYZE_EVENT.render(
            title=event.get("title", ""),
            source=event.get("source", ""),
            severity=event.get("severity", ""),
            description=event.get("description", ""),
            affected_assets=", ".join(event.get("affected_assets", [])),
            raw_payload=str(event.get("raw_payload", {})),
            knowledge_context=str(knowledge_context),
        )

        output_schema: dict[str, Any] = {
            "type": "object",
            "properties": {
                "threat_type": {"type": "string"},
                "attack_vector": {"type": "string"},
                "affected_systems": {"type": "array", "items": {"type": "string"}},
                "ioc_indicators": {"type": "array", "items": {"type": "string"}},
                "severity_assessment": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                },
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "reasoning": {"type": "string"},
                "recommended_actions": {"type": "array", "items": {"type": "string"}},
                "mitre_attack_ids": {"type": "array", "items": {"type": "string"}},
            },
            "required": [
                "threat_type",
                "attack_vector",
                "severity_assessment",
                "confidence",
                "reasoning",
            ],
        }

        response = await llm_client.generate_structured(prompt, output_schema)
        analysis = response.structured_output or {}
        existing_trace.append(f"Analysis completed: {analysis.get('threat_type', 'Unknown')}")
        return {"analysis": analysis, "reasoning_trace": existing_trace}

    except Exception as exc:
        fallback: dict[str, Any] = {
            "threat_type": "Unknown",
            "attack_vector": "Unknown",
            "severity_assessment": event.get("severity", "MEDIUM"),
            "confidence": 0.1,
            "reasoning": f"LLM analysis unavailable: {exc}",
        }
        existing_trace.append(f"Analysis fallback due to error: {exc}")
        return {
            "analysis": fallback,
            "error": str(exc),
            "reasoning_trace": existing_trace,
        }


async def recommend_node(state: dict[str, Any], *, llm_client: LLMClient) -> dict[str, Any]:
    """Generate remediation recommendation using LLM."""
    event = state["event"]
    analysis = state.get("analysis", {})
    trust_profile = state.get("trust_profile", {})
    existing_trace: list[str] = list(state.get("reasoning_trace") or [])

    try:
        prompt = GENERATE_RECOMMENDATION.render(
            analysis_summary=str(analysis),
            title=event.get("title", ""),
            severity=event.get("severity", ""),
            affected_assets=str(event.get("affected_assets", [])),
            customer_id=state.get("customer_id", ""),
            trust_phase=trust_profile.get("trust_phase", "manual"),
            positive_outcome_rate=str(trust_profile.get("positive_outcome_rate", 0.0)),
            action_classes="[patch_deployment, configuration_change, network_isolation, "
            "process_termination, account_lockout, detection_rule_update, "
            "compensating_control, rollback]",
        )

        output_schema: dict[str, Any] = {
            "type": "object",
            "properties": {
                "action_class": {"type": "string"},
                "description": {"type": "string"},
                "reasoning": {"type": "string"},
                "confidence_score": {"type": "number", "minimum": 0, "maximum": 1},
                "estimated_risk": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                },
                "rollback_plan": {"type": ["string", "null"]},
                "affected_asset_classes": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": [
                "action_class",
                "description",
                "reasoning",
                "confidence_score",
                "estimated_risk",
            ],
        }

        response = await llm_client.generate_structured(prompt, output_schema)
        recommendation = response.structured_output or {}
        existing_trace.append(
            f"Recommendation generated: {recommendation.get('action_class', 'unknown')}"
        )
        return {"recommendation": recommendation, "reasoning_trace": existing_trace}

    except Exception as exc:
        fallback: dict[str, Any] = {
            "action_class": "compensating_control",
            "description": f"Fallback recommendation for event {event.get('title', '')}",
            "reasoning": f"Automated fallback - LLM unavailable: {exc}",
            "confidence_score": 0.1,
            "estimated_risk": event.get("severity", "MEDIUM"),
        }
        existing_trace.append(f"Recommendation fallback due to error: {exc}")
        return {
            "recommendation": fallback,
            "error": str(exc),
            "reasoning_trace": existing_trace,
        }


async def simple_recommend_node(
    state: dict[str, Any],
    *,
    llm_client: LLMClient,
) -> dict[str, Any]:
    """Create a simple rule-based recommendation without LLM call."""
    event = state["event"]
    severity = str(event.get("severity", "LOW")).upper()
    existing_trace: list[str] = list(state.get("reasoning_trace") or [])

    action_class = "compensating_control" if severity == "MEDIUM" else "detection_rule_update"

    recommendation: dict[str, Any] = {
        "action_class": action_class,
        "description": f"Simple recommendation for {event.get('title', 'event')}",
        "reasoning": f"Rule-based: severity {severity} maps to {action_class}",
        "confidence_score": 0.6,
        "estimated_risk": severity if severity in ("LOW", "MEDIUM") else "LOW",
    }

    existing_trace.append(f"Simple recommendation: {action_class} (severity={severity})")
    return {"recommendation": recommendation, "reasoning_trace": existing_trace}
