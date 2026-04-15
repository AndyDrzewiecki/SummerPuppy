"""OfflineTriageEngine — handles critical incidents when cloud connectivity is lost."""

from __future__ import annotations

from typing import Any

from summer_puppy.local.models import OfflineTriage


class OfflineTriageEngine:
    """Uses a local LLM (e.g. Ollama) to triage security events offline.

    When cloud connectivity is lost:
    1. Uses LocalContextCache for tenant-specific KB context
    2. Sends a structured triage prompt to the local LLM
    3. Returns OfflineTriage with severity_assessment + recommended_action

    Designed for autonomous SEV-1 response even without internet access.
    """

    def __init__(
        self,
        llm_client: Any,
        context_cache: Any,
    ) -> None:
        self._llm = llm_client
        self._cache = context_cache

    async def triage_event(
        self,
        tenant_id: str,
        event_summary: str,
        event_severity: str = "UNKNOWN",
    ) -> OfflineTriage:
        """Triage a security event using the local LLM.

        Uses cached KB context if available. Falls back to LLM-only if not.
        """
        context = self._cache.build_context_string(tenant_id)
        used_cached_context = bool(context)

        context_section = f"\n\nContext from knowledge base:\n{context}" if context else ""
        prompt = (
            f"You are a security analyst. Triage this security event.\n\n"
            f"Event: {event_summary}\n"
            f"Severity: {event_severity}"
            f"{context_section}\n\n"
            f"Provide: severity_assessment (LOW/MEDIUM/HIGH/CRITICAL), "
            f"recommended_action, reasoning."
        )

        response = await self._llm.analyze(prompt)
        content = response.content

        # Parse response heuristically
        severity_assessment = _extract_field(content, "severity_assessment") or event_severity
        recommended_action = _extract_field(content, "recommended_action") or content
        reasoning = _extract_field(content, "reasoning") or content

        return OfflineTriage(
            tenant_id=tenant_id,
            event_summary=event_summary,
            severity_assessment=severity_assessment,
            recommended_action=recommended_action,
            reasoning=reasoning,
            used_cached_context=used_cached_context,
        )

    async def is_available(self) -> bool:
        """Return True if the local LLM is reachable (basic connectivity check)."""
        try:
            await self._llm.analyze("ping")
            return True
        except Exception:
            return False


def _extract_field(text: str, field: str) -> str:
    """Extract a field value from text using simple heuristics."""
    lower = text.lower()
    key = field.lower().replace("_", " ") + ":"
    key2 = field.lower() + ":"
    for k in (key, key2, field.lower() + " "):
        idx = lower.find(k)
        if idx != -1:
            start = idx + len(k)
            # Extract until newline or end
            end = text.find("\n", start)
            value = text[start:end].strip() if end != -1 else text[start:].strip()
            if value:
                return value
    return ""
