"""PatchGenerator — LLM-powered patch candidate generation from UserStory."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from summer_puppy.dev_bot.models import PatchCandidate, PatchType, UserStory

if TYPE_CHECKING:
    from summer_puppy.llm.client import LLMClient

_LOG = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are an expert security engineer generating minimal, safe patches with rollback mechanisms. "
    "Each patch must be production-ready, follow the principle of least privilege, and include "
    "explicit rollback instructions. Never introduce new vulnerabilities. Be concise and precise."
)

_PATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "patch_type": {"type": "string"},
        "title": {"type": "string"},
        "description": {"type": "string"},
        "content": {"type": "string"},
        "target_files": {"type": "array", "items": {"type": "string"}},
        "language": {"type": "string"},
        "confidence_score": {"type": "number", "minimum": 0, "maximum": 1},
        "reasoning": {"type": "string"},
        "rollback_content": {"type": "string"},
    },
    "required": [
        "patch_type",
        "title",
        "description",
        "content",
        "confidence_score",
        "reasoning",
        "rollback_content",
    ],
}


def _build_patch_prompt(story: UserStory, patch_type: PatchType) -> str:
    criteria_str = "\n".join(f"  - {c}" for c in story.acceptance_criteria)
    cve_str = ", ".join(story.cve_refs) if story.cve_refs else "(none)"
    mitre_str = ", ".join(story.mitre_attack_ids) if story.mitre_attack_ids else "(none)"
    assets_str = ", ".join(story.affected_assets) if story.affected_assets else "(none)"

    return (
        f"Generate a {patch_type} patch for the following security finding.\n\n"
        f"Story: {story.title}\n"
        f"Description: {story.description}\n"
        f"Severity: {story.severity}\n"
        f"CVE References: {cve_str}\n"
        f"MITRE ATT&CK IDs: {mitre_str}\n"
        f"Affected Assets: {assets_str}\n\n"
        f"Acceptance Criteria:\n{criteria_str}\n\n"
        f"Patch Type Required: {patch_type}\n\n"
        "Generate a minimal, safe patch with explicit rollback instructions. "
        "Include the exact content that would be applied, target file paths if applicable, "
        "confidence score, reasoning, and rollback procedure."
    )


class PatchGenerator:
    """Generates PatchCandidate objects from a UserStory using an LLM."""

    def __init__(self, llm_client: LLMClient, model_id: str = "") -> None:
        self._llm_client = llm_client
        self._model_id = model_id

    async def generate(
        self, story: UserStory, patch_type: PatchType | None = None
    ) -> list[PatchCandidate]:
        """Generate patch candidates for the given story.

        If patch_type is provided, generate only that type.
        Otherwise generate one candidate per recommended_patch_types in the story.
        """
        patch_types = [patch_type] if patch_type is not None else list(story.recommended_patch_types)
        if not patch_types:
            return []

        candidates: list[PatchCandidate] = []
        for pt in patch_types:
            try:
                candidate = await self._generate_one(story, pt)
                candidates.append(candidate)
            except Exception:
                _LOG.exception("PatchGenerator: LLM call failed for patch_type=%s", pt)
        return candidates

    async def _generate_one(self, story: UserStory, patch_type: PatchType) -> PatchCandidate:
        prompt = _build_patch_prompt(story, patch_type)
        response = await self._llm_client.generate_structured(
            prompt=prompt,
            output_schema=_PATCH_SCHEMA,
            system=_SYSTEM_PROMPT,
        )
        structured = response.structured_output or {}

        return PatchCandidate(
            story_id=story.story_id,
            customer_id=story.customer_id,
            correlation_id=story.correlation_id,
            patch_type=PatchType(structured.get("patch_type", patch_type)),
            title=structured.get("title", f"Patch for {story.title}"),
            description=structured.get("description", ""),
            content=structured.get("content", ""),
            target_files=structured.get("target_files", []),
            language=structured.get("language", ""),
            confidence_score=float(structured.get("confidence_score", 0.0)),
            reasoning=structured.get("reasoning", ""),
            rollback_content=structured.get("rollback_content", ""),
            generation_model=self._model_id,
        )
