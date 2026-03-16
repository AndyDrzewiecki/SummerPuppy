"""Promotion engine — classifies artifacts for knowledge-base promotion."""

from __future__ import annotations

from typing import Any

from summer_puppy.skills.models import (
    ArtifactPromotionDecision,
    PromotionLevel,
    RunReview,
)

_TEAM_KB_TYPES = frozenset({"CODE_PATCH", "DETECTION_RULE", "CONFIGURATION_CHANGE"})


class PromotionEngine:
    """Classifies artifacts into promotion levels based on a ``RunReview``."""

    def classify_artifacts(
        self,
        artifacts: list[dict[str, Any]],
        run_review: RunReview,
    ) -> list[ArtifactPromotionDecision]:
        """Return one ``ArtifactPromotionDecision`` per artifact."""
        decisions: list[ArtifactPromotionDecision] = []
        for artifact in artifacts:
            artifact_id: str = artifact["artifact_id"]
            artifact_type: str = artifact["artifact_type"]
            source_run_id: str = artifact["source_run_id"]

            level, reason = self._classify_single(artifact_type, run_review)
            decisions.append(
                ArtifactPromotionDecision(
                    artifact_id=artifact_id,
                    source_run_id=source_run_id,
                    promotion_level=level,
                    reason=reason,
                )
            )
        return decisions

    @staticmethod
    def _classify_single(
        artifact_type: str,
        run_review: RunReview,
    ) -> tuple[PromotionLevel, str]:
        if run_review.outcome_success and run_review.qa_reliability >= 0.8:
            if artifact_type in _TEAM_KB_TYPES:
                return PromotionLevel.TEAM_KB, "High-quality outcome with reliable QA"
            if artifact_type == "RUNBOOK":
                return (
                    PromotionLevel.PLAYBOOK_TEMPLATE,
                    "Successful runbook eligible for template promotion",
                )
            return PromotionLevel.RUN_RECORD, "Successful run archived"

        if run_review.outcome_success:
            return (
                PromotionLevel.RUN_RECORD,
                "Successful but QA unreliable \u2014 archived as run record",
            )

        if run_review.recommendation_quality < 0.3:
            return PromotionLevel.DISCARD, "Low recommendation quality \u2014 discarded"

        return PromotionLevel.RUN_RECORD, "Mixed results \u2014 archived as run record"
