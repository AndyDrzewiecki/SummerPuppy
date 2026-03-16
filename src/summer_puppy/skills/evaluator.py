"""Run evaluator — scores a pipeline run based on context summary data."""

from __future__ import annotations

from typing import Any

from summer_puppy.skills.models import RunReview

_EXECUTION_SAFETY_MAP: dict[str, float] = {
    "COMPLETED": 1.0,
    "FAILED": 0.5,
    "ROLLED_BACK": 0.3,
}

_QA_RELIABILITY_MAP: dict[str, float] = {
    "PASSED": 1.0,
    "PENDING": 0.5,
}


class RunEvaluator:
    """Evaluates a pipeline run and produces a ``RunReview``."""

    def evaluate(self, context_summary: dict[str, Any]) -> RunReview:
        """Extract scores from *context_summary* and return a ``RunReview``."""
        recommendation_quality: float = context_summary.get("confidence_score", 0.5)

        execution_status: str = str(context_summary.get("execution_status", ""))
        execution_safety: float = _EXECUTION_SAFETY_MAP.get(execution_status, 0.0)

        outcome_success: bool = context_summary.get("outcome_success", False)

        qa_status: str = str(context_summary.get("qa_status", ""))
        qa_reliability: float = _QA_RELIABILITY_MAP.get(qa_status, 0.0)

        human_override: bool = context_summary.get("approval_method") == "HUMAN_APPROVED"

        correlation_id: str = context_summary.get("correlation_id", "")
        customer_id: str = context_summary.get("customer_id", "")

        return RunReview(
            correlation_id=correlation_id,
            customer_id=customer_id,
            recommendation_quality=recommendation_quality,
            execution_safety=execution_safety,
            outcome_success=outcome_success,
            qa_reliability=qa_reliability,
            human_override=human_override,
        )
