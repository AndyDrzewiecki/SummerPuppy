"""DevBotQualityTracker — records PR outcomes and feeds learning loop."""

from __future__ import annotations

from typing import TYPE_CHECKING

from summer_puppy.dev_bot.models import DevBotPR, DevBotQualityRecord, PatchCandidate, PROutcome

if TYPE_CHECKING:
    from summer_puppy.skills.evaluator import RunEvaluator
    from summer_puppy.skills.trainer import Trainer


class DevBotQualityTracker:
    """Stores DevBotQualityRecords and feeds patch quality back into the learning loop.

    When a PR is approved/merged, records a DevBotQualityRecord and calls the
    RunEvaluator with a synthetic context_summary that includes patch_quality_score
    as an additional dimension.
    """

    def __init__(self, evaluator: RunEvaluator, trainer: Trainer) -> None:
        self._evaluator = evaluator
        self._trainer = trainer
        self._records: list[DevBotQualityRecord] = []

    def record_outcome(
        self,
        pr: DevBotPR,
        patch: PatchCandidate,
        pre_submit_test_passed: bool,
        merged_without_change: bool = False,
        rejection_reason: str = "",
    ) -> DevBotQualityRecord:
        """Record the outcome of a PR and feed it back into the learning loop.

        Patch quality scores:
        - 1.0 = merged without change
        - 0.5 = merged with edits
        - 0.0 = rejected
        """
        if pr.outcome in (PROutcome.MERGED, PROutcome.APPROVED):
            if merged_without_change:
                patch_quality_score = 1.0
            else:
                patch_quality_score = 0.5
        else:
            patch_quality_score = 0.0

        record = DevBotQualityRecord(
            pr_id=pr.pr_id,
            patch_id=pr.patch_id,
            story_id=pr.story_id,
            customer_id=pr.customer_id,
            correlation_id=pr.correlation_id,
            outcome=pr.outcome,
            patch_type=patch.patch_type,
            pre_submit_test_passed=pre_submit_test_passed,
            merged_without_change=merged_without_change,
            rejection_reason=rejection_reason,
            patch_quality_score=patch_quality_score,
        )

        self._records.append(record)
        self._feed_to_learning_loop(record)
        return record

    def _feed_to_learning_loop(self, record: DevBotQualityRecord) -> None:
        """Build context summary and call evaluator + trainer with quality data."""
        outcome_success = record.outcome in (PROutcome.MERGED, PROutcome.APPROVED)

        context_summary = {
            "agent_id": "dev_bot",
            "customer_id": record.customer_id,
            "correlation_id": record.correlation_id,
            "confidence_score": record.patch_quality_score,
            "execution_status": "COMPLETED" if outcome_success else "FAILED",
            "outcome_success": outcome_success,
            "qa_status": "PASSED" if record.pre_submit_test_passed else "PENDING",
            "approval_method": "HUMAN_APPROVED" if outcome_success else "",
            # Extra dimension for dev_bot domain
            "patch_quality_score": record.patch_quality_score,
            "patch_type": record.patch_type,
            "merged_without_change": record.merged_without_change,
        }

        self._evaluator.evaluate(context_summary)

    def get_records(self, customer_id: str | None = None) -> list[DevBotQualityRecord]:
        """Return all records, optionally filtered by customer_id."""
        if customer_id is None:
            return list(self._records)
        return [r for r in self._records if r.customer_id == customer_id]

    def approval_rate(self, customer_id: str | None = None) -> float:
        """Return the fraction of records with outcome APPROVED or MERGED."""
        records = self.get_records(customer_id)
        if not records:
            return 0.0
        approved = sum(
            1 for r in records if r.outcome in (PROutcome.APPROVED, PROutcome.MERGED)
        )
        return approved / len(records)
