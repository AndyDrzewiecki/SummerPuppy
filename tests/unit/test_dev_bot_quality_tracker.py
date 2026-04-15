"""Tests for DevBotQualityTracker — Phase 11, Sprint 11."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from summer_puppy.dev_bot.models import (
    DevBotPR,
    PatchCandidate,
    PatchStatus,
    PatchType,
    PROutcome,
)
from summer_puppy.dev_bot.quality_tracker import DevBotQualityTracker


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_pr(
    *,
    pr_id: str = "pr-001",
    patch_id: str = "patch-001",
    story_id: str = "story-001",
    customer_id: str = "cust-1",
    correlation_id: str = "corr-1",
    outcome: PROutcome = PROutcome.PENDING,
) -> DevBotPR:
    return DevBotPR(
        pr_id=pr_id,
        patch_id=patch_id,
        story_id=story_id,
        customer_id=customer_id,
        correlation_id=correlation_id,
        outcome=outcome,
        status=PatchStatus.PR_OPEN,
    )


def _make_patch(
    *,
    patch_id: str = "patch-001",
    story_id: str = "story-001",
    customer_id: str = "cust-1",
    patch_type: PatchType = PatchType.FIREWALL_RULE,
) -> PatchCandidate:
    return PatchCandidate(
        patch_id=patch_id,
        story_id=story_id,
        customer_id=customer_id,
        correlation_id="corr-1",
        patch_type=patch_type,
        title="Test patch",
        description="A test patch",
        content="iptables -A INPUT -s 1.2.3.4 -j DROP",
        rollback_content="iptables -D INPUT -s 1.2.3.4 -j DROP",
        confidence_score=0.9,
    )


@pytest.fixture
def tracker() -> DevBotQualityTracker:
    evaluator = MagicMock()
    evaluator.evaluate.return_value = MagicMock()
    trainer = MagicMock()
    return DevBotQualityTracker(evaluator=evaluator, trainer=trainer)


# ---------------------------------------------------------------------------
# Quality Score Tests
# ---------------------------------------------------------------------------


class TestRecordOutcomeQualityScore:
    def test_merged_without_change_gives_score_1(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(outcome=PROutcome.MERGED)
        patch = _make_patch()
        record = tracker.record_outcome(pr, patch, pre_submit_test_passed=True,
                                         merged_without_change=True)
        assert record.patch_quality_score == 1.0

    def test_merged_with_edits_gives_score_half(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(outcome=PROutcome.MERGED)
        patch = _make_patch()
        record = tracker.record_outcome(pr, patch, pre_submit_test_passed=True,
                                         merged_without_change=False)
        assert record.patch_quality_score == 0.5

    def test_approved_without_change_gives_score_1(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(outcome=PROutcome.APPROVED)
        patch = _make_patch()
        record = tracker.record_outcome(pr, patch, pre_submit_test_passed=True,
                                         merged_without_change=True)
        assert record.patch_quality_score == 1.0

    def test_approved_with_edits_gives_score_half(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(outcome=PROutcome.APPROVED)
        patch = _make_patch()
        record = tracker.record_outcome(pr, patch, pre_submit_test_passed=True,
                                         merged_without_change=False)
        assert record.patch_quality_score == 0.5

    def test_rejected_gives_score_zero(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(outcome=PROutcome.REJECTED)
        patch = _make_patch()
        record = tracker.record_outcome(pr, patch, pre_submit_test_passed=True,
                                         rejection_reason="Too risky")
        assert record.patch_quality_score == 0.0

    def test_pending_gives_score_zero(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(outcome=PROutcome.PENDING)
        patch = _make_patch()
        record = tracker.record_outcome(pr, patch, pre_submit_test_passed=False)
        assert record.patch_quality_score == 0.0

    def test_closed_gives_score_zero(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(outcome=PROutcome.CLOSED)
        patch = _make_patch()
        record = tracker.record_outcome(pr, patch, pre_submit_test_passed=False)
        assert record.patch_quality_score == 0.0


# ---------------------------------------------------------------------------
# Record creation
# ---------------------------------------------------------------------------


class TestRecordOutcomeCreation:
    def test_record_has_correct_ids(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(pr_id="pr-x", patch_id="patch-x", story_id="story-x",
                       customer_id="cust-2", correlation_id="corr-x",
                       outcome=PROutcome.MERGED)
        patch = _make_patch(patch_id="patch-x", story_id="story-x", customer_id="cust-2",
                             patch_type=PatchType.IAM_POLICY)
        record = tracker.record_outcome(pr, patch, pre_submit_test_passed=True,
                                         merged_without_change=True)
        assert record.pr_id == "pr-x"
        assert record.patch_id == "patch-x"
        assert record.story_id == "story-x"
        assert record.customer_id == "cust-2"
        assert record.correlation_id == "corr-x"
        assert record.patch_type == PatchType.IAM_POLICY
        assert record.pre_submit_test_passed is True
        assert record.merged_without_change is True

    def test_record_stored_in_tracker(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(outcome=PROutcome.MERGED)
        patch = _make_patch()
        tracker.record_outcome(pr, patch, pre_submit_test_passed=True, merged_without_change=True)
        assert len(tracker.get_records()) == 1

    def test_rejection_reason_stored(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(outcome=PROutcome.REJECTED)
        patch = _make_patch()
        record = tracker.record_outcome(pr, patch, pre_submit_test_passed=True,
                                         rejection_reason="Security risk")
        assert record.rejection_reason == "Security risk"

    def test_record_outcome_calls_evaluator(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(outcome=PROutcome.MERGED)
        patch = _make_patch()
        tracker.record_outcome(pr, patch, pre_submit_test_passed=True, merged_without_change=True)
        tracker._evaluator.evaluate.assert_called_once()

    def test_record_outcome_evaluator_context_has_quality_score(
        self, tracker: DevBotQualityTracker
    ) -> None:
        pr = _make_pr(outcome=PROutcome.MERGED)
        patch = _make_patch()
        tracker.record_outcome(pr, patch, pre_submit_test_passed=True, merged_without_change=True)
        call_args = tracker._evaluator.evaluate.call_args[0][0]
        assert "patch_quality_score" in call_args
        assert call_args["patch_quality_score"] == 1.0


# ---------------------------------------------------------------------------
# get_records
# ---------------------------------------------------------------------------


class TestGetRecords:
    def test_get_records_returns_all_when_no_filter(
        self, tracker: DevBotQualityTracker
    ) -> None:
        pr1 = _make_pr(pr_id="pr-1", patch_id="p1", customer_id="cust-1",
                        outcome=PROutcome.MERGED)
        pr2 = _make_pr(pr_id="pr-2", patch_id="p2", customer_id="cust-2",
                        outcome=PROutcome.REJECTED)
        patch1 = _make_patch(patch_id="p1", customer_id="cust-1")
        patch2 = _make_patch(patch_id="p2", customer_id="cust-2")
        tracker.record_outcome(pr1, patch1, pre_submit_test_passed=True)
        tracker.record_outcome(pr2, patch2, pre_submit_test_passed=False)
        assert len(tracker.get_records()) == 2

    def test_get_records_filters_by_customer_id(
        self, tracker: DevBotQualityTracker
    ) -> None:
        pr1 = _make_pr(pr_id="pr-1", patch_id="p1", customer_id="cust-1",
                        outcome=PROutcome.MERGED)
        pr2 = _make_pr(pr_id="pr-2", patch_id="p2", customer_id="cust-2",
                        outcome=PROutcome.REJECTED)
        patch1 = _make_patch(patch_id="p1", customer_id="cust-1")
        patch2 = _make_patch(patch_id="p2", customer_id="cust-2")
        tracker.record_outcome(pr1, patch1, pre_submit_test_passed=True)
        tracker.record_outcome(pr2, patch2, pre_submit_test_passed=False)
        records_cust1 = tracker.get_records(customer_id="cust-1")
        assert len(records_cust1) == 1
        assert records_cust1[0].customer_id == "cust-1"

    def test_get_records_returns_empty_list_when_none(
        self, tracker: DevBotQualityTracker
    ) -> None:
        assert tracker.get_records(customer_id="nonexistent") == []


# ---------------------------------------------------------------------------
# approval_rate
# ---------------------------------------------------------------------------


class TestApprovalRate:
    def test_approval_rate_zero_when_no_records(
        self, tracker: DevBotQualityTracker
    ) -> None:
        assert tracker.approval_rate() == 0.0

    def test_approval_rate_all_merged(self, tracker: DevBotQualityTracker) -> None:
        for i in range(4):
            pr = _make_pr(pr_id=f"pr-{i}", patch_id=f"p-{i}", outcome=PROutcome.MERGED)
            patch = _make_patch(patch_id=f"p-{i}")
            tracker.record_outcome(pr, patch, pre_submit_test_passed=True)
        assert tracker.approval_rate() == 1.0

    def test_approval_rate_half(self, tracker: DevBotQualityTracker) -> None:
        for i in range(2):
            pr = _make_pr(pr_id=f"pr-m-{i}", patch_id=f"pm-{i}", outcome=PROutcome.MERGED)
            patch = _make_patch(patch_id=f"pm-{i}")
            tracker.record_outcome(pr, patch, pre_submit_test_passed=True)
        for i in range(2):
            pr = _make_pr(pr_id=f"pr-r-{i}", patch_id=f"pr-{i}", outcome=PROutcome.REJECTED)
            patch = _make_patch(patch_id=f"pr-{i}")
            tracker.record_outcome(pr, patch, pre_submit_test_passed=False)
        assert tracker.approval_rate() == 0.5

    def test_approval_rate_filters_by_customer_id(
        self, tracker: DevBotQualityTracker
    ) -> None:
        pr1 = _make_pr(pr_id="pr-1", patch_id="p1", customer_id="cust-A",
                        outcome=PROutcome.MERGED)
        pr2 = _make_pr(pr_id="pr-2", patch_id="p2", customer_id="cust-B",
                        outcome=PROutcome.REJECTED)
        patch1 = _make_patch(patch_id="p1", customer_id="cust-A")
        patch2 = _make_patch(patch_id="p2", customer_id="cust-B")
        tracker.record_outcome(pr1, patch1, pre_submit_test_passed=True)
        tracker.record_outcome(pr2, patch2, pre_submit_test_passed=False)
        assert tracker.approval_rate(customer_id="cust-A") == 1.0
        assert tracker.approval_rate(customer_id="cust-B") == 0.0

    def test_approved_outcome_counts_in_rate(self, tracker: DevBotQualityTracker) -> None:
        pr = _make_pr(outcome=PROutcome.APPROVED)
        patch = _make_patch()
        tracker.record_outcome(pr, patch, pre_submit_test_passed=True)
        assert tracker.approval_rate() == 1.0


# ---------------------------------------------------------------------------
# feed_to_learning_loop
# ---------------------------------------------------------------------------


class TestFeedToLearningLoop:
    def test_feed_to_learning_loop_calls_evaluator(
        self, tracker: DevBotQualityTracker
    ) -> None:
        pr = _make_pr(outcome=PROutcome.MERGED)
        patch = _make_patch()
        tracker.record_outcome(pr, patch, pre_submit_test_passed=True, merged_without_change=True)
        assert tracker._evaluator.evaluate.call_count == 1

    def test_feed_to_learning_loop_evaluator_context_has_agent_id(
        self, tracker: DevBotQualityTracker
    ) -> None:
        pr = _make_pr(outcome=PROutcome.MERGED)
        patch = _make_patch()
        tracker.record_outcome(pr, patch, pre_submit_test_passed=True, merged_without_change=True)
        context = tracker._evaluator.evaluate.call_args[0][0]
        assert context["agent_id"] == "dev_bot"

    def test_feed_to_learning_loop_outcome_success_true_when_merged(
        self, tracker: DevBotQualityTracker
    ) -> None:
        pr = _make_pr(outcome=PROutcome.MERGED)
        patch = _make_patch()
        tracker.record_outcome(pr, patch, pre_submit_test_passed=True)
        context = tracker._evaluator.evaluate.call_args[0][0]
        assert context["outcome_success"] is True

    def test_feed_to_learning_loop_outcome_success_false_when_rejected(
        self, tracker: DevBotQualityTracker
    ) -> None:
        pr = _make_pr(outcome=PROutcome.REJECTED)
        patch = _make_patch()
        tracker.record_outcome(pr, patch, pre_submit_test_passed=False)
        context = tracker._evaluator.evaluate.call_args[0][0]
        assert context["outcome_success"] is False
