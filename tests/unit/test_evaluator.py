"""Tests for RunEvaluator — strict TDD, tests written before implementation."""

from __future__ import annotations

from summer_puppy.skills.evaluator import RunEvaluator
from summer_puppy.skills.models import RunReview

# ---------------------------------------------------------------------------
# RunEvaluator tests
# ---------------------------------------------------------------------------


class TestRunEvaluator:
    """Tests for RunEvaluator.evaluate()."""

    def test_evaluate_all_fields_present(self) -> None:
        evaluator = RunEvaluator()
        ctx = {
            "confidence_score": 0.85,
            "execution_status": "COMPLETED",
            "outcome_success": True,
            "qa_status": "PASSED",
            "approval_method": "HUMAN_APPROVED",
            "correlation_id": "corr-123",
            "customer_id": "cust-456",
        }
        review = evaluator.evaluate(ctx)
        assert isinstance(review, RunReview)
        assert review.recommendation_quality == 0.85
        assert review.execution_safety == 1.0
        assert review.outcome_success is True
        assert review.qa_reliability == 1.0
        assert review.human_override is True
        assert review.correlation_id == "corr-123"
        assert review.customer_id == "cust-456"

    def test_evaluate_missing_fields_uses_defaults(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({})
        assert isinstance(review, RunReview)
        assert review.recommendation_quality == 0.5
        assert review.execution_safety == 0.0
        assert review.outcome_success is False
        assert review.qa_reliability == 0.0  # None status is not in map, falls to default 0.0
        assert review.human_override is False
        assert review.correlation_id == ""
        assert review.customer_id == ""

    def test_execution_status_completed_safety_1(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"execution_status": "COMPLETED"})
        assert review.execution_safety == 1.0

    def test_execution_status_failed_safety_05(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"execution_status": "FAILED"})
        assert review.execution_safety == 0.5

    def test_execution_status_rolled_back_safety_03(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"execution_status": "ROLLED_BACK"})
        assert review.execution_safety == 0.3

    def test_execution_status_unknown_safety_0(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"execution_status": "SOMETHING_ELSE"})
        assert review.execution_safety == 0.0

    def test_qa_status_passed_reliability_1(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"qa_status": "PASSED"})
        assert review.qa_reliability == 1.0

    def test_qa_status_pending_reliability_05(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"qa_status": "PENDING"})
        assert review.qa_reliability == 0.5

    def test_qa_status_failed_reliability_0(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"qa_status": "FAILED"})
        assert review.qa_reliability == 0.0

    def test_human_approval_override_true(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"approval_method": "HUMAN_APPROVED"})
        assert review.human_override is True

    def test_auto_approval_override_false(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"approval_method": "AUTO_APPROVED"})
        assert review.human_override is False

    def test_no_approval_method_override_false(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({})
        assert review.human_override is False

    def test_review_id_is_generated(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({})
        assert review.review_id  # non-empty auto-generated uuid

    def test_confidence_score_boundary_zero(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"confidence_score": 0.0})
        assert review.recommendation_quality == 0.0

    def test_confidence_score_boundary_one(self) -> None:
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"confidence_score": 1.0})
        assert review.recommendation_quality == 1.0

    def test_execution_status_none_safety_0(self) -> None:
        """When execution_status is missing entirely, safety should be 0.0."""
        evaluator = RunEvaluator()
        review = evaluator.evaluate({"confidence_score": 0.7})
        assert review.execution_safety == 0.0
