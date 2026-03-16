"""Tests for PromotionEngine — strict TDD, tests written before implementation."""

from __future__ import annotations

from summer_puppy.skills.models import (
    ArtifactPromotionDecision,
    PromotionLevel,
    RunReview,
)
from summer_puppy.skills.promotion import PromotionEngine


def _make_review(
    *,
    outcome_success: bool = True,
    qa_reliability: float = 1.0,
    recommendation_quality: float = 0.8,
    correlation_id: str = "corr-1",
    customer_id: str = "cust-1",
) -> RunReview:
    return RunReview(
        correlation_id=correlation_id,
        customer_id=customer_id,
        recommendation_quality=recommendation_quality,
        execution_safety=1.0,
        outcome_success=outcome_success,
        qa_reliability=qa_reliability,
        human_override=False,
    )


def _make_artifact(
    artifact_id: str = "art-1",
    artifact_type: str = "CODE_PATCH",
    source_run_id: str = "run-1",
) -> dict[str, str]:
    return {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "source_run_id": source_run_id,
    }


# ---------------------------------------------------------------------------
# PromotionEngine tests
# ---------------------------------------------------------------------------


class TestPromotionEngine:
    """Tests for PromotionEngine.classify_artifacts()."""

    def test_success_high_qa_code_patch_promotes_to_team_kb(self) -> None:
        engine = PromotionEngine()
        review = _make_review(outcome_success=True, qa_reliability=1.0)
        artifacts = [_make_artifact(artifact_type="CODE_PATCH")]
        decisions = engine.classify_artifacts(artifacts, review)
        assert len(decisions) == 1
        assert decisions[0].promotion_level == PromotionLevel.TEAM_KB
        assert decisions[0].reason == "High-quality outcome with reliable QA"

    def test_success_high_qa_detection_rule_promotes_to_team_kb(self) -> None:
        engine = PromotionEngine()
        review = _make_review(outcome_success=True, qa_reliability=0.9)
        artifacts = [_make_artifact(artifact_type="DETECTION_RULE")]
        decisions = engine.classify_artifacts(artifacts, review)
        assert len(decisions) == 1
        assert decisions[0].promotion_level == PromotionLevel.TEAM_KB

    def test_success_high_qa_configuration_change_promotes_to_team_kb(self) -> None:
        engine = PromotionEngine()
        review = _make_review(outcome_success=True, qa_reliability=0.85)
        artifacts = [_make_artifact(artifact_type="CONFIGURATION_CHANGE")]
        decisions = engine.classify_artifacts(artifacts, review)
        assert len(decisions) == 1
        assert decisions[0].promotion_level == PromotionLevel.TEAM_KB
        assert decisions[0].reason == "High-quality outcome with reliable QA"

    def test_success_high_qa_runbook_promotes_to_playbook_template(self) -> None:
        engine = PromotionEngine()
        review = _make_review(outcome_success=True, qa_reliability=0.95)
        artifacts = [_make_artifact(artifact_type="RUNBOOK")]
        decisions = engine.classify_artifacts(artifacts, review)
        assert len(decisions) == 1
        assert decisions[0].promotion_level == PromotionLevel.PLAYBOOK_TEMPLATE
        assert decisions[0].reason == "Successful runbook eligible for template promotion"

    def test_success_high_qa_other_type_promotes_to_run_record(self) -> None:
        engine = PromotionEngine()
        review = _make_review(outcome_success=True, qa_reliability=1.0)
        artifacts = [_make_artifact(artifact_type="THREAT_REPORT")]
        decisions = engine.classify_artifacts(artifacts, review)
        assert len(decisions) == 1
        assert decisions[0].promotion_level == PromotionLevel.RUN_RECORD
        assert decisions[0].reason == "Successful run archived"

    def test_success_low_qa_promotes_to_run_record(self) -> None:
        engine = PromotionEngine()
        review = _make_review(outcome_success=True, qa_reliability=0.5)
        artifacts = [_make_artifact(artifact_type="CODE_PATCH")]
        decisions = engine.classify_artifacts(artifacts, review)
        assert len(decisions) == 1
        assert decisions[0].promotion_level == PromotionLevel.RUN_RECORD
        assert decisions[0].reason == "Successful but QA unreliable — archived as run record"

    def test_failure_low_recommendation_quality_discards(self) -> None:
        engine = PromotionEngine()
        review = _make_review(
            outcome_success=False,
            recommendation_quality=0.2,
            qa_reliability=0.5,
        )
        artifacts = [_make_artifact()]
        decisions = engine.classify_artifacts(artifacts, review)
        assert len(decisions) == 1
        assert decisions[0].promotion_level == PromotionLevel.DISCARD
        assert decisions[0].reason == "Low recommendation quality — discarded"

    def test_failure_decent_quality_promotes_to_run_record(self) -> None:
        engine = PromotionEngine()
        review = _make_review(
            outcome_success=False,
            recommendation_quality=0.6,
            qa_reliability=0.5,
        )
        artifacts = [_make_artifact()]
        decisions = engine.classify_artifacts(artifacts, review)
        assert len(decisions) == 1
        assert decisions[0].promotion_level == PromotionLevel.RUN_RECORD
        assert decisions[0].reason == "Mixed results — archived as run record"

    def test_empty_artifacts_returns_empty(self) -> None:
        engine = PromotionEngine()
        review = _make_review()
        decisions = engine.classify_artifacts([], review)
        assert decisions == []

    def test_multiple_artifacts_returns_decision_per_artifact(self) -> None:
        engine = PromotionEngine()
        review = _make_review(outcome_success=True, qa_reliability=1.0)
        artifacts = [
            _make_artifact(artifact_id="art-1", artifact_type="CODE_PATCH"),
            _make_artifact(artifact_id="art-2", artifact_type="RUNBOOK"),
            _make_artifact(artifact_id="art-3", artifact_type="THREAT_REPORT"),
        ]
        decisions = engine.classify_artifacts(artifacts, review)
        assert len(decisions) == 3
        levels = {d.artifact_id: d.promotion_level for d in decisions}
        assert levels["art-1"] == PromotionLevel.TEAM_KB
        assert levels["art-2"] == PromotionLevel.PLAYBOOK_TEMPLATE
        assert levels["art-3"] == PromotionLevel.RUN_RECORD

    def test_correct_artifact_id_propagation(self) -> None:
        engine = PromotionEngine()
        review = _make_review()
        artifacts = [_make_artifact(artifact_id="specific-art-id")]
        decisions = engine.classify_artifacts(artifacts, review)
        assert decisions[0].artifact_id == "specific-art-id"

    def test_correct_source_run_id_propagation(self) -> None:
        engine = PromotionEngine()
        review = _make_review()
        artifacts = [_make_artifact(source_run_id="specific-run-id")]
        decisions = engine.classify_artifacts(artifacts, review)
        assert decisions[0].source_run_id == "specific-run-id"

    def test_qa_reliability_boundary_at_08(self) -> None:
        """qa_reliability == 0.8 should count as high QA (>= 0.8)."""
        engine = PromotionEngine()
        review = _make_review(outcome_success=True, qa_reliability=0.8)
        artifacts = [_make_artifact(artifact_type="CODE_PATCH")]
        decisions = engine.classify_artifacts(artifacts, review)
        assert decisions[0].promotion_level == PromotionLevel.TEAM_KB

    def test_qa_reliability_just_below_08(self) -> None:
        """qa_reliability == 0.79 should count as low QA."""
        engine = PromotionEngine()
        review = _make_review(outcome_success=True, qa_reliability=0.79)
        artifacts = [_make_artifact(artifact_type="CODE_PATCH")]
        decisions = engine.classify_artifacts(artifacts, review)
        assert decisions[0].promotion_level == PromotionLevel.RUN_RECORD
        assert decisions[0].reason == "Successful but QA unreliable — archived as run record"

    def test_recommendation_quality_boundary_at_03(self) -> None:
        """recommendation_quality == 0.3 should NOT discard (only < 0.3 discards)."""
        engine = PromotionEngine()
        review = _make_review(
            outcome_success=False,
            recommendation_quality=0.3,
            qa_reliability=0.5,
        )
        artifacts = [_make_artifact()]
        decisions = engine.classify_artifacts(artifacts, review)
        assert decisions[0].promotion_level == PromotionLevel.RUN_RECORD

    def test_decision_is_artifact_promotion_decision(self) -> None:
        engine = PromotionEngine()
        review = _make_review()
        artifacts = [_make_artifact()]
        decisions = engine.classify_artifacts(artifacts, review)
        assert isinstance(decisions[0], ArtifactPromotionDecision)

    def test_incident_report_success_high_qa_archives_as_run_record(self) -> None:
        """INCIDENT_REPORT is not in the TEAM_KB set, so success+high QA archives."""
        engine = PromotionEngine()
        review = _make_review(outcome_success=True, qa_reliability=1.0)
        artifacts = [_make_artifact(artifact_type="INCIDENT_REPORT")]
        decisions = engine.classify_artifacts(artifacts, review)
        assert decisions[0].promotion_level == PromotionLevel.RUN_RECORD
        assert decisions[0].reason == "Successful run archived"
