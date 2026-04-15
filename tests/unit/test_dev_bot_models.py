"""Unit tests for dev_bot models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from summer_puppy.dev_bot.models import (
    DevBotPR,
    DevBotQualityRecord,
    PatchCandidate,
    PatchStatus,
    PatchTestCheck,
    PatchTestResult,
    PatchType,
    PROutcome,
    UserStory,
)
from summer_puppy.sandbox.models import FindingSeverity
from summer_puppy.trust.models import ActionClass


def make_user_story(**kwargs: object) -> UserStory:
    defaults: dict[str, object] = {
        "finding_id": "finding-1",
        "customer_id": "cust-1",
        "correlation_id": "corr-1",
        "title": "Test Story",
        "description": "As a security engineer...",
        "severity": FindingSeverity.HIGH,
    }
    defaults.update(kwargs)
    return UserStory(**defaults)  # type: ignore[arg-type]


def make_patch_candidate(**kwargs: object) -> PatchCandidate:
    defaults: dict[str, object] = {
        "story_id": "story-1",
        "customer_id": "cust-1",
        "correlation_id": "corr-1",
        "patch_type": PatchType.FIREWALL_RULE,
        "title": "Block malicious IP",
        "description": "Adds firewall rule",
        "content": "iptables -A INPUT -s 10.0.0.1 -j DROP",
        "confidence_score": 0.9,
    }
    defaults.update(kwargs)
    return PatchCandidate(**defaults)  # type: ignore[arg-type]


class TestUserStory:
    def test_creates_with_required_fields(self) -> None:
        story = make_user_story()
        assert story.finding_id == "finding-1"
        assert story.customer_id == "cust-1"
        assert story.severity == FindingSeverity.HIGH

    def test_auto_generates_story_id(self) -> None:
        s1 = make_user_story()
        s2 = make_user_story()
        assert s1.story_id != s2.story_id

    def test_defaults_action_class(self) -> None:
        story = make_user_story()
        assert story.action_class == ActionClass.PATCH_DEPLOYMENT

    def test_defaults_empty_lists(self) -> None:
        story = make_user_story()
        assert story.acceptance_criteria == []
        assert story.cve_refs == []
        assert story.affected_files == []
        assert story.affected_assets == []
        assert story.mitre_attack_ids == []
        assert story.recommended_patch_types == []

    def test_created_utc_is_aware(self) -> None:
        story = make_user_story()
        assert story.created_utc.tzinfo is not None

    def test_custom_fields(self) -> None:
        story = make_user_story(
            cve_refs=["CVE-2024-1234"],
            mitre_attack_ids=["T1059"],
            recommended_patch_types=[PatchType.FIREWALL_RULE],
        )
        assert story.cve_refs == ["CVE-2024-1234"]
        assert story.mitre_attack_ids == ["T1059"]
        assert story.recommended_patch_types == [PatchType.FIREWALL_RULE]


class TestPatchCandidate:
    def test_creates_with_required_fields(self) -> None:
        patch = make_patch_candidate()
        assert patch.story_id == "story-1"
        assert patch.patch_type == PatchType.FIREWALL_RULE
        assert patch.status == PatchStatus.PENDING

    def test_status_transitions(self) -> None:
        patch = make_patch_candidate()
        patch.status = PatchStatus.TESTING
        assert patch.status == PatchStatus.TESTING
        patch.status = PatchStatus.TEST_PASSED
        assert patch.status == PatchStatus.TEST_PASSED
        patch.status = PatchStatus.PR_OPEN
        assert patch.status == PatchStatus.PR_OPEN
        patch.status = PatchStatus.PR_MERGED
        assert patch.status == PatchStatus.PR_MERGED

    def test_confidence_score_bounds(self) -> None:
        with pytest.raises(Exception):
            make_patch_candidate(confidence_score=1.5)
        with pytest.raises(Exception):
            make_patch_candidate(confidence_score=-0.1)

    def test_auto_generates_patch_id(self) -> None:
        p1 = make_patch_candidate()
        p2 = make_patch_candidate()
        assert p1.patch_id != p2.patch_id

    def test_defaults(self) -> None:
        patch = make_patch_candidate()
        assert patch.rollback_content == ""
        assert patch.generation_model == ""
        assert patch.target_files == []
        assert patch.language == ""


class TestPatchTestResult:
    def test_all_checks_pass(self) -> None:
        checks = [
            PatchTestCheck(check_name="syntax_valid", passed=True),
            PatchTestCheck(check_name="content_not_empty", passed=True),
        ]
        result = PatchTestResult(
            patch_id="patch-1",
            customer_id="cust-1",
            passed=True,
            checks=checks,
            summary="All good",
        )
        assert result.passed is True
        assert len(result.checks) == 2

    def test_mixed_checks(self) -> None:
        checks = [
            PatchTestCheck(check_name="syntax_valid", passed=True, detail="ok"),
            PatchTestCheck(check_name="rollback_available", passed=False, detail="missing"),
        ]
        result = PatchTestResult(
            patch_id="patch-1",
            customer_id="cust-1",
            passed=False,
            checks=checks,
        )
        assert result.passed is False
        passing = [c for c in result.checks if c.passed]
        failing = [c for c in result.checks if not c.passed]
        assert len(passing) == 1
        assert len(failing) == 1

    def test_duration_ms_default(self) -> None:
        result = PatchTestResult(patch_id="p", customer_id="c", passed=True)
        assert result.duration_ms == 0.0


class TestDevBotPR:
    def test_creates_with_required_fields(self) -> None:
        pr = DevBotPR(
            patch_id="patch-1",
            story_id="story-1",
            customer_id="cust-1",
            correlation_id="corr-1",
        )
        assert pr.status == PatchStatus.PR_OPEN
        assert pr.outcome == PROutcome.PENDING

    def test_lifecycle_fields(self) -> None:
        pr = DevBotPR(
            patch_id="patch-1",
            story_id="story-1",
            customer_id="cust-1",
            correlation_id="corr-1",
        )
        assert pr.github_pr_number is None
        assert pr.github_pr_url is None
        assert pr.closed_utc is None
        assert pr.merged_utc is None
        assert pr.reviewed_by is None

    def test_can_set_pr_number_and_url(self) -> None:
        pr = DevBotPR(
            patch_id="patch-1",
            story_id="story-1",
            customer_id="cust-1",
            correlation_id="corr-1",
            github_pr_number=42,
            github_pr_url="https://github.com/org/repo/pull/42",
        )
        assert pr.github_pr_number == 42
        assert "42" in (pr.github_pr_url or "")

    def test_outcome_transitions(self) -> None:
        pr = DevBotPR(
            patch_id="patch-1",
            story_id="story-1",
            customer_id="cust-1",
            correlation_id="corr-1",
        )
        pr.outcome = PROutcome.MERGED
        pr.merged_utc = datetime.now(tz=UTC)
        assert pr.outcome == PROutcome.MERGED
        assert pr.merged_utc is not None


class TestDevBotQualityRecord:
    def test_patch_quality_score_bounds(self) -> None:
        with pytest.raises(Exception):
            DevBotQualityRecord(
                pr_id="pr-1",
                patch_id="p-1",
                story_id="s-1",
                customer_id="c-1",
                correlation_id="corr-1",
                outcome=PROutcome.MERGED,
                patch_type=PatchType.FIREWALL_RULE,
                pre_submit_test_passed=True,
                patch_quality_score=1.5,
            )
        with pytest.raises(Exception):
            DevBotQualityRecord(
                pr_id="pr-1",
                patch_id="p-1",
                story_id="s-1",
                customer_id="c-1",
                correlation_id="corr-1",
                outcome=PROutcome.MERGED,
                patch_type=PatchType.FIREWALL_RULE,
                pre_submit_test_passed=True,
                patch_quality_score=-0.1,
            )

    def test_creates_valid_record(self) -> None:
        record = DevBotQualityRecord(
            pr_id="pr-1",
            patch_id="p-1",
            story_id="s-1",
            customer_id="c-1",
            correlation_id="corr-1",
            outcome=PROutcome.MERGED,
            patch_type=PatchType.IAM_POLICY,
            pre_submit_test_passed=True,
            patch_quality_score=0.85,
        )
        assert record.patch_quality_score == 0.85
        assert record.outcome == PROutcome.MERGED

    def test_defaults(self) -> None:
        record = DevBotQualityRecord(
            pr_id="pr-1",
            patch_id="p-1",
            story_id="s-1",
            customer_id="c-1",
            correlation_id="corr-1",
            outcome=PROutcome.PENDING,
            patch_type=PatchType.EDR_CONFIG,
            pre_submit_test_passed=False,
        )
        assert record.merged_without_change is False
        assert record.rejection_reason == ""
        assert record.patch_quality_score == 0.0


class TestSerializationRoundtrip:
    def test_user_story_roundtrip(self) -> None:
        story = make_user_story(
            cve_refs=["CVE-2024-0001"],
            mitre_attack_ids=["T1059"],
            recommended_patch_types=[PatchType.FIREWALL_RULE, PatchType.EDR_CONFIG],
        )
        data = story.model_dump()
        restored = UserStory.model_validate(data)
        assert restored.story_id == story.story_id
        assert restored.cve_refs == story.cve_refs
        assert restored.recommended_patch_types == story.recommended_patch_types

    def test_patch_candidate_roundtrip(self) -> None:
        patch = make_patch_candidate(rollback_content="iptables -D INPUT ...", language="bash")
        data = patch.model_dump()
        restored = PatchCandidate.model_validate(data)
        assert restored.patch_id == patch.patch_id
        assert restored.rollback_content == patch.rollback_content

    def test_dev_bot_pr_roundtrip(self) -> None:
        pr = DevBotPR(
            patch_id="p-1",
            story_id="s-1",
            customer_id="c-1",
            correlation_id="corr-1",
            github_pr_number=7,
            github_pr_url="https://github.com/x/y/pull/7",
        )
        data = pr.model_dump()
        restored = DevBotPR.model_validate(data)
        assert restored.github_pr_number == pr.github_pr_number
        assert restored.pr_id == pr.pr_id
