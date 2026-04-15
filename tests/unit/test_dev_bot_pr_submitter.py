"""Unit tests for PRSubmitter."""

from __future__ import annotations

import pytest

from summer_puppy.dev_bot.github_client import StubGitHubClient
from summer_puppy.dev_bot.models import (
    PatchCandidate,
    PatchStatus,
    PatchTestCheck,
    PatchTestResult,
    PatchType,
    PROutcome,
    UserStory,
)
from summer_puppy.dev_bot.pr_submitter import PRSubmitter
from summer_puppy.sandbox.models import FindingSeverity


def make_story(**kwargs: object) -> UserStory:
    defaults: dict[str, object] = {
        "finding_id": "f-1",
        "customer_id": "cust-1",
        "correlation_id": "corr-1",
        "title": "Remediate CVE-2024-1234",
        "description": "As a security engineer, I need to remediate this finding.",
        "severity": FindingSeverity.HIGH,
        "acceptance_criteria": [
            "Threat is remediated",
            "Rollback is documented",
        ],
    }
    defaults.update(kwargs)
    return UserStory(**defaults)  # type: ignore[arg-type]


def make_patch(**kwargs: object) -> PatchCandidate:
    defaults: dict[str, object] = {
        "story_id": "story-1",
        "customer_id": "cust-1",
        "correlation_id": "corr-1",
        "patch_type": PatchType.FIREWALL_RULE,
        "title": "Block malicious C2 traffic",
        "description": "Adds firewall rule",
        "content": "iptables -A INPUT -s 10.0.0.1 -j DROP",
        "confidence_score": 0.9,
        "rollback_content": "iptables -D INPUT -s 10.0.0.1 -j DROP",
    }
    defaults.update(kwargs)
    return PatchCandidate(**defaults)  # type: ignore[arg-type]


def make_passed_test_result(patch: PatchCandidate) -> PatchTestResult:
    return PatchTestResult(
        patch_id=patch.patch_id,
        customer_id=patch.customer_id,
        passed=True,
        checks=[
            PatchTestCheck(check_name="syntax_valid", passed=True),
            PatchTestCheck(check_name="content_not_empty", passed=True),
            PatchTestCheck(check_name="rollback_available", passed=True, detail="Present"),
            PatchTestCheck(check_name="confidence_threshold", passed=True),
        ],
        summary="All checks passed.",
    )


def make_failed_test_result(patch: PatchCandidate) -> PatchTestResult:
    return PatchTestResult(
        patch_id=patch.patch_id,
        customer_id=patch.customer_id,
        passed=False,
        checks=[
            PatchTestCheck(check_name="rollback_available", passed=False, detail="Missing"),
        ],
        summary="Patch failed checks: rollback_available.",
    )


class TestPRSubmitterSuccess:
    @pytest.mark.asyncio
    async def test_submit_creates_pr_when_test_passed(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch()
        test_result = make_passed_test_result(patch)
        story = make_story()

        pr = await submitter.submit(patch, test_result, story)

        assert pr.github_pr_number is not None
        assert pr.github_pr_url is not None
        assert pr.status == PatchStatus.PR_OPEN
        assert pr.outcome == PROutcome.PENDING

    @pytest.mark.asyncio
    async def test_branch_name_format_uses_patch_id_prefix(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch()
        test_result = make_passed_test_result(patch)
        story = make_story()

        pr = await submitter.submit(patch, test_result, story)

        expected_branch = f"sumpy/patch/{patch.patch_id[:8]}"
        assert pr.branch_name == expected_branch
        assert stub.branches_created[0]["branch"] == expected_branch

    @pytest.mark.asyncio
    async def test_pr_title_format(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch(title="Block C2 traffic")
        test_result = make_passed_test_result(patch)
        story = make_story()

        pr = await submitter.submit(patch, test_result, story)

        assert pr.pr_title == "[SummerPuppy] Block C2 traffic"
        assert stub.prs_created[0]["title"] == "[SummerPuppy] Block C2 traffic"

    @pytest.mark.asyncio
    async def test_pr_body_contains_acceptance_criteria(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch()
        test_result = make_passed_test_result(patch)
        story = make_story(acceptance_criteria=["Threat is remediated", "No regression"])

        pr = await submitter.submit(patch, test_result, story)

        assert "Threat is remediated" in pr.pr_body
        assert "No regression" in pr.pr_body

    @pytest.mark.asyncio
    async def test_pr_body_contains_story_description(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch()
        test_result = make_passed_test_result(patch)
        story = make_story(description="As a security engineer, this is critical.")

        pr = await submitter.submit(patch, test_result, story)

        assert "As a security engineer" in pr.pr_body

    @pytest.mark.asyncio
    async def test_pr_body_contains_test_result_summary(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch()
        test_result = make_passed_test_result(patch)
        story = make_story()

        pr = await submitter.submit(patch, test_result, story)

        assert "All checks passed" in pr.pr_body

    @pytest.mark.asyncio
    async def test_pr_body_contains_rollback_instructions(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch(rollback_content="iptables -D INPUT -s 10.0.0.1 -j DROP")
        test_result = make_passed_test_result(patch)
        story = make_story()

        pr = await submitter.submit(patch, test_result, story)

        assert "iptables -D INPUT" in pr.pr_body

    @pytest.mark.asyncio
    async def test_submit_creates_branch_and_file(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch()
        test_result = make_passed_test_result(patch)
        story = make_story()

        await submitter.submit(patch, test_result, story)

        assert len(stub.branches_created) == 1
        assert len(stub.files_created) == 1
        assert len(stub.prs_created) == 1

    @pytest.mark.asyncio
    async def test_pr_linked_to_patch_and_story(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch()
        test_result = make_passed_test_result(patch)
        story = make_story()

        pr = await submitter.submit(patch, test_result, story)

        assert pr.patch_id == patch.patch_id
        assert pr.story_id == story.story_id
        assert pr.customer_id == patch.customer_id


class TestPRSubmitterFailure:
    @pytest.mark.asyncio
    async def test_returns_abandoned_pr_when_test_failed(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch()
        test_result = make_failed_test_result(patch)
        story = make_story()

        pr = await submitter.submit(patch, test_result, story)

        assert pr.status == PatchStatus.ABANDONED
        assert pr.outcome == PROutcome.REJECTED

    @pytest.mark.asyncio
    async def test_no_github_calls_when_test_failed(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch()
        test_result = make_failed_test_result(patch)
        story = make_story()

        await submitter.submit(patch, test_result, story)

        assert len(stub.branches_created) == 0
        assert len(stub.files_created) == 0
        assert len(stub.prs_created) == 0

    @pytest.mark.asyncio
    async def test_abandoned_pr_has_no_pr_number(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch()
        test_result = make_failed_test_result(patch)
        story = make_story()

        pr = await submitter.submit(patch, test_result, story)

        assert pr.github_pr_number is None
        assert pr.github_pr_url is None

    @pytest.mark.asyncio
    async def test_abandoned_pr_has_review_notes(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo")
        patch = make_patch()
        test_result = make_failed_test_result(patch)
        story = make_story()

        pr = await submitter.submit(patch, test_result, story)

        assert len(pr.review_notes) > 0


class TestPRSubmitterConfig:
    @pytest.mark.asyncio
    async def test_uses_default_repo(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="myorg/myrepo")
        patch = make_patch()
        test_result = make_passed_test_result(patch)
        story = make_story()

        pr = await submitter.submit(patch, test_result, story)

        assert pr.github_repo == "myorg/myrepo"
        assert stub.branches_created[0]["repo"] == "myorg/myrepo"

    @pytest.mark.asyncio
    async def test_uses_default_base_branch(self) -> None:
        stub = StubGitHubClient()
        submitter = PRSubmitter(stub, default_repo="org/repo", default_base_branch="develop")
        patch = make_patch()
        test_result = make_passed_test_result(patch)
        story = make_story()

        await submitter.submit(patch, test_result, story)

        assert stub.branches_created[0]["base_branch"] == "develop"
        assert stub.prs_created[0]["base_branch"] == "develop"
