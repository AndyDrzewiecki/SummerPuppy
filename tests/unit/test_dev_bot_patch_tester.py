"""Unit tests for PatchTester."""

from __future__ import annotations

import pytest

from summer_puppy.dev_bot.models import PatchCandidate, PatchType
from summer_puppy.dev_bot.patch_tester import PatchTester


def make_valid_patch(**kwargs: object) -> PatchCandidate:
    defaults: dict[str, object] = {
        "story_id": "story-1",
        "customer_id": "cust-1",
        "correlation_id": "corr-1",
        "patch_type": PatchType.FIREWALL_RULE,
        "title": "Block malicious IP",
        "description": "Adds firewall rule to block C2 traffic",
        "content": "iptables -A INPUT -s 10.0.0.1 -j DROP",
        "confidence_score": 0.9,
        "rollback_content": "iptables -D INPUT -s 10.0.0.1 -j DROP",
    }
    defaults.update(kwargs)
    return PatchCandidate(**defaults)  # type: ignore[arg-type]


class TestPatchTesterAllChecksPassing:
    @pytest.mark.asyncio
    async def test_all_checks_pass_for_valid_patch(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch()
        result = await tester.test(patch)
        assert result.passed is True
        assert all(c.passed for c in result.checks)

    @pytest.mark.asyncio
    async def test_returns_correct_patch_id(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch()
        result = await tester.test(patch)
        assert result.patch_id == patch.patch_id

    @pytest.mark.asyncio
    async def test_returns_correct_customer_id(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch()
        result = await tester.test(patch)
        assert result.customer_id == patch.customer_id

    @pytest.mark.asyncio
    async def test_summary_mentions_all_passed(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch()
        result = await tester.test(patch)
        assert "passed" in result.summary.lower() or "ready" in result.summary.lower()


class TestPatchTesterFailures:
    @pytest.mark.asyncio
    async def test_fails_when_content_is_empty(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch(content="")
        result = await tester.test(patch)
        assert result.passed is False
        failed = [c for c in result.checks if not c.passed]
        failed_names = {c.check_name for c in failed}
        assert "content_not_empty" in failed_names or "syntax_valid" in failed_names

    @pytest.mark.asyncio
    async def test_fails_when_content_too_short(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch(content="x")
        result = await tester.test(patch)
        assert result.passed is False
        failed_names = {c.check_name for c in result.checks if not c.passed}
        assert "syntax_valid" in failed_names

    @pytest.mark.asyncio
    async def test_fails_when_rollback_content_empty(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch(rollback_content="")
        result = await tester.test(patch)
        assert result.passed is False
        failed_names = {c.check_name for c in result.checks if not c.passed}
        assert "rollback_available" in failed_names

    @pytest.mark.asyncio
    async def test_fails_when_rollback_content_whitespace_only(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch(rollback_content="   \n   ")
        result = await tester.test(patch)
        assert result.passed is False
        failed_names = {c.check_name for c in result.checks if not c.passed}
        assert "rollback_available" in failed_names

    @pytest.mark.asyncio
    async def test_fails_when_confidence_below_threshold(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch(confidence_score=0.3)
        result = await tester.test(patch)
        assert result.passed is False
        failed_names = {c.check_name for c in result.checks if not c.passed}
        assert "confidence_threshold" in failed_names

    @pytest.mark.asyncio
    async def test_fails_when_confidence_exactly_at_boundary(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch(confidence_score=0.49)
        result = await tester.test(patch)
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_passes_when_confidence_at_threshold(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch(confidence_score=0.5)
        result = await tester.test(patch)
        confidence_check = next(c for c in result.checks if c.check_name == "confidence_threshold")
        assert confidence_check.passed is True

    @pytest.mark.asyncio
    async def test_multiple_failures_all_reported(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch(content="", rollback_content="", confidence_score=0.1)
        result = await tester.test(patch)
        assert result.passed is False
        failed_names = {c.check_name for c in result.checks if not c.passed}
        assert len(failed_names) >= 2


class TestPatchTesterChecks:
    @pytest.mark.asyncio
    async def test_returns_four_checks(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch()
        result = await tester.test(patch)
        assert len(result.checks) == 4

    @pytest.mark.asyncio
    async def test_check_names_are_correct(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch()
        result = await tester.test(patch)
        check_names = {c.check_name for c in result.checks}
        assert check_names == {
            "syntax_valid",
            "content_not_empty",
            "rollback_available",
            "confidence_threshold",
        }

    @pytest.mark.asyncio
    async def test_duration_ms_is_populated(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch()
        result = await tester.test(patch)
        assert result.duration_ms >= 0.0

    @pytest.mark.asyncio
    async def test_summary_contains_failed_check_names_on_failure(self) -> None:
        tester = PatchTester()
        patch = make_valid_patch(rollback_content="")
        result = await tester.test(patch)
        assert "rollback_available" in result.summary
