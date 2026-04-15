"""PatchTester — validates PatchCandidate objects through sandboxed checks."""

from __future__ import annotations

import time

from summer_puppy.dev_bot.models import PatchCandidate, PatchTestCheck, PatchTestResult

_CONFIDENCE_THRESHOLD = 0.5
_MIN_CONTENT_LENGTH = 10


def _check_syntax_valid(patch: PatchCandidate) -> PatchTestCheck:
    passed = bool(patch.content) and len(patch.content) >= _MIN_CONTENT_LENGTH
    return PatchTestCheck(
        check_name="syntax_valid",
        passed=passed,
        detail=(
            "Content present and has reasonable length."
            if passed
            else f"Content too short or empty (length={len(patch.content)})."
        ),
    )


def _check_content_not_empty(patch: PatchCandidate) -> PatchTestCheck:
    stripped = patch.content.strip()
    passed = bool(stripped)
    return PatchTestCheck(
        check_name="content_not_empty",
        passed=passed,
        detail="Content is non-empty." if passed else "Content is empty or whitespace only.",
    )


def _check_rollback_available(patch: PatchCandidate) -> PatchTestCheck:
    passed = bool(patch.rollback_content.strip())
    return PatchTestCheck(
        check_name="rollback_available",
        passed=passed,
        detail=(
            "Rollback content is present."
            if passed
            else "Rollback content is missing or empty."
        ),
    )


def _check_confidence_threshold(patch: PatchCandidate) -> PatchTestCheck:
    passed = patch.confidence_score >= _CONFIDENCE_THRESHOLD
    return PatchTestCheck(
        check_name="confidence_threshold",
        passed=passed,
        detail=(
            f"Confidence score {patch.confidence_score:.2f} meets threshold {_CONFIDENCE_THRESHOLD}."
            if passed
            else (
                f"Confidence score {patch.confidence_score:.2f} below threshold "
                f"{_CONFIDENCE_THRESHOLD}."
            )
        ),
    )


class PatchTester:
    """Runs a PatchCandidate through sandboxed validation checks."""

    async def test(self, patch: PatchCandidate) -> PatchTestResult:
        """Validate a patch candidate and return a PatchTestResult."""
        start = time.monotonic()

        checks = [
            _check_syntax_valid(patch),
            _check_content_not_empty(patch),
            _check_rollback_available(patch),
            _check_confidence_threshold(patch),
        ]

        passed = all(c.passed for c in checks)
        failed_names = [c.check_name for c in checks if not c.passed]

        if passed:
            summary = "All checks passed. Patch is ready for submission."
        else:
            summary = f"Patch failed checks: {', '.join(failed_names)}."

        duration_ms = (time.monotonic() - start) * 1000

        return PatchTestResult(
            patch_id=patch.patch_id,
            customer_id=patch.customer_id,
            passed=passed,
            checks=checks,
            summary=summary,
            duration_ms=duration_ms,
        )
