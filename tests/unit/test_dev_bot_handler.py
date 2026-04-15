"""Tests for DevBotHandler — Phase 11, Sprint 11."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from summer_puppy.audit.models import AuditEntryType
from summer_puppy.channel.models import Envelope, Topic
from summer_puppy.dev_bot.models import (
    DevBotPR,
    PatchCandidate,
    PatchStatus,
    PatchTestResult,
    PatchType,
    PROutcome,
    UserStory,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_envelope(
    *,
    action_class: str = "patch_deployment",
    outcome_success: bool = True,
    confidence_score: float = 0.9,
    findings: list[dict] | None = None,
    customer_id: str = "cust-1",
    correlation_id: str = "corr-1",
) -> Envelope:
    raw_payload = {}
    if findings is not None:
        raw_payload["findings"] = findings

    return Envelope(
        topic=Topic.ACTION_OUTCOMES,
        customer_id=customer_id,
        correlation_id=correlation_id,
        payload_type="test.Payload",
        payload={
            "action_class": action_class,
            "outcome_success": outcome_success,
            "confidence_score": confidence_score,
            "raw_payload": raw_payload,
        },
    )


def _make_finding_dict(
    finding_id: str = "finding-001",
    severity: str = "high",
    category: str = "vulnerability",
) -> dict:
    return {
        "finding_id": finding_id,
        "category": category,
        "severity": severity,
        "title": "Test vulnerability",
        "description": "A test security finding",
        "affected_assets": ["server-1"],
        "mitre_attack_ids": [],
        "ioc_indicators": [],
        "evidence": [],
        "recommended_actions": [],
        "confidence": 0.8,
    }


def _make_story(customer_id: str = "cust-1") -> UserStory:
    from summer_puppy.sandbox.models import FindingSeverity

    return UserStory(
        finding_id="finding-001",
        customer_id=customer_id,
        correlation_id="corr-1",
        title="[HIGH] Remediate: Test vulnerability",
        description="Fix this",
        severity=FindingSeverity.HIGH,
    )


def _make_patch(
    customer_id: str = "cust-1",
    patch_id: str = "patch-001",
    confidence: float = 0.9,
) -> PatchCandidate:
    return PatchCandidate(
        patch_id=patch_id,
        story_id="story-001",
        customer_id=customer_id,
        correlation_id="corr-1",
        patch_type=PatchType.FIREWALL_RULE,
        title="Block malicious IP",
        description="Add firewall rule",
        content="iptables -A INPUT -s 1.2.3.4 -j DROP",
        rollback_content="iptables -D INPUT -s 1.2.3.4 -j DROP",
        confidence_score=confidence,
    )


def _make_test_result(patch_id: str = "patch-001", passed: bool = True) -> PatchTestResult:
    return PatchTestResult(
        patch_id=patch_id,
        customer_id="cust-1",
        passed=passed,
        summary="All checks passed." if passed else "Checks failed.",
    )


def _make_pr(
    pr_id: str = "pr-001",
    customer_id: str = "cust-1",
    patch_id: str = "patch-001",
) -> DevBotPR:
    return DevBotPR(
        pr_id=pr_id,
        patch_id=patch_id,
        story_id="story-001",
        customer_id=customer_id,
        correlation_id="corr-1",
        status=PatchStatus.PR_OPEN,
        outcome=PROutcome.PENDING,
        github_pr_url="https://github.com/test/repo/pull/1",
        github_pr_number=1,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_logger():
    logger = MagicMock()
    logger.append = AsyncMock()
    return logger


@pytest.fixture
def event_bus():
    bus = MagicMock()
    bus.publish = AsyncMock()
    return bus


@pytest.fixture
def quality_tracker():
    qt = MagicMock()
    qt.record_outcome = MagicMock(return_value=MagicMock())
    return qt


@pytest.fixture
def story_builder():
    builder = MagicMock()
    builder.build = MagicMock(return_value=_make_story())
    return builder


@pytest.fixture
def patch_generator():
    gen = MagicMock()
    gen.generate = AsyncMock(return_value=[_make_patch()])
    return gen


@pytest.fixture
def patch_tester():
    tester = MagicMock()
    tester.test = AsyncMock(return_value=_make_test_result(passed=True))
    return tester


@pytest.fixture
def pr_submitter():
    submitter = MagicMock()
    submitter.submit = AsyncMock(return_value=_make_pr())
    return submitter


@pytest.fixture
def handler(
    story_builder,
    patch_generator,
    patch_tester,
    pr_submitter,
    quality_tracker,
    audit_logger,
    event_bus,
):
    from summer_puppy.dev_bot.handler import DevBotHandler

    return DevBotHandler(
        story_builder=story_builder,
        patch_generator=patch_generator,
        patch_tester=patch_tester,
        pr_submitter=pr_submitter,
        quality_tracker=quality_tracker,
        audit_logger=audit_logger,
        event_bus=event_bus,
        min_confidence_threshold=0.7,
    )


# ---------------------------------------------------------------------------
# Gate checks
# ---------------------------------------------------------------------------


class TestHandleOutcomeGates:
    async def test_ignores_non_patch_deployment_action_class(self, handler) -> None:
        envelope = _make_envelope(action_class="network_isolation",
                                   findings=[_make_finding_dict()])
        result = await handler.handle_outcome(envelope)
        assert result == []

    async def test_ignores_failed_outcomes(self, handler) -> None:
        envelope = _make_envelope(outcome_success=False,
                                   findings=[_make_finding_dict()])
        result = await handler.handle_outcome(envelope)
        assert result == []

    async def test_ignores_below_threshold_confidence(self, handler) -> None:
        envelope = _make_envelope(confidence_score=0.5,
                                   findings=[_make_finding_dict()])
        result = await handler.handle_outcome(envelope)
        assert result == []

    async def test_ignores_at_exactly_below_threshold(self, handler) -> None:
        # Default threshold is 0.7; 0.69 should be excluded
        envelope = _make_envelope(confidence_score=0.69,
                                   findings=[_make_finding_dict()])
        result = await handler.handle_outcome(envelope)
        assert result == []

    async def test_ignores_missing_findings(self, handler) -> None:
        envelope = _make_envelope(findings=None)
        result = await handler.handle_outcome(envelope)
        assert result == []

    async def test_ignores_empty_findings_list(self, handler) -> None:
        envelope = _make_envelope(findings=[])
        result = await handler.handle_outcome(envelope)
        assert result == []


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------


class TestHandleOutcomeFullPipeline:
    async def test_triggers_pipeline_for_valid_envelope(self, handler) -> None:
        envelope = _make_envelope(findings=[_make_finding_dict()])
        result = await handler.handle_outcome(envelope)
        assert len(result) == 1
        assert isinstance(result[0], DevBotPR)

    async def test_calls_story_builder(self, handler, story_builder) -> None:
        envelope = _make_envelope(findings=[_make_finding_dict()])
        await handler.handle_outcome(envelope)
        story_builder.build.assert_called_once()

    async def test_calls_patch_generator(self, handler, patch_generator) -> None:
        envelope = _make_envelope(findings=[_make_finding_dict()])
        await handler.handle_outcome(envelope)
        patch_generator.generate.assert_called_once()

    async def test_calls_patch_tester(self, handler, patch_tester) -> None:
        envelope = _make_envelope(findings=[_make_finding_dict()])
        await handler.handle_outcome(envelope)
        patch_tester.test.assert_called_once()

    async def test_calls_pr_submitter(self, handler, pr_submitter) -> None:
        envelope = _make_envelope(findings=[_make_finding_dict()])
        await handler.handle_outcome(envelope)
        pr_submitter.submit.assert_called_once()

    async def test_audit_logs_story_creation(self, handler, audit_logger) -> None:
        envelope = _make_envelope(findings=[_make_finding_dict()])
        await handler.handle_outcome(envelope)
        entry_types = [
            call.args[0].entry_type for call in audit_logger.append.call_args_list
        ]
        assert AuditEntryType.DEV_BOT_STORY_CREATED in entry_types

    async def test_audit_logs_patch_generated(self, handler, audit_logger) -> None:
        envelope = _make_envelope(findings=[_make_finding_dict()])
        await handler.handle_outcome(envelope)
        entry_types = [
            call.args[0].entry_type for call in audit_logger.append.call_args_list
        ]
        assert AuditEntryType.DEV_BOT_PATCH_GENERATED in entry_types

    async def test_audit_logs_patch_tested(self, handler, audit_logger) -> None:
        envelope = _make_envelope(findings=[_make_finding_dict()])
        await handler.handle_outcome(envelope)
        entry_types = [
            call.args[0].entry_type for call in audit_logger.append.call_args_list
        ]
        assert AuditEntryType.DEV_BOT_PATCH_TESTED in entry_types

    async def test_audit_logs_pr_opened(self, handler, audit_logger) -> None:
        envelope = _make_envelope(findings=[_make_finding_dict()])
        await handler.handle_outcome(envelope)
        entry_types = [
            call.args[0].entry_type for call in audit_logger.append.call_args_list
        ]
        assert AuditEntryType.DEV_BOT_PR_OPENED in entry_types

    async def test_publishes_pr_to_event_bus(self, handler, event_bus) -> None:
        envelope = _make_envelope(findings=[_make_finding_dict()])
        await handler.handle_outcome(envelope)
        event_bus.publish.assert_called_once()
        call_kwargs = event_bus.publish.call_args
        assert call_kwargs.kwargs.get("topic") == Topic.DEV_BOT_PR_EVENTS or \
               call_kwargs.args[0] == Topic.DEV_BOT_PR_EVENTS

    async def test_processes_multiple_findings(
        self, handler, story_builder, patch_generator, pr_submitter
    ) -> None:
        pr2 = _make_pr(pr_id="pr-002", patch_id="patch-002")
        pr_submitter.submit = AsyncMock(side_effect=[_make_pr(), pr2])
        story_builder.build = MagicMock(side_effect=[_make_story(), _make_story()])
        patch_generator.generate = AsyncMock(side_effect=[[_make_patch()], [_make_patch()]])

        findings = [_make_finding_dict("f1"), _make_finding_dict("f2")]
        envelope = _make_envelope(findings=findings)
        result = await handler.handle_outcome(envelope)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# _process_finding returns None when test fails
# ---------------------------------------------------------------------------


class TestProcessFindingFailedTest:
    async def test_returns_none_when_patch_test_fails(
        self, handler, patch_tester
    ) -> None:
        patch_tester.test = AsyncMock(return_value=_make_test_result(passed=False))
        result = await handler._process_finding(
            _make_finding_dict(), customer_id="cust-1", correlation_id="corr-1"
        )
        assert result is None

    async def test_does_not_submit_pr_when_test_fails(
        self, handler, patch_tester, pr_submitter
    ) -> None:
        patch_tester.test = AsyncMock(return_value=_make_test_result(passed=False))
        await handler._process_finding(
            _make_finding_dict(), customer_id="cust-1", correlation_id="corr-1"
        )
        pr_submitter.submit.assert_not_called()

    async def test_returns_none_when_no_patches_generated(
        self, handler, patch_generator
    ) -> None:
        patch_generator.generate = AsyncMock(return_value=[])
        result = await handler._process_finding(
            _make_finding_dict(), customer_id="cust-1", correlation_id="corr-1"
        )
        assert result is None
