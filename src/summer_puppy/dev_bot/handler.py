"""DevBotHandler — out-of-band event subscriber triggering the dev bot pipeline."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from summer_puppy.audit.models import AuditEntry, AuditEntryType
from summer_puppy.channel.models import Topic
from summer_puppy.dev_bot.models import DevBotPR, PROutcome
from summer_puppy.sandbox.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    IndicatorOfCompromise,
    IoCType,
)
from summer_puppy.trust.models import ActionClass

if TYPE_CHECKING:
    from summer_puppy.audit.logger import AuditLogger
    from summer_puppy.channel.bus import EventBus
    from summer_puppy.channel.models import Envelope
    from summer_puppy.dev_bot.patch_generator import PatchGenerator
    from summer_puppy.dev_bot.patch_tester import PatchTester
    from summer_puppy.dev_bot.pr_submitter import PRSubmitter
    from summer_puppy.dev_bot.quality_tracker import DevBotQualityTracker
    from summer_puppy.dev_bot.story_builder import StoryBuilder

_LOG = logging.getLogger(__name__)


def _parse_finding(data: dict[str, Any]) -> Finding:
    """Build a Finding from a raw dict, using sensible defaults."""
    ioc_raw = data.get("ioc_indicators", [])
    iocs: list[IndicatorOfCompromise] = []
    for ioc in ioc_raw:
        try:
            iocs.append(
                IndicatorOfCompromise(
                    ioc_type=IoCType(ioc.get("ioc_type", "domain")),
                    value=ioc.get("value", ""),
                    confidence=float(ioc.get("confidence", 0.5)),
                    context=ioc.get("context", ""),
                )
            )
        except (ValueError, KeyError):
            continue

    return Finding(
        finding_id=data.get("finding_id", ""),
        category=FindingCategory(data.get("category", FindingCategory.VULNERABILITY)),
        severity=FindingSeverity(data.get("severity", FindingSeverity.MEDIUM)),
        title=data.get("title", "Unknown Finding"),
        description=data.get("description", ""),
        mitre_attack_ids=data.get("mitre_attack_ids", []),
        ioc_indicators=iocs,
        affected_assets=data.get("affected_assets", []),
        evidence=data.get("evidence", []),
        recommended_actions=data.get("recommended_actions", []),
        confidence=float(data.get("confidence", 0.5)),
    )


class DevBotHandler:
    """Out-of-band event subscriber that triggers the dev bot pipeline.

    Listens on Topic.ACTION_OUTCOMES. When a completed PATCH_DEPLOYMENT run is found,
    extracts findings from raw_payload, generates user stories, patches, tests, and PRs.
    """

    def __init__(
        self,
        story_builder: StoryBuilder,
        patch_generator: PatchGenerator,
        patch_tester: PatchTester,
        pr_submitter: PRSubmitter,
        quality_tracker: DevBotQualityTracker,
        audit_logger: AuditLogger,
        event_bus: EventBus,
        min_confidence_threshold: float = 0.7,
    ) -> None:
        self._story_builder = story_builder
        self._patch_generator = patch_generator
        self._patch_tester = patch_tester
        self._pr_submitter = pr_submitter
        self._quality_tracker = quality_tracker
        self._audit_logger = audit_logger
        self._event_bus = event_bus
        self._min_confidence_threshold = min_confidence_threshold

        # In-memory state for API queries
        self._stories: list[Any] = []
        self._patches: list[Any] = []
        self._prs: list[DevBotPR] = []

    async def handle_outcome(self, envelope: Envelope) -> list[DevBotPR]:
        """Process an ACTION_OUTCOMES envelope. Returns list of submitted PRs.

        Only triggers when:
        - envelope payload has action_class == PATCH_DEPLOYMENT
        - outcome_success == True
        - confidence_score >= min_confidence_threshold
        - findings exist in raw_payload
        """
        payload = envelope.payload

        action_class = payload.get("action_class", "")
        if action_class != ActionClass.PATCH_DEPLOYMENT:
            return []

        outcome_success = payload.get("outcome_success", False)
        if not outcome_success:
            return []

        confidence_score = float(payload.get("confidence_score", 0.0))
        if confidence_score < self._min_confidence_threshold:
            return []

        raw_payload = payload.get("raw_payload", {})
        findings_data: list[dict[str, Any]] = raw_payload.get("findings", [])
        if not findings_data:
            return []

        customer_id = envelope.customer_id
        correlation_id = envelope.correlation_id or ""

        submitted_prs: list[DevBotPR] = []
        for finding_data in findings_data:
            pr = await self._process_finding(finding_data, customer_id, correlation_id)
            if pr is not None:
                submitted_prs.append(pr)

        return submitted_prs

    async def _process_finding(
        self,
        finding_data: dict[str, Any],
        customer_id: str,
        correlation_id: str,
    ) -> DevBotPR | None:
        """Process a single finding: story → patches → test → PR → quality record."""
        try:
            finding = _parse_finding(finding_data)
        except Exception:
            _LOG.exception("DevBotHandler: failed to parse finding")
            return None

        # Build story
        story = self._story_builder.build(finding, customer_id, correlation_id)
        self._stories.append(story)

        await self._audit_logger.append(
            AuditEntry(
                customer_id=customer_id,
                entry_type=AuditEntryType.DEV_BOT_STORY_CREATED,
                actor="dev_bot",
                correlation_id=correlation_id,
                resource_id=story.story_id,
                resource_type="user_story",
                details={"story_id": story.story_id, "title": story.title},
            )
        )

        # Generate patches
        patches = await self._patch_generator.generate(story)
        if not patches:
            return None

        self._patches.extend(patches)

        await self._audit_logger.append(
            AuditEntry(
                customer_id=customer_id,
                entry_type=AuditEntryType.DEV_BOT_PATCH_GENERATED,
                actor="dev_bot",
                correlation_id=correlation_id,
                resource_id=story.story_id,
                resource_type="patch_batch",
                details={"patch_count": len(patches), "story_id": story.story_id},
            )
        )

        # Test and submit each patch — return the first successful PR
        for patch in patches:
            test_result = await self._patch_tester.test(patch)

            await self._audit_logger.append(
                AuditEntry(
                    customer_id=customer_id,
                    entry_type=AuditEntryType.DEV_BOT_PATCH_TESTED,
                    actor="dev_bot",
                    correlation_id=correlation_id,
                    resource_id=patch.patch_id,
                    resource_type="patch",
                    details={"passed": test_result.passed, "summary": test_result.summary},
                )
            )

            if not test_result.passed:
                continue

            pr = await self._pr_submitter.submit(patch, test_result, story)
            self._prs.append(pr)

            await self._audit_logger.append(
                AuditEntry(
                    customer_id=customer_id,
                    entry_type=AuditEntryType.DEV_BOT_PR_OPENED,
                    actor="dev_bot",
                    correlation_id=correlation_id,
                    resource_id=pr.pr_id,
                    resource_type="pr",
                    details={
                        "pr_id": pr.pr_id,
                        "github_pr_url": pr.github_pr_url,
                        "patch_id": patch.patch_id,
                    },
                )
            )

            # Publish to event bus
            await self._event_bus.publish(
                topic=Topic.DEV_BOT_PR_EVENTS,
                message=pr,
                customer_id=customer_id,
                correlation_id=correlation_id,
            )

            # Record initial quality (outcome is PENDING at this point)
            self._quality_tracker.record_outcome(
                pr=pr,
                patch=patch,
                pre_submit_test_passed=test_result.passed,
                merged_without_change=False,
                rejection_reason="",
            )

            return pr

        return None

    def get_stories(self, customer_id: str | None = None) -> list[Any]:
        """Return stored user stories, optionally filtered by customer_id."""
        if customer_id is None:
            return list(self._stories)
        return [s for s in self._stories if s.customer_id == customer_id]

    def get_patches(self, customer_id: str | None = None) -> list[Any]:
        """Return stored patch candidates, optionally filtered by customer_id."""
        if customer_id is None:
            return list(self._patches)
        return [p for p in self._patches if p.customer_id == customer_id]

    def get_prs(self, customer_id: str | None = None) -> list[DevBotPR]:
        """Return stored PRs, optionally filtered by customer_id."""
        if customer_id is None:
            return list(self._prs)
        return [pr for pr in self._prs if pr.customer_id == customer_id]

    def get_pr_by_id(self, pr_id: str) -> DevBotPR | None:
        """Return a single PR by its ID."""
        for pr in self._prs:
            if pr.pr_id == pr_id:
                return pr
        return None

    def update_pr(self, updated_pr: DevBotPR) -> None:
        """Replace an existing PR record with an updated one."""
        for i, pr in enumerate(self._prs):
            if pr.pr_id == updated_pr.pr_id:
                self._prs[i] = updated_pr
                return
