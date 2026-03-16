"""Trainer — orchestrates run evaluation, artifact promotion, and skill updates."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from summer_puppy.skills.models import (
    KnowledgeArticle,
    PlaybookTemplate,
    PromotionLevel,
    SkillProfile,
    TrainingRecommendation,
)
from summer_puppy.trust.models import ActionClass

if TYPE_CHECKING:
    from summer_puppy.audit.logger import AuditLogger
    from summer_puppy.skills.evaluator import RunEvaluator
    from summer_puppy.skills.kb import SkillKnowledgeBase
    from summer_puppy.skills.promotion import PromotionEngine
    from summer_puppy.skills.registry import SkillRegistry


class Trainer:
    """Orchestrates run evaluation, skill-profile updates, and KB promotion."""

    def __init__(
        self,
        evaluator: RunEvaluator,
        promotion_engine: PromotionEngine,
        skill_registry: SkillRegistry,
        knowledge_base: SkillKnowledgeBase,
        audit_logger: AuditLogger,
    ) -> None:
        self._evaluator = evaluator
        self._promotion_engine = promotion_engine
        self._skill_registry = skill_registry
        self._knowledge_base = knowledge_base
        self._audit_logger = audit_logger

    async def review_and_train(
        self,
        context_summary: dict[str, Any],
        artifacts: list[dict[str, Any]],
    ) -> TrainingRecommendation:
        """Evaluate a run, update the skill profile, and promote artifacts."""

        # 1. Evaluate the run
        run_review = self._evaluator.evaluate(context_summary)

        # 2. Classify artifacts for promotion
        decisions = self._promotion_engine.classify_artifacts(artifacts, run_review)

        # 3. Update skill profile in registry
        agent_id: str = context_summary.get("agent_id", "default")
        customer_id: str = context_summary.get("customer_id", "")

        profile = self._skill_registry.get_agent_profile(agent_id)
        if profile is None:
            profile = SkillProfile(agent_id=agent_id, customer_id=customer_id)

        profile.total_runs += 1
        if run_review.outcome_success:
            profile.successful_runs += 1
        else:
            profile.failed_runs += 1
        if run_review.human_override:
            profile.human_override_count += 1

        profile.qa_pass_rate = (
            profile.successful_runs / profile.total_runs if profile.total_runs > 0 else 0.0
        )
        profile.last_updated_utc = datetime.now(tz=UTC)

        self._skill_registry.update_agent_profile(profile)

        # 4. Promote artifacts to knowledge base
        artifact_map: dict[str, dict[str, Any]] = {a["artifact_id"]: a for a in artifacts}
        correlation_id: str = context_summary.get("correlation_id", "")

        for decision in decisions:
            if decision.promotion_level in (PromotionLevel.TEAM_KB, PromotionLevel.GLOBAL_KB):
                artifact = artifact_map[decision.artifact_id]
                article = KnowledgeArticle(
                    customer_id=customer_id,
                    title=f"KB from {decision.artifact_id}",
                    content=artifact.get("content", ""),
                    promotion_level=decision.promotion_level,
                    source_run_id=correlation_id,
                )
                self._knowledge_base.store_article(article)
            elif decision.promotion_level == PromotionLevel.PLAYBOOK_TEMPLATE:
                artifact = artifact_map[decision.artifact_id]
                playbook = PlaybookTemplate(
                    customer_id=customer_id,
                    action_class=ActionClass(artifact.get("action_class", "patch_deployment")),
                    name=f"Playbook from {decision.artifact_id}",
                    steps=[artifact.get("content", "")],
                )
                self._knowledge_base.store_playbook(playbook)

        # 5. Build and return TrainingRecommendation
        promoted_levels = frozenset(
            {
                PromotionLevel.TEAM_KB,
                PromotionLevel.GLOBAL_KB,
                PromotionLevel.PLAYBOOK_TEMPLATE,
            }
        )
        kb_promotions = [d.artifact_id for d in decisions if d.promotion_level in promoted_levels]

        return TrainingRecommendation(
            review_id=run_review.review_id,
            skill_updates={
                "agent_id": agent_id,
                "total_runs": profile.total_runs,
                "successful_runs": profile.successful_runs,
                "failed_runs": profile.failed_runs,
                "human_override_count": profile.human_override_count,
                "qa_pass_rate": profile.qa_pass_rate,
            },
            kb_promotions=kb_promotions,
            trust_adjustments={},
        )
