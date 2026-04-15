"""Skills models, registries, and knowledge base."""

from __future__ import annotations

from summer_puppy.skills.evaluator import RunEvaluator
from summer_puppy.skills.injector import SkillInjector
from summer_puppy.skills.kb import InMemorySkillKnowledgeBase, SkillKnowledgeBase
from summer_puppy.skills.models import (
    ArtifactPromotionDecision,
    ClusterSkillProfile,
    KnowledgeArticle,
    PlaybookTemplate,
    PromotionLevel,
    RunReview,
    SkillProfile,
    TrainingRecommendation,
)
from summer_puppy.skills.promotion import PromotionEngine
from summer_puppy.skills.prompt_enricher import NullPromptEnricher, PromptEnricher
from summer_puppy.skills.registry import InMemorySkillRegistry, SkillRegistry
from summer_puppy.skills.trainer import Trainer
from summer_puppy.trust.models import ActionClass as _ActionClass

# Resolve deferred ActionClass annotation used by PlaybookTemplate.
PlaybookTemplate.model_rebuild(_types_namespace={"ActionClass": _ActionClass})

__all__ = [
    "ArtifactPromotionDecision",
    "ClusterSkillProfile",
    "InMemorySkillKnowledgeBase",
    "InMemorySkillRegistry",
    "KnowledgeArticle",
    "NullPromptEnricher",
    "PlaybookTemplate",
    "PromotionEngine",
    "PromotionLevel",
    "PromptEnricher",
    "RunEvaluator",
    "RunReview",
    "SkillInjector",
    "SkillKnowledgeBase",
    "SkillProfile",
    "SkillRegistry",
    "Trainer",
    "TrainingRecommendation",
]
