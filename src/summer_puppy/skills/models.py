"""Skill tracking models: profiles, knowledge articles, playbooks, and reviews."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from summer_puppy.trust.models import ActionClass  # noqa: TC001


class PromotionLevel(StrEnum):
    DISCARD = "discard"
    RUN_RECORD = "run_record"
    TEAM_KB = "team_kb"
    GLOBAL_KB = "global_kb"
    PLAYBOOK_TEMPLATE = "playbook_template"


class SkillProfile(BaseModel):
    agent_id: str
    customer_id: str
    total_runs: int = 0
    successful_runs: int = 0
    failed_runs: int = 0
    human_override_count: int = 0
    qa_pass_rate: float = Field(default=0.0, ge=0, le=1)
    confidence_by_task_type: dict[str, float] = Field(default_factory=dict)
    last_updated_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class ClusterSkillProfile(BaseModel):
    cluster_id: str
    customer_id: str
    total_runs: int = 0
    successful_runs: int = 0
    failed_runs: int = 0
    human_override_count: int = 0
    qa_pass_rate: float = Field(default=0.0, ge=0, le=1)
    routing_weight: float = Field(default=1.0, ge=0)
    last_updated_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class KnowledgeArticle(BaseModel):
    article_id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str
    title: str
    content: str
    tags: list[str] = Field(default_factory=list)
    source_run_id: str | None = None
    promotion_level: PromotionLevel = PromotionLevel.RUN_RECORD
    version: int = 1
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    deprecated_utc: datetime | None = None


class PlaybookTemplate(BaseModel):
    template_id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str
    action_class: ActionClass
    name: str
    steps: list[str] = Field(default_factory=list)
    source_article_id: str | None = None
    version: int = 1
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class RunReview(BaseModel):
    review_id: str = Field(default_factory=lambda: str(uuid4()))
    correlation_id: str
    customer_id: str
    recommendation_quality: float = Field(ge=0, le=1)
    execution_safety: float = Field(ge=0, le=1)
    outcome_success: bool = False
    qa_reliability: float = Field(ge=0, le=1)
    human_override: bool = False
    reviewed_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class TrainingRecommendation(BaseModel):
    recommendation_id: str = Field(default_factory=lambda: str(uuid4()))
    review_id: str
    skill_updates: dict[str, Any] = Field(default_factory=dict)
    kb_promotions: list[str] = Field(default_factory=list)
    trust_adjustments: dict[str, Any] = Field(default_factory=dict)


class ArtifactPromotionDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    artifact_id: str
    source_run_id: str
    promotion_level: PromotionLevel
    reason: str
    decided_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
