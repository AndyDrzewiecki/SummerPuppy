from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

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
from summer_puppy.skills.registry import InMemorySkillRegistry, SkillRegistry
from summer_puppy.trust.models import ActionClass

# ---------------------------------------------------------------------------
# PromotionLevel enum tests
# ---------------------------------------------------------------------------


class TestPromotionLevel:
    def test_enum_values(self) -> None:
        assert PromotionLevel.DISCARD == "discard"
        assert PromotionLevel.RUN_RECORD == "run_record"
        assert PromotionLevel.TEAM_KB == "team_kb"
        assert PromotionLevel.GLOBAL_KB == "global_kb"
        assert PromotionLevel.PLAYBOOK_TEMPLATE == "playbook_template"

    def test_member_count(self) -> None:
        assert len(PromotionLevel) == 5


# ---------------------------------------------------------------------------
# SkillProfile tests
# ---------------------------------------------------------------------------


class TestSkillProfile:
    def test_minimal_creation(self) -> None:
        sp = SkillProfile(agent_id="agent-1", customer_id="cust-1")
        assert sp.agent_id == "agent-1"
        assert sp.customer_id == "cust-1"
        assert sp.total_runs == 0
        assert sp.successful_runs == 0
        assert sp.failed_runs == 0
        assert sp.human_override_count == 0
        assert sp.qa_pass_rate == 0.0
        assert sp.confidence_by_task_type == {}
        assert isinstance(sp.last_updated_utc, datetime)

    def test_all_fields(self) -> None:
        now = datetime(2026, 3, 16, 10, 0, 0, tzinfo=UTC)
        sp = SkillProfile(
            agent_id="agent-2",
            customer_id="cust-2",
            total_runs=100,
            successful_runs=90,
            failed_runs=10,
            human_override_count=5,
            qa_pass_rate=0.85,
            confidence_by_task_type={"threat_analysis": 0.9, "patch_deploy": 0.7},
            last_updated_utc=now,
        )
        assert sp.total_runs == 100
        assert sp.successful_runs == 90
        assert sp.failed_runs == 10
        assert sp.human_override_count == 5
        assert sp.qa_pass_rate == 0.85
        assert sp.confidence_by_task_type == {"threat_analysis": 0.9, "patch_deploy": 0.7}
        assert sp.last_updated_utc == now

    def test_qa_pass_rate_too_high(self) -> None:
        with pytest.raises(ValidationError):
            SkillProfile(agent_id="a", customer_id="c", qa_pass_rate=1.1)

    def test_qa_pass_rate_too_low(self) -> None:
        with pytest.raises(ValidationError):
            SkillProfile(agent_id="a", customer_id="c", qa_pass_rate=-0.1)

    def test_qa_pass_rate_boundary_zero(self) -> None:
        sp = SkillProfile(agent_id="a", customer_id="c", qa_pass_rate=0.0)
        assert sp.qa_pass_rate == 0.0

    def test_qa_pass_rate_boundary_one(self) -> None:
        sp = SkillProfile(agent_id="a", customer_id="c", qa_pass_rate=1.0)
        assert sp.qa_pass_rate == 1.0

    def test_unique_default_timestamps(self) -> None:
        sp1 = SkillProfile(agent_id="a", customer_id="c")
        time.sleep(0.001)
        sp2 = SkillProfile(agent_id="a", customer_id="c")
        assert sp1.last_updated_utc != sp2.last_updated_utc


# ---------------------------------------------------------------------------
# ClusterSkillProfile tests
# ---------------------------------------------------------------------------


class TestClusterSkillProfile:
    def test_minimal_creation(self) -> None:
        csp = ClusterSkillProfile(cluster_id="cluster-1", customer_id="cust-1")
        assert csp.cluster_id == "cluster-1"
        assert csp.customer_id == "cust-1"
        assert csp.total_runs == 0
        assert csp.successful_runs == 0
        assert csp.failed_runs == 0
        assert csp.human_override_count == 0
        assert csp.qa_pass_rate == 0.0
        assert csp.routing_weight == 1.0
        assert isinstance(csp.last_updated_utc, datetime)

    def test_routing_weight_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ClusterSkillProfile(cluster_id="c", customer_id="cust", routing_weight=-0.1)

    def test_routing_weight_zero_accepted(self) -> None:
        csp = ClusterSkillProfile(cluster_id="c", customer_id="cust", routing_weight=0.0)
        assert csp.routing_weight == 0.0


# ---------------------------------------------------------------------------
# KnowledgeArticle tests
# ---------------------------------------------------------------------------


class TestKnowledgeArticle:
    def test_minimal_creation(self) -> None:
        ka = KnowledgeArticle(
            customer_id="cust-1",
            title="How to patch CVE-2025-1234",
            content="Step 1: ...",
        )
        assert ka.article_id  # auto-generated uuid
        assert ka.customer_id == "cust-1"
        assert ka.title == "How to patch CVE-2025-1234"
        assert ka.content == "Step 1: ..."
        assert ka.tags == []
        assert ka.source_run_id is None
        assert ka.promotion_level == PromotionLevel.RUN_RECORD
        assert ka.version == 1
        assert isinstance(ka.created_utc, datetime)
        assert ka.deprecated_utc is None

    def test_promotion_level_default(self) -> None:
        ka = KnowledgeArticle(customer_id="c", title="t", content="c")
        assert ka.promotion_level == PromotionLevel.RUN_RECORD

    def test_serialization_round_trip(self) -> None:
        ka = KnowledgeArticle(
            customer_id="cust-1",
            title="Article Title",
            content="Body text",
            tags=["security", "patch"],
            source_run_id="run-42",
            promotion_level=PromotionLevel.TEAM_KB,
            version=3,
        )
        data = ka.model_dump()
        restored = KnowledgeArticle.model_validate(data)
        assert restored.article_id == ka.article_id
        assert restored.title == ka.title
        assert restored.tags == ka.tags
        assert restored.promotion_level == PromotionLevel.TEAM_KB
        assert restored.version == 3


# ---------------------------------------------------------------------------
# PlaybookTemplate tests
# ---------------------------------------------------------------------------


class TestPlaybookTemplate:
    def test_minimal_creation(self) -> None:
        pt = PlaybookTemplate(
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            name="Patch Playbook",
        )
        assert pt.template_id  # auto-generated uuid
        assert pt.customer_id == "cust-1"
        assert pt.action_class == ActionClass.PATCH_DEPLOYMENT
        assert pt.name == "Patch Playbook"
        assert pt.steps == []
        assert pt.source_article_id is None
        assert pt.version == 1
        assert isinstance(pt.created_utc, datetime)

    def test_all_fields(self) -> None:
        now = datetime(2026, 3, 16, 12, 0, 0, tzinfo=UTC)
        pt = PlaybookTemplate(
            template_id="tmpl-custom",
            customer_id="cust-2",
            action_class=ActionClass.NETWORK_ISOLATION,
            name="Isolation Playbook",
            steps=["Identify host", "Isolate segment", "Verify"],
            source_article_id="art-99",
            version=2,
            created_utc=now,
        )
        assert pt.template_id == "tmpl-custom"
        assert pt.action_class == ActionClass.NETWORK_ISOLATION
        assert pt.steps == ["Identify host", "Isolate segment", "Verify"]
        assert pt.source_article_id == "art-99"
        assert pt.version == 2
        assert pt.created_utc == now


# ---------------------------------------------------------------------------
# RunReview tests
# ---------------------------------------------------------------------------


class TestRunReview:
    def test_minimal_creation(self) -> None:
        rr = RunReview(
            correlation_id="corr-1",
            customer_id="cust-1",
            recommendation_quality=0.8,
            execution_safety=0.9,
            qa_reliability=0.75,
        )
        assert rr.review_id  # auto-generated uuid
        assert rr.correlation_id == "corr-1"
        assert rr.customer_id == "cust-1"
        assert rr.recommendation_quality == 0.8
        assert rr.execution_safety == 0.9
        assert rr.outcome_success is False
        assert rr.qa_reliability == 0.75
        assert rr.human_override is False
        assert isinstance(rr.reviewed_utc, datetime)

    def test_all_fields(self) -> None:
        now = datetime(2026, 3, 16, 14, 0, 0, tzinfo=UTC)
        rr = RunReview(
            review_id="rev-custom",
            correlation_id="corr-2",
            customer_id="cust-2",
            recommendation_quality=0.95,
            execution_safety=0.99,
            outcome_success=True,
            qa_reliability=0.88,
            human_override=True,
            reviewed_utc=now,
        )
        assert rr.review_id == "rev-custom"
        assert rr.outcome_success is True
        assert rr.human_override is True
        assert rr.reviewed_utc == now

    def test_recommendation_quality_too_high(self) -> None:
        with pytest.raises(ValidationError):
            RunReview(
                correlation_id="c",
                customer_id="c",
                recommendation_quality=1.1,
                execution_safety=0.5,
                qa_reliability=0.5,
            )

    def test_recommendation_quality_too_low(self) -> None:
        with pytest.raises(ValidationError):
            RunReview(
                correlation_id="c",
                customer_id="c",
                recommendation_quality=-0.1,
                execution_safety=0.5,
                qa_reliability=0.5,
            )


# ---------------------------------------------------------------------------
# TrainingRecommendation tests
# ---------------------------------------------------------------------------


class TestTrainingRecommendation:
    def test_minimal_creation(self) -> None:
        tr = TrainingRecommendation(review_id="rev-1")
        assert tr.recommendation_id  # auto-generated uuid
        assert tr.review_id == "rev-1"
        assert tr.skill_updates == {}
        assert tr.kb_promotions == []
        assert tr.trust_adjustments == {}

    def test_defaults(self) -> None:
        tr = TrainingRecommendation(review_id="rev-2")
        assert tr.skill_updates == {}
        assert tr.kb_promotions == []
        assert tr.trust_adjustments == {}


# ---------------------------------------------------------------------------
# ArtifactPromotionDecision tests
# ---------------------------------------------------------------------------


class TestArtifactPromotionDecision:
    def test_minimal_creation(self) -> None:
        apd = ArtifactPromotionDecision(
            artifact_id="art-1",
            source_run_id="run-1",
            promotion_level=PromotionLevel.GLOBAL_KB,
            reason="High quality artifact",
        )
        assert apd.decision_id  # auto-generated uuid
        assert apd.artifact_id == "art-1"
        assert apd.source_run_id == "run-1"
        assert apd.promotion_level == PromotionLevel.GLOBAL_KB
        assert apd.reason == "High quality artifact"
        assert isinstance(apd.decided_utc, datetime)

    def test_all_fields(self) -> None:
        now = datetime(2026, 3, 16, 16, 0, 0, tzinfo=UTC)
        apd = ArtifactPromotionDecision(
            decision_id="dec-custom",
            artifact_id="art-2",
            source_run_id="run-2",
            promotion_level=PromotionLevel.PLAYBOOK_TEMPLATE,
            reason="Promoted to playbook",
            decided_utc=now,
        )
        assert apd.decision_id == "dec-custom"
        assert apd.promotion_level == PromotionLevel.PLAYBOOK_TEMPLATE
        assert apd.decided_utc == now


# ---------------------------------------------------------------------------
# InMemorySkillRegistry tests
# ---------------------------------------------------------------------------


class TestInMemorySkillRegistry:
    def test_get_agent_profile_returns_none_for_missing(self) -> None:
        registry = InMemorySkillRegistry()
        assert registry.get_agent_profile("nonexistent") is None

    def test_update_and_get_agent_profile(self) -> None:
        registry = InMemorySkillRegistry()
        profile = SkillProfile(agent_id="agent-1", customer_id="cust-1", total_runs=10)
        registry.update_agent_profile(profile)
        retrieved = registry.get_agent_profile("agent-1")
        assert retrieved is not None
        assert retrieved.agent_id == "agent-1"
        assert retrieved.total_runs == 10

    def test_get_cluster_profile_returns_none_for_missing(self) -> None:
        registry = InMemorySkillRegistry()
        assert registry.get_cluster_profile("nonexistent") is None

    def test_update_and_get_cluster_profile(self) -> None:
        registry = InMemorySkillRegistry()
        profile = ClusterSkillProfile(
            cluster_id="cluster-1", customer_id="cust-1", routing_weight=2.5
        )
        registry.update_cluster_profile(profile)
        retrieved = registry.get_cluster_profile("cluster-1")
        assert retrieved is not None
        assert retrieved.cluster_id == "cluster-1"
        assert retrieved.routing_weight == 2.5

    def test_update_agent_profile_overwrites(self) -> None:
        registry = InMemorySkillRegistry()
        p1 = SkillProfile(agent_id="agent-1", customer_id="cust-1", total_runs=5)
        registry.update_agent_profile(p1)
        p2 = SkillProfile(agent_id="agent-1", customer_id="cust-1", total_runs=15)
        registry.update_agent_profile(p2)
        retrieved = registry.get_agent_profile("agent-1")
        assert retrieved is not None
        assert retrieved.total_runs == 15

    def test_protocol_conformance(self) -> None:
        registry = InMemorySkillRegistry()
        assert isinstance(registry, SkillRegistry)


# ---------------------------------------------------------------------------
# InMemorySkillKnowledgeBase tests
# ---------------------------------------------------------------------------


class TestInMemorySkillKnowledgeBase:
    def test_store_and_get_article(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        article = KnowledgeArticle(
            customer_id="cust-1", title="Test Article", content="Content here"
        )
        kb.store_article(article)
        retrieved = kb.get_article(article.article_id)
        assert retrieved is not None
        assert retrieved.title == "Test Article"

    def test_get_article_returns_none_for_missing(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        assert kb.get_article("nonexistent") is None

    def test_list_articles_filters_by_customer_id(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        a1 = KnowledgeArticle(customer_id="cust-1", title="A1", content="c")
        a2 = KnowledgeArticle(customer_id="cust-2", title="A2", content="c")
        a3 = KnowledgeArticle(customer_id="cust-1", title="A3", content="c")
        kb.store_article(a1)
        kb.store_article(a2)
        kb.store_article(a3)
        results = kb.list_articles("cust-1")
        assert len(results) == 2
        titles = {a.title for a in results}
        assert titles == {"A1", "A3"}

    def test_list_articles_filters_by_promotion_level(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        a1 = KnowledgeArticle(
            customer_id="cust-1",
            title="A1",
            content="c",
            promotion_level=PromotionLevel.TEAM_KB,
        )
        a2 = KnowledgeArticle(
            customer_id="cust-1",
            title="A2",
            content="c",
            promotion_level=PromotionLevel.RUN_RECORD,
        )
        kb.store_article(a1)
        kb.store_article(a2)
        results = kb.list_articles("cust-1", promotion_level=PromotionLevel.TEAM_KB)
        assert len(results) == 1
        assert results[0].title == "A1"

    def test_list_articles_respects_limit(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        for i in range(10):
            kb.store_article(KnowledgeArticle(customer_id="cust-1", title=f"A{i}", content="c"))
        results = kb.list_articles("cust-1", limit=3)
        assert len(results) == 3

    def test_deprecate_article_sets_deprecated_utc(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        article = KnowledgeArticle(customer_id="cust-1", title="To Deprecate", content="c")
        kb.store_article(article)
        assert article.deprecated_utc is None
        kb.deprecate_article(article.article_id)
        retrieved = kb.get_article(article.article_id)
        assert retrieved is not None
        assert retrieved.deprecated_utc is not None
        assert isinstance(retrieved.deprecated_utc, datetime)

    def test_store_and_get_playbook(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        playbook = PlaybookTemplate(
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            name="Patch Playbook",
            steps=["Step 1", "Step 2"],
        )
        kb.store_playbook(playbook)
        retrieved = kb.get_playbook(playbook.template_id)
        assert retrieved is not None
        assert retrieved.name == "Patch Playbook"
        assert retrieved.steps == ["Step 1", "Step 2"]

    def test_get_playbook_returns_none_for_missing(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        assert kb.get_playbook("nonexistent") is None

    def test_list_playbooks_filters_by_customer_id(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        p1 = PlaybookTemplate(
            customer_id="cust-1",
            action_class=ActionClass.PATCH_DEPLOYMENT,
            name="P1",
        )
        p2 = PlaybookTemplate(
            customer_id="cust-2",
            action_class=ActionClass.ROLLBACK,
            name="P2",
        )
        kb.store_playbook(p1)
        kb.store_playbook(p2)
        results = kb.list_playbooks("cust-1")
        assert len(results) == 1
        assert results[0].name == "P1"

    def test_list_playbooks_respects_limit(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        for i in range(10):
            kb.store_playbook(
                PlaybookTemplate(
                    customer_id="cust-1",
                    action_class=ActionClass.BLOCK_IP,
                    name=f"P{i}",
                )
            )
        results = kb.list_playbooks("cust-1", limit=5)
        assert len(results) == 5

    def test_protocol_conformance(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        assert isinstance(kb, SkillKnowledgeBase)
