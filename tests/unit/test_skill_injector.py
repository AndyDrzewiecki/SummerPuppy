"""Unit tests for SkillInjector and PromptEnricher."""

from __future__ import annotations

import pytest

from summer_puppy.memory.store import InMemoryKnowledgeStore
from summer_puppy.skills.injector import SkillInjector, _article_to_artifact, _playbook_to_artifact
from summer_puppy.skills.kb import InMemorySkillKnowledgeBase
from summer_puppy.skills.models import (
    KnowledgeArticle,
    PlaybookTemplate,
    PromotionLevel,
)
from summer_puppy.skills.prompt_enricher import NullPromptEnricher, PromptEnricher
from summer_puppy.trust.models import ActionClass


def make_playbook(
    customer_id: str = "cust-1",
    action_class: ActionClass = ActionClass.PATCH_DEPLOYMENT,
    name: str = "Test Playbook",
    steps: list[str] | None = None,
) -> PlaybookTemplate:
    return PlaybookTemplate(
        customer_id=customer_id,
        action_class=action_class,
        name=name,
        steps=steps or ["Step 1: Identify affected systems", "Step 2: Apply patch"],
    )


def make_article(
    customer_id: str = "cust-1",
    title: str = "Test Article",
    content: str = "Test knowledge content",
    level: PromotionLevel = PromotionLevel.TEAM_KB,
) -> KnowledgeArticle:
    return KnowledgeArticle(
        customer_id=customer_id,
        title=title,
        content=content,
        promotion_level=level,
    )


class TestPlaybookToArtifact:
    def test_includes_required_fields(self) -> None:
        pb = make_playbook(name="Patch Deploy")
        artifact = _playbook_to_artifact(pb)
        assert artifact["type"] == "playbook"
        assert artifact["name"] == "Patch Deploy"
        assert artifact["action_class"] == ActionClass.PATCH_DEPLOYMENT
        assert artifact["customer_id"] == "cust-1"
        assert len(artifact["steps"]) == 2

    def test_summary_contains_name_and_steps(self) -> None:
        pb = make_playbook(steps=["Identify", "Remediate", "Verify"])
        artifact = _playbook_to_artifact(pb)
        summary = artifact["summary"]
        assert "Identify" in summary
        assert "Remediate" in summary
        assert "Verify" in summary


class TestArticleToArtifact:
    def test_includes_required_fields(self) -> None:
        art = make_article(title="CVE Analysis", content="CVE-2024-1234 is critical")
        artifact = _article_to_artifact(art)
        assert artifact["type"] == "knowledge_article"
        assert artifact["title"] == "CVE Analysis"
        assert artifact["promotion_level"] == PromotionLevel.TEAM_KB

    def test_summary_contains_title_and_content(self) -> None:
        art = make_article(title="My Article", content="Important finding")
        artifact = _article_to_artifact(art)
        assert "My Article" in artifact["summary"]
        assert "Important finding" in artifact["summary"]


class TestSkillInjector:
    @pytest.mark.asyncio
    async def test_inject_playbooks_stores_artifacts(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        store = InMemoryKnowledgeStore()
        injector = SkillInjector(knowledge_base=kb, knowledge_store=store)

        pb1 = make_playbook(name="Playbook A")
        pb2 = make_playbook(name="Playbook B", action_class=ActionClass.NETWORK_ISOLATION)
        kb.store_playbook(pb1)
        kb.store_playbook(pb2)

        count = await injector.inject_playbooks("cust-1")
        assert count == 2

    @pytest.mark.asyncio
    async def test_inject_playbooks_only_for_customer(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        store = InMemoryKnowledgeStore()
        injector = SkillInjector(knowledge_base=kb, knowledge_store=store)

        pb_cust1 = make_playbook(customer_id="cust-1")
        pb_cust2 = make_playbook(customer_id="cust-2")
        kb.store_playbook(pb_cust1)
        kb.store_playbook(pb_cust2)

        count = await injector.inject_playbooks("cust-1")
        assert count == 1

    @pytest.mark.asyncio
    async def test_inject_kb_articles_stores_team_level(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        store = InMemoryKnowledgeStore()
        injector = SkillInjector(knowledge_base=kb, knowledge_store=store)

        kb.store_article(make_article(level=PromotionLevel.TEAM_KB, title="Team Article"))
        kb.store_article(make_article(level=PromotionLevel.GLOBAL_KB, title="Global Article"))
        kb.store_article(make_article(level=PromotionLevel.RUN_RECORD, title="Run Record"))

        count = await injector.inject_kb_articles("cust-1")
        assert count == 2  # RUN_RECORD skipped

    @pytest.mark.asyncio
    async def test_inject_kb_articles_skips_deprecated(self) -> None:
        from datetime import UTC, datetime

        kb = InMemorySkillKnowledgeBase()
        store = InMemoryKnowledgeStore()
        injector = SkillInjector(knowledge_base=kb, knowledge_store=store)

        article = make_article(level=PromotionLevel.TEAM_KB)
        kb.store_article(article)
        kb.deprecate_article(article.article_id)

        count = await injector.inject_kb_articles("cust-1")
        assert count == 0

    @pytest.mark.asyncio
    async def test_run_injection_cycle_returns_counts(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        store = InMemoryKnowledgeStore()
        injector = SkillInjector(knowledge_base=kb, knowledge_store=store)

        kb.store_playbook(make_playbook())
        kb.store_article(make_article(level=PromotionLevel.GLOBAL_KB))

        result = await injector.run_injection_cycle("cust-1")
        assert result["playbooks_injected"] == 1
        assert result["articles_injected"] == 1
        assert result["total_injected"] == 2
        assert result["customer_id"] == "cust-1"
        assert "injected_utc" in result

    @pytest.mark.asyncio
    async def test_run_injection_cycle_empty_kb(self) -> None:
        kb = InMemorySkillKnowledgeBase()
        store = InMemoryKnowledgeStore()
        injector = SkillInjector(knowledge_base=kb, knowledge_store=store)

        result = await injector.run_injection_cycle("cust-1")
        assert result["total_injected"] == 0


class TestNullPromptEnricher:
    @pytest.mark.asyncio
    async def test_returns_no_context_string(self) -> None:
        enricher = NullPromptEnricher()
        ctx = await enricher.build_context("cust-1")
        assert "No historical context" in ctx

    @pytest.mark.asyncio
    async def test_ignores_parameters(self) -> None:
        enricher = NullPromptEnricher()
        ctx = await enricher.build_context(
            "cust-1",
            event_tags=["mitre:T1059"],
            action_class="patch_deployment",
        )
        assert isinstance(ctx, str)
