"""Unit tests for Neo4j-backed Skill Knowledge Base (Phase 12)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from summer_puppy.events.models import ActionClass
from summer_puppy.skills.models import KnowledgeArticle, PlaybookTemplate, PromotionLevel
from summer_puppy.skills.neo4j_kb import (
    SKILLS_SCHEMA,
    Neo4jSkillKnowledgeBase,
    init_skills_schema,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_driver() -> tuple[Any, AsyncMock]:
    mock_session = AsyncMock()
    mock_session.run = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    mock_driver = MagicMock()
    mock_driver.session = MagicMock(return_value=mock_session)
    return mock_driver, mock_session


def _make_article(
    *,
    article_id: str = "art-1",
    customer_id: str = "cust-1",
    title: str = "Patch CVE-2024-001",
    content: str = "Apply patch to libssl",
    tags: list[str] | None = None,
    promotion_level: PromotionLevel = PromotionLevel.RUN_RECORD,
) -> KnowledgeArticle:
    return KnowledgeArticle(
        article_id=article_id,
        customer_id=customer_id,
        title=title,
        content=content,
        tags=tags or ["ssl", "patch"],
        promotion_level=promotion_level,
    )


def _make_playbook(
    *,
    template_id: str = "pb-1",
    customer_id: str = "cust-1",
    action_class: ActionClass = ActionClass.PATCH_DEPLOYMENT,
    name: str = "Deploy SSL patch",
    steps: list[str] | None = None,
) -> PlaybookTemplate:
    return PlaybookTemplate(
        template_id=template_id,
        customer_id=customer_id,
        action_class=action_class,
        name=name,
        steps=steps or ["backup", "patch", "verify"],
    )


# ---------------------------------------------------------------------------
# SKILLS_SCHEMA
# ---------------------------------------------------------------------------


class TestSkillsSchema:
    def test_schema_is_nonempty_list(self) -> None:
        assert isinstance(SKILLS_SCHEMA, list)
        assert len(SKILLS_SCHEMA) >= 4

    def test_schema_contains_article_constraint(self) -> None:
        assert any("KnowledgeArticle" in s for s in SKILLS_SCHEMA)

    def test_schema_contains_playbook_constraint(self) -> None:
        assert any("PlaybookTemplate" in s for s in SKILLS_SCHEMA)

    def test_schema_contains_indexes(self) -> None:
        assert any("INDEX" in s for s in SKILLS_SCHEMA)

    async def test_init_skills_schema_runs_all_statements(self) -> None:
        driver, session = _make_mock_driver()
        await init_skills_schema(driver)
        assert session.run.call_count == len(SKILLS_SCHEMA)


# ---------------------------------------------------------------------------
# Neo4jSkillKnowledgeBase — store_article
# ---------------------------------------------------------------------------


class TestNeo4jKBStoreArticle:
    async def test_store_article_calls_merge(self) -> None:
        driver, session = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)
        article = _make_article()

        await kb.store_article(article)

        session.run.assert_called_once()
        cypher = session.run.call_args[0][0]
        assert "MERGE" in cypher
        assert "KnowledgeArticle" in cypher

    async def test_store_article_passes_article_id(self) -> None:
        driver, session = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)
        article = _make_article(article_id="art-xyz")

        await kb.store_article(article)

        kwargs = session.run.call_args[1]
        assert kwargs["article_id"] == "art-xyz"

    async def test_store_article_passes_customer_id(self) -> None:
        driver, session = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)
        article = _make_article(customer_id="cust-42")

        await kb.store_article(article)

        kwargs = session.run.call_args[1]
        assert kwargs["customer_id"] == "cust-42"

    async def test_store_article_passes_promotion_level(self) -> None:
        driver, session = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)
        article = _make_article(promotion_level=PromotionLevel.TEAM_KB)

        await kb.store_article(article)

        kwargs = session.run.call_args[1]
        assert kwargs["promotion_level"] == PromotionLevel.TEAM_KB.value

    async def test_store_article_serializes_tags(self) -> None:
        driver, session = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)
        article = _make_article(tags=["ssl", "patch", "critical"])

        await kb.store_article(article)

        kwargs = session.run.call_args[1]
        assert "ssl" in kwargs["tags"]
        assert "patch" in kwargs["tags"]


# ---------------------------------------------------------------------------
# Neo4jSkillKnowledgeBase — get_article
# ---------------------------------------------------------------------------


class TestNeo4jKBGetArticle:
    async def test_get_article_returns_none_when_not_found(self) -> None:
        driver, session = _make_mock_driver()
        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=None)
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        result = await kb.get_article("nonexistent")

        assert result is None

    async def test_get_article_returns_article_when_found(self) -> None:
        driver, session = _make_mock_driver()

        node_props = {
            "article_id": "art-1",
            "customer_id": "cust-1",
            "title": "Fix CVE",
            "content": "Patch the library",
            "tags": "ssl,patch",
            "source_run_id": None,
            "promotion_level": "run_record",
            "version": 1,
            "created_utc": datetime.now(tz=UTC).isoformat(),
            "deprecated_utc": None,
        }
        mock_record = {"a": node_props}
        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        article = await kb.get_article("art-1")

        assert article is not None
        assert article.article_id == "art-1"
        assert article.customer_id == "cust-1"
        assert article.title == "Fix CVE"
        assert article.content == "Patch the library"
        assert "ssl" in article.tags
        assert article.promotion_level == PromotionLevel.RUN_RECORD

    async def test_get_article_calls_match_cypher(self) -> None:
        driver, session = _make_mock_driver()
        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=None)
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        await kb.get_article("art-1")

        cypher = session.run.call_args[0][0]
        assert "MATCH" in cypher
        assert "article_id" in cypher


# ---------------------------------------------------------------------------
# Neo4jSkillKnowledgeBase — list_articles
# ---------------------------------------------------------------------------


class TestNeo4jKBListArticles:
    async def test_list_articles_returns_empty_when_none(self) -> None:
        driver, session = _make_mock_driver()
        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=[])
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        results = await kb.list_articles("cust-1")

        assert results == []

    async def test_list_articles_filters_by_promotion_level(self) -> None:
        driver, session = _make_mock_driver()
        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=[])
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        await kb.list_articles("cust-1", promotion_level=PromotionLevel.TEAM_KB)

        cypher = session.run.call_args[0][0]
        assert "promotion_level" in cypher

    async def test_list_articles_without_level_has_no_level_filter(self) -> None:
        driver, session = _make_mock_driver()
        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=[])
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        await kb.list_articles("cust-1")

        cypher = session.run.call_args[0][0]
        assert "KnowledgeArticle" in cypher

    async def test_list_articles_passes_limit(self) -> None:
        driver, session = _make_mock_driver()
        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=[])
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        await kb.list_articles("cust-1", limit=25)

        kwargs = session.run.call_args[1]
        assert kwargs.get("limit") == 25


# ---------------------------------------------------------------------------
# Neo4jSkillKnowledgeBase — deprecate_article
# ---------------------------------------------------------------------------


class TestNeo4jKBDeprecateArticle:
    async def test_deprecate_article_sets_deprecated_utc(self) -> None:
        driver, session = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)

        await kb.deprecate_article("art-1")

        session.run.assert_called_once()
        cypher = session.run.call_args[0][0]
        assert "deprecated_utc" in cypher
        assert "MATCH" in cypher


# ---------------------------------------------------------------------------
# Neo4jSkillKnowledgeBase — store_playbook / get_playbook
# ---------------------------------------------------------------------------


class TestNeo4jKBPlaybooks:
    async def test_store_playbook_calls_merge(self) -> None:
        driver, session = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)
        pb = _make_playbook()

        await kb.store_playbook(pb)

        session.run.assert_called_once()
        cypher = session.run.call_args[0][0]
        assert "MERGE" in cypher
        assert "PlaybookTemplate" in cypher

    async def test_store_playbook_passes_template_id(self) -> None:
        driver, session = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)
        pb = _make_playbook(template_id="pb-abc")

        await kb.store_playbook(pb)

        kwargs = session.run.call_args[1]
        assert kwargs["template_id"] == "pb-abc"

    async def test_store_playbook_serializes_steps(self) -> None:
        driver, session = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)
        pb = _make_playbook(steps=["step1", "step2", "step3"])

        await kb.store_playbook(pb)

        kwargs = session.run.call_args[1]
        assert "step1" in kwargs["steps"]
        assert "step2" in kwargs["steps"]

    async def test_get_playbook_returns_none_when_not_found(self) -> None:
        driver, session = _make_mock_driver()
        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=None)
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        result = await kb.get_playbook("nonexistent")

        assert result is None

    async def test_get_playbook_returns_playbook_when_found(self) -> None:
        driver, session = _make_mock_driver()

        node_props = {
            "template_id": "pb-1",
            "customer_id": "cust-1",
            "action_class": "PATCH_DEPLOYMENT",
            "name": "Deploy patch",
            "steps": "backup|patch|verify",
            "source_article_id": None,
            "version": 1,
            "created_utc": datetime.now(tz=UTC).isoformat(),
        }
        mock_record = {"p": node_props}
        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        pb = await kb.get_playbook("pb-1")

        assert pb is not None
        assert pb.template_id == "pb-1"
        assert pb.customer_id == "cust-1"
        assert pb.action_class == ActionClass.PATCH_DEPLOYMENT
        assert "backup" in pb.steps

    async def test_list_playbooks_returns_empty_when_none(self) -> None:
        driver, session = _make_mock_driver()
        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=[])
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        results = await kb.list_playbooks("cust-1")

        assert results == []

    async def test_find_playbooks_by_action_class(self) -> None:
        driver, session = _make_mock_driver()
        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=[])
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        results = await kb.find_playbooks_by_action_class("cust-1", "PATCH_DEPLOYMENT")

        assert isinstance(results, list)
        cypher = session.run.call_args[0][0]
        assert "action_class" in cypher

    async def test_find_articles_by_tag(self) -> None:
        driver, session = _make_mock_driver()
        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=[])
        session.run.return_value = mock_result

        kb = Neo4jSkillKnowledgeBase(driver)
        results = await kb.find_articles_by_tag("cust-1", "ssl")

        assert isinstance(results, list)
        cypher = session.run.call_args[0][0]
        assert "tag" in cypher.lower() or "tags" in cypher.lower()


# ---------------------------------------------------------------------------
# Internal helpers — round-trip field mapping
# ---------------------------------------------------------------------------


class TestRecordToArticle:
    def test_round_trip_tags(self) -> None:
        driver, _ = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)

        props = {
            "article_id": "a1",
            "customer_id": "c1",
            "title": "t",
            "content": "c",
            "tags": "a,b,c",
            "source_run_id": None,
            "promotion_level": "team_kb",
            "version": 1,
            "created_utc": datetime.now(tz=UTC).isoformat(),
            "deprecated_utc": None,
        }
        article = kb._record_to_article(props)
        assert article.tags == ["a", "b", "c"]
        assert article.promotion_level == PromotionLevel.TEAM_KB

    def test_empty_tags(self) -> None:
        driver, _ = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)

        props = {
            "article_id": "a1",
            "customer_id": "c1",
            "title": "t",
            "content": "c",
            "tags": "",
            "source_run_id": None,
            "promotion_level": "run_record",
            "version": 1,
            "created_utc": datetime.now(tz=UTC).isoformat(),
            "deprecated_utc": None,
        }
        article = kb._record_to_article(props)
        assert article.tags == []

    def test_deprecated_utc_parsed(self) -> None:
        driver, _ = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)
        ts = datetime.now(tz=UTC)

        props = {
            "article_id": "a1",
            "customer_id": "c1",
            "title": "t",
            "content": "c",
            "tags": "",
            "source_run_id": None,
            "promotion_level": "run_record",
            "version": 1,
            "created_utc": ts.isoformat(),
            "deprecated_utc": ts.isoformat(),
        }
        article = kb._record_to_article(props)
        assert article.deprecated_utc is not None


class TestRecordToPlaybook:
    def test_round_trip_steps(self) -> None:
        driver, _ = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)

        props = {
            "template_id": "p1",
            "customer_id": "c1",
            "action_class": "PATCH_DEPLOYMENT",
            "name": "My playbook",
            "steps": "backup|patch|verify",
            "source_article_id": None,
            "version": 1,
            "created_utc": datetime.now(tz=UTC).isoformat(),
        }
        pb = kb._record_to_playbook(props)
        assert pb.steps == ["backup", "patch", "verify"]

    def test_empty_steps(self) -> None:
        driver, _ = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)

        props = {
            "template_id": "p1",
            "customer_id": "c1",
            "action_class": "FIREWALL_RULE",
            "name": "FW rule",
            "steps": "",
            "source_article_id": None,
            "version": 1,
            "created_utc": datetime.now(tz=UTC).isoformat(),
        }
        pb = kb._record_to_playbook(props)
        assert pb.steps == []

    def test_invalid_action_class_falls_back(self) -> None:
        driver, _ = _make_mock_driver()
        kb = Neo4jSkillKnowledgeBase(driver)

        props = {
            "template_id": "p1",
            "customer_id": "c1",
            "action_class": "UNKNOWN_CLASS",
            "name": "x",
            "steps": "",
            "source_article_id": None,
            "version": 1,
            "created_utc": datetime.now(tz=UTC).isoformat(),
        }
        pb = kb._record_to_playbook(props)
        assert pb.action_class == ActionClass.PATCH_DEPLOYMENT
