"""Neo4j-backed Skill Knowledge Base for production deployments (Phase 12).

Stores KnowledgeArticle and PlaybookTemplate nodes in the graph database,
enabling similarity-based retrieval and richer cross-article relationships.

Note: Unlike InMemorySkillKnowledgeBase this implementation is async-first
(required by the Neo4j async driver).
"""

from __future__ import annotations

from typing import Any

from summer_puppy.logging.config import get_logger
from summer_puppy.skills.models import KnowledgeArticle, PlaybookTemplate, PromotionLevel

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Neo4j schema statements for the skills graph
# ---------------------------------------------------------------------------

SKILLS_SCHEMA: list[str] = [
    (
        "CREATE CONSTRAINT article_id IF NOT EXISTS "
        "FOR (a:KnowledgeArticle) REQUIRE a.article_id IS UNIQUE"
    ),
    (
        "CREATE CONSTRAINT playbook_id IF NOT EXISTS "
        "FOR (p:PlaybookTemplate) REQUIRE p.template_id IS UNIQUE"
    ),
    "CREATE INDEX article_customer IF NOT EXISTS FOR (a:KnowledgeArticle) ON (a.customer_id)",
    "CREATE INDEX article_promotion IF NOT EXISTS FOR (a:KnowledgeArticle) ON (a.promotion_level)",
    "CREATE INDEX playbook_customer IF NOT EXISTS FOR (p:PlaybookTemplate) ON (p.customer_id)",
    "CREATE INDEX playbook_action IF NOT EXISTS FOR (p:PlaybookTemplate) ON (p.action_class)",
]


async def init_skills_schema(driver: Any) -> None:
    """Apply skills-specific schema constraints/indexes to Neo4j."""
    async with driver.session() as session:
        for stmt in SKILLS_SCHEMA:
            await session.run(stmt)
    logger.info("neo4j_skills_schema_initialized", statements=len(SKILLS_SCHEMA))


# ---------------------------------------------------------------------------
# Neo4j KB implementation
# ---------------------------------------------------------------------------


class Neo4jSkillKnowledgeBase:
    """Neo4j-backed async skill knowledge base.

    Provides equivalent functionality to InMemorySkillKnowledgeBase
    but persists data in Neo4j.  All methods are coroutines.
    """

    def __init__(self, driver: Any) -> None:
        self._driver = driver

    # ------------------------------------------------------------------
    # Articles
    # ------------------------------------------------------------------

    async def store_article(self, article: KnowledgeArticle) -> None:
        tags_json = ",".join(article.tags)
        async with self._driver.session() as session:
            await session.run(
                "MERGE (a:KnowledgeArticle {article_id: $article_id}) "
                "SET a.customer_id = $customer_id, "
                "    a.title = $title, "
                "    a.content = $content, "
                "    a.tags = $tags, "
                "    a.source_run_id = $source_run_id, "
                "    a.promotion_level = $promotion_level, "
                "    a.version = $version, "
                "    a.created_utc = $created_utc, "
                "    a.deprecated_utc = $deprecated_utc",
                article_id=article.article_id,
                customer_id=article.customer_id,
                title=article.title,
                content=article.content,
                tags=tags_json,
                source_run_id=article.source_run_id,
                promotion_level=article.promotion_level.value
                if hasattr(article.promotion_level, "value")
                else str(article.promotion_level),
                version=article.version,
                created_utc=article.created_utc.isoformat(),
                deprecated_utc=article.deprecated_utc.isoformat()
                if article.deprecated_utc
                else None,
            )
        logger.debug(
            "neo4j_article_stored",
            article_id=article.article_id,
            customer_id=article.customer_id,
        )

    async def get_article(self, article_id: str) -> KnowledgeArticle | None:
        async with self._driver.session() as session:
            result = await session.run(
                "MATCH (a:KnowledgeArticle {article_id: $article_id}) RETURN a",
                article_id=article_id,
            )
            record = await result.single()
            if record is None:
                return None
            return self._record_to_article(dict(record["a"]))

    async def list_articles(
        self,
        customer_id: str,
        promotion_level: PromotionLevel | None = None,
        limit: int = 50,
    ) -> list[KnowledgeArticle]:
        if promotion_level is not None:
            level_val = (
                promotion_level.value
                if hasattr(promotion_level, "value")
                else str(promotion_level)
            )
            async with self._driver.session() as session:
                result = await session.run(
                    "MATCH (a:KnowledgeArticle {customer_id: $cid, promotion_level: $lvl}) "
                    "WHERE a.deprecated_utc IS NULL "
                    "RETURN a LIMIT $limit",
                    cid=customer_id,
                    lvl=level_val,
                    limit=limit,
                )
                records = await result.data()
        else:
            async with self._driver.session() as session:
                result = await session.run(
                    "MATCH (a:KnowledgeArticle {customer_id: $cid}) "
                    "WHERE a.deprecated_utc IS NULL "
                    "RETURN a LIMIT $limit",
                    cid=customer_id,
                    limit=limit,
                )
                records = await result.data()

        return [self._record_to_article(dict(r["a"])) for r in records]

    async def deprecate_article(self, article_id: str) -> None:
        from datetime import UTC, datetime

        async with self._driver.session() as session:
            await session.run(
                "MATCH (a:KnowledgeArticle {article_id: $article_id}) "
                "SET a.deprecated_utc = $ts",
                article_id=article_id,
                ts=datetime.now(tz=UTC).isoformat(),
            )
        logger.info("neo4j_article_deprecated", article_id=article_id)

    async def find_articles_by_tag(
        self, customer_id: str, tag: str, limit: int = 10
    ) -> list[KnowledgeArticle]:
        """Return articles whose tags field contains the given tag."""
        async with self._driver.session() as session:
            result = await session.run(
                "MATCH (a:KnowledgeArticle {customer_id: $cid}) "
                "WHERE a.deprecated_utc IS NULL "
                "  AND a.tags CONTAINS $tag "
                "RETURN a LIMIT $limit",
                cid=customer_id,
                tag=tag,
                limit=limit,
            )
            records = await result.data()
        return [self._record_to_article(dict(r["a"])) for r in records]

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------

    async def store_playbook(self, playbook: PlaybookTemplate) -> None:
        steps_json = "|".join(playbook.steps)  # pipe-delimited for simple storage
        async with self._driver.session() as session:
            await session.run(
                "MERGE (p:PlaybookTemplate {template_id: $template_id}) "
                "SET p.customer_id = $customer_id, "
                "    p.action_class = $action_class, "
                "    p.name = $name, "
                "    p.steps = $steps, "
                "    p.source_article_id = $source_article_id, "
                "    p.version = $version, "
                "    p.created_utc = $created_utc",
                template_id=playbook.template_id,
                customer_id=playbook.customer_id,
                action_class=playbook.action_class.value
                if hasattr(playbook.action_class, "value")
                else str(playbook.action_class),
                name=playbook.name,
                steps=steps_json,
                source_article_id=playbook.source_article_id,
                version=playbook.version,
                created_utc=playbook.created_utc.isoformat(),
            )

    async def get_playbook(self, template_id: str) -> PlaybookTemplate | None:
        async with self._driver.session() as session:
            result = await session.run(
                "MATCH (p:PlaybookTemplate {template_id: $template_id}) RETURN p",
                template_id=template_id,
            )
            record = await result.single()
            if record is None:
                return None
            return self._record_to_playbook(dict(record["p"]))

    async def list_playbooks(
        self,
        customer_id: str,
        limit: int = 50,
    ) -> list[PlaybookTemplate]:
        async with self._driver.session() as session:
            result = await session.run(
                "MATCH (p:PlaybookTemplate {customer_id: $cid}) "
                "RETURN p LIMIT $limit",
                cid=customer_id,
                limit=limit,
            )
            records = await result.data()
        return [self._record_to_playbook(dict(r["p"])) for r in records]

    async def find_playbooks_by_action_class(
        self, customer_id: str, action_class: str, limit: int = 10
    ) -> list[PlaybookTemplate]:
        """Return playbooks filtered by action_class value."""
        async with self._driver.session() as session:
            result = await session.run(
                "MATCH (p:PlaybookTemplate {customer_id: $cid, action_class: $ac}) "
                "RETURN p LIMIT $limit",
                cid=customer_id,
                ac=action_class,
                limit=limit,
            )
            records = await result.data()
        return [self._record_to_playbook(dict(r["p"])) for r in records]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_to_article(self, props: dict[str, Any]) -> KnowledgeArticle:
        from datetime import datetime

        deprecated: datetime | None = None
        if props.get("deprecated_utc") and props["deprecated_utc"] not in (None, "None"):
            try:
                deprecated = datetime.fromisoformat(str(props["deprecated_utc"]))
            except ValueError:
                deprecated = None

        tags_raw = props.get("tags", "")
        tags = [t for t in str(tags_raw).split(",") if t] if tags_raw else []

        created_utc: datetime
        try:
            created_utc = datetime.fromisoformat(str(props.get("created_utc", "")))
        except (ValueError, TypeError):
            from datetime import UTC

            created_utc = datetime.now(tz=UTC)

        return KnowledgeArticle(
            article_id=props["article_id"],
            customer_id=props["customer_id"],
            title=props.get("title", ""),
            content=props.get("content", ""),
            tags=tags,
            source_run_id=props.get("source_run_id"),
            promotion_level=PromotionLevel(
                props.get("promotion_level", PromotionLevel.RUN_RECORD.value)
            ),
            version=int(props.get("version", 1)),
            created_utc=created_utc,
            deprecated_utc=deprecated,
        )

    def _record_to_playbook(self, props: dict[str, Any]) -> PlaybookTemplate:
        from summer_puppy.events.models import ActionClass

        raw_ac = props.get("action_class", "PATCH_DEPLOYMENT")
        try:
            action_class = ActionClass(raw_ac)
        except ValueError:
            action_class = ActionClass.PATCH_DEPLOYMENT

        steps_raw = props.get("steps", "")
        steps = [s for s in str(steps_raw).split("|") if s] if steps_raw else []

        from datetime import UTC, datetime

        try:
            created_utc = datetime.fromisoformat(str(props.get("created_utc", "")))
        except (ValueError, TypeError):
            created_utc = datetime.now(tz=UTC)

        return PlaybookTemplate(
            template_id=props["template_id"],
            customer_id=props["customer_id"],
            action_class=action_class,
            name=props.get("name", ""),
            steps=steps,
            source_article_id=props.get("source_article_id"),
            version=int(props.get("version", 1)),
            created_utc=created_utc,
        )
