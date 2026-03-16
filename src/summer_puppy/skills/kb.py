"""Skill knowledge base protocol and in-memory implementation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from summer_puppy.skills.models import KnowledgeArticle, PlaybookTemplate, PromotionLevel


@runtime_checkable
class SkillKnowledgeBase(Protocol):
    """Protocol for skill knowledge base storage backends."""

    def store_article(self, article: KnowledgeArticle) -> None: ...

    def get_article(self, article_id: str) -> KnowledgeArticle | None: ...

    def list_articles(
        self,
        customer_id: str,
        promotion_level: PromotionLevel | None = None,
        limit: int = 50,
    ) -> list[KnowledgeArticle]: ...

    def deprecate_article(self, article_id: str) -> None: ...

    def store_playbook(self, playbook: PlaybookTemplate) -> None: ...

    def get_playbook(self, template_id: str) -> PlaybookTemplate | None: ...

    def list_playbooks(self, customer_id: str, limit: int = 50) -> list[PlaybookTemplate]: ...


class InMemorySkillKnowledgeBase:
    """In-memory implementation of SkillKnowledgeBase for testing and development."""

    def __init__(self) -> None:
        self._articles: dict[str, KnowledgeArticle] = {}
        self._playbooks: dict[str, PlaybookTemplate] = {}

    def store_article(self, article: KnowledgeArticle) -> None:
        self._articles[article.article_id] = article

    def get_article(self, article_id: str) -> KnowledgeArticle | None:
        return self._articles.get(article_id)

    def list_articles(
        self,
        customer_id: str,
        promotion_level: PromotionLevel | None = None,
        limit: int = 50,
    ) -> list[KnowledgeArticle]:
        results = [a for a in self._articles.values() if a.customer_id == customer_id]
        if promotion_level is not None:
            results = [a for a in results if a.promotion_level == promotion_level]
        return results[:limit]

    def deprecate_article(self, article_id: str) -> None:
        article = self._articles.get(article_id)
        if article is not None:
            article.deprecated_utc = datetime.now(tz=UTC)

    def store_playbook(self, playbook: PlaybookTemplate) -> None:
        self._playbooks[playbook.template_id] = playbook

    def get_playbook(self, template_id: str) -> PlaybookTemplate | None:
        return self._playbooks.get(template_id)

    def list_playbooks(self, customer_id: str, limit: int = 50) -> list[PlaybookTemplate]:
        results = [p for p in self._playbooks.values() if p.customer_id == customer_id]
        return results[:limit]
