"""SkillInjector — writes promoted playbooks and articles back into the knowledge graph.

After the Trainer promotes high-quality artifacts to TEAM_KB, GLOBAL_KB, or
PLAYBOOK_TEMPLATE level, the SkillInjector writes them into the KnowledgeStore so they
are available to the TriageHandler and PromptEnricher during future incident analysis.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from summer_puppy.skills.models import KnowledgeArticle, PlaybookTemplate, PromotionLevel

if TYPE_CHECKING:
    from summer_puppy.memory.store import KnowledgeStore
    from summer_puppy.skills.kb import SkillKnowledgeBase


class SkillInjector:
    """Synchronizes promoted skills from the SkillKB into the KnowledgeStore.

    The KnowledgeStore is the shared memory visible to pipeline handlers (TriageHandler,
    PromptEnricher). By writing promoted playbooks here, future incidents can benefit
    from past successful remediations without any human curation.
    """

    def __init__(
        self,
        knowledge_base: SkillKnowledgeBase,
        knowledge_store: KnowledgeStore,
    ) -> None:
        self._kb = knowledge_base
        self._store = knowledge_store

    async def inject_playbooks(self, customer_id: str) -> int:
        """Write all PLAYBOOK_TEMPLATE level playbooks for a customer to the knowledge graph.

        Returns the number of playbooks injected.
        """
        playbooks = self._kb.list_playbooks(customer_id)
        injected = 0
        for playbook in playbooks:
            artifact_data = _playbook_to_artifact(playbook)
            await self._store.store_artifact(
                artifact_id=f"playbook:{playbook.template_id}",
                artifact_data=artifact_data,
            )
            injected += 1
        return injected

    async def inject_kb_articles(
        self,
        customer_id: str,
        min_level: PromotionLevel = PromotionLevel.TEAM_KB,
    ) -> int:
        """Write KB articles at or above min_level to the knowledge graph.

        Returns the number of articles injected.
        """
        levels_to_inject = {PromotionLevel.TEAM_KB, PromotionLevel.GLOBAL_KB}
        articles = self._kb.list_articles(customer_id)
        articles = [a for a in articles if a.promotion_level in levels_to_inject]

        injected = 0
        for article in articles:
            if article.deprecated_utc is not None:
                continue
            artifact_data = _article_to_artifact(article)
            await self._store.store_artifact(
                artifact_id=f"article:{article.article_id}",
                artifact_data=artifact_data,
            )
            injected += 1
        return injected

    async def run_injection_cycle(self, customer_id: str) -> dict[str, int]:
        """Run a full injection cycle: playbooks + articles. Returns counts."""
        playbooks_injected = await self.inject_playbooks(customer_id)
        articles_injected = await self.inject_kb_articles(customer_id)
        return {
            "playbooks_injected": playbooks_injected,
            "articles_injected": articles_injected,
            "total_injected": playbooks_injected + articles_injected,
            "customer_id": customer_id,
            "injected_utc": datetime.now(tz=UTC).isoformat(),
        }


def _playbook_to_artifact(playbook: PlaybookTemplate) -> dict[str, Any]:
    return {
        "type": "playbook",
        "template_id": playbook.template_id,
        "customer_id": playbook.customer_id,
        "action_class": playbook.action_class,
        "name": playbook.name,
        "steps": playbook.steps,
        "version": playbook.version,
        "created_utc": playbook.created_utc.isoformat(),
        "source_article_id": playbook.source_article_id,
        # Flat-text summary for LLM context injection
        "summary": (
            f"Playbook: {playbook.name}\n"
            f"Action class: {playbook.action_class}\n"
            f"Steps:\n" + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(playbook.steps))
        ),
    }


def _article_to_artifact(article: KnowledgeArticle) -> dict[str, Any]:
    return {
        "type": "knowledge_article",
        "article_id": article.article_id,
        "customer_id": article.customer_id,
        "title": article.title,
        "content": article.content,
        "tags": article.tags,
        "promotion_level": article.promotion_level,
        "version": article.version,
        "source_run_id": article.source_run_id,
        "created_utc": article.created_utc.isoformat(),
        # Flat-text summary for LLM context injection
        "summary": f"KB Article: {article.title}\n{article.content}",
    }
