"""PromptEnricher — injects relevant KB playbooks into LLM prompts as few-shot context.

Before the LLM analyzes or recommends on an incident, the PromptEnricher queries the
knowledge store for past playbooks and articles that are semantically relevant to the
current event. These are injected as few-shot examples, improving LLM recommendations
over time as the KB grows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from summer_puppy.memory.store import KnowledgeStore


_MAX_PLAYBOOKS = 3
_MAX_ARTICLES = 3


class PromptEnricher:
    """Enriches LLM prompts with relevant historical playbooks and KB articles."""

    def __init__(self, knowledge_store: KnowledgeStore) -> None:
        self._store = knowledge_store

    async def build_context(
        self,
        customer_id: str,
        event_tags: list[str] | None = None,
        action_class: str | None = None,
    ) -> str:
        """Build a rich context string to inject into LLM prompts.

        Pulls playbooks (filtered by action_class if given) and recent KB articles,
        and formats them as plain text for inclusion in prompts.
        """
        # Fetch all artifacts from the store
        summaries = await self._store.get_work_item_summaries(customer_id, limit=100)

        playbooks: list[dict[str, Any]] = []
        articles: list[dict[str, Any]] = []

        for summary in summaries:
            artifact_type = summary.get("type", "")
            if artifact_type == "playbook":
                if action_class is None or summary.get("action_class") == action_class:
                    playbooks.append(summary)
            elif artifact_type == "knowledge_article":
                articles.append(summary)

        # Limit to most recent N entries
        playbooks = playbooks[:_MAX_PLAYBOOKS]
        articles = articles[:_MAX_ARTICLES]

        sections: list[str] = []

        if playbooks:
            sections.append("## Relevant Playbooks from Previous Incidents")
            for pb in playbooks:
                sections.append(pb.get("summary", f"Playbook: {pb.get('name', 'unknown')}"))

        if articles:
            sections.append("## KB Articles from Previous Incidents")
            for art in articles:
                sections.append(art.get("summary", f"Article: {art.get('title', 'unknown')}"))

        if not sections:
            return "No historical playbooks or KB articles available."

        return "\n\n".join(sections)


class NullPromptEnricher:
    """No-op enricher for testing and environments without a knowledge store."""

    async def build_context(
        self,
        customer_id: str,
        event_tags: list[str] | None = None,
        action_class: str | None = None,
    ) -> str:
        return "No historical context available."
