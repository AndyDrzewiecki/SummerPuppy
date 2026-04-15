"""LangGraph state graph for security analysis."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, Any, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel

from summer_puppy.agents.nodes import (
    analyze_node,
    recommend_node,
    simple_recommend_node,
    triage_node,
)

if TYPE_CHECKING:
    from langgraph.graph.state import CompiledStateGraph

    from summer_puppy.events.models import SecurityEvent
    from summer_puppy.llm.client import LLMClient
    from summer_puppy.skills.prompt_enricher import PromptEnricher
    from summer_puppy.trust.models import TrustProfile


class AgentState(TypedDict):
    """Full state flowing through the LangGraph security analysis pipeline."""

    event: dict[str, Any]
    customer_id: str
    trust_profile: dict[str, Any]
    knowledge_context: dict[str, Any]
    enriched_context: str
    analysis: dict[str, Any] | None
    recommendation: dict[str, Any] | None
    severity_route: str
    reasoning_trace: list[str]
    error: str | None


class AgentResult(BaseModel):
    """Pydantic model returned by the graph run."""

    analysis: dict[str, Any] | None = None
    recommendation: dict[str, Any] | None = None
    reasoning_trace: list[str] = []
    error: str | None = None


def _route_severity(state: AgentState) -> str:
    """Route based on severity_route set by triage node."""
    return "high" if state["severity_route"] == "high" else "low"


class SecurityAnalysisGraph:
    """Orchestrates security event analysis via a LangGraph state graph."""

    def __init__(
        self,
        llm_client: LLMClient,
        prompt_enricher: PromptEnricher | None = None,
    ) -> None:
        self._llm_client = llm_client
        self._enricher = prompt_enricher
        self._compiled = self._build_graph()

    def _build_graph(self) -> CompiledStateGraph:  # type: ignore[type-arg]
        graph = StateGraph(AgentState)

        graph.add_node("triage", partial(triage_node, llm_client=self._llm_client))
        graph.add_node("analyze", partial(analyze_node, llm_client=self._llm_client))
        graph.add_node("recommend", partial(recommend_node, llm_client=self._llm_client))
        graph.add_node(
            "simple_recommend",
            partial(simple_recommend_node, llm_client=self._llm_client),
        )

        graph.add_edge(START, "triage")
        graph.add_conditional_edges(
            "triage",
            _route_severity,
            {"high": "analyze", "low": "simple_recommend"},
        )
        graph.add_edge("analyze", "recommend")
        graph.add_edge("recommend", END)
        graph.add_edge("simple_recommend", END)

        return graph.compile()

    async def run(
        self,
        event: SecurityEvent,
        trust_profile: TrustProfile,
        knowledge_context: dict[str, Any] | None = None,
    ) -> AgentResult:
        """Run the graph with the given inputs and return an AgentResult."""
        enriched_context = ""
        if self._enricher is not None:
            enriched_context = await self._enricher.build_context(
                customer_id=event.customer_id,
                event_tags=event.tags,
                action_class=None,
            )
        initial_state: AgentState = {
            "event": event.model_dump(),
            "customer_id": event.customer_id,
            "trust_profile": trust_profile.model_dump(),
            "knowledge_context": knowledge_context or {},
            "enriched_context": enriched_context,
            "analysis": None,
            "recommendation": None,
            "severity_route": "",
            "reasoning_trace": [],
            "error": None,
        }

        final_state: dict[str, Any] = await self._compiled.ainvoke(initial_state)

        return AgentResult(
            analysis=final_state.get("analysis"),
            recommendation=final_state.get("recommendation"),
            reasoning_trace=final_state.get("reasoning_trace", []),
            error=final_state.get("error"),
        )
