from __future__ import annotations

from datetime import datetime  # noqa: TC003

from pydantic import BaseModel

from summer_puppy.trust.models import TrustPhase  # noqa: TC001


class DashboardSummary(BaseModel):
    events_24h: int
    events_7d: int
    open_critical: int
    avg_time_to_remediate_minutes: float
    execution_success_rate: float
    active_agents: int
    trust_phase: TrustPhase | None
    orchestrator_ready: bool


class EventSummary(BaseModel):
    event_id: str
    correlation_id: str | None
    severity: str | None
    stage: str | None
    status: str | None
    action_class: str | None
    submitted_utc: datetime | None


class AgentSummary(BaseModel):
    agent_id: str
    customer_id: str
    total_runs: int
    successful_runs: int
    failed_runs: int
    qa_pass_rate: float


class TrustSummary(BaseModel):
    customer_id: str
    trust_phase: TrustPhase
    total_recommendations: int
    total_approvals: int
    total_rejections: int
    positive_outcome_rate: float
