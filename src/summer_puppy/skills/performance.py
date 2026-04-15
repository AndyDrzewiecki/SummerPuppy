"""Per-agent performance degradation detection.

Tracks agent success rates over a sliding window and fires alerts when
an agent's quality drops below configurable thresholds.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import NamedTuple
from uuid import uuid4

from pydantic import BaseModel, Field


class DegradationAlertType(StrEnum):
    LOW_SUCCESS_RATE = "low_success_rate"
    HIGH_OVERRIDE_RATE = "high_override_rate"
    INSUFFICIENT_DATA = "insufficient_data"


class PerformanceWindow(BaseModel):
    """A time-bucketed performance snapshot for one agent."""

    agent_id: str
    customer_id: str
    window_start_utc: datetime
    window_end_utc: datetime
    total_runs: int = 0
    successful_runs: int = 0
    human_override_count: int = 0

    @property
    def success_rate(self) -> float:
        """Return successful_runs / total_runs, or 0.0 if no runs."""
        if self.total_runs == 0:
            return 0.0
        return self.successful_runs / self.total_runs

    @property
    def override_rate(self) -> float:
        """Return human_override_count / total_runs, or 0.0 if no runs."""
        if self.total_runs == 0:
            return 0.0
        return self.human_override_count / self.total_runs


class DegradationAlert(BaseModel):
    """Fired when an agent's performance degrades below threshold."""

    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str
    customer_id: str
    alert_type: DegradationAlertType
    current_value: float
    threshold: float
    window_start_utc: datetime
    window_end_utc: datetime
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    message: str


class _RunRecord(NamedTuple):
    run_utc: datetime
    success: bool
    human_override: bool


class AgentPerformanceTracker:
    """Tracks per-agent performance over sliding windows and detects degradation.

    Usage:
        tracker = AgentPerformanceTracker()
        tracker.record_run(agent_id, customer_id, success=True, human_override=False)
        alerts = tracker.check_degradation(agent_id, customer_id)
    """

    def __init__(
        self,
        success_rate_threshold: float = 0.7,
        override_rate_threshold: float = 0.3,
        min_runs_for_alert: int = 5,
        window_size_minutes: int = 60,
    ) -> None:
        self._success_rate_threshold = success_rate_threshold
        self._override_rate_threshold = override_rate_threshold
        self._min_runs_for_alert = min_runs_for_alert
        self._window_size_minutes = window_size_minutes
        # keyed by (agent_id, customer_id) -> list of _RunRecord
        self._runs: dict[tuple[str, str], list[_RunRecord]] = {}

    def record_run(
        self,
        agent_id: str,
        customer_id: str,
        *,
        success: bool,
        human_override: bool = False,
        run_utc: datetime | None = None,
    ) -> None:
        """Record the outcome of one agent run."""
        if run_utc is None:
            run_utc = datetime.now(tz=UTC)
        key = (agent_id, customer_id)
        self._runs.setdefault(key, []).append(
            _RunRecord(run_utc=run_utc, success=success, human_override=human_override)
        )

    def _get_window_runs(
        self, agent_id: str, customer_id: str
    ) -> list[_RunRecord]:
        """Return only runs within the current rolling window."""
        key = (agent_id, customer_id)
        all_runs = self._runs.get(key, [])
        cutoff = datetime.now(tz=UTC) - timedelta(minutes=self._window_size_minutes)
        return [r for r in all_runs if r.run_utc >= cutoff]

    def get_current_window(
        self, agent_id: str, customer_id: str
    ) -> PerformanceWindow | None:
        """Return the current rolling window stats for this agent."""
        runs = self._get_window_runs(agent_id, customer_id)
        if not runs:
            return None
        now = datetime.now(tz=UTC)
        window_start = now - timedelta(minutes=self._window_size_minutes)
        return PerformanceWindow(
            agent_id=agent_id,
            customer_id=customer_id,
            window_start_utc=window_start,
            window_end_utc=now,
            total_runs=len(runs),
            successful_runs=sum(1 for r in runs if r.success),
            human_override_count=sum(1 for r in runs if r.human_override),
        )

    def check_degradation(
        self, agent_id: str, customer_id: str
    ) -> list[DegradationAlert]:
        """Check if agent performance has degraded below thresholds.

        Returns a list of DegradationAlert (empty if healthy).
        """
        window = self.get_current_window(agent_id, customer_id)
        if window is None or window.total_runs < self._min_runs_for_alert:
            return []

        alerts: list[DegradationAlert] = []

        if window.success_rate < self._success_rate_threshold:
            alerts.append(
                DegradationAlert(
                    agent_id=agent_id,
                    customer_id=customer_id,
                    alert_type=DegradationAlertType.LOW_SUCCESS_RATE,
                    current_value=window.success_rate,
                    threshold=self._success_rate_threshold,
                    window_start_utc=window.window_start_utc,
                    window_end_utc=window.window_end_utc,
                    message=(
                        f"Agent {agent_id} success rate {window.success_rate:.2%} is below "
                        f"threshold {self._success_rate_threshold:.2%} "
                        f"({window.total_runs} runs in window)"
                    ),
                )
            )

        if window.override_rate > self._override_rate_threshold:
            alerts.append(
                DegradationAlert(
                    agent_id=agent_id,
                    customer_id=customer_id,
                    alert_type=DegradationAlertType.HIGH_OVERRIDE_RATE,
                    current_value=window.override_rate,
                    threshold=self._override_rate_threshold,
                    window_start_utc=window.window_start_utc,
                    window_end_utc=window.window_end_utc,
                    message=(
                        f"Agent {agent_id} override rate {window.override_rate:.2%} exceeds "
                        f"threshold {self._override_rate_threshold:.2%} "
                        f"({window.total_runs} runs in window)"
                    ),
                )
            )

        return alerts

    def list_degraded_agents(self, customer_id: str) -> list[str]:
        """Return agent_ids that currently have degradation alerts for this customer."""
        agent_ids = {agent_id for (agent_id, cid) in self._runs if cid == customer_id}
        return [
            agent_id
            for agent_id in agent_ids
            if self.check_degradation(agent_id, customer_id)
        ]

    def get_all_windows(self, customer_id: str) -> list[PerformanceWindow]:
        """Return all current windows for all agents in this customer."""
        agent_ids = {agent_id for (agent_id, cid) in self._runs if cid == customer_id}
        windows = []
        for agent_id in agent_ids:
            window = self.get_current_window(agent_id, customer_id)
            if window is not None:
                windows.append(window)
        return windows

    def reset_agent(self, agent_id: str, customer_id: str) -> None:
        """Clear history for an agent (e.g., after retraining)."""
        self._runs.pop((agent_id, customer_id), None)
