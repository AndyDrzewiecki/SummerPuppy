from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from summer_puppy.skills.performance import (
    AgentPerformanceTracker,
    DegradationAlert,
    DegradationAlertType,
    PerformanceWindow,
)


# ---------------------------------------------------------------------------
# PerformanceWindow tests
# ---------------------------------------------------------------------------


class TestPerformanceWindow:
    def _make_window(self, total: int, successful: int, overrides: int) -> PerformanceWindow:
        now = datetime.now(tz=UTC)
        return PerformanceWindow(
            agent_id="agent-1",
            customer_id="cust-1",
            window_start_utc=now - timedelta(minutes=60),
            window_end_utc=now,
            total_runs=total,
            successful_runs=successful,
            human_override_count=overrides,
        )

    def test_success_rate_zero_runs(self) -> None:
        w = self._make_window(total=0, successful=0, overrides=0)
        assert w.success_rate == 0.0

    def test_success_rate_calculation(self) -> None:
        w = self._make_window(total=5, successful=3, overrides=0)
        assert w.success_rate == pytest.approx(0.6)

    def test_override_rate_calculation(self) -> None:
        w = self._make_window(total=5, successful=3, overrides=2)
        assert w.override_rate == pytest.approx(0.4)

    def test_override_rate_zero_runs(self) -> None:
        w = self._make_window(total=0, successful=0, overrides=0)
        assert w.override_rate == 0.0


# ---------------------------------------------------------------------------
# AgentPerformanceTracker tests
# ---------------------------------------------------------------------------


class TestAgentPerformanceTracker:
    def test_record_run_increments_window(self) -> None:
        tracker = AgentPerformanceTracker()
        tracker.record_run("agent-1", "cust-1", success=True)
        tracker.record_run("agent-1", "cust-1", success=False)
        window = tracker.get_current_window("agent-1", "cust-1")
        assert window is not None
        assert window.total_runs == 2
        assert window.successful_runs == 1

    def test_no_window_before_runs(self) -> None:
        tracker = AgentPerformanceTracker()
        assert tracker.get_current_window("agent-1", "cust-1") is None

    def test_check_degradation_returns_empty_below_min_runs(self) -> None:
        tracker = AgentPerformanceTracker(min_runs_for_alert=5)
        # Record only 4 runs, all failures
        for _ in range(4):
            tracker.record_run("agent-1", "cust-1", success=False)
        alerts = tracker.check_degradation("agent-1", "cust-1")
        assert alerts == []

    def test_check_degradation_low_success_rate(self) -> None:
        tracker = AgentPerformanceTracker(
            success_rate_threshold=0.7,
            override_rate_threshold=0.9,  # high threshold so only success fires
            min_runs_for_alert=5,
        )
        for _ in range(5):
            tracker.record_run("agent-1", "cust-1", success=False)
        alerts = tracker.check_degradation("agent-1", "cust-1")
        alert_types = [a.alert_type for a in alerts]
        assert DegradationAlertType.LOW_SUCCESS_RATE in alert_types

    def test_check_degradation_high_override_rate(self) -> None:
        tracker = AgentPerformanceTracker(
            success_rate_threshold=0.0,  # low threshold so only override fires
            override_rate_threshold=0.3,
            min_runs_for_alert=5,
        )
        for _ in range(5):
            tracker.record_run("agent-1", "cust-1", success=True, human_override=True)
        alerts = tracker.check_degradation("agent-1", "cust-1")
        alert_types = [a.alert_type for a in alerts]
        assert DegradationAlertType.HIGH_OVERRIDE_RATE in alert_types

    def test_check_degradation_healthy_agent_no_alerts(self) -> None:
        tracker = AgentPerformanceTracker(
            success_rate_threshold=0.7,
            override_rate_threshold=0.3,
            min_runs_for_alert=5,
        )
        for _ in range(10):
            tracker.record_run("agent-1", "cust-1", success=True, human_override=False)
        alerts = tracker.check_degradation("agent-1", "cust-1")
        assert alerts == []

    def test_list_degraded_agents_returns_degraded(self) -> None:
        tracker = AgentPerformanceTracker(
            success_rate_threshold=0.7,
            min_runs_for_alert=5,
        )
        for _ in range(5):
            tracker.record_run("agent-bad", "cust-1", success=False)
        for _ in range(5):
            tracker.record_run("agent-good", "cust-1", success=True)

        degraded = tracker.list_degraded_agents("cust-1")
        assert "agent-bad" in degraded
        assert "agent-good" not in degraded

    def test_list_degraded_agents_empty_when_healthy(self) -> None:
        tracker = AgentPerformanceTracker(min_runs_for_alert=5)
        for _ in range(5):
            tracker.record_run("agent-1", "cust-1", success=True)
        assert tracker.list_degraded_agents("cust-1") == []

    def test_reset_agent_clears_history(self) -> None:
        tracker = AgentPerformanceTracker()
        for _ in range(5):
            tracker.record_run("agent-1", "cust-1", success=False)
        assert tracker.get_current_window("agent-1", "cust-1") is not None
        tracker.reset_agent("agent-1", "cust-1")
        assert tracker.get_current_window("agent-1", "cust-1") is None

    def test_get_all_windows_all_agents_for_customer(self) -> None:
        tracker = AgentPerformanceTracker()
        tracker.record_run("agent-1", "cust-1", success=True)
        tracker.record_run("agent-2", "cust-1", success=False)
        tracker.record_run("agent-3", "cust-2", success=True)  # different customer

        windows = tracker.get_all_windows("cust-1")
        assert len(windows) == 2
        agent_ids = {w.agent_id for w in windows}
        assert agent_ids == {"agent-1", "agent-2"}

    def test_window_excludes_old_runs(self) -> None:
        tracker = AgentPerformanceTracker(window_size_minutes=60)
        old_time = datetime.now(tz=UTC) - timedelta(minutes=90)
        recent_time = datetime.now(tz=UTC) - timedelta(minutes=10)

        tracker.record_run("agent-1", "cust-1", success=True, run_utc=old_time)
        tracker.record_run("agent-1", "cust-1", success=True, run_utc=recent_time)

        window = tracker.get_current_window("agent-1", "cust-1")
        assert window is not None
        assert window.total_runs == 1  # only recent run counts

    def test_multiple_customers_isolated(self) -> None:
        tracker = AgentPerformanceTracker(min_runs_for_alert=5)
        for _ in range(5):
            tracker.record_run("agent-1", "cust-1", success=False)
        for _ in range(5):
            tracker.record_run("agent-1", "cust-2", success=True)

        degraded_cust1 = tracker.list_degraded_agents("cust-1")
        degraded_cust2 = tracker.list_degraded_agents("cust-2")

        assert "agent-1" in degraded_cust1
        assert "agent-1" not in degraded_cust2

    def test_both_alert_types_can_fire_together(self) -> None:
        tracker = AgentPerformanceTracker(
            success_rate_threshold=0.7,
            override_rate_threshold=0.3,
            min_runs_for_alert=5,
        )
        # All runs fail and all have human overrides
        for _ in range(5):
            tracker.record_run("agent-1", "cust-1", success=False, human_override=True)

        alerts = tracker.check_degradation("agent-1", "cust-1")
        alert_types = {a.alert_type for a in alerts}
        assert DegradationAlertType.LOW_SUCCESS_RATE in alert_types
        assert DegradationAlertType.HIGH_OVERRIDE_RATE in alert_types

    def test_insufficient_data_alert_not_fired_by_default(self) -> None:
        # With default min_runs_for_alert=5, running < 5 runs should NOT fire INSUFFICIENT_DATA
        tracker = AgentPerformanceTracker(min_runs_for_alert=5)
        for _ in range(3):
            tracker.record_run("agent-1", "cust-1", success=False)

        alerts = tracker.check_degradation("agent-1", "cust-1")
        alert_types = [a.alert_type for a in alerts]
        assert DegradationAlertType.INSUFFICIENT_DATA not in alert_types
        assert alerts == []  # no alerts at all when insufficient data

    def test_alert_has_expected_fields(self) -> None:
        tracker = AgentPerformanceTracker(
            success_rate_threshold=0.7,
            min_runs_for_alert=5,
        )
        for _ in range(5):
            tracker.record_run("agent-1", "cust-1", success=False)

        alerts = tracker.check_degradation("agent-1", "cust-1")
        assert len(alerts) >= 1
        alert = next(a for a in alerts if a.alert_type == DegradationAlertType.LOW_SUCCESS_RATE)
        assert alert.agent_id == "agent-1"
        assert alert.customer_id == "cust-1"
        assert alert.threshold == pytest.approx(0.7)
        assert alert.current_value == pytest.approx(0.0)
        assert alert.alert_id  # non-empty string
        assert isinstance(alert.created_utc, datetime)
        assert alert.message  # non-empty string
