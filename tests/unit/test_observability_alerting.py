"""Unit tests for Prometheus alerting rules (Phase 12)."""

from __future__ import annotations

import pytest

from summer_puppy.observability.alerting import (
    ALERT_RULES,
    AlertGroup,
    AlertRule,
    AlertSeverity,
    get_alert_rule,
    get_all_alert_rules,
    render_prometheus_yaml,
)


class TestAlertSeverity:
    def test_values(self) -> None:
        assert AlertSeverity.CRITICAL == "critical"
        assert AlertSeverity.WARNING == "warning"
        assert AlertSeverity.INFO == "info"


class TestAlertRule:
    def test_fields(self) -> None:
        rule = AlertRule(
            name="TestAlert",
            expr="metric > 0",
            duration="5m",
            severity=AlertSeverity.WARNING,
            summary="Test summary",
            description="Test description",
        )
        assert rule.name == "TestAlert"
        assert rule.expr == "metric > 0"
        assert rule.duration == "5m"
        assert rule.severity == AlertSeverity.WARNING
        assert rule.labels == {}
        assert rule.annotations == {}


class TestAlertGroup:
    def test_fields(self) -> None:
        group = AlertGroup(
            name="test.group",
            rules=[
                AlertRule(
                    name="Alert1",
                    expr="x > 1",
                    duration="1m",
                    severity=AlertSeverity.INFO,
                    summary="s",
                    description="d",
                )
            ],
        )
        assert group.name == "test.group"
        assert len(group.rules) == 1
        assert group.interval == "1m"


class TestAlertRulesCatalogue:
    def test_alert_rules_nonempty(self) -> None:
        assert len(ALERT_RULES) >= 3

    def test_all_groups_have_names(self) -> None:
        for group in ALERT_RULES:
            assert group.name

    def test_all_groups_have_rules(self) -> None:
        for group in ALERT_RULES:
            assert len(group.rules) >= 1, f"{group.name} has no rules"

    def test_all_rules_have_required_fields(self) -> None:
        for group in ALERT_RULES:
            for rule in group.rules:
                assert rule.name, f"Rule missing name in {group.name}"
                assert rule.expr, f"{rule.name} missing expr"
                assert rule.duration, f"{rule.name} missing duration"
                assert rule.summary, f"{rule.name} missing summary"
                assert rule.description, f"{rule.name} missing description"

    def test_high_event_failure_rate_rule_exists(self) -> None:
        rule = get_alert_rule("HighEventFailureRate")
        assert rule is not None
        assert rule.severity == AlertSeverity.CRITICAL

    def test_slow_pipeline_rule_exists(self) -> None:
        rule = get_alert_rule("SlowPipelineP99")
        assert rule is not None
        assert rule.severity == AlertSeverity.WARNING

    def test_no_events_received_rule_exists(self) -> None:
        rule = get_alert_rule("NoEventsReceived")
        assert rule is not None

    def test_neo4j_unhealthy_rule_exists(self) -> None:
        rule = get_alert_rule("Neo4jUnhealthy")
        assert rule is not None
        assert rule.severity == AlertSeverity.CRITICAL

    def test_redis_unhealthy_rule_exists(self) -> None:
        rule = get_alert_rule("RedisUnhealthy")
        assert rule is not None

    def test_kafka_unhealthy_rule_exists(self) -> None:
        rule = get_alert_rule("KafkaUnhealthy")
        assert rule is not None

    def test_high_human_override_rule_exists(self) -> None:
        rule = get_alert_rule("HighHumanOverrideRate")
        assert rule is not None
        # Override threshold should be >= 20%
        assert "0.20" in rule.expr

    def test_no_healthy_workers_rule_exists(self) -> None:
        rule = get_alert_rule("NoHealthyWorkers")
        assert rule is not None

    def test_get_all_alert_rules_returns_flat_list(self) -> None:
        rules = get_all_alert_rules()
        assert len(rules) > 0
        assert all(isinstance(r, AlertRule) for r in rules)

    def test_get_alert_rule_returns_none_for_unknown(self) -> None:
        assert get_alert_rule("NonexistentRule") is None


class TestRenderPrometheusYaml:
    def test_render_returns_string(self) -> None:
        try:
            import yaml  # noqa: F401
            result = render_prometheus_yaml()
            assert isinstance(result, str)
            assert len(result) > 0
        except ImportError:
            pytest.skip("pyyaml not installed")

    def test_render_contains_groups_key(self) -> None:
        try:
            import yaml

            result = render_prometheus_yaml()
            parsed = yaml.safe_load(result)
            assert "groups" in parsed
        except ImportError:
            pytest.skip("pyyaml not installed")

    def test_render_contains_alert_names(self) -> None:
        try:
            import yaml

            result = render_prometheus_yaml()
            assert "HighEventFailureRate" in result
            assert "Neo4jUnhealthy" in result
            assert "NoHealthyWorkers" in result
        except ImportError:
            pytest.skip("pyyaml not installed")

    def test_render_contains_severity_labels(self) -> None:
        try:
            import yaml

            result = render_prometheus_yaml()
            assert "critical" in result
            assert "warning" in result
        except ImportError:
            pytest.skip("pyyaml not installed")
