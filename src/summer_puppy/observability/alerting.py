"""Prometheus alerting rules definitions for SummerPuppy (Phase 12).

Provides Pythonic alert rule models and a function to render them as
Prometheus YAML so they can be written to disk or served via the Ruler API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AlertSeverity(StrEnum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass
class AlertRule:
    """A single Prometheus alerting rule."""

    name: str
    expr: str  # PromQL expression
    duration: str  # e.g. "5m", "1m", "30s"
    severity: AlertSeverity
    summary: str
    description: str
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)


@dataclass
class AlertGroup:
    """A named group of alert rules."""

    name: str
    rules: list[AlertRule]
    interval: str = "1m"


# ---------------------------------------------------------------------------
# Default alert rules for SummerPuppy
# ---------------------------------------------------------------------------

ALERT_RULES: list[AlertGroup] = [
    AlertGroup(
        name="summerpuppy.pipeline",
        rules=[
            AlertRule(
                name="HighEventFailureRate",
                expr=(
                    "rate(summerpuppy_events_failed_total[5m]) / "
                    "rate(summerpuppy_events_received_total[5m]) > 0.05"
                ),
                duration="5m",
                severity=AlertSeverity.CRITICAL,
                summary="High event processing failure rate",
                description=(
                    "More than 5% of security events are failing to process. "
                    "Investigate pipeline logs immediately."
                ),
            ),
            AlertRule(
                name="SlowPipelineP99",
                expr=(
                    "histogram_quantile(0.99, "
                    "rate(summerpuppy_pipeline_duration_seconds_bucket[5m])) > 60"
                ),
                duration="5m",
                severity=AlertSeverity.WARNING,
                summary="P99 pipeline duration exceeds 60 seconds",
                description=(
                    "The 99th percentile pipeline duration has exceeded the 60-second SLO. "
                    "MTTC may be at risk."
                ),
            ),
            AlertRule(
                name="NoEventsReceived",
                expr="rate(summerpuppy_events_received_total[15m]) == 0",
                duration="15m",
                severity=AlertSeverity.WARNING,
                summary="No security events received for 15 minutes",
                description=(
                    "SummerPuppy has received no security events in the last 15 minutes. "
                    "Check ingest pipeline and customer agents."
                ),
            ),
        ],
    ),
    AlertGroup(
        name="summerpuppy.infrastructure",
        rules=[
            AlertRule(
                name="Neo4jUnhealthy",
                expr='summerpuppy_component_health{component="neo4j"} == 0',
                duration="2m",
                severity=AlertSeverity.CRITICAL,
                summary="Neo4j knowledge graph is unreachable",
                description="Neo4j connection has been failing for 2+ minutes.",
            ),
            AlertRule(
                name="RedisUnhealthy",
                expr='summerpuppy_component_health{component="redis"} == 0',
                duration="2m",
                severity=AlertSeverity.CRITICAL,
                summary="Redis state store is unreachable",
                description=(
                    "Redis has been failing for 2+ minutes. "
                    "Worker coordination and distributed locking are impaired."
                ),
            ),
            AlertRule(
                name="KafkaUnhealthy",
                expr='summerpuppy_component_health{component="kafka"} == 0',
                duration="2m",
                severity=AlertSeverity.CRITICAL,
                summary="Kafka broker is unreachable",
                description=(
                    "Kafka has been failing for 2+ minutes. "
                    "Event streaming is impaired."
                ),
            ),
            AlertRule(
                name="HighKafkaConsumerLag",
                expr="summerpuppy_kafka_consumer_lag > 10000",
                duration="10m",
                severity=AlertSeverity.WARNING,
                summary="Kafka consumer group lag is high",
                description=(
                    "A Kafka consumer group has accumulated more than 10,000 unprocessed "
                    "messages. Scale workers or investigate processing bottlenecks."
                ),
            ),
        ],
    ),
    AlertGroup(
        name="summerpuppy.trust",
        rules=[
            AlertRule(
                name="HighHumanOverrideRate",
                expr=(
                    "rate(summerpuppy_human_rejections_total[1h]) / "
                    "(rate(summerpuppy_human_approvals_total[1h]) + "
                    "rate(summerpuppy_human_rejections_total[1h]) + 0.001) > 0.20"
                ),
                duration="30m",
                severity=AlertSeverity.WARNING,
                summary="Human rejection rate exceeds 20%",
                description=(
                    "More than 20% of human-reviewed actions are being rejected. "
                    "Review recommendation quality and trust thresholds."
                ),
            ),
        ],
    ),
    AlertGroup(
        name="summerpuppy.workers",
        rules=[
            AlertRule(
                name="NoHealthyWorkers",
                expr="sum(summerpuppy_worker_active_tasks) == 0",
                duration="5m",
                severity=AlertSeverity.CRITICAL,
                summary="No healthy worker instances",
                description="All SummerPuppy workers appear to be inactive.",
            ),
        ],
    ),
]


def render_prometheus_yaml() -> str:
    """Render all alert rules as a Prometheus rules YAML string."""
    import yaml  # type: ignore[import-untyped]

    groups: list[dict[str, Any]] = []
    for group in ALERT_RULES:
        rules_list: list[dict[str, Any]] = []
        for rule in group.rules:
            rules_list.append(
                {
                    "alert": rule.name,
                    "expr": rule.expr,
                    "for": rule.duration,
                    "labels": {"severity": rule.severity.value, **rule.labels},
                    "annotations": {
                        "summary": rule.summary,
                        "description": rule.description,
                        **rule.annotations,
                    },
                }
            )
        groups.append(
            {
                "name": group.name,
                "interval": group.interval,
                "rules": rules_list,
            }
        )

    return yaml.dump({"groups": groups}, default_flow_style=False, sort_keys=False)


def get_all_alert_rules() -> list[AlertRule]:
    """Return a flat list of all defined alert rules."""
    return [rule for group in ALERT_RULES for rule in group.rules]


def get_alert_rule(name: str) -> AlertRule | None:
    """Return the AlertRule with the given name, or None."""
    for rule in get_all_alert_rules():
        if rule.name == name:
            return rule
    return None
