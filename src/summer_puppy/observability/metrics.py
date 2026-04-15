"""Prometheus metrics registry for SummerPuppy (Phase 12).

Defines all application metrics in one place and exposes a singleton
``MetricsRegistry`` accessible via ``get_metrics()``.

Metrics are lazily registered — importing this module does NOT start a
Prometheus HTTP server.  Callers should scrape via the ``/metrics``
FastAPI endpoint added in Phase 12.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from summer_puppy.logging.config import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Metric name constants
# ---------------------------------------------------------------------------

METRIC_EVENTS_RECEIVED_TOTAL = "summerpuppy_events_received_total"
METRIC_EVENTS_PROCESSED_TOTAL = "summerpuppy_events_processed_total"
METRIC_EVENTS_FAILED_TOTAL = "summerpuppy_events_failed_total"
METRIC_PIPELINE_DURATION_SECONDS = "summerpuppy_pipeline_duration_seconds"
METRIC_PIPELINE_STAGE_DURATION_SECONDS = "summerpuppy_pipeline_stage_duration_seconds"
METRIC_ACTIVE_PIPELINES = "summerpuppy_active_pipelines"
METRIC_TRUST_PHASE_TRANSITIONS_TOTAL = "summerpuppy_trust_phase_transitions_total"
METRIC_AUTO_APPROVALS_TOTAL = "summerpuppy_auto_approvals_total"
METRIC_HUMAN_APPROVALS_TOTAL = "summerpuppy_human_approvals_total"
METRIC_HUMAN_REJECTIONS_TOTAL = "summerpuppy_human_rejections_total"
METRIC_SKILL_PROMOTIONS_TOTAL = "summerpuppy_skill_promotions_total"
METRIC_KAFKA_MESSAGES_PUBLISHED_TOTAL = "summerpuppy_kafka_messages_published_total"
METRIC_KAFKA_MESSAGES_CONSUMED_TOTAL = "summerpuppy_kafka_messages_consumed_total"
METRIC_NEO4J_QUERY_DURATION_SECONDS = "summerpuppy_neo4j_query_duration_seconds"
METRIC_REDIS_OPERATIONS_TOTAL = "summerpuppy_redis_operations_total"
METRIC_API_REQUEST_DURATION_SECONDS = "summerpuppy_api_request_duration_seconds"
METRIC_API_REQUESTS_TOTAL = "summerpuppy_api_requests_total"
METRIC_WORKER_ACTIVE_TASKS = "summerpuppy_worker_active_tasks"
METRIC_SANDBOX_ANALYSES_TOTAL = "summerpuppy_sandbox_analyses_total"


@dataclass
class MetricDefinition:
    """Descriptor for a single Prometheus metric."""

    name: str
    metric_type: str  # counter | gauge | histogram | summary
    help_text: str
    labels: list[str] = field(default_factory=list)
    buckets: list[float] | None = None  # for histograms


# ---------------------------------------------------------------------------
# Metric catalogue
# ---------------------------------------------------------------------------

METRIC_DEFINITIONS: list[MetricDefinition] = [
    MetricDefinition(
        name=METRIC_EVENTS_RECEIVED_TOTAL,
        metric_type="counter",
        help_text="Total security events received",
        labels=["customer_id", "severity", "source"],
    ),
    MetricDefinition(
        name=METRIC_EVENTS_PROCESSED_TOTAL,
        metric_type="counter",
        help_text="Total security events successfully processed",
        labels=["customer_id", "severity"],
    ),
    MetricDefinition(
        name=METRIC_EVENTS_FAILED_TOTAL,
        metric_type="counter",
        help_text="Total security events that failed during processing",
        labels=["customer_id", "stage"],
    ),
    MetricDefinition(
        name=METRIC_PIPELINE_DURATION_SECONDS,
        metric_type="histogram",
        help_text="End-to-end pipeline duration in seconds",
        labels=["customer_id", "severity"],
        buckets=[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0],
    ),
    MetricDefinition(
        name=METRIC_PIPELINE_STAGE_DURATION_SECONDS,
        metric_type="histogram",
        help_text="Duration of individual pipeline stages",
        labels=["stage"],
        buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0],
    ),
    MetricDefinition(
        name=METRIC_ACTIVE_PIPELINES,
        metric_type="gauge",
        help_text="Number of currently active pipeline executions",
        labels=["customer_id"],
    ),
    MetricDefinition(
        name=METRIC_TRUST_PHASE_TRANSITIONS_TOTAL,
        metric_type="counter",
        help_text="Trust phase transitions",
        labels=["customer_id", "from_phase", "to_phase"],
    ),
    MetricDefinition(
        name=METRIC_AUTO_APPROVALS_TOTAL,
        metric_type="counter",
        help_text="Actions automatically approved by trust engine",
        labels=["customer_id", "action_class"],
    ),
    MetricDefinition(
        name=METRIC_HUMAN_APPROVALS_TOTAL,
        metric_type="counter",
        help_text="Actions approved by a human operator",
        labels=["customer_id"],
    ),
    MetricDefinition(
        name=METRIC_HUMAN_REJECTIONS_TOTAL,
        metric_type="counter",
        help_text="Actions rejected by a human operator",
        labels=["customer_id"],
    ),
    MetricDefinition(
        name=METRIC_SKILL_PROMOTIONS_TOTAL,
        metric_type="counter",
        help_text="Knowledge articles promoted to a higher tier",
        labels=["customer_id", "promotion_level"],
    ),
    MetricDefinition(
        name=METRIC_KAFKA_MESSAGES_PUBLISHED_TOTAL,
        metric_type="counter",
        help_text="Total Kafka messages published",
        labels=["topic"],
    ),
    MetricDefinition(
        name=METRIC_KAFKA_MESSAGES_CONSUMED_TOTAL,
        metric_type="counter",
        help_text="Total Kafka messages consumed",
        labels=["topic", "consumer_group"],
    ),
    MetricDefinition(
        name=METRIC_NEO4J_QUERY_DURATION_SECONDS,
        metric_type="histogram",
        help_text="Neo4j query execution duration",
        labels=["operation"],
        buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
    ),
    MetricDefinition(
        name=METRIC_REDIS_OPERATIONS_TOTAL,
        metric_type="counter",
        help_text="Total Redis operations performed",
        labels=["operation", "status"],
    ),
    MetricDefinition(
        name=METRIC_API_REQUEST_DURATION_SECONDS,
        metric_type="histogram",
        help_text="HTTP API request duration",
        labels=["method", "path", "status_code"],
        buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    ),
    MetricDefinition(
        name=METRIC_API_REQUESTS_TOTAL,
        metric_type="counter",
        help_text="Total HTTP API requests",
        labels=["method", "path", "status_code"],
    ),
    MetricDefinition(
        name=METRIC_WORKER_ACTIVE_TASKS,
        metric_type="gauge",
        help_text="Number of active tasks on this worker",
        labels=["worker_id"],
    ),
    MetricDefinition(
        name=METRIC_SANDBOX_ANALYSES_TOTAL,
        metric_type="counter",
        help_text="Total sandbox analyses completed",
        labels=["customer_id", "verdict"],
    ),
]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class MetricsRegistry:
    """Wraps the prometheus_client registry and exposes typed metric objects.

    The registry registers all metrics on first instantiation and provides
    convenience methods for incrementing counters, recording observations,
    and setting gauges.
    """

    def __init__(self, registry: Any = None) -> None:
        """Create or use the provided prometheus_client CollectorRegistry."""
        self._registry = registry
        self._counters: dict[str, Any] = {}
        self._gauges: dict[str, Any] = {}
        self._histograms: dict[str, Any] = {}
        self._initialized = False

    def initialize(self) -> None:
        """Register all metrics with Prometheus (idempotent)."""
        if self._initialized:
            return

        try:
            from prometheus_client import (  # type: ignore[import-untyped]
                Counter,
                Gauge,
                Histogram,
                REGISTRY,
            )

            reg = self._registry or REGISTRY

            for defn in METRIC_DEFINITIONS:
                if defn.metric_type == "counter":
                    self._counters[defn.name] = Counter(
                        defn.name,
                        defn.help_text,
                        defn.labels,
                        registry=reg,
                    )
                elif defn.metric_type == "gauge":
                    self._gauges[defn.name] = Gauge(
                        defn.name,
                        defn.help_text,
                        defn.labels,
                        registry=reg,
                    )
                elif defn.metric_type == "histogram":
                    kwargs: dict[str, Any] = {
                        "registry": reg,
                    }
                    if defn.buckets:
                        kwargs["buckets"] = defn.buckets
                    self._histograms[defn.name] = Histogram(
                        defn.name,
                        defn.help_text,
                        defn.labels,
                        **kwargs,
                    )

            self._initialized = True
            logger.info("prometheus_metrics_registered", count=len(METRIC_DEFINITIONS))
        except ImportError:
            logger.warning("prometheus_client_not_installed_metrics_disabled")

    # ------------------------------------------------------------------
    # Counter helpers
    # ------------------------------------------------------------------

    def increment(self, name: str, labels: dict[str, str] | None = None, amount: float = 1) -> None:
        """Increment a counter metric."""
        counter = self._counters.get(name)
        if counter is None:
            return
        if labels:
            counter.labels(**labels).inc(amount)
        else:
            counter.inc(amount)

    # ------------------------------------------------------------------
    # Gauge helpers
    # ------------------------------------------------------------------

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Set a gauge metric to a specific value."""
        gauge = self._gauges.get(name)
        if gauge is None:
            return
        if labels:
            gauge.labels(**labels).set(value)
        else:
            gauge.set(value)

    def increment_gauge(
        self, name: str, amount: float = 1, labels: dict[str, str] | None = None
    ) -> None:
        """Increment a gauge metric."""
        gauge = self._gauges.get(name)
        if gauge is None:
            return
        if labels:
            gauge.labels(**labels).inc(amount)
        else:
            gauge.inc(amount)

    def decrement_gauge(
        self, name: str, amount: float = 1, labels: dict[str, str] | None = None
    ) -> None:
        """Decrement a gauge metric."""
        gauge = self._gauges.get(name)
        if gauge is None:
            return
        if labels:
            gauge.labels(**labels).dec(amount)
        else:
            gauge.dec(amount)

    # ------------------------------------------------------------------
    # Histogram helpers
    # ------------------------------------------------------------------

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Record an observation in a histogram."""
        hist = self._histograms.get(name)
        if hist is None:
            return
        if labels:
            hist.labels(**labels).observe(value)
        else:
            hist.observe(value)

    # ------------------------------------------------------------------
    # Prometheus output
    # ------------------------------------------------------------------

    def generate_latest(self) -> bytes:
        """Generate Prometheus text format metrics output."""
        if not self._initialized:
            return b""
        try:
            from prometheus_client import (  # type: ignore[import-untyped]
                CONTENT_TYPE_LATEST,
                REGISTRY,
                generate_latest,
            )

            reg = self._registry or REGISTRY
            return generate_latest(reg)  # type: ignore[no-any-return]
        except ImportError:
            return b""

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    def get_metric_names(self) -> list[str]:
        return [d.name for d in METRIC_DEFINITIONS]

    def get_definition(self, name: str) -> MetricDefinition | None:
        for d in METRIC_DEFINITIONS:
            if d.name == name:
                return d
        return None


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_registry: MetricsRegistry | None = None


def get_metrics() -> MetricsRegistry:
    """Return the singleton MetricsRegistry, creating it if necessary."""
    global _registry  # noqa: PLW0603
    if _registry is None:
        _registry = MetricsRegistry()
    return _registry


def reset_metrics() -> None:
    """Reset the singleton (for testing only)."""
    global _registry  # noqa: PLW0603
    _registry = None
