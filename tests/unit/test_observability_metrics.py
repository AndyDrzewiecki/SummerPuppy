"""Unit tests for Prometheus metrics registry (Phase 12)."""

from __future__ import annotations

import pytest

from summer_puppy.observability.metrics import (
    METRIC_ACTIVE_PIPELINES,
    METRIC_API_REQUESTS_TOTAL,
    METRIC_EVENTS_RECEIVED_TOTAL,
    METRIC_KAFKA_MESSAGES_PUBLISHED_TOTAL,
    METRIC_NEO4J_QUERY_DURATION_SECONDS,
    METRIC_PIPELINE_DURATION_SECONDS,
    METRIC_SKILL_PROMOTIONS_TOTAL,
    METRIC_WORKER_ACTIVE_TASKS,
    METRIC_DEFINITIONS,
    MetricDefinition,
    MetricsRegistry,
    get_metrics,
    reset_metrics,
)


@pytest.fixture(autouse=True)
def reset_singleton() -> None:
    """Reset the metrics singleton between tests."""
    reset_metrics()
    yield
    reset_metrics()


# ---------------------------------------------------------------------------
# MetricDefinition
# ---------------------------------------------------------------------------


class TestMetricDefinition:
    def test_fields(self) -> None:
        d = MetricDefinition(
            name="my_metric",
            metric_type="counter",
            help_text="A test metric",
            labels=["env"],
        )
        assert d.name == "my_metric"
        assert d.metric_type == "counter"
        assert d.labels == ["env"]
        assert d.buckets is None

    def test_histogram_with_buckets(self) -> None:
        d = MetricDefinition(
            name="latency",
            metric_type="histogram",
            help_text="Latency",
            buckets=[0.1, 0.5, 1.0],
        )
        assert d.buckets == [0.1, 0.5, 1.0]


# ---------------------------------------------------------------------------
# METRIC_DEFINITIONS catalogue
# ---------------------------------------------------------------------------


class TestMetricDefinitionsCatalogue:
    def test_all_expected_metrics_present(self) -> None:
        names = {d.name for d in METRIC_DEFINITIONS}
        assert METRIC_EVENTS_RECEIVED_TOTAL in names
        assert METRIC_PIPELINE_DURATION_SECONDS in names
        assert METRIC_ACTIVE_PIPELINES in names
        assert METRIC_KAFKA_MESSAGES_PUBLISHED_TOTAL in names
        assert METRIC_NEO4J_QUERY_DURATION_SECONDS in names
        assert METRIC_WORKER_ACTIVE_TASKS in names
        assert METRIC_SKILL_PROMOTIONS_TOTAL in names
        assert METRIC_API_REQUESTS_TOTAL in names

    def test_all_have_help_text(self) -> None:
        for d in METRIC_DEFINITIONS:
            assert d.help_text, f"{d.name} missing help_text"

    def test_all_have_valid_type(self) -> None:
        valid_types = {"counter", "gauge", "histogram", "summary"}
        for d in METRIC_DEFINITIONS:
            assert d.metric_type in valid_types, f"{d.name} has invalid type {d.metric_type}"

    def test_events_received_has_labels(self) -> None:
        defn = next(d for d in METRIC_DEFINITIONS if d.name == METRIC_EVENTS_RECEIVED_TOTAL)
        assert "customer_id" in defn.labels
        assert "severity" in defn.labels

    def test_histograms_have_buckets(self) -> None:
        histograms = [d for d in METRIC_DEFINITIONS if d.metric_type == "histogram"]
        for h in histograms:
            assert h.buckets is not None, f"{h.name} histogram missing buckets"
            assert len(h.buckets) > 0

    def test_pipeline_duration_buckets_cover_slo(self) -> None:
        defn = next(d for d in METRIC_DEFINITIONS if d.name == METRIC_PIPELINE_DURATION_SECONDS)
        assert defn.buckets is not None
        assert 60.0 in defn.buckets  # MTTC SLO is 60s


# ---------------------------------------------------------------------------
# MetricsRegistry — init
# ---------------------------------------------------------------------------


class TestMetricsRegistryInit:
    def test_not_initialized_by_default(self) -> None:
        reg = MetricsRegistry()
        assert reg.is_initialized is False

    def test_get_metric_names_returns_all(self) -> None:
        reg = MetricsRegistry()
        names = reg.get_metric_names()
        assert len(names) == len(METRIC_DEFINITIONS)

    def test_get_definition_known_metric(self) -> None:
        reg = MetricsRegistry()
        defn = reg.get_definition(METRIC_EVENTS_RECEIVED_TOTAL)
        assert defn is not None
        assert defn.name == METRIC_EVENTS_RECEIVED_TOTAL

    def test_get_definition_unknown_returns_none(self) -> None:
        reg = MetricsRegistry()
        assert reg.get_definition("nonexistent_metric") is None


# ---------------------------------------------------------------------------
# MetricsRegistry — no-op when not initialized
# ---------------------------------------------------------------------------


class TestMetricsRegistryNoOp:
    def test_increment_is_noop_when_not_initialized(self) -> None:
        reg = MetricsRegistry()
        # Should not raise
        reg.increment(METRIC_EVENTS_RECEIVED_TOTAL, labels={"customer_id": "c", "severity": "HIGH", "source": "siem"})

    def test_set_gauge_is_noop_when_not_initialized(self) -> None:
        reg = MetricsRegistry()
        reg.set_gauge(METRIC_ACTIVE_PIPELINES, 5.0, labels={"customer_id": "c"})

    def test_observe_is_noop_when_not_initialized(self) -> None:
        reg = MetricsRegistry()
        reg.observe(METRIC_PIPELINE_DURATION_SECONDS, 2.5, labels={"customer_id": "c", "severity": "HIGH"})

    def test_generate_latest_returns_empty_when_not_initialized(self) -> None:
        reg = MetricsRegistry()
        assert reg.generate_latest() == b""

    def test_increment_gauge_is_noop(self) -> None:
        reg = MetricsRegistry()
        reg.increment_gauge(METRIC_ACTIVE_PIPELINES)

    def test_decrement_gauge_is_noop(self) -> None:
        reg = MetricsRegistry()
        reg.decrement_gauge(METRIC_ACTIVE_PIPELINES)


# ---------------------------------------------------------------------------
# MetricsRegistry — with prometheus_client (if installed)
# ---------------------------------------------------------------------------


class TestMetricsRegistryWithPrometheus:
    def test_initialize_with_separate_registry(self) -> None:
        try:
            from prometheus_client import CollectorRegistry

            test_registry = CollectorRegistry()
            reg = MetricsRegistry(registry=test_registry)
            reg.initialize()
            assert reg.is_initialized is True
        except ImportError:
            pytest.skip("prometheus_client not installed")

    def test_initialize_is_idempotent(self) -> None:
        try:
            from prometheus_client import CollectorRegistry

            test_registry = CollectorRegistry()
            reg = MetricsRegistry(registry=test_registry)
            reg.initialize()
            reg.initialize()  # second call should be no-op
            assert reg.is_initialized is True
        except ImportError:
            pytest.skip("prometheus_client not installed")

    def test_increment_counter_after_init(self) -> None:
        try:
            from prometheus_client import CollectorRegistry

            test_registry = CollectorRegistry()
            reg = MetricsRegistry(registry=test_registry)
            reg.initialize()
            # Should not raise
            reg.increment(
                METRIC_EVENTS_RECEIVED_TOTAL,
                labels={"customer_id": "c1", "severity": "HIGH", "source": "siem"},
            )
        except ImportError:
            pytest.skip("prometheus_client not installed")

    def test_set_gauge_after_init(self) -> None:
        try:
            from prometheus_client import CollectorRegistry

            test_registry = CollectorRegistry()
            reg = MetricsRegistry(registry=test_registry)
            reg.initialize()
            reg.set_gauge(METRIC_ACTIVE_PIPELINES, 3.0, labels={"customer_id": "c1"})
        except ImportError:
            pytest.skip("prometheus_client not installed")

    def test_observe_histogram_after_init(self) -> None:
        try:
            from prometheus_client import CollectorRegistry

            test_registry = CollectorRegistry()
            reg = MetricsRegistry(registry=test_registry)
            reg.initialize()
            reg.observe(
                METRIC_PIPELINE_DURATION_SECONDS,
                15.3,
                labels={"customer_id": "c1", "severity": "CRITICAL"},
            )
        except ImportError:
            pytest.skip("prometheus_client not installed")

    def test_generate_latest_returns_bytes(self) -> None:
        try:
            from prometheus_client import CollectorRegistry

            test_registry = CollectorRegistry()
            reg = MetricsRegistry(registry=test_registry)
            reg.initialize()
            output = reg.generate_latest()
            assert isinstance(output, bytes)
        except ImportError:
            pytest.skip("prometheus_client not installed")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


class TestGetMetricsSingleton:
    def test_returns_same_instance(self) -> None:
        r1 = get_metrics()
        r2 = get_metrics()
        assert r1 is r2

    def test_reset_clears_singleton(self) -> None:
        r1 = get_metrics()
        reset_metrics()
        r2 = get_metrics()
        assert r1 is not r2
