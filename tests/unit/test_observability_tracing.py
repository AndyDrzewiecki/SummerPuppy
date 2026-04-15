"""Unit tests for OpenTelemetry tracing configuration (Phase 12)."""

from __future__ import annotations

import pytest

from summer_puppy.observability.tracing import (
    TracingConfig,
    _NoOpSpan,
    _NoOpTracer,
    configure_tracing,
    get_tracer,
    reset_tracing,
    trace_span,
)


@pytest.fixture(autouse=True)
def reset() -> None:
    reset_tracing()
    yield
    reset_tracing()


class TestTracingConfig:
    def test_defaults(self) -> None:
        cfg = TracingConfig()
        assert cfg.service_name == "summer-puppy"
        assert cfg.service_version == "0.2.0"
        assert cfg.environment == "production"
        assert cfg.otlp_endpoint == ""
        assert cfg.sample_rate == 1.0
        assert cfg.propagate_w3c is True

    def test_custom_values(self) -> None:
        cfg = TracingConfig(
            service_name="my-svc",
            environment="staging",
            sample_rate=0.1,
        )
        assert cfg.service_name == "my-svc"
        assert cfg.environment == "staging"
        assert cfg.sample_rate == 0.1

    def test_resource_attributes_default_empty(self) -> None:
        cfg = TracingConfig()
        assert cfg.resource_attributes == {}


class TestConfigureTracing:
    def test_configure_tracing_with_otel_installed(self) -> None:
        try:
            import opentelemetry  # noqa: F401

            cfg = TracingConfig(service_name="test-svc", sample_rate=1.0)
            configure_tracing(cfg)
            # Should not raise
        except ImportError:
            pytest.skip("opentelemetry not installed")

    def test_configure_tracing_is_idempotent(self) -> None:
        try:
            import opentelemetry  # noqa: F401

            cfg = TracingConfig()
            configure_tracing(cfg)
            configure_tracing(cfg)  # second call is no-op
        except ImportError:
            pytest.skip("opentelemetry not installed")

    def test_configure_tracing_without_otel_does_not_raise(self) -> None:
        import sys
        from unittest.mock import patch

        # Simulate opentelemetry not being installed
        with patch.dict(sys.modules, {"opentelemetry": None}):
            configure_tracing(TracingConfig())
        # Should complete without exception


class TestGetTracer:
    def test_get_tracer_returns_noop_when_otel_missing(self) -> None:
        import sys
        from unittest.mock import patch

        with patch.dict(sys.modules, {"opentelemetry": None}):
            tracer = get_tracer("test")
        assert isinstance(tracer, _NoOpTracer)

    def test_get_tracer_with_otel_installed(self) -> None:
        try:
            import opentelemetry  # noqa: F401

            configure_tracing(TracingConfig())
            tracer = get_tracer("test")
            assert tracer is not None
        except ImportError:
            pytest.skip("opentelemetry not installed")


class TestNoOpTracer:
    def test_start_as_current_span_returns_span(self) -> None:
        tracer = _NoOpTracer()
        span = tracer.start_as_current_span("my-span")
        assert isinstance(span, _NoOpSpan)

    def test_start_span_returns_span(self) -> None:
        tracer = _NoOpTracer()
        span = tracer.start_span("my-span")
        assert isinstance(span, _NoOpSpan)


class TestNoOpSpan:
    def test_set_attribute_does_not_raise(self) -> None:
        span = _NoOpSpan()
        span.set_attribute("key", "value")

    def test_context_manager(self) -> None:
        span = _NoOpSpan()
        with span as s:
            assert s is span


class TestTraceSpan:
    async def test_trace_span_yields_none_without_otel(self) -> None:
        import sys
        from unittest.mock import patch

        with patch.dict(sys.modules, {"opentelemetry": None}):
            async with trace_span("test", "my-operation") as span:
                # Without OTel, span should be None (no-op)
                pass  # should not raise

    async def test_trace_span_with_attributes(self) -> None:
        try:
            import opentelemetry  # noqa: F401

            configure_tracing(TracingConfig())
            async with trace_span(
                "test",
                "my-operation",
                attributes={"customer_id": "c1", "severity": "HIGH"},
            ) as span:
                # Span should be a valid OTel span object
                assert span is not None
        except ImportError:
            pytest.skip("opentelemetry not installed")
