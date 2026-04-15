"""OpenTelemetry tracing configuration for SummerPuppy (Phase 12).

Provides a thin wrapper around the OTel SDK that can be configured once at
startup and then used via the standard ``opentelemetry.trace`` API anywhere
in the codebase.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from summer_puppy.logging.config import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = get_logger(__name__)


@dataclass
class TracingConfig:
    """Configuration for OpenTelemetry tracing."""

    service_name: str = "summer-puppy"
    service_version: str = "0.2.0"
    environment: str = "production"
    # OTLP exporter endpoint (empty = disabled)
    otlp_endpoint: str = ""
    # Jaeger exporter endpoint (empty = disabled)
    jaeger_endpoint: str = ""
    # Sampling rate: 1.0 = always, 0.0 = never, 0.1 = 10%
    sample_rate: float = 1.0
    # Whether to propagate W3C trace context headers
    propagate_w3c: bool = True
    # Additional resource attributes
    resource_attributes: dict[str, str] = field(default_factory=dict)


_tracer_provider: Any = None
_configured: bool = False


def configure_tracing(config: TracingConfig) -> None:
    """Initialise the OpenTelemetry tracer provider.  Idempotent."""
    global _tracer_provider, _configured  # noqa: PLW0603

    if _configured:
        return

    try:
        from opentelemetry import trace  # type: ignore[import-untyped]
        from opentelemetry.sdk.resources import Resource  # type: ignore[import-untyped]
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import-untyped]
        from opentelemetry.sdk.trace.sampling import (  # type: ignore[import-untyped]
            ParentBased,
            TraceIdRatioBased,
        )

        resource_attrs = {
            "service.name": config.service_name,
            "service.version": config.service_version,
            "deployment.environment": config.environment,
            **config.resource_attributes,
        }
        resource = Resource.create(resource_attrs)

        sampler = ParentBased(root=TraceIdRatioBased(config.sample_rate))
        provider = TracerProvider(resource=resource, sampler=sampler)

        # OTLP exporter
        if config.otlp_endpoint:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore[import-untyped]
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.trace.export import (  # type: ignore[import-untyped]
                BatchSpanProcessor,
            )

            exporter = OTLPSpanExporter(endpoint=config.otlp_endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info("otel_otlp_exporter_configured", endpoint=config.otlp_endpoint)

        # W3C trace context propagation
        if config.propagate_w3c:
            from opentelemetry.propagate import set_global_textmap  # type: ignore[import-untyped]
            from opentelemetry.propagators.composite import (  # type: ignore[import-untyped]
                CompositePropagator,
            )
            from opentelemetry.trace.propagation.tracecontext import (  # type: ignore[import-untyped]
                TraceContextTextMapPropagator,
            )

            set_global_textmap(
                CompositePropagator([TraceContextTextMapPropagator()])
            )

        trace.set_tracer_provider(provider)
        _tracer_provider = provider
        _configured = True
        logger.info(
            "otel_tracing_configured",
            service=config.service_name,
            sample_rate=config.sample_rate,
        )
    except ImportError:
        logger.warning("opentelemetry_not_installed_tracing_disabled")


def get_tracer(name: str) -> Any:
    """Return an OTel tracer (or a no-op tracer if OTel is not installed)."""
    try:
        from opentelemetry import trace  # type: ignore[import-untyped]

        return trace.get_tracer(name)
    except ImportError:
        return _NoOpTracer()


@asynccontextmanager
async def trace_span(
    tracer_name: str,
    span_name: str,
    attributes: dict[str, Any] | None = None,
) -> AsyncIterator[Any]:
    """Async context manager that creates a named span.

    Falls back to a no-op if OpenTelemetry is not installed.
    """
    try:
        from opentelemetry import trace  # type: ignore[import-untyped]

        tracer = trace.get_tracer(tracer_name)
        with tracer.start_as_current_span(span_name) as span:
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, v)
            yield span
    except ImportError:
        yield None  # no-op span


def reset_tracing() -> None:
    """Reset tracing state (for testing only)."""
    global _tracer_provider, _configured  # noqa: PLW0603
    _tracer_provider = None
    _configured = False


# ---------------------------------------------------------------------------
# No-op tracer (used when opentelemetry is not installed)
# ---------------------------------------------------------------------------


class _NoOpSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def __enter__(self) -> "_NoOpSpan":
        return self

    def __exit__(self, *_: Any) -> None:
        pass


class _NoOpTracer:
    def start_as_current_span(self, name: str) -> "_NoOpSpan":
        return _NoOpSpan()

    def start_span(self, name: str) -> "_NoOpSpan":
        return _NoOpSpan()
