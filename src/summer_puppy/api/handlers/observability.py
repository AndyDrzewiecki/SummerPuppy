"""Observability API endpoints: detailed health, Prometheus metrics (Phase 12)."""

from __future__ import annotations

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse

from summer_puppy.observability.health import HealthAggregator, HealthReport, HealthStatus
from summer_puppy.observability.metrics import get_metrics

router = APIRouter()

# Module-level health aggregator — wired at startup by the application
_health_aggregator: HealthAggregator | None = None


def set_health_aggregator(aggregator: HealthAggregator) -> None:
    """Wire the health aggregator (called during app startup)."""
    global _health_aggregator  # noqa: PLW0603
    _health_aggregator = aggregator


def get_health_aggregator() -> HealthAggregator:
    global _health_aggregator  # noqa: PLW0603
    if _health_aggregator is None:
        _health_aggregator = HealthAggregator()
    return _health_aggregator


@router.get("/health/detailed", response_model=HealthReport, tags=["observability"])
async def detailed_health() -> JSONResponse:
    """Detailed health report for all production components.

    Returns 200 if healthy, 207 if degraded, 503 if unhealthy.
    """
    aggregator = get_health_aggregator()
    report = await aggregator.run_checks()

    status_code: int
    if report.overall_status == HealthStatus.HEALTHY:
        status_code = 200
    elif report.overall_status == HealthStatus.DEGRADED:
        status_code = 207
    else:
        status_code = 503

    return JSONResponse(
        content=report.model_dump(mode="json"),
        status_code=status_code,
    )


@router.get("/metrics", tags=["observability"], include_in_schema=False)
async def prometheus_metrics() -> Response:
    """Expose Prometheus metrics in text format for scraping."""
    metrics = get_metrics()
    content = metrics.generate_latest()
    return Response(
        content=content,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/health/components", tags=["observability"])
async def list_health_components() -> dict[str, list[str]]:
    """List all registered health check components."""
    aggregator = get_health_aggregator()
    return {"components": aggregator.registered_components}
