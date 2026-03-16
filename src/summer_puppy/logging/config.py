"""Structured logging configuration for SummerPuppy."""

from __future__ import annotations

from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, MutableMapping

_correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)
_tenant_id_var: ContextVar[str | None] = ContextVar("tenant_id", default=None)

_configured: bool = False


def inject_context(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Structlog processor that injects correlation_id and tenant_id from contextvars."""
    correlation_id = _correlation_id_var.get(None)
    if correlation_id is not None:
        event_dict["correlation_id"] = correlation_id

    tenant_id = _tenant_id_var.get(None)
    if tenant_id is not None:
        event_dict["tenant_id"] = tenant_id

    return event_dict


def configure_logging(
    level: str = "INFO",
    fmt: str = "json",
    tenant_id: str | None = None,
) -> None:
    """Configure structlog with standard processors.

    Idempotent: subsequent calls after the first are no-ops.
    """
    global _configured  # noqa: PLW0603

    if _configured:
        return

    if tenant_id is not None:
        _tenant_id_var.set(tenant_id)

    renderer: structlog.types.Processor
    if fmt == "console":
        renderer = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            inject_context,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )

    _configured = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a structlog bound logger with the given name.

    Calls configure_logging() if not yet configured.
    """
    if not _configured:
        configure_logging()

    return structlog.get_logger(name)  # type: ignore[no-any-return]


@asynccontextmanager
async def correlation_context(correlation_id: str) -> AsyncIterator[None]:
    """Async context manager that sets/clears correlation_id in contextvars."""
    token = _correlation_id_var.set(correlation_id)
    try:
        yield
    finally:
        _correlation_id_var.reset(token)


@asynccontextmanager
async def tenant_context(tenant_id: str) -> AsyncIterator[None]:
    """Async context manager that sets/clears tenant_id in contextvars."""
    token = _tenant_id_var.set(tenant_id)
    try:
        yield
    finally:
        _tenant_id_var.reset(token)


def _reset_logging() -> None:
    """Reset configured state. For test use only."""
    global _configured  # noqa: PLW0603
    _configured = False
