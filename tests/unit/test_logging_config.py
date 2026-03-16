from __future__ import annotations

import json

import structlog

from summer_puppy.logging.config import (
    _correlation_id_var,
    _reset_logging,
    _tenant_id_var,
    configure_logging,
    correlation_context,
    get_logger,
    inject_context,
    tenant_context,
)


class TestConfigureLogging:
    def setup_method(self) -> None:
        _reset_logging()

    def test_configure_json_format(self) -> None:
        configure_logging(level="INFO", fmt="json")
        # Should not raise; structlog should be configured

    def test_configure_console_format(self) -> None:
        configure_logging(level="DEBUG", fmt="console")

    def test_idempotent(self) -> None:
        configure_logging(level="INFO", fmt="json")
        configure_logging(level="DEBUG", fmt="console")
        # Second call is a no-op; no error raised


class TestGetLogger:
    def setup_method(self) -> None:
        _reset_logging()

    def test_returns_bound_logger(self) -> None:
        configure_logging()
        logger = get_logger("test.module")
        assert hasattr(logger, "info")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")

    def test_auto_configures_if_not_configured(self) -> None:
        # Do NOT call configure_logging(); get_logger should do it
        logger = get_logger("test.auto")
        assert hasattr(logger, "info")
        assert hasattr(logger, "warning")


class TestCorrelationContext:
    def setup_method(self) -> None:
        _correlation_id_var.set(None)

    async def test_sets_and_clears_correlation_id(self) -> None:
        assert _correlation_id_var.get(None) is None
        async with correlation_context("req-123"):
            assert _correlation_id_var.get(None) == "req-123"
        assert _correlation_id_var.get(None) is None

    async def test_clears_on_exception(self) -> None:
        try:
            async with correlation_context("req-err"):
                assert _correlation_id_var.get(None) == "req-err"
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        assert _correlation_id_var.get(None) is None


class TestTenantContext:
    def setup_method(self) -> None:
        _tenant_id_var.set(None)

    async def test_sets_and_clears_tenant_id(self) -> None:
        assert _tenant_id_var.get(None) is None
        async with tenant_context("tenant-abc"):
            assert _tenant_id_var.get(None) == "tenant-abc"
        assert _tenant_id_var.get(None) is None

    async def test_clears_on_exception(self) -> None:
        try:
            async with tenant_context("tenant-err"):
                assert _tenant_id_var.get(None) == "tenant-err"
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        assert _tenant_id_var.get(None) is None


class TestInjectContext:
    def setup_method(self) -> None:
        _correlation_id_var.set(None)
        _tenant_id_var.set(None)

    def test_adds_correlation_and_tenant_when_set(self) -> None:
        _correlation_id_var.set("corr-1")
        _tenant_id_var.set("tenant-1")
        event_dict: dict[str, object] = {"event": "test"}
        result = inject_context(None, "", event_dict)
        assert result["correlation_id"] == "corr-1"
        assert result["tenant_id"] == "tenant-1"

    def test_excludes_none_values(self) -> None:
        event_dict: dict[str, object] = {"event": "test"}
        result = inject_context(None, "", event_dict)
        assert "correlation_id" not in result
        assert "tenant_id" not in result


class TestLoggingOutput:
    """Integration-style tests to verify log output contains expected fields."""

    def setup_method(self) -> None:
        _reset_logging()
        _correlation_id_var.set(None)
        _tenant_id_var.set(None)

    def test_json_output_contains_expected_fields(self) -> None:
        """Verify that JSON-formatted log output includes timestamp and log level."""
        captured: list[str] = []

        def capture_processor(
            logger: object, method_name: str, event_dict: dict[str, object]
        ) -> str:
            output = json.dumps(event_dict, default=str)
            captured.append(output)
            raise structlog.DropEvent

        configure_logging(level="INFO", fmt="json")
        # Reconfigure structlog with our capture processor at the end
        structlog.configure(
            processors=[
                structlog.stdlib.add_log_level,
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                inject_context,
                structlog.processors.format_exc_info,
                capture_processor,
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=False,
        )
        log = get_logger("test.output")
        log.info("hello")

        assert len(captured) == 1
        data = json.loads(captured[0])
        assert data["event"] == "hello"
        assert "timestamp" in data
        assert data["level"] == "info"
