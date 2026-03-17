"""Tests for the notifications module: models, dispatcher, and Slack handler (Story 5)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from summer_puppy.notifications import (
    AlertEvent,
    AlertSeverity,
    ChannelType,
    NotificationChannel,
    NotificationDispatcher,
)
from summer_puppy.notifications.handlers.slack import send_slack

# ---------------------------------------------------------------------------
# TestNotificationModels
# ---------------------------------------------------------------------------


class TestNotificationModels:
    def test_channel_type_enum_values(self) -> None:
        assert ChannelType.SLACK == "slack"
        assert ChannelType.EMAIL == "email"
        assert ChannelType.PAGERDUTY == "pagerduty"

    def test_alert_severity_enum_values(self) -> None:
        assert AlertSeverity.LOW == "low"
        assert AlertSeverity.MEDIUM == "medium"
        assert AlertSeverity.HIGH == "high"
        assert AlertSeverity.CRITICAL == "critical"

    def test_notification_channel_defaults(self) -> None:
        channel = NotificationChannel(
            customer_id="cust-1",
            channel_type=ChannelType.SLACK,
        )
        assert channel.enabled is True
        assert channel.config == {}
        assert channel.channel_id  # auto-generated uuid
        assert channel.created_utc is not None

    def test_notification_channel_custom(self) -> None:
        channel = NotificationChannel(
            customer_id="cust-2",
            channel_type=ChannelType.EMAIL,
            config={"to": "ops@example.com"},
            enabled=False,
        )
        assert channel.customer_id == "cust-2"
        assert channel.channel_type == ChannelType.EMAIL
        assert channel.config == {"to": "ops@example.com"}
        assert channel.enabled is False

    def test_alert_event_creation(self) -> None:
        alert = AlertEvent(
            customer_id="cust-3",
            severity=AlertSeverity.HIGH,
            title="Disk full",
            body="Disk at 99% on host-a",
            correlation_id="corr-xyz",
        )
        assert alert.customer_id == "cust-3"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.title == "Disk full"
        assert alert.body == "Disk at 99% on host-a"
        assert alert.correlation_id == "corr-xyz"
        assert alert.triggered_utc is not None

    def test_alert_event_auto_id(self) -> None:
        a1 = AlertEvent(
            customer_id="cust-4",
            severity=AlertSeverity.LOW,
            title="T1",
            body="B1",
        )
        a2 = AlertEvent(
            customer_id="cust-4",
            severity=AlertSeverity.LOW,
            title="T2",
            body="B2",
        )
        assert a1.alert_id != a2.alert_id
        assert len(a1.alert_id) == 36  # UUID format


# ---------------------------------------------------------------------------
# TestNotificationDispatcher
# ---------------------------------------------------------------------------


class TestNotificationDispatcher:
    def test_register_channel(self) -> None:
        dispatcher = NotificationDispatcher()
        channel = NotificationChannel(
            customer_id="cust-1",
            channel_type=ChannelType.SLACK,
            config={"webhook_url": "https://hooks.slack.com/test"},
        )
        dispatcher.register_channel(channel)
        channels = dispatcher.list_channels("cust-1")
        assert len(channels) == 1
        assert channels[0].channel_id == channel.channel_id

    def test_list_channels_empty(self) -> None:
        dispatcher = NotificationDispatcher()
        assert dispatcher.list_channels("unknown-cust") == []

    def test_list_channels_returns_registered(self) -> None:
        dispatcher = NotificationDispatcher()
        ch1 = NotificationChannel(
            customer_id="cust-A",
            channel_type=ChannelType.SLACK,
        )
        ch2 = NotificationChannel(
            customer_id="cust-B",
            channel_type=ChannelType.EMAIL,
        )
        dispatcher.register_channel(ch1)
        dispatcher.register_channel(ch2)
        result = dispatcher.list_channels("cust-A")
        assert len(result) == 1
        assert result[0].customer_id == "cust-A"

    @pytest.mark.asyncio
    async def test_dispatch_to_matching_customer_only(self) -> None:
        dispatcher = NotificationDispatcher(mock_mode=False)
        ch_target = NotificationChannel(
            customer_id="cust-X",
            channel_type=ChannelType.SLACK,
            config={"webhook_url": "https://hooks.slack.com/x"},
        )
        ch_other = NotificationChannel(
            customer_id="cust-Y",
            channel_type=ChannelType.SLACK,
            config={"webhook_url": "https://hooks.slack.com/y"},
        )
        dispatcher.register_channel(ch_target)
        dispatcher.register_channel(ch_other)

        alert = AlertEvent(
            customer_id="cust-X",
            severity=AlertSeverity.CRITICAL,
            title="Breach detected",
            body="Unauthorized access",
        )

        call_log: list[str] = []

        async def capture(channel: NotificationChannel, evt: AlertEvent) -> None:
            call_log.append(channel.config.get("webhook_url", ""))

        with patch.object(dispatcher, "_send_to_channel", side_effect=capture):
            await dispatcher.dispatch(alert)

        assert call_log == ["https://hooks.slack.com/x"]

    @pytest.mark.asyncio
    async def test_dispatch_skips_disabled_channel(self) -> None:
        dispatcher = NotificationDispatcher(mock_mode=False)
        ch = NotificationChannel(
            customer_id="cust-1",
            channel_type=ChannelType.SLACK,
            config={"webhook_url": "https://hooks.slack.com/test"},
            enabled=False,
        )
        dispatcher.register_channel(ch)
        alert = AlertEvent(
            customer_id="cust-1",
            severity=AlertSeverity.LOW,
            title="Info",
            body="Details",
        )
        call_log: list[str] = []

        async def capture(config: dict, evt: AlertEvent, mock_mode: bool = False) -> None:
            call_log.append("called")

        with patch.object(dispatcher, "_send_to_channel", side_effect=capture):
            await dispatcher.dispatch(alert)

        assert call_log == []

    @pytest.mark.asyncio
    async def test_dispatch_mock_mode_captures_alerts(self) -> None:
        dispatcher = NotificationDispatcher(mock_mode=True)
        alert = AlertEvent(
            customer_id="cust-1",
            severity=AlertSeverity.MEDIUM,
            title="Test",
            body="Mock dispatch",
        )
        await dispatcher.dispatch(alert)
        assert len(dispatcher.sent_alerts) == 1
        assert dispatcher.sent_alerts[0].alert_id == alert.alert_id

    @pytest.mark.asyncio
    async def test_dispatch_no_channels_no_error(self) -> None:
        dispatcher = NotificationDispatcher(mock_mode=False)
        alert = AlertEvent(
            customer_id="cust-nobody",
            severity=AlertSeverity.LOW,
            title="Noise",
            body="No channels configured",
        )
        # Should not raise
        await dispatcher.dispatch(alert)

    @pytest.mark.asyncio
    async def test_multiple_channels_same_customer(self) -> None:
        dispatcher = NotificationDispatcher(mock_mode=True)
        for _ in range(3):
            ch = NotificationChannel(
                customer_id="cust-multi",
                channel_type=ChannelType.SLACK,
                config={"webhook_url": "https://hooks.slack.com/test"},
            )
            dispatcher.register_channel(ch)
        channels = dispatcher.list_channels("cust-multi")
        assert len(channels) == 3

    def test_deregister_channel(self) -> None:
        dispatcher = NotificationDispatcher()
        ch = NotificationChannel(
            customer_id="cust-1",
            channel_type=ChannelType.SLACK,
        )
        dispatcher.register_channel(ch)
        result = dispatcher.deregister_channel(ch.channel_id)
        assert result is True
        assert dispatcher.list_channels("cust-1") == []

    def test_deregister_unknown_returns_false(self) -> None:
        dispatcher = NotificationDispatcher()
        result = dispatcher.deregister_channel("nonexistent-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_get_sent_alerts_mock_mode(self) -> None:
        dispatcher = NotificationDispatcher(mock_mode=True)
        a1 = AlertEvent(
            customer_id="cust-1",
            severity=AlertSeverity.HIGH,
            title="A1",
            body="Body1",
        )
        a2 = AlertEvent(
            customer_id="cust-1",
            severity=AlertSeverity.CRITICAL,
            title="A2",
            body="Body2",
        )
        await dispatcher.dispatch(a1)
        await dispatcher.dispatch(a2)
        sent = dispatcher.sent_alerts
        assert len(sent) == 2
        ids = {a.alert_id for a in sent}
        assert a1.alert_id in ids
        assert a2.alert_id in ids

    def test_get_sent_alerts_empty_in_live_mode(self) -> None:
        dispatcher = NotificationDispatcher(mock_mode=False)
        assert dispatcher.sent_alerts == []


# ---------------------------------------------------------------------------
# TestSlackHandler
# ---------------------------------------------------------------------------


class TestSlackHandler:
    @pytest.mark.asyncio
    async def test_send_slack_mock_mode_no_http(self) -> None:
        """In mock_mode, send_slack logs but does NOT make HTTP calls."""
        config = {"webhook_url": "https://hooks.slack.com/test"}
        alert = AlertEvent(
            customer_id="cust-1",
            severity=AlertSeverity.HIGH,
            title="Mock alert",
            body="No real HTTP",
        )
        with patch("httpx.AsyncClient") as mock_client:
            await send_slack(config, alert, mock_mode=True)
            mock_client.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_slack_calls_webhook(self) -> None:
        """In live mode, send_slack POSTs to the webhook_url via httpx."""
        config = {"webhook_url": "https://hooks.slack.com/services/REAL"}
        alert = AlertEvent(
            customer_id="cust-1",
            severity=AlertSeverity.CRITICAL,
            title="Critical alert",
            body="Server down",
        )

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = AsyncMock()
        mock_client_instance.post = AsyncMock(return_value=mock_response)
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=None)

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            await send_slack(config, alert, mock_mode=False)

        mock_client_instance.post.assert_called_once()
        call_kwargs = mock_client_instance.post.call_args
        assert call_kwargs[0][0] == "https://hooks.slack.com/services/REAL"
        payload = call_kwargs[1]["json"]
        assert "CRITICAL" in payload["text"]
        assert "Critical alert" in payload["text"]

    @pytest.mark.asyncio
    async def test_send_slack_missing_webhook_url_raises(self) -> None:
        """send_slack raises ValueError when webhook_url is absent from config."""
        config: dict[str, str] = {}
        alert = AlertEvent(
            customer_id="cust-1",
            severity=AlertSeverity.LOW,
            title="Misconfigured",
            body="No webhook",
        )
        with pytest.raises(ValueError, match="webhook_url"):
            await send_slack(config, alert)


# ---------------------------------------------------------------------------
# TestNotificationAPI
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_state():
    """Reset AppState singleton before/after each test."""
    from summer_puppy.api.state import init_app_state, reset_app_state

    reset_app_state()
    init_app_state()
    yield
    reset_app_state()


@pytest.fixture
def app():
    from summer_puppy.api.app import app as _app

    return _app


def _make_token(customer_id: str) -> str:
    from summer_puppy.api.auth.jwt_handler import create_token

    return create_token(customer_id, scopes=["notifications:write"])


async def _request(app, method: str, path: str, **kwargs):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await getattr(client, method)(path, **kwargs)


class TestNotificationAPI:
    @pytest.mark.asyncio
    async def test_register_channel_returns_201(self, app) -> None:
        token = _make_token("cust-1")
        response = await _request(
            app,
            "post",
            "/api/v1/customers/cust-1/notifications/channels",
            json={"channel_type": "slack", "config": {"webhook_url": "https://hooks.slack.com/x"}},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["customer_id"] == "cust-1"
        assert data["channel_type"] == "slack"
        assert data["enabled"] is True
        assert "channel_id" in data

    @pytest.mark.asyncio
    async def test_register_channel_stored_in_dispatcher(self, app) -> None:
        from summer_puppy.api.state import get_app_state

        token = _make_token("cust-2")
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-2/notifications/channels",
            json={"channel_type": "email", "config": {}},
            headers={"Authorization": f"Bearer {token}"},
        )
        state = get_app_state()
        assert state.notification_dispatcher is not None
        channels = state.notification_dispatcher.list_channels("cust-2")
        assert len(channels) == 1
        assert channels[0].channel_type == "email"

    @pytest.mark.asyncio
    async def test_list_channels_empty(self, app) -> None:
        token = _make_token("cust-empty")
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-empty/notifications/channels",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_list_channels_returns_registered(self, app) -> None:
        token = _make_token("cust-list")
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-list/notifications/channels",
            json={"channel_type": "slack", "config": {"webhook_url": "https://hooks.slack.com/a"}},
            headers={"Authorization": f"Bearer {token}"},
        )
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-list/notifications/channels",
            json={"channel_type": "email", "config": {}},
            headers={"Authorization": f"Bearer {token}"},
        )
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-list/notifications/channels",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        types = {c["channel_type"] for c in data}
        assert types == {"slack", "email"}

    @pytest.mark.asyncio
    async def test_delete_channel_204(self, app) -> None:
        token = _make_token("cust-del")
        create_resp = await _request(
            app,
            "post",
            "/api/v1/customers/cust-del/notifications/channels",
            json={"channel_type": "slack", "config": {"webhook_url": "https://hooks.slack.com/d"}},
            headers={"Authorization": f"Bearer {token}"},
        )
        channel_id = create_resp.json()["channel_id"]
        delete_resp = await _request(
            app,
            "delete",
            f"/api/v1/customers/cust-del/notifications/channels/{channel_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert delete_resp.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_channel_not_found_404(self, app) -> None:
        token = _make_token("cust-del2")
        response = await _request(
            app,
            "delete",
            "/api/v1/customers/cust-del2/notifications/channels/nonexistent-channel-id",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_test_alert_dispatches_in_mock_mode(self, app) -> None:
        token = _make_token("cust-test-alert")
        response = await _request(
            app,
            "post",
            "/api/v1/customers/cust-test-alert/notifications/test",
            json={"title": "Ping", "body": "Check", "severity": "low"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["dispatched"] is True
        assert data["sent_count"] == 1

    @pytest.mark.asyncio
    async def test_notification_endpoints_require_auth(self, app) -> None:
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-noauth/notifications/channels",
        )
        assert response.status_code == 422  # missing Authorization header

    @pytest.mark.asyncio
    async def test_channel_customer_mismatch_403(self, app) -> None:
        token = _make_token("cust-other")
        response = await _request(
            app,
            "get",
            "/api/v1/customers/cust-1/notifications/channels",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_test_alert_returns_sent_alerts(self, app) -> None:
        from summer_puppy.api.state import get_app_state

        token = _make_token("cust-sent")
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-sent/notifications/test",
            json={"title": "Alert1", "body": "Body1", "severity": "high"},
            headers={"Authorization": f"Bearer {token}"},
        )
        await _request(
            app,
            "post",
            "/api/v1/customers/cust-sent/notifications/test",
            json={"title": "Alert2", "body": "Body2", "severity": "medium"},
            headers={"Authorization": f"Bearer {token}"},
        )
        state = get_app_state()
        assert state.notification_dispatcher is not None
        assert len(state.notification_dispatcher.sent_alerts) == 2
