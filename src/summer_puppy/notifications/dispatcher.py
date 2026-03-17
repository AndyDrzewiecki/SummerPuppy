from __future__ import annotations

import structlog

from summer_puppy.notifications.models import AlertEvent, NotificationChannel  # noqa: TC001

logger = structlog.get_logger()


class NotificationDispatcher:
    def __init__(self, mock_mode: bool = False) -> None:
        self._mock_mode = mock_mode
        self._channels: dict[str, NotificationChannel] = {}  # channel_id → channel
        self._sent_alerts: list[AlertEvent] = []

    def register_channel(self, channel: NotificationChannel) -> None:
        self._channels[channel.channel_id] = channel

    def deregister_channel(self, channel_id: str) -> bool:
        if channel_id not in self._channels:
            return False
        del self._channels[channel_id]
        return True

    def list_channels(self, customer_id: str) -> list[NotificationChannel]:
        return [c for c in self._channels.values() if c.customer_id == customer_id]

    @property
    def sent_alerts(self) -> list[AlertEvent]:
        return list(self._sent_alerts)

    async def dispatch(self, alert: AlertEvent) -> None:
        if self._mock_mode:
            self._sent_alerts.append(alert)
            logger.info(
                "notification_dispatched_mock",
                alert_id=alert.alert_id,
                customer_id=alert.customer_id,
            )
            return
        channels = [
            c for c in self._channels.values() if c.customer_id == alert.customer_id and c.enabled
        ]
        for channel in channels:
            await self._send_to_channel(channel, alert)

    async def _send_to_channel(self, channel: NotificationChannel, alert: AlertEvent) -> None:
        from summer_puppy.notifications.handlers.slack import send_slack
        from summer_puppy.notifications.models import ChannelType

        if channel.channel_type == ChannelType.SLACK:
            await send_slack(channel.config, alert, mock_mode=self._mock_mode)
        else:
            logger.info(
                "notification_channel_stub",
                channel_type=channel.channel_type,
                alert_id=alert.alert_id,
            )
