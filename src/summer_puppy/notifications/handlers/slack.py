from __future__ import annotations

import structlog

from summer_puppy.notifications.models import AlertEvent  # noqa: TC001

logger = structlog.get_logger()


async def send_slack(config: dict[str, str], alert: AlertEvent, mock_mode: bool = False) -> None:
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        raise ValueError("Slack channel config missing 'webhook_url'")
    if mock_mode:
        logger.info("slack_send_mock", webhook_url=webhook_url, alert_id=alert.alert_id)
        return
    import httpx

    payload = {
        "text": f"[{alert.severity.upper()}] {alert.title}",
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{alert.title}*\n{alert.body}"},
            },
        ],
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(webhook_url, json=payload, timeout=10.0)
        response.raise_for_status()
