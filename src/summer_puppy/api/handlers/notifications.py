from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from summer_puppy.api.middleware.auth_middleware import verify_customer_path
from summer_puppy.api.schemas.notifications import (
    ChannelRequest,
    ChannelResponse,
    TestAlertRequest,
    TestAlertResponse,
)
from summer_puppy.api.state import AppState, get_app_state
from summer_puppy.notifications.dispatcher import NotificationDispatcher
from summer_puppy.notifications.models import AlertEvent, NotificationChannel

router = APIRouter()


def _get_dispatcher(state: AppState) -> NotificationDispatcher:
    if state.notification_dispatcher is None:
        state.notification_dispatcher = NotificationDispatcher(mock_mode=True)
    return state.notification_dispatcher


@router.post(
    "/{customer_id}/notifications/channels",
    status_code=201,
    response_model=ChannelResponse,
    dependencies=[Depends(verify_customer_path)],
)
async def register_channel(
    customer_id: str,
    body: ChannelRequest,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> ChannelResponse:
    dispatcher = _get_dispatcher(state)
    channel = NotificationChannel(
        customer_id=customer_id,
        channel_type=body.channel_type,
        config=body.config,
        enabled=body.enabled,
    )
    dispatcher.register_channel(channel)
    return ChannelResponse(
        channel_id=channel.channel_id,
        customer_id=customer_id,
        channel_type=body.channel_type,
        enabled=body.enabled,
    )


@router.get(
    "/{customer_id}/notifications/channels",
    response_model=list[ChannelResponse],
    dependencies=[Depends(verify_customer_path)],
)
async def list_channels(
    customer_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> list[ChannelResponse]:
    dispatcher = _get_dispatcher(state)
    return [
        ChannelResponse(
            channel_id=c.channel_id,
            customer_id=c.customer_id,
            channel_type=c.channel_type,
            enabled=c.enabled,
        )
        for c in dispatcher.list_channels(customer_id)
    ]


@router.delete(
    "/{customer_id}/notifications/channels/{channel_id}",
    status_code=204,
    response_class=Response,
    dependencies=[Depends(verify_customer_path)],
)
async def delete_channel(
    customer_id: str,
    channel_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> Response:
    dispatcher = _get_dispatcher(state)
    removed = dispatcher.deregister_channel(channel_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Channel not found")
    return Response(status_code=204)


@router.post(
    "/{customer_id}/notifications/test",
    response_model=TestAlertResponse,
    dependencies=[Depends(verify_customer_path)],
)
async def test_alert(
    customer_id: str,
    body: TestAlertRequest,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> TestAlertResponse:
    dispatcher = _get_dispatcher(state)
    original_mock = dispatcher._mock_mode
    dispatcher._mock_mode = True
    initial_count = len(dispatcher.sent_alerts)
    alert = AlertEvent(
        customer_id=customer_id,
        severity=body.severity,
        title=body.title,
        body=body.body,
    )
    await dispatcher.dispatch(alert)
    new_count = len(dispatcher.sent_alerts) - initial_count
    dispatcher._mock_mode = original_mock
    return TestAlertResponse(dispatched=True, sent_count=new_count)
