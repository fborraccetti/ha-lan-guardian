"""Tests for the notifier."""

from __future__ import annotations

from datetime import timedelta

from freezegun.api import FrozenDateTimeFactory
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError
import pytest
from pytest_homeassistant_custom_component.common import async_capture_events, async_mock_service

from custom_components.lan_guardian.const import (
    CONF_NOTIFY_ENTITIES,
    CONF_NOTIFY_PERSISTENT,
    CONF_NOTIFY_SERVICE,
    DEFAULT_OPTIONS,
)
from custom_components.lan_guardian.notifier import (
    EVENT_CRITICAL_ONLINE,
    EVENT_NAME,
    EVENT_NEW_DEVICE,
    Notifier,
)

ENTITY = "notify.telegram_bot_5052948072_561923526"


def _notifier(hass: HomeAssistant, **options: object) -> Notifier:
    return Notifier(hass, {**DEFAULT_OPTIONS, **options})


async def test_channels_and_cooldown(hass: HomeAssistant, freezer: FrozenDateTimeFactory) -> None:
    """Notify entity and legacy action receive the message; repeats are held back."""
    entity_calls = async_mock_service(hass, "notify", "send_message")
    legacy_calls = async_mock_service(hass, "notify", "mobile_app_sm_g991b")
    events = async_capture_events(hass, EVENT_NAME)
    hass.config.language = "it"
    notifier = _notifier(
        hass,
        **{
            CONF_NOTIFY_PERSISTENT: False,
            CONF_NOTIFY_ENTITIES: [ENTITY],
            CONF_NOTIFY_SERVICE: "notify.mobile_app_sm_g991b",
        },
    )
    placeholders = {"name": "Stampante", "ip": "192.168.1.99", "mac": "x", "vendor": "HP"}

    assert await notifier.async_notify(EVENT_NEW_DEVICE, "x", placeholders)
    assert entity_calls[0].data["entity_id"] == [ENTITY]
    assert entity_calls[0].data["title"] == "LAN Guardian: nuovo dispositivo"
    assert "Stampante (192.168.1.99, x, HP)" in legacy_calls[0].data["message"]

    # Within the cooldown: event fired, no message.
    assert not await notifier.async_notify(EVENT_NEW_DEVICE, "x", placeholders)
    assert len(entity_calls) == 1
    assert len(events) == 2

    # Recovery events ignore the cooldown.
    assert await notifier.async_notify(EVENT_CRITICAL_ONLINE, "x", placeholders)
    assert await notifier.async_notify(EVENT_CRITICAL_ONLINE, "x", placeholders)

    freezer.tick(timedelta(minutes=61))
    assert await notifier.async_notify(EVENT_NEW_DEVICE, "x", placeholders)
    assert len(legacy_calls) == 4


async def test_missing_placeholder_and_failing_service(
    hass: HomeAssistant, caplog: pytest.LogCaptureFixture
) -> None:
    """A broken notify target is logged, never raised; missing placeholders render '?'."""

    async def boom(call: ServiceCall) -> None:
        raise HomeAssistantError("bot offline")

    hass.services.async_register("notify", "send_message", boom)
    notifier = _notifier(hass, **{CONF_NOTIFY_PERSISTENT: False, CONF_NOTIFY_ENTITIES: [ENTITY]})
    assert await notifier.async_notify(EVENT_NEW_DEVICE, "y", {"name": "Z"})
    assert "notify.send_message failed: bot offline" in caplog.text
    assert notifier._text(EVENT_NEW_DEVICE, {})[1].startswith("New device on the network: ?")
