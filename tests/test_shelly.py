"""Tests for the Shelly probe and the Shelly security check."""

from __future__ import annotations

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.setup import async_setup_component
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_capture_events
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.lan_guardian.const import CONF_SHELLY_WARN_NO_PASSWORD, DOMAIN
from custom_components.lan_guardian.notifier import EVENT_NAME
from custom_components.lan_guardian.shelly.probe import ShellyProbe, async_probe_shelly
from custom_components.lan_guardian.tasmota.probe import WebAuth

from .conftest import FakeNetwork

IP = "192.168.1.50"
BASE = f"http://{IP}"
GEN1 = {"type": "SHSW-1", "mac": "A4CF12000050", "auth": False, "fw": "20230913-112003/v1.14.0"}
GEN2 = {
    "id": "shellyplus1-a0a3b3000051",
    "mac": "A0A3B3000051",
    "model": "SNSW-001X16EU",
    "gen": 2,
    "ver": "1.4.4",
    "app": "Plus1",
    "auth_en": False,
    "auth_domain": None,
}


async def test_probe_gen1_open(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    """Gen1 without login: /settings answers to anyone."""
    aioclient_mock.get(f"{BASE}/shelly", json=GEN1)
    aioclient_mock.get(f"{BASE}/settings", json={"device": {}})
    result = await async_probe_shelly(async_get_clientsession(hass), IP)
    assert result == ShellyProbe(
        ip=IP, auth=WebAuth.OPEN, gen=1, model="SHSW-1", firmware="20230913-112003/v1.14.0"
    )


async def test_probe_gen1_protected(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Gen1 with login enabled."""
    aioclient_mock.get(f"{BASE}/shelly", json={**GEN1, "auth": True})
    aioclient_mock.get(f"{BASE}/settings", status=401)
    result = await async_probe_shelly(async_get_clientsession(hass), IP)
    assert result is not None
    assert result.auth is WebAuth.PROTECTED


async def test_probe_gen2(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    """Gen2+: auth_en, verified on Sys.GetConfig."""
    aioclient_mock.get(f"{BASE}/shelly", json=GEN2)
    aioclient_mock.get(f"{BASE}/rpc/Sys.GetConfig", json={"device": {}})
    result = await async_probe_shelly(async_get_clientsession(hass), IP)
    assert result == ShellyProbe(
        ip=IP, auth=WebAuth.OPEN, gen=2, model="SNSW-001X16EU", firmware="1.4.4"
    )


async def test_probe_verification_wins(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """The guarded endpoint decides, whatever /shelly claims."""
    session = async_get_clientsession(hass)
    aioclient_mock.get(f"{BASE}/shelly", json={**GEN2, "auth_en": True})
    aioclient_mock.get(f"{BASE}/rpc/Sys.GetConfig", json={"device": {}})
    result = await async_probe_shelly(session, IP)
    assert result is not None
    assert result.auth is WebAuth.OPEN

    aioclient_mock.clear_requests()
    aioclient_mock.get(f"{BASE}/shelly", json={**GEN2, "gen": 3})
    aioclient_mock.get(f"{BASE}/rpc/Sys.GetConfig", status=401)
    result = await async_probe_shelly(session, IP)
    assert result is not None
    assert result.auth is WebAuth.PROTECTED
    assert result.gen == 3


async def test_probe_verification_unreachable(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """If the check fails, the flag reported by /shelly is kept."""
    aioclient_mock.get(f"{BASE}/shelly", json=GEN1)
    aioclient_mock.get(f"{BASE}/settings", exc=TimeoutError())
    result = await async_probe_shelly(async_get_clientsession(hass), IP)
    assert result is not None
    assert result.auth is WebAuth.OPEN


@pytest.mark.parametrize(
    "answer",
    [
        {"status": 404},
        {"status": 401},
        {"text": "<html>router</html>"},
        {"json": {"other": 1}},
        {"json": {"gen": 2}},
        {"json": ["shelly"]},
        {"exc": aiohttp.ClientConnectionError()},
        {"exc": TimeoutError()},
    ],
)
async def test_probe_not_shelly(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, answer: dict[str, object]
) -> None:
    """Other web servers, garbage and network errors are not Shelly."""
    aioclient_mock.get(f"{BASE}/shelly", **answer)
    assert await async_probe_shelly(async_get_clientsession(hass), IP) is None


async def _setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    await async_setup_component(hass, "repairs", {})
    if hass.config_entries.async_get_entry(entry.entry_id) is None:
        entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)


def _add_shelly(net: FakeNetwork, ip: str, mac: str, auth: WebAuth) -> None:
    net.arp[ip] = mac
    net.shelly[ip] = ShellyProbe(ip=ip, auth=auth, gen=2, model="SNSW-001X16EU")


async def test_shelly_without_password(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """Open Shelly devices get a sensor, a category, a notification and an issue."""
    _add_shelly(fake_network, "192.168.1.50", "a0:a3:b3:00:00:50", WebAuth.OPEN)
    _add_shelly(fake_network, "192.168.1.51", "a0:a3:b3:00:00:51", WebAuth.PROTECTED)
    events = async_capture_events(hass, EVENT_NAME)
    await _setup(hass, config_entry)

    state = hass.states.get("sensor.lan_guardian_shelly_without_password")
    assert state is not None
    assert state.state == "1"
    assert state.attributes["shelly_found"] == 2
    [device] = state.attributes["devices"]
    assert (device["ip"], device["generation"], device["model"]) == (
        "192.168.1.50",
        2,
        "SNSW-001X16EU",
    )
    issue = ir.async_get(hass).async_get_issue(DOMAIN, "shelly_no_password")
    assert issue is not None
    assert not issue.is_fixable
    assert issue.translation_placeholders["count"] == "1"
    assert "shelly_no_password" in [e.data["type"] for e in events]
    inventory = config_entry.runtime_data.scan.inventory
    assert inventory.devices["a0:a3:b3:00:00:50"].category == "shelly"
    # Shelly devices are not Tasmota: no Tasmota entities, not counted there.
    tasmota = hass.states.get("sensor.lan_guardian_tasmota_without_password")
    assert tasmota is not None
    assert tasmota.attributes["tasmota_found"] == 1

    # Password set: the issue goes away on the next round.
    _add_shelly(fake_network, "192.168.1.50", "a0:a3:b3:00:00:50", WebAuth.PROTECTED)
    await config_entry.runtime_data.security.async_refresh()
    await hass.async_block_till_done()
    assert ir.async_get(hass).async_get_issue(DOMAIN, "shelly_no_password") is None
    state = hass.states.get("sensor.lan_guardian_shelly_without_password")
    assert state is not None
    assert state.state == "0"


async def test_shelly_offline_is_remembered(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """An open Shelly that goes offline is still a risk when it comes back."""
    _add_shelly(fake_network, "192.168.1.50", "a0:a3:b3:00:00:50", WebAuth.OPEN)
    await _setup(hass, config_entry)
    del fake_network.shelly["192.168.1.50"]
    await config_entry.runtime_data.security.async_refresh()
    await hass.async_block_till_done()
    assert ir.async_get(hass).async_get_issue(DOMAIN, "shelly_no_password") is not None


async def test_shelly_warning_disabled(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """With the warning off, open Shelly devices are counted but raise nothing."""
    _add_shelly(fake_network, "192.168.1.50", "a0:a3:b3:00:00:50", WebAuth.OPEN)
    config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        config_entry, options={CONF_SHELLY_WARN_NO_PASSWORD: False}
    )
    events = async_capture_events(hass, EVENT_NAME)
    await _setup(hass, config_entry)
    state = hass.states.get("sensor.lan_guardian_shelly_without_password")
    assert state is not None
    assert state.state == "1"
    assert ir.async_get(hass).async_get_issue(DOMAIN, "shelly_no_password") is None
    assert "shelly_no_password" not in [e.data["type"] for e in events]
