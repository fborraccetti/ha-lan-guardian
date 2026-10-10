"""Tests for the health and security coordinators."""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_capture_events

from custom_components.lan_guardian.const import CONF_TASMOTA_WARN_NO_PASSWORD, DOMAIN
from custom_components.lan_guardian.notifier import EVENT_NAME
from custom_components.lan_guardian.tasmota.probe import WebAuth

from .conftest import FakeNetwork


async def _setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    await async_setup_component(hass, "repairs", {})
    if hass.config_entries.async_get_entry(entry.entry_id) is None:
        entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)


async def _recheck(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    await entry.runtime_data.health.async_refresh()
    await hass.async_block_till_done()


def _state(hass: HomeAssistant, entity_id: str) -> str:
    state = hass.states.get(entity_id)
    assert state is not None, entity_id
    return state.state


async def test_health_entities(hass: HomeAssistant, config_entry: MockConfigEntry) -> None:
    """Gateway/Internet stats, DNS timings and the Pi-hole check become entities."""
    await _setup(hass, config_entry)
    assert _state(hass, "sensor.lan_guardian_gateway_packet_loss") == "0.0"
    assert _state(hass, "sensor.lan_guardian_gateway_latency") == "1.0"
    assert _state(hass, "sensor.lan_guardian_internet_max_latency") == "20.0"
    assert _state(hass, "sensor.lan_guardian_dns_resolve_time_192_168_1_9") == "8.5"
    assert _state(hass, "binary_sensor.lan_guardian_dns_192_168_1_1") == "on"
    assert _state(hass, "binary_sensor.lan_guardian_internet") == "on"
    assert _state(hass, "binary_sensor.lan_guardian_ad_blocking_active") == "on"


async def test_primary_dns_down_needs_two_failures(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """One failed check is tolerated; two raise the issue; one success clears it."""
    await _setup(hass, config_entry)
    events = async_capture_events(hass, EVENT_NAME)
    fake_network.dns_down.add("192.168.1.9")

    await _recheck(hass, config_entry)
    assert _state(hass, "binary_sensor.lan_guardian_dns_192_168_1_9") == "off"
    assert ir.async_get(hass).async_get_issue(DOMAIN, "dns_primary_down") is None

    await _recheck(hass, config_entry)
    issue = ir.async_get(hass).async_get_issue(DOMAIN, "dns_primary_down")
    assert issue is not None
    assert issue.translation_placeholders == {"server": "192.168.1.9"}
    assert [e.data["type"] for e in events] == ["dns_down"]

    fake_network.dns_down.clear()
    await _recheck(hass, config_entry)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "dns_primary_down") is None
    assert [e.data["type"] for e in events] == ["dns_down", "dns_up"]


async def test_secondary_dns_down_notifies_without_issue(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """Only the primary DNS raises a repair issue."""
    await _setup(hass, config_entry)
    events = async_capture_events(hass, EVENT_NAME)
    fake_network.dns_down.add("192.168.1.1")
    await _recheck(hass, config_entry)
    await _recheck(hass, config_entry)
    assert [e.data["key"] for e in events] == ["192.168.1.1"]
    assert ir.async_get(hass).async_get_issue(DOMAIN, "dns_primary_down") is None


async def test_gateway_loss_and_internet_down(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """Loss above threshold twice raises an issue; Internet down/up notify."""
    await _setup(hass, config_entry)
    events = async_capture_events(hass, EVENT_NAME)
    fake_network.gateway_loss = 0.3
    fake_network.internet_alive = False
    await _recheck(hass, config_entry)
    await _recheck(hass, config_entry)

    issue = ir.async_get(hass).async_get_issue(DOMAIN, "gateway_packet_loss")
    assert issue is not None
    assert issue.translation_placeholders["loss"] == "30"
    assert _state(hass, "binary_sensor.lan_guardian_internet") == "off"
    assert sorted(e.data["type"] for e in events) == ["gateway_loss", "internet_down"]

    fake_network.gateway_loss = 0.0
    fake_network.internet_alive = True
    await _recheck(hass, config_entry)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "gateway_packet_loss") is None
    assert events[-1].data["type"] == "internet_up"


async def test_adblock_inactive(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """A real address for the ad domain means Pi-hole is not blocking."""
    await _setup(hass, config_entry)
    fake_network.adblock_addresses = ("142.250.180.46",)
    await _recheck(hass, config_entry)
    assert _state(hass, "binary_sensor.lan_guardian_ad_blocking_active") == "off"
    assert ir.async_get(hass).async_get_issue(DOMAIN, "adblock_inactive") is not None

    fake_network.adblock_addresses = ()
    await _recheck(hass, config_entry)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "adblock_inactive") is None


async def test_tasmota_without_password(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """Open Tasmota devices are listed in a sensor and a security issue."""
    fake_network.arp["192.168.1.228"] = "a4:cf:12:00:02:28"
    fake_network.tasmota["192.168.1.228"] = WebAuth.PROTECTED
    await _setup(hass, config_entry)

    state = hass.states.get("sensor.lan_guardian_tasmota_without_password")
    assert state is not None
    assert state.state == "1"
    assert state.attributes["tasmota_found"] == 2
    assert state.attributes["devices"] == [{"name": "sensore-gas", "ip": "192.168.1.248"}]
    issue = ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_no_password")
    assert issue is not None
    assert issue.translation_placeholders["count"] == "1"
    inventory = config_entry.runtime_data.scan.inventory
    assert inventory.devices["a4:cf:12:00:02:48"].category == "tasmota"

    # Password set: the issue goes away on the next round.
    fake_network.tasmota["192.168.1.248"] = WebAuth.PROTECTED
    await config_entry.runtime_data.security.async_refresh()
    await hass.async_block_till_done()
    assert ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_no_password") is None


async def test_tasmota_without_password_warning_disabled(
    hass: HomeAssistant, config_entry: MockConfigEntry
) -> None:
    """With the warning off, open Tasmota devices are counted but raise nothing."""
    config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        config_entry, options={CONF_TASMOTA_WARN_NO_PASSWORD: False}
    )
    events = async_capture_events(hass, EVENT_NAME)
    await _setup(hass, config_entry)
    state = hass.states.get("sensor.lan_guardian_tasmota_without_password")
    assert state is not None
    assert state.state == "1"
    assert ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_no_password") is None
    assert "tasmota_no_password" not in [e.data["type"] for e in events]
