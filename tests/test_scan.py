"""End-to-end tests of the scan coordinator, issues, notifications, repairs and services."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock, patch

from freezegun.api import FrozenDateTimeFactory
from homeassistant.components import persistent_notification
from homeassistant.components.repairs import repairs_flow_manager
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import (
    device_registry as dr,
    entity_registry as er,
    issue_registry as ir,
)
from homeassistant.setup import async_setup_component
import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_capture_events,
    async_fire_time_changed,
)

from custom_components.lan_guardian.const import (
    CONF_CRITICAL_OFFLINE_MINUTES,
    CONF_NOTIFY_ENTITIES,
    DOMAIN,
)
from custom_components.lan_guardian.notifier import EVENT_NAME

from .conftest import FakeNetwork

GAS_MAC = "a4:cf:12:00:02:48"
NEW_MAC = "a8:bb:cc:00:00:99"
NEW_ISSUE = "new_device_a8bbcc000099"


async def _setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    await async_setup_component(hass, "repairs", {})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)


async def _rescan(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    await entry.runtime_data.scan.async_refresh()
    await hass.async_block_till_done()


def _notifications(hass: HomeAssistant) -> dict[str, dict[str, str]]:
    return persistent_notification._async_get_or_create_notifications(hass)


async def test_first_scan_is_baseline(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """The first scan creates the inventory without new-device issues."""
    fake_network.tasmota.clear()
    events = async_capture_events(hass, EVENT_NAME)
    await _setup(hass, config_entry)

    assert hass.states.get("sensor.lan_guardian_devices_online").state == "3"
    assert hass.states.get("sensor.lan_guardian_unknown_devices").state == "0"
    assert [e.data["type"] for e in events] == ["baseline"]
    assert "lan_guardian_baseline_baseline" in _notifications(hass)
    inv = config_entry.runtime_data.scan.inventory
    assert inv.devices[GAS_MAC].hostname == "sensore-gas.fritz.box"
    assert inv.devices[GAS_MAC].vendor == "Espressif Inc."
    assert not ir.async_get(hass).issues


async def test_host_dropping_icmp_counts_online(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """A complete ARP entry is enough to be online."""
    fake_network.no_icmp.add("192.168.1.9")
    await _setup(hass, config_entry)
    assert hass.states.get("sensor.lan_guardian_devices_online").state == "3"


async def test_new_device_issue_and_approve(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """A new MAC raises an issue and a notification; approving it adds the entity."""
    await _setup(hass, config_entry)
    events = async_capture_events(hass, EVENT_NAME)

    fake_network.arp["192.168.1.99"] = NEW_MAC
    await _rescan(hass, config_entry)

    assert [e.data["type"] for e in events] == ["new_device"]
    assert hass.states.get("sensor.lan_guardian_unknown_devices").state == "1"
    issue = ir.async_get(hass).async_get_issue(DOMAIN, NEW_ISSUE)
    assert issue is not None
    assert issue.is_fixable
    assert issue.translation_placeholders["ip"] == "192.168.1.99"
    assert f"lan_guardian_new_device_{NEW_MAC}" in _notifications(hass)

    # Same device next scan: no second notification, issue still there.
    await _rescan(hass, config_entry)
    assert len(events) == 1

    manager = repairs_flow_manager(hass)
    assert manager is not None
    result = await manager.async_init(DOMAIN, data={"issue_id": NEW_ISSUE})
    assert result["type"] is FlowResultType.MENU
    result = await manager.async_configure(result["flow_id"], {"next_step_id": "approve"})
    assert result["type"] is FlowResultType.FORM
    result = await manager.async_configure(
        result["flow_id"], {"name": "Stampante", "category": "computer", "critical": True}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()

    assert ir.async_get(hass).async_get_issue(DOMAIN, NEW_ISSUE) is None
    dev = config_entry.runtime_data.scan.inventory.devices[NEW_MAC]
    assert (dev.status, dev.name, dev.critical) == ("known", "Stampante", True)
    assert hass.states.get("sensor.lan_guardian_unknown_devices").state == "0"

    entity_id = er.async_get(hass).async_get_entity_id(
        "binary_sensor", DOMAIN, f"{NEW_MAC}_connectivity"
    )
    assert entity_id is not None
    assert er.async_get(hass).async_get(entity_id).disabled_by is None
    assert hass.states.get(entity_id).state == "on"


async def test_new_device_ignore(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """Ignoring closes the issue and no entity is created."""
    await _setup(hass, config_entry)
    fake_network.arp["192.168.1.99"] = NEW_MAC
    await _rescan(hass, config_entry)

    manager = repairs_flow_manager(hass)
    assert manager is not None
    result = await manager.async_init(DOMAIN, data={"issue_id": NEW_ISSUE})
    result = await manager.async_configure(result["flow_id"], {"next_step_id": "ignore"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await _rescan(hass, config_entry)

    assert ir.async_get(hass).async_get_issue(DOMAIN, NEW_ISSUE) is None
    assert config_entry.runtime_data.scan.inventory.devices[NEW_MAC].status == "ignored"
    assert (
        er.async_get(hass).async_get_entity_id("binary_sensor", DOMAIN, f"{NEW_MAC}_connectivity")
        is None
    )


async def test_connectivity_entities_disabled_unless_critical(
    hass: HomeAssistant, config_entry: MockConfigEntry
) -> None:
    """Every known device gets an entity, disabled by default; update_device toggles it."""
    await _setup(hass, config_entry)
    registry = er.async_get(hass)
    entity_id = registry.async_get_entity_id("binary_sensor", DOMAIN, f"{GAS_MAC}_connectivity")
    assert entity_id is not None
    assert registry.async_get(entity_id).disabled_by is er.RegistryEntryDisabler.INTEGRATION

    await hass.services.async_call(
        DOMAIN,
        "update_device",
        {"mac": GAS_MAC.upper(), "name": "Sensore gas", "critical": True},
        blocking=True,
    )
    assert registry.async_get(entity_id).disabled_by is None
    assert config_entry.runtime_data.scan.inventory.devices[GAS_MAC].name == "Sensore gas"

    await hass.services.async_call(
        DOMAIN, "update_device", {"mac": GAS_MAC, "critical": False}, blocking=True
    )
    assert registry.async_get(entity_id).disabled_by is er.RegistryEntryDisabler.INTEGRATION


async def test_services_errors_and_forget(
    hass: HomeAssistant, config_entry: MockConfigEntry
) -> None:
    """Unknown MACs are rejected; forget removes device and entity."""
    await _setup(hass, config_entry)
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(
            DOMAIN, "update_device", {"mac": NEW_MAC, "name": "x"}, blocking=True
        )
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(DOMAIN, "forget_device", {"mac": NEW_MAC}, blocking=True)

    await hass.services.async_call(DOMAIN, "forget_device", {"mac": GAS_MAC}, blocking=True)
    assert GAS_MAC not in config_entry.runtime_data.scan.inventory.devices
    assert (
        er.async_get(hass).async_get_entity_id("binary_sensor", DOMAIN, f"{GAS_MAC}_connectivity")
        is None
    )

    with patch.object(
        config_entry.runtime_data.scan, "async_request_refresh", AsyncMock()
    ) as refresh:
        await hass.services.async_call(DOMAIN, "scan_now", {}, blocking=True)
    refresh.assert_awaited_once()


async def test_inventory_entities_on_device_page(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """Each known device gets entities to see and edit its inventory entry."""
    await _setup(hass, config_entry)
    registry = er.async_get(hass)

    def entity_id(platform: str, key: str, mac: str = GAS_MAC) -> str:
        found = registry.async_get_entity_id(platform, DOMAIN, f"{mac}_{key}")
        assert found is not None, f"{platform} {key}"
        return found

    assert hass.states.get(entity_id("sensor", "ip")).state == "192.168.1.248"
    assert hass.states.get(entity_id("sensor", "vendor")).state == "Espressif Inc."
    assert hass.states.get(entity_id("sensor", "last_seen")).state not in ("unknown", None)
    assert hass.states.get(entity_id("select", "status")).state == "known"

    switch = entity_id("switch", "critical")
    assert hass.states.get(switch).state == "off"
    await hass.services.async_call("switch", "turn_on", {"entity_id": switch}, blocking=True)
    dev = config_entry.runtime_data.scan.inventory.devices[GAS_MAC]
    assert dev.critical
    assert hass.states.get(switch).state == "on"
    assert registry.async_get(entity_id("binary_sensor", "connectivity")).disabled_by is None

    await hass.services.async_call(
        "select",
        "select_option",
        {"entity_id": entity_id("select", "category"), "option": "iot"},
        blocking=True,
    )
    assert dev.category == "iot"

    forget = entity_id("button", "forget")
    await hass.services.async_call("button", "press", {"entity_id": forget}, blocking=True)
    await hass.async_block_till_done()
    assert GAS_MAC not in config_entry.runtime_data.scan.inventory.devices
    assert registry.async_get_entity_id("switch", DOMAIN, f"{GAS_MAC}_critical") is None
    assert registry.async_get_entity_id("button", DOMAIN, f"{GAS_MAC}_forget") is None
    assert not [
        device
        for device in dr.async_entries_for_config_entry(dr.async_get(hass), config_entry.entry_id)
        if (dr.CONNECTION_NETWORK_MAC, GAS_MAC) in device.connections
    ]

    # Back as a new device, approved again: it gets its entities back.
    await _rescan(hass, config_entry)
    assert config_entry.runtime_data.scan.inventory.devices[GAS_MAC].status == "new"
    await hass.services.async_call(
        DOMAIN, "update_device", {"mac": GAS_MAC, "status": "known"}, blocking=True
    )
    await hass.async_block_till_done()
    assert hass.states.get(entity_id("switch", "critical")).state == "off"


async def test_critical_offline_issue_and_recovery(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    fake_network: FakeNetwork,
    freezer: FrozenDateTimeFactory,
) -> None:
    """A critical device offline past the threshold raises an issue that closes on return."""
    config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        config_entry, options={CONF_CRITICAL_OFFLINE_MINUTES: 15, CONF_NOTIFY_ENTITIES: []}
    )
    await _setup(hass, config_entry)
    await hass.services.async_call(
        DOMAIN, "update_device", {"mac": GAS_MAC, "critical": True}, blocking=True
    )
    events = async_capture_events(hass, EVENT_NAME)
    issue_id = "critical_offline_a4cf12000248"

    gas_ip = "192.168.1.248"
    del fake_network.arp[gas_ip]
    freezer.tick(timedelta(minutes=20))
    async_fire_time_changed(hass)
    await _rescan(hass, config_entry)
    assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is not None
    assert [e.data["type"] for e in events] == ["critical_offline"]

    fake_network.arp[gas_ip] = GAS_MAC
    await _rescan(hass, config_entry)
    assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is None
    assert [e.data["type"] for e in events] == ["critical_offline", "critical_online"]
    assert f"lan_guardian_critical_offline_{GAS_MAC}" not in _notifications(hass)


async def test_gateway_mac_change_repair(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """A changed gateway MAC raises a critical issue; confirming trusts the new MAC."""
    await _setup(hass, config_entry)
    new_mac = "3c:a6:2f:00:00:02"
    fake_network.arp["192.168.1.1"] = new_mac
    await _rescan(hass, config_entry)

    issue = ir.async_get(hass).async_get_issue(DOMAIN, "gateway_mac_changed")
    assert issue is not None
    assert issue.severity is ir.IssueSeverity.CRITICAL

    manager = repairs_flow_manager(hass)
    assert manager is not None
    result = await manager.async_init(DOMAIN, data={"issue_id": "gateway_mac_changed"})
    assert result["step_id"] == "confirm"
    assert result["description_placeholders"]["current"] == new_mac
    result = await manager.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY

    await _rescan(hass, config_entry)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "gateway_mac_changed") is None
    assert config_entry.runtime_data.scan.inventory.gateway_mac == new_mac


async def test_mac_on_multiple_ips_issue(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """The issue appears while the MAC answers on two IPs and closes afterwards."""
    await _setup(hass, config_entry)
    fake_network.arp["192.168.1.250"] = GAS_MAC
    await _rescan(hass, config_entry)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "mac_multiple_ips_a4cf12000248")

    del fake_network.arp["192.168.1.250"]
    await _rescan(hass, config_entry)
    assert not ir.async_get(hass).async_get_issue(DOMAIN, "mac_multiple_ips_a4cf12000248")
