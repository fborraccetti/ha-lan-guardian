"""End-to-end tests of the Tasmota coordinator: discovery, sensors, backups, alerts."""

from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path

from freezegun.api import FrozenDateTimeFactory
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import HomeAssistantError
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
    CONF_BACKUP_RETENTION,
    CONF_TASMOTA_DEVICE_PASSWORDS,
    CONF_TASMOTA_PASSWORD,
    DOMAIN,
)
from custom_components.lan_guardian.notifier import EVENT_NAME

from .conftest import FakeNetwork, load_fixture, make_dump

GAS_MAC = "a4:cf:12:00:02:48"
GATE_MAC = "e8:68:e7:00:02:28"
GATE_IP = "192.168.1.228"


@pytest.fixture(autouse=True)
def config_dir(hass: HomeAssistant, tmp_path: Path) -> Path:
    """Write backups to a temporary config dir."""
    hass.config.config_dir = str(tmp_path)
    return tmp_path


def _add_gate(net: FakeNetwork) -> None:
    net.arp[GATE_IP] = GATE_MAC
    net.tasmota[GATE_IP] = net.tasmota.get(GATE_IP) or net.tasmota["192.168.1.248"]
    net.tasmota_status[GATE_IP] = load_fixture("status0_esp32.json")
    net.tasmota_dumps[GATE_IP] = make_dump(7)


async def _setup(hass: HomeAssistant, entry: MockConfigEntry, **options: object) -> None:
    await async_setup_component(hass, "repairs", {})
    entry.add_to_hass(hass)
    if options:
        hass.config_entries.async_update_entry(entry, options=options)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)


async def _poll(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    await entry.runtime_data.tasmota.async_refresh()
    await hass.async_block_till_done()


def _backups(config_dir: Path, mac: str) -> list[str]:
    directory = config_dir / DOMAIN / "backups" / mac.replace(":", "")
    return sorted(p.name for p in directory.glob("*.dmp")) if directory.is_dir() else []


async def test_discovery_and_sensors(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """Probed Tasmota devices get diagnostic sensors and a backup button."""
    _add_gate(fake_network)
    await _setup(hass, config_entry)

    devices = config_entry.runtime_data.tasmota.devices
    assert set(devices) == {GAS_MAC, GATE_MAC}
    assert hass.states.get("sensor.sensore_gas_wi_fi_signal").state == "22"
    assert hass.states.get("sensor.apri_cancello_wi_fi_signal").state == "64"
    assert hass.states.get("sensor.sensore_gas_last_restart_reason").state == (
        "Software/System restart"
    )
    assert hass.states.get("sensor.sensore_gas_last_backup").state == "unknown"
    assert hass.states.get("button.sensore_gas_back_up_now") is not None

    rssi = er.async_get(hass).async_get("sensor.sensore_gas_wi_fi_rssi")
    assert rssi is not None
    assert rssi.disabled_by is er.RegistryEntryDisabler.INTEGRATION


async def test_backup_button_dedup_and_rotation(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    fake_network: FakeNetwork,
    config_dir: Path,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Pressing writes .dmp + .json; identical configs are skipped; old ones rotate."""
    await _setup(hass, config_entry, **{CONF_BACKUP_RETENTION: 2})

    async def press() -> None:
        await hass.services.async_call(
            "button", "press", {"entity_id": "button.sensore_gas_back_up_now"}, blocking=True
        )

    await press()
    assert len(_backups(config_dir, GAS_MAC)) == 1
    assert hass.states.get("sensor.sensore_gas_last_backup").state != "unknown"

    freezer.tick(timedelta(hours=1))
    await press()
    assert len(_backups(config_dir, GAS_MAC)) == 1  # unchanged config

    for seed in (2, 3, 4):
        freezer.tick(timedelta(days=1))
        fake_network.tasmota_dumps["192.168.1.248"] = make_dump(seed)
        await press()
    files = _backups(config_dir, GAS_MAC)
    assert len(files) == 2
    assert all(name.endswith("_sensore-gas.dmp") for name in files)
    directory = config_dir / DOMAIN / "backups" / "a4cf12000248"
    record = json.loads((directory / files[-1].replace(".dmp", ".json")).read_text())
    assert record["device"]["mac"] == GAS_MAC
    assert record["device"]["ip"] == "192.168.1.248"
    assert record["device"]["name"] == "sensore_gas"
    assert record["device"]["hostname"] == "sensore-gas"
    assert record["backup"]["tasmota_filename"] == "Config_x_14.3.0.dmp"
    assert json.loads((directory / "device.json").read_text())["latest_backup"] == files[-1]


async def test_backup_service_all_and_failures(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    fake_network: FakeNetwork,
    config_dir: Path,
) -> None:
    """The service backs up everything; failures raise and send one summary."""
    _add_gate(fake_network)
    await _setup(hass, config_entry)
    await hass.services.async_call(DOMAIN, "backup_tasmota", {}, blocking=True)
    assert _backups(config_dir, GAS_MAC)
    assert _backups(config_dir, GATE_MAC)

    events = async_capture_events(hass, EVENT_NAME)
    del fake_network.tasmota_status[GATE_IP]  # gate unreachable
    device = dr.async_get(hass).async_get_device_by_connection(
        (dr.CONNECTION_NETWORK_MAC, GATE_MAC), config_entry.entry_id
    )
    assert device is not None
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(
            DOMAIN, "backup_tasmota", {"device_id": [device.id]}, blocking=True
        )
    assert [e.data["type"] for e in events] == ["backup_failed"]
    state = hass.states.get("sensor.apri_cancello_last_backup")
    assert state is not None
    assert "192.168.1.228" in state.attributes["error"]


async def test_scheduled_backup(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    config_dir: Path,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Devices never backed up are saved by the hourly check, then only after the interval."""
    await _setup(hass, config_entry)
    assert not _backups(config_dir, GAS_MAC)

    freezer.tick(timedelta(hours=1, seconds=1))
    async_fire_time_changed(hass)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert len(_backups(config_dir, GAS_MAC)) == 1
    first = config_entry.runtime_data.tasmota.devices[GAS_MAC].last_backup

    freezer.tick(timedelta(hours=1))
    async_fire_time_changed(hass)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert config_entry.runtime_data.tasmota.devices[GAS_MAC].last_backup == first


async def test_passwords_global_and_per_device(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """Wrong password raises an issue; the per-device one overrides the global one."""
    _add_gate(fake_network)
    fake_network.tasmota_passwords = {"192.168.1.248": "global-pw", GATE_IP: "gate-pw-01"}
    await _setup(hass, config_entry, **{CONF_TASMOTA_PASSWORD: "global-pw"})

    issue = ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_auth_failed")
    assert issue is not None
    assert "Apri cancello" not in issue.translation_placeholders["devices"]  # no name yet
    assert GATE_IP in issue.translation_placeholders["devices"]
    assert hass.states.get("sensor.apri_cancello_wi_fi_signal") is None or (
        hass.states.get("sensor.apri_cancello_wi_fi_signal").state == "unavailable"
    )

    result = await hass.config_entries.options.async_init(config_entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "tasmota_device"}
    )
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"device": GATE_MAC, CONF_TASMOTA_PASSWORD: "gate-pw-01"}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert config_entry.options[CONF_TASMOTA_DEVICE_PASSWORDS] == {GATE_MAC: "gate-pw-01"}
    await hass.async_block_till_done(wait_background_tasks=True)  # reload

    assert ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_auth_failed") is None
    used = {(host, pw) for host, _what, pw in fake_network.tasmota_calls}
    assert (GATE_IP, "gate-pw-01") in used
    assert ("192.168.1.248", "global-pw") in used


async def test_signal_drop_and_restarts(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """A drop against the usual level raises an issue; three boots in 24 h a restart issue."""
    status = fake_network.tasmota_status["192.168.1.248"]
    status["StatusSTS"]["Wifi"]["RSSI"] = 30
    await _setup(hass, config_entry)
    status["StatusSTS"]["Wifi"]["RSSI"] = 80
    for _ in range(3):  # a drop on a device still building its usual level is not reported
        await _poll(hass, config_entry)
    status["StatusSTS"]["Wifi"]["RSSI"] = 30
    for _ in range(3):
        await _poll(hass, config_entry)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_signal_drop") is None

    status["StatusSTS"]["Wifi"]["RSSI"] = 80
    for _ in range(30):
        await _poll(hass, config_entry)

    status["StatusSTS"]["Wifi"]["RSSI"] = 75  # small dips are normal
    for _ in range(3):
        await _poll(hass, config_entry)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_signal_drop") is None

    status["StatusSTS"]["Wifi"]["RSSI"] = 30
    for _ in range(3):
        status["StatusPRM"]["BootCount"] += 1
        await _poll(hass, config_entry)

    drop = ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_signal_drop")
    assert drop is not None
    assert "sensore_gas (192.168.1.248, " in drop.translation_placeholders["devices"]
    assert "% → 30%)" in drop.translation_placeholders["devices"]
    restarts = ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_frequent_restarts_a4cf12000248")
    assert restarts is not None
    assert restarts.translation_placeholders["count"] == "3"
    assert hass.states.get("sensor.sensore_gas_restarts_in_24_hours").state == "3"

    status["StatusSTS"]["Wifi"]["RSSI"] = 80
    for _ in range(3):
        await _poll(hass, config_entry)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_signal_drop") is None


async def test_import_from_mqtt_integration(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """A device of the official tasmota integration is polled even if the probe missed it."""
    fake_network.tasmota.clear()  # HTTP probe finds nothing
    tasmota_entry = MockConfigEntry(domain="tasmota")
    tasmota_entry.add_to_hass(hass)
    dr.async_get(hass).async_get_or_create(
        config_entry_id=tasmota_entry.entry_id,
        connections={(dr.CONNECTION_NETWORK_MAC, GAS_MAC.upper())},
        name="Sensore gas (MQTT)",
    )
    await _setup(hass, config_entry)
    assert GAS_MAC in config_entry.runtime_data.tasmota.devices
    # Since HA 2026.9 devices are per config entry: ours is separate, theirs untouched.
    registry = dr.async_get(hass)
    connection = (dr.CONNECTION_NETWORK_MAC, GAS_MAC)
    theirs = registry.async_get_device_by_connection(connection, tasmota_entry.entry_id)
    ours = registry.async_get_device_by_connection(connection, config_entry.entry_id)
    assert theirs is not None
    assert ours is not None
    assert theirs.name == "Sensore gas (MQTT)"
    assert (ours.name, ours.sw_version, ours.manufacturer) == ("sensore_gas", "14.3.0", "Tasmota")


async def test_backup_retries_dropped_transfers(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    fake_network: FakeNetwork,
    config_dir: Path,
) -> None:
    """Two dropped transfers are retried; three fail; a wrong password is never retried."""
    await _setup(hass, config_entry)
    tasmota = config_entry.runtime_data.tasmota

    fake_network.tasmota_flaky["192.168.1.248"] = 2
    await tasmota.async_backup(GAS_MAC)
    assert len(_backups(config_dir, GAS_MAC)) == 1

    fake_network.tasmota_flaky["192.168.1.248"] = 3
    with pytest.raises(HomeAssistantError):
        await tasmota.async_backup(GAS_MAC)
    assert "ClientPayloadError" in (tasmota.devices[GAS_MAC].last_backup_error or "")

    fake_network.tasmota_calls.clear()
    fake_network.tasmota_passwords["192.168.1.248"] = "secret"
    with pytest.raises(HomeAssistantError):
        await tasmota.async_backup(GAS_MAC)
    assert [what for _h, what, _p in fake_network.tasmota_calls] == ["dl"]
    assert tasmota.devices[GAS_MAC].last_backup_error == "auth"
