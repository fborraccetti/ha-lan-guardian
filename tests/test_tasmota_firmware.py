"""Firmware updates: latest release, OTA image, update entities."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from freezegun.api import FrozenDateTimeFactory
from homeassistant.components.update import UpdateEntityFeature
from homeassistant.const import STATE_OFF, STATE_ON
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.setup import async_setup_component
import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_capture_events,
)
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.lan_guardian.const import DOMAIN
from custom_components.lan_guardian.notifier import EVENT_NAME
from custom_components.lan_guardian.tasmota.firmware import (
    RELEASES_URL,
    FirmwareError,
    async_fetch_latest_release,
    ota_url,
    parse_release,
)
from custom_components.lan_guardian.tasmota.models import parse_status0

from .conftest import FakeNetwork, load_fixture, make_dump

GAS = "update.sensore_gas_firmware"
GATE_MAC = "e8:68:e7:00:02:28"
GATE_IP = "192.168.1.228"
GATE = "update.apri_cancello_firmware"


@pytest.fixture(autouse=True)
def config_dir(hass: HomeAssistant, tmp_path: Path) -> Path:
    """Write backups to a temporary config dir."""
    hass.config.config_dir = str(tmp_path)
    return tmp_path


async def _setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    await async_setup_component(hass, "repairs", {})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)


def _add_gate(net: FakeNetwork) -> None:
    net.arp[GATE_IP] = GATE_MAC
    net.tasmota[GATE_IP] = net.tasmota["192.168.1.248"]
    net.tasmota_status[GATE_IP] = load_fixture("status0_esp32.json")
    net.tasmota_dumps[GATE_IP] = make_dump(7)


async def _install(hass: HomeAssistant, entity_id: str, *, backup: bool = False) -> None:
    await hass.services.async_call(
        "update", "install", {"entity_id": entity_id, "backup": backup}, blocking=True
    )


def _info(fixture: str, version: str | None = None, ota: str | None = "keep") -> object:
    data = load_fixture(fixture)
    if version is not None:
        data["StatusFWR"]["Version"] = version
    if ota != "keep":
        data["StatusPRM"]["OtaUrl"] = ota
    return parse_status0(data)


@pytest.mark.parametrize(
    ("fixture", "version", "ota", "expected"),
    [
        # The device's official OtaUrl gives the exact image name.
        (
            "status0_esp8266.json",
            None,
            "keep",
            "http://ota.tasmota.com/tasmota/release/tasmota-sensors.bin.gz",
        ),
        (
            "status0_esp32.json",
            None,
            "keep",
            "http://ota.tasmota.com/tasmota32/release/tasmota32.bin",
        ),
        # Development channel on the official server: switched to the release folder.
        (
            "status0_esp8266.json",
            None,
            "http://ota.tasmota.com/tasmota/tasmota-sensors.bin.gz",
            "http://ota.tasmota.com/tasmota/release/tasmota-sensors.bin.gz",
        ),
        # No OtaUrl: from the variant, which the device reports without "tasmota-".
        (
            "status0_esp8266.json",
            None,
            "",
            "http://ota.tasmota.com/tasmota/release/tasmota-sensors.bin.gz",
        ),
        (
            "status0_esp32.json",
            "15.0.1(release-tasmota32)",
            "",
            "http://ota.tasmota.com/tasmota32/release/tasmota32.bin",
        ),
        # Self-built firmware is never replaced.
        ("status0_esp8266.json", None, "http://192.168.1.5/tasmota.bin.gz", None),
    ],
)
def test_ota_url(fixture: str, version: str | None, ota: str, expected: str | None) -> None:
    """Official release image matching the running build."""
    assert ota_url(_info(fixture, version, ota)) == expected  # type: ignore[arg-type]


def test_release_flag() -> None:
    """Development builds carry a git hash instead of 'release-'."""
    assert _info("status0_esp8266.json").release  # type: ignore[attr-defined]
    assert _info("status0_esp8266.json", "13.1.0(tasmota)").release  # type: ignore[attr-defined]
    dev = _info("status0_esp32.json", "15.3.0.2(85cff52-tasmota32)")
    assert not dev.release  # type: ignore[attr-defined]


def test_parse_release() -> None:
    """tag_name without the v, body as notes."""
    release = parse_release(
        {"tag_name": "v15.6.0", "html_url": "https://x/v15.6.0", "body": "notes"}
    )
    assert (release.version, release.url, release.notes) == ("15.6.0", "https://x/v15.6.0", "notes")
    assert parse_release({"tag_name": "v15.6.0", "body": ""}).notes is None
    for bad in ([], {}, {"tag_name": 15}, {"tag_name": "latest"}):
        with pytest.raises(FirmwareError):
            parse_release(bad)


async def test_fetch_latest_release(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """GitHub answer, HTTP errors and bad JSON."""
    session = async_get_clientsession(hass)
    aioclient_mock.get(RELEASES_URL, json={"tag_name": "v15.6.0", "body": "x"})
    assert (await async_fetch_latest_release(session)).version == "15.6.0"

    for kwargs in ({"status": 403}, {"text": "nope"}, {"exc": TimeoutError()}):
        aioclient_mock.clear_requests()
        aioclient_mock.get(RELEASES_URL, **kwargs)
        with pytest.raises(FirmwareError):
            await async_fetch_latest_release(session)


async def test_update_entities(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    fake_network: FakeNetwork,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Each Tasmota gets an update entity; GitHub is asked at most every 12 hours."""
    _add_gate(fake_network)
    await _setup(hass, config_entry)

    state = hass.states.get(GAS)
    assert state.state == STATE_ON
    assert state.attributes["installed_version"] == "14.3.0"
    assert state.attributes["latest_version"] == "15.6.0"
    assert state.attributes["release_url"].endswith("v15.6.0")
    features = UpdateEntityFeature(state.attributes["supported_features"])
    assert UpdateEntityFeature.INSTALL in features
    assert UpdateEntityFeature.BACKUP in features
    assert UpdateEntityFeature.RELEASE_NOTES in features
    assert hass.states.get(GATE).attributes["installed_version"] == "15.0.1"

    checks = fake_network.release_checks
    await config_entry.runtime_data.tasmota.async_refresh()
    assert fake_network.release_checks == checks
    freezer.tick(timedelta(hours=13))
    await config_entry.runtime_data.tasmota.async_refresh()
    assert fake_network.release_checks == checks + 1


async def test_install_with_backup(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    fake_network: FakeNetwork,
    config_dir: Path,
) -> None:
    """Backup first, then OtaUrl + Upgrade 1; done once the new version answers."""
    events = async_capture_events(hass, EVENT_NAME)
    await _setup(hass, config_entry)

    await _install(hass, GAS, backup=True)

    host = "192.168.1.248"
    assert fake_network.tasmota_ota_urls[host] == (
        "http://ota.tasmota.com/tasmota/release/tasmota-sensors.bin.gz"
    )
    commands = [what for h, what, _ in fake_network.tasmota_calls if h == host]
    assert commands.index("dl") < commands.index("Upgrade 1")
    backups = list((config_dir / DOMAIN / "backups" / "a4cf12000248").glob("*.dmp"))
    assert len(backups) == 1

    state = hass.states.get(GAS)
    assert state.state == STATE_OFF
    assert state.attributes["installed_version"] == "15.6.0"
    assert state.attributes["in_progress"] is False
    assert any(
        e.data["type"] == "tasmota_firmware_updated" and e.data["previous"] == "14.3.0"
        for e in events
    )


async def test_install_failure(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """No restart after the download window: the old firmware is still running."""
    events = async_capture_events(hass, EVENT_NAME)
    fake_network.tasmota_ota_fail.add("192.168.1.248")
    await _setup(hass, config_entry)

    with (
        patch(
            "custom_components.lan_guardian.coordinator.tasmota.OTA_RESTART_TIMEOUT",
            timedelta(0),
        ),
        pytest.raises(HomeAssistantError, match="no restart"),
    ):
        await _install(hass, GAS)

    state = hass.states.get(GAS)
    assert state.state == STATE_ON
    assert state.attributes["in_progress"] is False
    assert any(e.data["type"] == "tasmota_firmware_failed" for e in events)


async def test_backup_failure_stops_install(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """A requested backup that fails leaves the firmware alone."""
    await _setup(hass, config_entry)
    fake_network.tasmota_flaky["192.168.1.248"] = 10

    with pytest.raises(HomeAssistantError):
        await _install(hass, GAS, backup=True)
    assert "Upgrade 1" not in [what for _, what, _ in fake_network.tasmota_calls]


@pytest.mark.parametrize(
    ("version", "ota"),
    [
        ("15.3.0.2(85cff52-sensors)", "http://ota.tasmota.com/tasmota/tasmota-sensors.bin.gz"),
        ("14.3.0(release-sensors)", "http://192.168.1.5/my-build.bin.gz"),
    ],
)
async def test_not_installable(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    fake_network: FakeNetwork,
    version: str,
    ota: str,
) -> None:
    """Development and self-built firmware show no update and cannot be installed."""
    status = fake_network.tasmota_status["192.168.1.248"]
    status["StatusFWR"]["Version"] = version
    status["StatusPRM"]["OtaUrl"] = ota
    await _setup(hass, config_entry)

    state = hass.states.get(GAS)
    assert state.state == STATE_OFF
    assert state.attributes["latest_version"] == state.attributes["installed_version"]
    assert state.attributes["supported_features"] == 0
    with pytest.raises(HomeAssistantError):
        await config_entry.runtime_data.tasmota.async_upgrade("a4:cf:12:00:02:48", backup=False)


async def test_github_unreachable(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """Without release information the entity shows no update."""
    fake_network.release = None
    await _setup(hass, config_entry)

    state = hass.states.get(GAS)
    assert state.state == STATE_OFF
    assert state.attributes["latest_version"] == "14.3.0"
