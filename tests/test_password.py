"""Tests for setting one WebPassword on every Tasmota."""

from __future__ import annotations

from pathlib import Path

from homeassistant.components import persistent_notification
from homeassistant.components.repairs import repairs_flow_manager
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import entity_registry as er, issue_registry as ir
from homeassistant.setup import async_setup_component
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_capture_events

from custom_components.lan_guardian.const import CONF_TASMOTA_PASSWORD, DOMAIN
from custom_components.lan_guardian.notifier import EVENT_NAME
from custom_components.lan_guardian.tasmota.password import generate_password, password_problem

from .conftest import FakeNetwork, load_fixture, make_dump

PASSWORD = "Example-Pass-2026"
GAS_IP = "192.168.1.248"
GATE_IP = "192.168.1.228"
OTHER_IP = "192.168.1.27"
LOSSY_IP = "192.168.1.132"


@pytest.fixture(autouse=True)
def config_dir(hass: HomeAssistant, tmp_path: Path) -> Path:
    """Keep files out of the package."""
    hass.config.config_dir = str(tmp_path)
    return tmp_path


def _add(net: FakeNetwork, ip: str, mac: str, name: str) -> None:
    status = load_fixture("status0_esp8266.json")
    status["Status"]["DeviceName"] = name
    status["StatusNET"]["Mac"] = mac.upper()
    net.arp[ip] = mac
    net.tasmota[ip] = net.tasmota[GAS_IP]
    net.tasmota_status[ip] = status
    net.tasmota_dumps[ip] = make_dump(len(net.arp))


async def _setup(hass: HomeAssistant, entry: MockConfigEntry, password: str | None) -> None:
    await async_setup_component(hass, "repairs", {})
    entry.add_to_hass(hass)
    if password:
        hass.config_entries.async_update_entry(entry, options={CONF_TASMOTA_PASSWORD: password})
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)


def _everything_visible(hass: HomeAssistant, events: list, caplog: pytest.LogCaptureFixture) -> str:
    notifications = persistent_notification._async_get_or_create_notifications(hass)
    return " ".join(
        [caplog.text, repr([e.data for e in events]), repr(notifications)]
        + [repr(issue.translation_placeholders) for issue in ir.async_get(hass).issues.values()]
    )


@pytest.mark.parametrize(
    ("password", "problem"),
    [
        ("Example-Pass-2026", None),
        ("short", "password_length"),
        ("x" * 33, "password_length"),
        ("with space1", "password_chars"),
        ("semi;colon1", "password_chars"),
        ("accentàèìò1", "password_chars"),
        ("0", "password_reserved"),
        ("1", "password_reserved"),
    ],
)
def test_password_rules(password: str, problem: str | None) -> None:
    """Tasmota's limits on WebPassword."""
    assert password_problem(password) == problem


def test_generated_passwords_are_valid() -> None:
    """Generated passwords pass the rules and differ every time."""
    generated = {generate_password() for _ in range(50)}
    assert len(generated) == 50
    assert all(password_problem(p) is None for p in generated)


async def test_apply_to_all(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    fake_network: FakeNetwork,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Open devices get the password; others are reported; the secret never shows up."""
    caplog.set_level("DEBUG")
    _add(fake_network, GATE_IP, "e8:db:84:00:00:01", "Apri cancello")
    _add(fake_network, OTHER_IP, "e8:db:84:00:00:02", "Luce studio")
    _add(fake_network, LOSSY_IP, "e8:db:84:00:00:03", "Luce garage")
    fake_network.tasmota_passwords[OTHER_IP] = "someone-elses"
    fake_network.ptr[OTHER_IP] = "luce-studio.fritz.box"  # never answers: name from DNS
    fake_network.tasmota_lose_answer.add(LOSSY_IP)
    await _setup(hass, config_entry, PASSWORD)
    events = async_capture_events(hass, EVENT_NAME)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_no_password") is not None

    await hass.services.async_call(DOMAIN, "apply_tasmota_password", {}, blocking=True)
    await hass.async_block_till_done(wait_background_tasks=True)

    assert fake_network.tasmota_passwords[GAS_IP] == PASSWORD
    assert fake_network.tasmota_passwords[GATE_IP] == PASSWORD
    assert fake_network.tasmota_passwords[LOSSY_IP] == PASSWORD  # verified despite lost answer
    assert fake_network.tasmota_passwords[OTHER_IP] == "someone-elses"

    applied = [e.data for e in events if e.data["type"] == "tasmota_password_applied"]
    assert len(applied) == 1
    assert set(applied[0]["applied"].split(", ")) == {"sensore_gas", "Apri cancello", "Luce garage"}
    assert applied[0]["other"] == "luce-studio"
    assert ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_no_password") is None

    # Polling keeps working with the password.
    await config_entry.runtime_data.tasmota.async_refresh()
    assert config_entry.runtime_data.tasmota.devices["a4:cf:12:00:02:48"].available

    assert PASSWORD not in _everything_visible(hass, events, caplog)

    # Second run: everything already done, nothing re-sent.
    fake_network.tasmota_calls.clear()
    await hass.services.async_call(DOMAIN, "apply_tasmota_password", {}, blocking=True)
    assert not any(what.startswith("WebPassword2") for _h, what, _p in fake_network.tasmota_calls)


async def test_unverified_password_raises(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """A device that ignores the command is reported as failed."""
    fake_network.tasmota_ignore_password.add(GAS_IP)
    await _setup(hass, config_entry, PASSWORD)
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(DOMAIN, "apply_tasmota_password", {}, blocking=True)


async def test_apply_password_button_targets_one_device(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """The button on the device page secures that Tasmota only."""
    await _setup(hass, config_entry, PASSWORD)
    entity_id = er.async_get(hass).async_get_entity_id(
        "button", DOMAIN, "a4:cf:12:00:02:48_tasmota_apply_password"
    )
    assert entity_id is not None
    await hass.services.async_call("button", "press", {"entity_id": entity_id}, blocking=True)
    assert fake_network.tasmota_passwords[GAS_IP] == PASSWORD
    assert GATE_IP not in fake_network.tasmota_passwords


async def test_no_stored_password(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """Without a stored password the service refuses and the repair aborts."""
    await _setup(hass, config_entry, None)
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(DOMAIN, "apply_tasmota_password", {}, blocking=True)
    manager = repairs_flow_manager(hass)
    assert manager is not None
    result = await manager.async_init(DOMAIN, data={"issue_id": "tasmota_no_password"})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_password"
    assert GAS_IP not in fake_network.tasmota_passwords


async def test_repair_flow_applies(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """The issue's fix flow lists the devices and applies the password on confirm."""
    await _setup(hass, config_entry, PASSWORD)
    manager = repairs_flow_manager(hass)
    assert manager is not None
    result = await manager.async_init(DOMAIN, data={"issue_id": "tasmota_no_password"})
    assert result["step_id"] == "confirm"
    assert result["description_placeholders"] == {"count": "1", "devices": "sensore-gas"}
    result = await manager.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done(wait_background_tasks=True)
    assert fake_network.tasmota_passwords[GAS_IP] == PASSWORD
    assert ir.async_get(hass).async_get_issue(DOMAIN, "tasmota_no_password") is None


async def test_options_generate_and_validate(
    hass: HomeAssistant, config_entry: MockConfigEntry
) -> None:
    """Invalid passwords are refused; a generated one is shown once, then stored."""
    await _setup(hass, config_entry, None)
    base = {
        "tasmota_concurrency": 3,
        "tasmota_signal_drop": 20,
        "backup_interval_days": 7,
        "backup_retention": 10,
    }

    async def open_tasmota() -> str:
        result = await hass.config_entries.options.async_init(config_entry.entry_id)
        result = await hass.config_entries.options.async_configure(
            result["flow_id"], {"next_step_id": "tasmota"}
        )
        return str(result["flow_id"])

    flow_id = await open_tasmota()
    result = await hass.config_entries.options.async_configure(
        flow_id, {**base, CONF_TASMOTA_PASSWORD: "short"}
    )
    assert result["errors"] == {CONF_TASMOTA_PASSWORD: "password_length"}

    result = await hass.config_entries.options.async_configure(
        flow_id, {**base, "generate_password": True}
    )
    assert result["step_id"] == "tasmota_password_generated"
    shown = result["description_placeholders"]["password"]
    assert password_problem(shown) is None
    assert CONF_TASMOTA_PASSWORD not in config_entry.options  # not saved yet
    result = await hass.config_entries.options.async_configure(flow_id, {})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert config_entry.options[CONF_TASMOTA_PASSWORD] == shown
    assert "generate_password" not in config_entry.options
