"""Tests for the config and options flow."""

from __future__ import annotations

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lan_guardian.const import (
    CONF_ADBLOCK_TEST_DOMAIN,
    CONF_BACKUP_INTERVAL_DAYS,
    CONF_BACKUP_RETENTION,
    CONF_CRITICAL_OFFLINE_MINUTES,
    CONF_DNS_SERVERS,
    CONF_DNS_TEST_DOMAIN,
    CONF_GATEWAY,
    CONF_HEALTH_INTERVAL,
    CONF_INTERNET_TARGET,
    CONF_LOSS_THRESHOLD,
    CONF_NOTIFY_COOLDOWN_MINUTES,
    CONF_NOTIFY_ENTITIES,
    CONF_NOTIFY_PERSISTENT,
    CONF_NOTIFY_SERVICE,
    CONF_PING_CONCURRENCY,
    CONF_RANDOM_MAC_MODE,
    CONF_SCAN_INTERVAL,
    CONF_SUBNET,
    CONF_TASMOTA_CONCURRENCY,
    CONF_TASMOTA_PASSWORD,
    CONF_TASMOTA_SIGNAL_DROP,
    DOMAIN,
    RANDOM_MAC_IGNORE,
)


@pytest.mark.usefixtures("mock_adapters")
async def test_user_flow_defaults_and_create(hass: HomeAssistant) -> None:
    """The form proposes the detected subnet and creates the entry."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    schema = result["data_schema"].schema
    defaults = {str(key): key.default() for key in schema}
    assert defaults == {CONF_SUBNET: "192.168.1.0/24", CONF_GATEWAY: "192.168.1.1"}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_SUBNET: "192.168.1.77/24", CONF_GATEWAY: " 192.168.1.1 "}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "LAN Guardian (192.168.1.0/24)"
    assert result["data"] == {CONF_SUBNET: "192.168.1.0/24", CONF_GATEWAY: "192.168.1.1"}


@pytest.mark.usefixtures("mock_adapters")
@pytest.mark.parametrize(
    ("subnet", "gateway", "errors"),
    [
        ("not-a-net", "192.168.1.1", {CONF_SUBNET: "invalid_subnet"}),
        ("fd00::/64", "192.168.1.1", {CONF_SUBNET: "invalid_subnet"}),
        ("10.0.0.0/16", "10.0.0.1", {CONF_SUBNET: "subnet_too_large"}),
        ("192.168.1.0/24", "nope", {CONF_GATEWAY: "invalid_ip"}),
        ("192.168.1.0/24", "192.168.2.1", {CONF_GATEWAY: "gateway_outside_subnet"}),
    ],
)
async def test_user_flow_errors(
    hass: HomeAssistant, subnet: str, gateway: str, errors: dict[str, str]
) -> None:
    """Invalid input shows the form again with an error."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_SUBNET: subnet, CONF_GATEWAY: gateway}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == errors


async def test_single_instance(hass: HomeAssistant, config_entry: MockConfigEntry) -> None:
    """Only one entry is allowed."""
    config_entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "single_instance_allowed"


async def _open_options(hass: HomeAssistant, entry: MockConfigEntry, step: str) -> str:
    if hass.config_entries.async_get_entry(entry.entry_id) is None:
        entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.MENU
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": step}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == step
    return str(result["flow_id"])


async def test_options_scan(hass: HomeAssistant, config_entry: MockConfigEntry) -> None:
    """Scan options are saved as integers next to the defaults."""
    flow_id = await _open_options(hass, config_entry, "scan")
    result = await hass.config_entries.options.async_configure(
        flow_id,
        {
            CONF_SCAN_INTERVAL: 5.0,
            CONF_RANDOM_MAC_MODE: RANDOM_MAC_IGNORE,
            CONF_CRITICAL_OFFLINE_MINUTES: 30.0,
            CONF_PING_CONCURRENCY: 16.0,
        },
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert config_entry.options[CONF_SCAN_INTERVAL] == 5
    assert isinstance(config_entry.options[CONF_SCAN_INTERVAL], int)
    assert config_entry.options[CONF_RANDOM_MAC_MODE] == RANDOM_MAC_IGNORE
    # Untouched sections keep their defaults.
    assert config_entry.options[CONF_BACKUP_RETENTION] == 10


async def test_options_health_validation(
    hass: HomeAssistant, config_entry: MockConfigEntry
) -> None:
    """Bad hosts and DNS servers are rejected; good input is saved."""
    flow_id = await _open_options(hass, config_entry, "health")
    good = {
        CONF_HEALTH_INTERVAL: 2,
        CONF_INTERNET_TARGET: "1.1.1.1",
        CONF_LOSS_THRESHOLD: 20,
        CONF_DNS_SERVERS: ["192.168.1.9", "192.168.1.1"],
        CONF_DNS_TEST_DOMAIN: "www.google.com",
        CONF_ADBLOCK_TEST_DOMAIN: "doubleclick.net",
    }
    result = await hass.config_entries.options.async_configure(
        flow_id,
        {
            **good,
            CONF_INTERNET_TARGET: "bad host!",
            CONF_DNS_SERVERS: ["pihole"],
            CONF_ADBLOCK_TEST_DOMAIN: "-x-",
        },
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {
        CONF_INTERNET_TARGET: "invalid_host",
        CONF_DNS_SERVERS: "invalid_ip",
        CONF_ADBLOCK_TEST_DOMAIN: "invalid_host",
    }

    result = await hass.config_entries.options.async_configure(
        flow_id, {**good, CONF_DNS_SERVERS: [" 192.168.1.9 ", ""]}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert config_entry.options[CONF_DNS_SERVERS] == ["192.168.1.9"]


async def test_options_tasmota_keeps_password(
    hass: HomeAssistant, config_entry: MockConfigEntry
) -> None:
    """An empty password field keeps the stored password."""
    config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(config_entry, options={CONF_TASMOTA_PASSWORD: "s3cret"})
    flow_id = await _open_options(hass, config_entry, "tasmota")
    result = await hass.config_entries.options.async_configure(
        flow_id,
        {
            CONF_TASMOTA_CONCURRENCY: 2,
            CONF_TASMOTA_SIGNAL_DROP: 25,
            CONF_BACKUP_INTERVAL_DAYS: 14,
            CONF_BACKUP_RETENTION: 5,
        },
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert config_entry.options[CONF_TASMOTA_PASSWORD] == "s3cret"
    assert config_entry.options[CONF_BACKUP_INTERVAL_DAYS] == 14


async def test_options_notify(hass: HomeAssistant, config_entry: MockConfigEntry) -> None:
    """The legacy notify action must look like domain.action."""
    flow_id = await _open_options(hass, config_entry, "notify")
    base = {CONF_NOTIFY_PERSISTENT: True, CONF_NOTIFY_COOLDOWN_MINUTES: 60}
    result = await hass.config_entries.options.async_configure(
        flow_id, {**base, CONF_NOTIFY_SERVICE: "telegram send"}
    )
    assert result["errors"] == {CONF_NOTIFY_SERVICE: "invalid_service"}

    result = await hass.config_entries.options.async_configure(
        flow_id, {**base, CONF_NOTIFY_SERVICE: "notify.mobile_app_sm_g991b"}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert config_entry.options[CONF_NOTIFY_SERVICE] == "notify.mobile_app_sm_g991b"
    assert config_entry.options[CONF_NOTIFY_ENTITIES] == []
