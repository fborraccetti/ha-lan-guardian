"""LAN Guardian: watch the home network and manage Tasmota devices."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .const import CONF_TASMOTA_CONCURRENCY, DEFAULT_OPTIONS, DOMAIN

if TYPE_CHECKING:
    from .coordinator.health import HealthCoordinator
    from .coordinator.scan import ScanCoordinator
    from .coordinator.security import SecurityCoordinator
    from .coordinator.tasmota import TasmotaCoordinator
    from .notifier import Notifier

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.SELECT,
    Platform.SENSOR,
    Platform.SWITCH,
    Platform.UPDATE,
]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


@dataclass
class LanGuardianData:
    """Runtime data attached to the config entry."""

    options: dict[str, Any]
    notifier: Notifier
    scan: ScanCoordinator
    health: HealthCoordinator
    security: SecurityCoordinator
    tasmota: TasmotaCoordinator


type LanGuardianConfigEntry = ConfigEntry[LanGuardianData]


def merged_options(entry: ConfigEntry) -> dict[str, Any]:
    """Return the entry options with defaults filled in."""
    return {**DEFAULT_OPTIONS, **entry.options}


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register services once for the domain."""
    from .services import async_setup_services  # noqa: PLC0415

    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: LanGuardianConfigEntry) -> bool:
    """Set up LAN Guardian from a config entry."""
    from .coordinator.health import HealthCoordinator  # noqa: PLC0415
    from .coordinator.scan import ScanCoordinator  # noqa: PLC0415
    from .coordinator.security import SecurityCoordinator  # noqa: PLC0415
    from .coordinator.tasmota import TasmotaCoordinator  # noqa: PLC0415
    from .inventory import Inventory  # noqa: PLC0415
    from .notifier import Notifier  # noqa: PLC0415

    options = merged_options(entry)
    notifier = Notifier(hass, options)
    scan = ScanCoordinator(hass, entry, options, Inventory(hass), notifier)
    await scan.async_prepare()
    health = HealthCoordinator(hass, entry, options, notifier, lambda: scan.probe_mode)
    # One budget for every HTTP request to Tasmota: many of them are on weak 2.4 GHz links.
    tasmota_semaphore = asyncio.Semaphore(int(options[CONF_TASMOTA_CONCURRENCY]))
    security = SecurityCoordinator(hass, entry, options, scan, notifier, tasmota_semaphore)
    tasmota = TasmotaCoordinator(hass, entry, options, scan, security, notifier, tasmota_semaphore)
    entry.runtime_data = LanGuardianData(
        options=options,
        notifier=notifier,
        scan=scan,
        health=health,
        security=security,
        tasmota=tasmota,
    )
    await tasmota.async_prepare()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # A sweep of a /24 takes up to a minute: run the first round in the background
    # instead of blocking startup. The security probe needs the scan results.
    async def first_round() -> None:
        await scan.async_refresh()
        await security.async_refresh()
        await tasmota.async_refresh()

    entry.async_create_background_task(hass, health.async_refresh(), f"{DOMAIN} first health")
    entry.async_create_background_task(hass, first_round(), f"{DOMAIN} first scan")
    return True


async def async_unload_entry(hass: HomeAssistant, entry: LanGuardianConfigEntry) -> bool:
    """Unload a config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.scan.inventory.async_save()
        await entry.runtime_data.tasmota.async_save()
    return unloaded
