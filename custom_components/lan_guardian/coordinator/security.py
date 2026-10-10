"""Security coordinator: find Tasmota devices on the LAN and flag those without WebPassword."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from ..const import CONF_SECURITY_INTERVAL_HOURS, CONF_TASMOTA_WARN_NO_PASSWORD, DOMAIN
from ..issues import ISSUE_TASMOTA_NO_PASSWORD, sync_issues
from ..notifier import EVENT_TASMOTA_NO_PASSWORD, Notifier
from ..tasmota.probe import ProbeResult, WebAuth, async_probe_tasmota

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry

    from .scan import ScanCoordinator

_LOGGER = logging.getLogger(__name__)

TASMOTA_CATEGORY = "tasmota"
DEFAULT_CATEGORY = "other"


@dataclass(frozen=True, slots=True)
class SecurityResult:
    """Tasmota devices found, keyed by MAC."""

    tasmota: dict[str, ProbeResult] = field(default_factory=dict)

    @property
    def open_macs(self) -> list[str]:
        """Tasmota devices without WebPassword."""
        return sorted(mac for mac, res in self.tasmota.items() if res.auth is WebAuth.OPEN)


class SecurityCoordinator(DataUpdateCoordinator[SecurityResult]):
    """Probe online hosts over HTTP, a few at a time (weak 2.4 GHz devices)."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        options: dict[str, Any],
        scan: ScanCoordinator,
        notifier: Notifier,
        semaphore: asyncio.Semaphore,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} security",
            update_interval=timedelta(hours=int(options[CONF_SECURITY_INTERVAL_HOURS])),
        )
        self.scan = scan
        self.notifier = notifier
        self._semaphore = semaphore
        self.warn_no_password = bool(options[CONF_TASMOTA_WARN_NO_PASSWORD])

    async def _async_update_data(self) -> SecurityResult:
        session = async_get_clientsession(self.hass)
        candidates = {
            dev.mac: dev.ip
            for dev in self.scan.inventory.devices.values()
            if dev.online and dev.ip and dev.ip != self.scan.gateway
        }

        async def probe(mac: str, ip: str) -> tuple[str, ProbeResult | None]:
            async with self._semaphore:
                return mac, await async_probe_tasmota(session, ip)

        found = {
            mac: res
            for mac, res in await asyncio.gather(*(probe(m, ip) for m, ip in candidates.items()))
            if res is not None
        }
        # Keep devices seen before but offline now: still a risk when they come back.
        previous = self.data.tasmota if self.data else {}
        merged = {
            **{mac: res for mac, res in previous.items() if mac in self.scan.inventory.devices},
            **found,
        }
        result = SecurityResult(tasmota=merged)

        inventory = self.scan.inventory
        for mac in found:
            if (dev := inventory.devices.get(mac)) and dev.category == DEFAULT_CATEGORY:
                dev.category = TASMOTA_CATEGORY
        inventory.async_schedule_save()

        await self._async_alerts(result)
        return result

    async def _async_alerts(self, result: SecurityResult) -> None:
        # The warning can be turned off in the options; then sync_issues({}) also
        # closes an issue raised earlier.
        open_macs = result.open_macs if self.warn_no_password else []
        inventory = self.scan.inventory
        labels = [
            f"{dev.display_name} ({result.tasmota[mac].ip})"
            if (dev := inventory.devices.get(mac))
            else result.tasmota[mac].ip
            for mac in open_macs
        ]
        placeholders = {"count": str(len(open_macs)), "devices": ", ".join(labels)}
        if open_macs:
            # Key on the set of devices: a new unprotected device notifies again.
            await self.notifier.async_notify(
                EVENT_TASMOTA_NO_PASSWORD, ",".join(open_macs), placeholders
            )
        sync_issues(
            self.hass,
            ISSUE_TASMOTA_NO_PASSWORD,
            {ISSUE_TASMOTA_NO_PASSWORD: placeholders} if open_macs else {},
            severity=ir.IssueSeverity.WARNING,
            is_fixable=True,
            learn_more_url="https://tasmota.github.io/docs/Commands/#management",
        )
