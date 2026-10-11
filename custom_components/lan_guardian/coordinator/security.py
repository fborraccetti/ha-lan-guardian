"""Security coordinator: find Tasmota and Shelly devices, flag and secure the open ones."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import timedelta
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from ..const import (
    CONF_SECURITY_INTERVAL_HOURS,
    CONF_SHELLY_WARN_NO_PASSWORD,
    CONF_TASMOTA_PASSWORD,
    CONF_TASMOTA_WARN_NO_PASSWORD,
    DOMAIN,
)
from ..issues import ISSUE_SHELLY_NO_PASSWORD, ISSUE_TASMOTA_NO_PASSWORD, sync_issues
from ..notifier import (
    EVENT_SHELLY_NO_PASSWORD,
    EVENT_SHELLY_PASSWORD_APPLIED,
    EVENT_TASMOTA_NO_PASSWORD,
    Notifier,
)
from ..shelly.auth import ShellyError, async_guarded_status, async_set_password
from ..shelly.probe import ShellyProbe, async_probe_shelly
from ..tasmota.password import ApplyResult
from ..tasmota.probe import ProbeResult, WebAuth, async_probe_tasmota

if TYPE_CHECKING:
    import aiohttp
    from homeassistant.config_entries import ConfigEntry

    from .scan import ScanCoordinator

_LOGGER = logging.getLogger(__name__)

TASMOTA_CATEGORY = "tasmota"
SHELLY_CATEGORY = "shelly"
DEFAULT_CATEGORY = "other"


@dataclass(frozen=True, slots=True)
class SecurityResult:
    """Tasmota and Shelly devices found, keyed by MAC."""

    tasmota: dict[str, ProbeResult] = field(default_factory=dict)
    shelly: dict[str, ShellyProbe] = field(default_factory=dict)

    @property
    def open_macs(self) -> list[str]:
        """Tasmota devices without WebPassword."""
        return sorted(mac for mac, res in self.tasmota.items() if res.auth is WebAuth.OPEN)

    @property
    def open_shelly_macs(self) -> list[str]:
        """Shelly devices without authentication."""
        return sorted(mac for mac, res in self.shelly.items() if res.auth is WebAuth.OPEN)


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
        self.options = options
        self.scan = scan
        self.notifier = notifier
        self._semaphore = semaphore
        self.warn_no_password = bool(options[CONF_TASMOTA_WARN_NO_PASSWORD])
        self.warn_shelly_no_password = bool(options[CONF_SHELLY_WARN_NO_PASSWORD])

    async def _async_update_data(self) -> SecurityResult:
        session = async_get_clientsession(self.hass)
        candidates = {
            dev.mac: dev.ip
            for dev in self.scan.inventory.devices.values()
            if dev.online and dev.ip and dev.ip != self.scan.gateway
        }

        async def probe(mac: str, ip: str) -> tuple[str, ProbeResult | ShellyProbe | None]:
            async with self._semaphore:
                if tasmota := await async_probe_tasmota(session, ip):
                    return mac, tasmota
                return mac, await async_probe_shelly(session, ip)

        answers = await asyncio.gather(*(probe(m, ip) for m, ip in candidates.items()))
        found_tasmota = {mac: res for mac, res in answers if isinstance(res, ProbeResult)}
        found_shelly = {mac: res for mac, res in answers if isinstance(res, ShellyProbe)}
        # Keep devices seen before but offline now: still a risk when they come back.
        # A device found now under the other kind (reflashed) leaves the old list.
        inventory = self.scan.inventory
        found = found_tasmota.keys() | found_shelly.keys()
        previous = self.data or SecurityResult()
        result = SecurityResult(
            tasmota={
                **{
                    mac: res
                    for mac, res in previous.tasmota.items()
                    if mac in inventory.devices and mac not in found
                },
                **found_tasmota,
            },
            shelly={
                **{
                    mac: res
                    for mac, res in previous.shelly.items()
                    if mac in inventory.devices and mac not in found
                },
                **found_shelly,
            },
        )

        for macs, category in ((found_tasmota, TASMOTA_CATEGORY), (found_shelly, SHELLY_CATEGORY)):
            for mac in macs:
                if (dev := inventory.devices.get(mac)) and dev.category == DEFAULT_CATEGORY:
                    dev.category = category
        inventory.async_schedule_save()

        await self._async_alerts(result)
        await self._async_shelly_alerts(result)
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

    async def _async_shelly_alerts(self, result: SecurityResult) -> None:
        open_macs = result.open_shelly_macs if self.warn_shelly_no_password else []
        inventory = self.scan.inventory
        labels = [
            f"{dev.display_name} ({result.shelly[mac].ip})"
            if (dev := inventory.devices.get(mac))
            else result.shelly[mac].ip
            for mac in open_macs
        ]
        placeholders = {"count": str(len(open_macs)), "devices": ", ".join(labels)}
        if open_macs:
            await self.notifier.async_notify(
                EVENT_SHELLY_NO_PASSWORD, ",".join(open_macs), placeholders
            )
        sync_issues(
            self.hass,
            ISSUE_SHELLY_NO_PASSWORD,
            {ISSUE_SHELLY_NO_PASSWORD: placeholders} if open_macs else {},
            severity=ir.IssueSeverity.WARNING,
            is_fixable=True,
            learn_more_url="https://shelly-api-docs.shelly.cloud/gen2/General/Authentication",
        )

    # -- Shelly password ---------------------------------------------------------------

    def _shelly_name(self, mac: str) -> str:
        if dev := self.scan.inventory.devices.get(mac):
            return dev.display_name
        return probe.ip if (probe := (self.data or SecurityResult()).shelly.get(mac)) else mac

    async def async_apply_shelly_password(self, macs: Iterable[str] | None = None) -> ApplyResult:
        """Set the stored global password on the given (default: all known) Shelly devices.

        Same rules as the Tasmota WebPassword: the password never leaves the config entry.
        """
        password = str(self.options.get(CONF_TASMOTA_PASSWORD) or "")
        if not password:
            raise ServiceValidationError(translation_domain=DOMAIN, translation_key="no_password")
        known = (self.data or SecurityResult()).shelly
        session = async_get_clientsession(self.hass)
        result = ApplyResult()
        for mac in list(macs) if macs is not None else sorted(known):
            name = self._shelly_name(mac)
            if (probe := known.get(mac)) is None:
                result.offline.append(name)
                continue
            # The IP may have changed since the last security check.
            dev = self.scan.inventory.devices.get(mac)
            ip = dev.ip if dev and dev.ip else probe.ip
            async with self._semaphore:
                outcome = await self._async_apply_shelly(session, probe, ip, password)
            getattr(result, outcome).append(name)
            _LOGGER.debug("Password on Shelly %s: %s", name, outcome)

        none = "-"
        await self.notifier.async_notify(
            EVENT_SHELLY_PASSWORD_APPLIED,
            dt_util.utcnow().isoformat(),  # every run is reported
            {
                "applied": ", ".join(result.applied) or none,
                "already": ", ".join(result.already) or none,
                "other": ", ".join(result.other_password) or none,
                "offline": ", ".join(result.offline) or none,
                "failed": ", ".join(result.failed) or none,
            },
        )
        self.config_entry.async_create_background_task(
            self.hass, self.async_refresh(), f"{DOMAIN} security after Shelly password"
        )
        return result

    async def _async_apply_shelly(
        self, session: aiohttp.ClientSession, probe: ShellyProbe, ip: str, password: str
    ) -> str:
        """Return the ApplyResult field this device belongs to."""
        try:
            status = await async_guarded_status(session, ip, probe.gen, None)
            if status == 401:
                status = await async_guarded_status(session, ip, probe.gen, password)
                return "already" if status == 200 else "other_password"
            if status != 200:
                return "failed"
        except ShellyError:
            return "offline"

        try:
            await async_set_password(session, ip, probe.gen, probe.device_id, password)
        except ShellyError as err:
            # The answer may be lost while the setting went through: the checks decide.
            _LOGGER.debug("Password on Shelly %s: no answer (%s)", ip, err)

        try:
            if await async_guarded_status(session, ip, probe.gen, None) != 401:
                return "failed"  # still open
            if await async_guarded_status(session, ip, probe.gen, password) != 200:
                return "failed"
        except ShellyError:
            return "failed"
        return "applied"
