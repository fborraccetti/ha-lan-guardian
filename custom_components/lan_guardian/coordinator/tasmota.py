"""Tasmota coordinator: discovery, status polling, signal/restart alerts, backups, OTA."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import device_registry as dr, issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from ..const import (
    CONF_BACKUP_INTERVAL_DAYS,
    CONF_BACKUP_RETENTION,
    CONF_TASMOTA_DEVICE_PASSWORDS,
    CONF_TASMOTA_IMPORT_MQTT,
    CONF_TASMOTA_PASSWORD,
    CONF_TASMOTA_SIGNAL_DROP,
    DOMAIN,
)
from ..issues import (
    ISSUE_TASMOTA_AUTH,
    ISSUE_TASMOTA_RESTARTS,
    ISSUE_TASMOTA_SIGNAL_DROP,
    issue_id,
    mac_key,
    sync_issues,
)
from ..notifier import (
    EVENT_BACKUP_FAILED,
    EVENT_FIRMWARE_FAILED,
    EVENT_FIRMWARE_UPDATED,
    EVENT_PASSWORD_APPLIED,
    EVENT_TASMOTA_AUTH,
    EVENT_TASMOTA_RESTARTS,
    EVENT_TASMOTA_SIGNAL_DROP,
    Notifier,
)
from ..tasmota.backup import BackupResult, BackupStore
from ..tasmota.client import TasmotaAuthError, TasmotaClient, TasmotaError
from ..tasmota.firmware import FirmwareError, Release, async_fetch_latest_release, ota_url
from ..tasmota.models import TasmotaInfo, parse_status0
from ..tasmota.password import ApplyResult

if TYPE_CHECKING:
    from .. import LanGuardianConfigEntry
    from .scan import ScanCoordinator
    from .security import SecurityCoordinator

_LOGGER = logging.getLogger(__name__)

POLL_INTERVAL = timedelta(minutes=5)
BACKUP_CHECK_INTERVAL = timedelta(hours=1)
BACKUP_ATTEMPTS = 3
BACKUP_RETRY_DELAY = 5.0
SIGNAL_SAMPLES = 3  # average over the last polls: one bad reading is not a drop
# The usual level is a running average over about 24 h of polls: it follows slow changes,
# so a sudden drop stands out, and a lasting one becomes the new normal within a day.
BASELINE_SAMPLES = 288
BASELINE_MIN_SAMPLES = 12  # one hour of polls before a new device is compared
RESTART_WINDOW = timedelta(hours=24)
RESTARTS_ALERT = 3
RELEASE_CHECK_INTERVAL = timedelta(hours=12)
# ESP8266 images that do not fit go through tasmota-minimal first: two downloads, two boots.
OTA_TIMEOUT = timedelta(minutes=10)
# Without a restart by then, the download failed and the old firmware kept running.
OTA_RESTART_TIMEOUT = timedelta(minutes=4)
OTA_POLL_SECONDS = 15.0

STORAGE_VERSION = 1
STORAGE_KEY = f"{DOMAIN}.tasmota"


@dataclass
class TasmotaDevice:
    """Live and persisted state of one Tasmota."""

    mac: str
    ip: str | None = None
    info: TasmotaInfo | None = None
    status: dict[str, Any] | None = None
    polled_at: datetime | None = None
    available: bool = False
    auth_failed: bool = False
    error: str | None = None
    updating: bool = False  # OTA running: polls leave the device alone
    signal_samples: deque[int] = field(default_factory=lambda: deque(maxlen=SIGNAL_SAMPLES))
    # Persisted:
    signal_baseline: float | None = None
    baseline_samples: int = 0
    restarts: list[datetime] = field(default_factory=list)
    boot_count: int | None = None
    last_backup: datetime | None = None
    last_backup_error: str | None = None

    label: str | None = None  # inventory name, for devices that never answered

    @property
    def name(self) -> str:
        """Tasmota DeviceName, else the inventory name, the IP or the MAC."""
        return (self.info.name if self.info else None) or self.label or self.ip or self.mac

    @property
    def signal_avg(self) -> float | None:
        """Average signal over the last polls, once enough samples exist."""
        if len(self.signal_samples) < SIGNAL_SAMPLES:
            return None
        return sum(self.signal_samples) / len(self.signal_samples)

    @property
    def signal_drop(self) -> float | None:
        """Points lost by the recent average against the usual level."""
        avg = self.signal_avg
        if avg is None or self.signal_baseline is None:
            return None
        if self.baseline_samples < BASELINE_MIN_SAMPLES:
            return None
        return self.signal_baseline - avg

    def add_signal(self, signal: int) -> None:
        """Record a reading and fold it into the usual level."""
        self.signal_samples.append(signal)
        # Plain mean while warming up, then an exponential average over BASELINE_SAMPLES.
        self.baseline_samples = min(self.baseline_samples + 1, BASELINE_SAMPLES)
        prev = self.signal_baseline if self.signal_baseline is not None else signal
        self.signal_baseline = prev + (signal - prev) / self.baseline_samples

    @property
    def last_restart(self) -> datetime | None:
        """Boot time derived from the uptime at the last poll."""
        if self.info is None or self.info.uptime_sec is None or self.polled_at is None:
            return None
        return self.polled_at - timedelta(seconds=self.info.uptime_sec)

    def to_store(self) -> dict[str, Any]:
        """Persisted fields."""
        return {
            "restarts": [ts.isoformat() for ts in self.restarts],
            "boot_count": self.boot_count,
            "last_backup": self.last_backup.isoformat() if self.last_backup else None,
            "last_backup_error": self.last_backup_error,
            "signal_baseline": self.signal_baseline,
            "baseline_samples": self.baseline_samples,
        }

    def load_store(self, data: dict[str, Any]) -> None:
        """Restore persisted fields."""
        self.restarts = [datetime.fromisoformat(ts) for ts in data.get("restarts", [])]
        self.boot_count = data.get("boot_count")
        last = data.get("last_backup")
        self.last_backup = datetime.fromisoformat(last) if last else None
        self.last_backup_error = data.get("last_backup_error")
        self.signal_baseline = data.get("signal_baseline")
        self.baseline_samples = data.get("baseline_samples", 0)


class TasmotaCoordinator(DataUpdateCoordinator[dict[str, TasmotaDevice]]):
    """Poll every known Tasmota with Status 0."""

    config_entry: LanGuardianConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: LanGuardianConfigEntry,
        options: dict[str, Any],
        scan: ScanCoordinator,
        security: SecurityCoordinator,
        notifier: Notifier,
        semaphore: asyncio.Semaphore,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} tasmota",
            update_interval=POLL_INTERVAL,
        )
        self.options = options
        self.scan = scan
        self.security = security
        self.notifier = notifier
        self.semaphore = semaphore
        self.devices: dict[str, TasmotaDevice] = {}
        self.backups = BackupStore(Path(hass.config.path(DOMAIN, "backups")))
        self._store: Store[dict[str, Any]] = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self._stored: dict[str, Any] = {}
        # One operation per device at a time (poll vs backup vs OTA commands).
        self._device_locks: dict[str, asyncio.Lock] = {}
        # One OTA at a time on the whole LAN: the downloads share the same Wi-Fi.
        self._ota_lock = asyncio.Lock()
        self.release: Release | None = None
        self._release_checked: datetime | None = None

    async def async_prepare(self) -> None:
        """Load persisted state and start the backup schedule."""
        self._stored = await self._store.async_load() or {}
        # Replaced by tasmota_signal_drop: the fixed weak-signal threshold is gone.
        ir.async_delete_issue(self.hass, DOMAIN, "tasmota_weak_signal")
        self.config_entry.async_on_unload(
            async_track_time_interval(
                self.hass, self._async_backup_due, BACKUP_CHECK_INTERVAL, cancel_on_shutdown=True
            )
        )

    def _save(self) -> None:
        self._store.async_delay_save(
            lambda: {mac: dev.to_store() for mac, dev in self.devices.items()}, 10
        )

    async def async_save(self) -> None:
        """Persist now (on unload)."""
        await self._store.async_save({mac: dev.to_store() for mac, dev in self.devices.items()})

    def device_lock(self, mac: str) -> asyncio.Lock:
        """Per-device lock."""
        return self._device_locks.setdefault(mac, asyncio.Lock())

    def password_for(self, mac: str) -> str | None:
        """Per-device WebPassword, else the global one, else none."""
        per_device: dict[str, str] = self.options.get(CONF_TASMOTA_DEVICE_PASSWORDS) or {}
        return per_device.get(mac) or self.options.get(CONF_TASMOTA_PASSWORD) or None

    def client(self, dev: TasmotaDevice) -> TasmotaClient:
        """HTTP client for a device."""
        assert dev.ip is not None
        return TasmotaClient(
            async_get_clientsession(self.hass), dev.ip, self.password_for(dev.mac), self.semaphore
        )

    # -- discovery ---------------------------------------------------------------

    @callback
    def _discover(self) -> None:
        """Tasmota MACs from the HTTP probe, the inventory and the official integration."""
        inventory = self.scan.inventory
        macs: set[str] = {
            mac for mac, dev in inventory.devices.items() if dev.category == "tasmota"
        }
        if self.security.data:
            macs |= set(self.security.data.tasmota)
        if self.options.get(CONF_TASMOTA_IMPORT_MQTT, True):
            macs |= set(self._mqtt_tasmota_macs())

        for mac in macs:
            if mac not in self.devices:
                dev = TasmotaDevice(mac=mac)
                dev.load_store(self._stored.get(mac, {}))
                self.devices[mac] = dev
        for mac, dev in self.devices.items():
            inv = inventory.devices.get(mac)
            probe = self.security.data.tasmota.get(mac) if self.security.data else None
            dev.ip = (inv.ip if inv and inv.ip else None) or (probe.ip if probe else dev.ip)
            if inv is not None and inv.display_name != inv.mac:
                dev.label = inv.display_name

    def _mqtt_tasmota_macs(self) -> Iterable[str]:
        """MACs of devices registered by the official tasmota (MQTT) integration."""
        registry = dr.async_get(self.hass)
        for entry in self.hass.config_entries.async_entries("tasmota"):
            for device in dr.async_entries_for_config_entry(registry, entry.entry_id):
                for kind, value in device.connections:
                    if kind == dr.CONNECTION_NETWORK_MAC:
                        yield dr.format_mac(value)

    # -- polling -----------------------------------------------------------------

    async def _async_update_data(self) -> dict[str, TasmotaDevice]:
        self._discover()
        await self._async_check_release()
        await asyncio.gather(*(self._async_poll(dev) for dev in self.devices.values()))
        await self._async_alerts()
        self._save()
        return self.devices

    async def _async_poll(self, dev: TasmotaDevice) -> None:
        if dev.updating:
            return  # rebooting on purpose: keep the last state until the OTA ends
        if dev.ip is None:
            dev.available = False
            return
        async with self.device_lock(dev.mac):
            try:
                status = await self.client(dev).async_status0()
            except TasmotaAuthError:
                dev.available, dev.auth_failed, dev.error = False, True, "auth"
                return
            except TasmotaError as err:
                dev.available, dev.auth_failed, dev.error = False, False, str(err)
                return
        now = dt_util.utcnow()
        info = parse_status0(status)
        dev.available, dev.auth_failed, dev.error = True, False, None
        dev.info, dev.status, dev.polled_at = info, status, now
        if info.signal is not None:
            dev.add_signal(info.signal)
        if info.boot_count is not None:
            if dev.boot_count is not None and info.boot_count > dev.boot_count:
                # Several boots between two polls count as several restarts.
                dev.restarts.extend([now] * min(info.boot_count - dev.boot_count, 10))
            dev.boot_count = info.boot_count
        dev.restarts = [ts for ts in dev.restarts if now - ts < RESTART_WINDOW]

    async def _async_alerts(self) -> None:
        threshold = int(self.options[CONF_TASMOTA_SIGNAL_DROP])
        dropped = sorted(
            (
                dev
                for dev in self.devices.values()
                if (drop := dev.signal_drop) is not None and drop >= threshold
            ),
            key=lambda d: -(d.signal_drop or 0),
        )
        drop_placeholders = {
            "threshold": str(threshold),
            "devices": ", ".join(
                f"{d.name} ({d.ip}, {d.signal_baseline:.0f}% → {d.signal_avg:.0f}%)"
                for d in dropped
            ),
        }
        if dropped:
            await self.notifier.async_notify(
                EVENT_TASMOTA_SIGNAL_DROP, ",".join(d.mac for d in dropped), drop_placeholders
            )
        sync_issues(
            self.hass,
            ISSUE_TASMOTA_SIGNAL_DROP,
            {ISSUE_TASMOTA_SIGNAL_DROP: drop_placeholders} if dropped else {},
            severity=ir.IssueSeverity.WARNING,
            is_fixable=False,
        )

        restarting: dict[str, dict[str, str]] = {}
        for dev in self.devices.values():
            if len(dev.restarts) < RESTARTS_ALERT:
                continue
            placeholders = {
                "name": dev.name,
                "ip": dev.ip or "?",
                "count": str(len(dev.restarts)),
                "reason": (dev.info.restart_reason if dev.info else None) or "?",
            }
            restarting[issue_id(ISSUE_TASMOTA_RESTARTS, mac_key(dev.mac))] = placeholders
            await self.notifier.async_notify(EVENT_TASMOTA_RESTARTS, dev.mac, placeholders)
        sync_issues(
            self.hass,
            ISSUE_TASMOTA_RESTARTS,
            restarting,
            severity=ir.IssueSeverity.WARNING,
            is_fixable=False,
        )

        denied = [dev for dev in self.devices.values() if dev.auth_failed]
        auth_placeholders = {"devices": ", ".join(f"{d.name} ({d.ip})" for d in denied)}
        if denied:
            await self.notifier.async_notify(
                EVENT_TASMOTA_AUTH, ",".join(d.mac for d in denied), auth_placeholders
            )
        sync_issues(
            self.hass,
            ISSUE_TASMOTA_AUTH,
            {ISSUE_TASMOTA_AUTH: auth_placeholders} if denied else {},
            severity=ir.IssueSeverity.ERROR,
            is_fixable=False,
        )

    # -- backups -------------------------------------------------------------------

    async def async_backup(self, mac: str) -> BackupResult:
        """Back up one device now. Raises HomeAssistantError on failure."""
        dev = self.devices.get(mac)
        if dev is None or dev.ip is None:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="tasmota_unknown",
                translation_placeholders={"mac": mac},
            )
        try:
            async with self.device_lock(mac):
                dump, tasmota_filename, status = await self._async_download(dev)
            now = dt_util.utcnow()
            identity = self._identity(dev, parse_status0(status))
            result = await self.hass.async_add_executor_job(
                lambda: self.backups.save(
                    mac,
                    dump,
                    status,
                    identity=identity,
                    now=now,
                    retention=int(self.options[CONF_BACKUP_RETENTION]),
                    tasmota_filename=tasmota_filename,
                )
            )
        except (TasmotaError, OSError) as err:
            dev.last_backup_error = "auth" if isinstance(err, TasmotaAuthError) else str(err)
            self._save()
            self.async_update_listeners()
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="backup_failed",
                translation_placeholders={"name": dev.name, "error": dev.last_backup_error},
            ) from err
        dev.last_backup = now
        dev.last_backup_error = None
        self._save()
        self.async_update_listeners()
        _LOGGER.debug(
            "Backup of %s: %s", dev.name, "saved" if result.saved else "unchanged, skipped"
        )
        return result

    async def _async_download(self, dev: TasmotaDevice) -> tuple[bytes, str | None, dict[str, Any]]:
        """Config dump + Status 0, retrying dropped transfers on weak Wi-Fi links.

        A wrong password is never retried.
        """
        client = self.client(dev)
        for attempt in range(1, BACKUP_ATTEMPTS + 1):
            try:
                dump, filename = await client.async_download_config()
                status = await client.async_status0()
            except TasmotaAuthError:
                raise
            except TasmotaError as err:
                if attempt == BACKUP_ATTEMPTS:
                    raise
                _LOGGER.debug("Backup of %s, attempt %s failed: %s", dev.name, attempt, err)
                await asyncio.sleep(BACKUP_RETRY_DELAY)
            else:
                return dump, filename, status
        raise AssertionError("unreachable")  # pragma: no cover

    def _identity(self, dev: TasmotaDevice, info: TasmotaInfo) -> dict[str, Any]:
        """Everything needed to recognise the device a backup belongs to."""
        inv = self.scan.inventory.devices.get(dev.mac)
        return {
            "mac": dev.mac,
            "ip": info.ip or dev.ip,
            "name": (inv.name if inv else None) or info.name,
            "device_name": info.device_name,
            "friendly_name": info.friendly_name,
            "hostname": info.hostname,
            "topic": info.topic,
            "version": info.version,
            "variant": info.variant,
            "hardware": info.hardware,
            "status_mac": info.mac,
        }

    async def async_backup_many(self, macs: Iterable[str] | None = None) -> dict[str, str]:
        """Back up several devices one after the other; return mac -> error for failures.

        A single summary notification lists the failures.
        """
        targets = list(macs) if macs is not None else list(self.devices)
        failures: dict[str, str] = {}
        for mac in targets:
            try:
                await self.async_backup(mac)
            except HomeAssistantError as err:
                failures[mac] = str(err)
        if failures:
            names = [
                f"{self.devices[mac].name}" if mac in self.devices else mac for mac in failures
            ]
            await self.notifier.async_notify(
                EVENT_BACKUP_FAILED,
                ",".join(sorted(failures)),
                {"devices": ", ".join(names)},
            )
        return failures

    # -- WebPassword -----------------------------------------------------------------

    async def async_apply_password(self, macs: Iterable[str] | None = None) -> ApplyResult:
        """Set the stored global WebPassword on the given (default: all) devices.

        The password never leaves the config entry: it is not a service parameter,
        it is not logged, and it is not in any event or notification.
        """
        password = str(self.options.get(CONF_TASMOTA_PASSWORD) or "")
        if not password:
            raise ServiceValidationError(translation_domain=DOMAIN, translation_key="no_password")
        result = ApplyResult()
        for mac in list(macs) if macs is not None else list(self.devices):
            dev = self.devices.get(mac)
            if dev is None or dev.ip is None:
                result.offline.append(dev.name if dev else mac)
                continue
            async with self.device_lock(mac):
                outcome = await self._async_apply_one(dev, password)
            getattr(result, outcome).append(dev.name)
            _LOGGER.debug("WebPassword on %s: %s", dev.name, outcome)

        none = "-"
        await self.notifier.async_notify(
            EVENT_PASSWORD_APPLIED,
            dt_util.utcnow().isoformat(),  # every run is reported
            {
                "applied": ", ".join(result.applied) or none,
                "already": ", ".join(result.already) or none,
                "other": ", ".join(result.other_password) or none,
                "offline": ", ".join(result.offline) or none,
                "failed": ", ".join(result.failed) or none,
            },
        )
        # Refresh what the security check knows, without making the caller wait for
        # a probe of the whole LAN.
        self.config_entry.async_create_background_task(
            self.hass, self.security.async_refresh(), f"{DOMAIN} security after password"
        )
        await self.async_request_refresh()
        return result

    async def _async_apply_one(self, dev: TasmotaDevice, password: str) -> str:
        """Return the ApplyResult field this device belongs to."""
        assert dev.ip is not None
        session = async_get_clientsession(self.hass)
        anonymous = TasmotaClient(session, dev.ip, None, self.semaphore)
        with_password = TasmotaClient(session, dev.ip, password, self.semaphore)

        try:
            await anonymous.async_command("Status")
        except TasmotaAuthError:
            try:
                await with_password.async_command("Status")
            except TasmotaAuthError:
                return "other_password"
            except TasmotaError:
                return "offline"
            return "already"
        except TasmotaError:
            return "offline"

        try:
            # WebPassword2 answers with asterisks; WebPassword would echo the password.
            await anonymous.async_command(f"WebPassword2 {password}")
        except TasmotaError as err:
            # The answer may be lost on a weak link while the command went through:
            # the checks below decide.
            _LOGGER.debug("WebPassword2 on %s: no answer (%s)", dev.name, err)

        try:
            await anonymous.async_command("Status")
        except TasmotaAuthError:
            pass  # protected now, as expected
        except TasmotaError:
            return "failed"
        else:
            return "failed"  # still open
        try:
            await with_password.async_command("Status")
        except TasmotaError:
            return "failed"
        return "applied"

    async def _async_backup_due(self, _now: datetime | None = None) -> None:
        """Hourly: back up the reachable devices whose last backup is too old."""
        interval = timedelta(days=int(self.options[CONF_BACKUP_INTERVAL_DAYS]))
        now = dt_util.utcnow()
        due = [
            mac
            for mac, dev in self.devices.items()
            if dev.available and (dev.last_backup is None or now - dev.last_backup >= interval)
        ]
        if due:
            await self.async_backup_many(due)

    # -- firmware ----------------------------------------------------------------------

    async def _async_check_release(self, *, force: bool = False) -> None:
        """Latest Tasmota release from GitHub, at most every RELEASE_CHECK_INTERVAL."""
        now = dt_util.utcnow()
        if (
            not force
            and self._release_checked is not None
            and now - self._release_checked < RELEASE_CHECK_INTERVAL
        ):
            return
        # Also on failure: GitHub's anonymous limit is 60 requests per hour.
        self._release_checked = now
        try:
            self.release = await async_fetch_latest_release(async_get_clientsession(self.hass))
        except FirmwareError as err:
            _LOGGER.debug("Latest Tasmota release unavailable: %s", err)

    async def async_check_release(self) -> None:
        """Check GitHub now and update the entities."""
        await self._async_check_release(force=True)
        self.async_update_listeners()

    def ota_target(self, mac: str) -> str | None:
        """Official OTA image for the device, None when it cannot be updated from here."""
        dev = self.devices.get(mac)
        if dev is None or dev.info is None or not dev.info.release:
            return None
        return ota_url(dev.info)

    async def async_upgrade(self, mac: str, *, backup: bool) -> None:
        """Install the latest release on one device and wait for it to come back.

        Devices are upgraded one at a time. Raises HomeAssistantError on failure.
        """
        dev = self.devices.get(mac)
        if dev is None or dev.ip is None or dev.info is None:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="tasmota_unknown",
                translation_placeholders={"mac": mac},
            )
        release = self.release
        url = self.ota_target(mac)
        if release is None or url is None:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="firmware_unsupported",
                translation_placeholders={"name": dev.name},
            )
        if backup:
            await self.async_backup(mac)

        previous = dev.info.version
        placeholders = {
            "name": dev.name,
            "ip": dev.ip,
            "previous": previous,
            "version": release.version,
        }
        async with self._ota_lock:
            dev.updating = True
            self.async_update_listeners()
            try:
                await self._async_run_upgrade(dev, url, release.version)
            except TasmotaError as err:
                error = "auth" if isinstance(err, TasmotaAuthError) else str(err)
                await self.notifier.async_notify(
                    EVENT_FIRMWARE_FAILED, dev.mac, {**placeholders, "error": error}
                )
                raise HomeAssistantError(
                    translation_domain=DOMAIN,
                    translation_key="firmware_failed",
                    translation_placeholders={"name": dev.name, "error": error},
                ) from err
            finally:
                dev.updating = False
                await self._async_poll(dev)
                self.async_update_listeners()
        await self.notifier.async_notify(EVENT_FIRMWARE_UPDATED, dev.mac, placeholders)

    async def _async_run_upgrade(self, dev: TasmotaDevice, url: str, version: str) -> None:
        """OtaUrl + Upgrade 1, then wait for the device to run the new version."""
        client = self.client(dev)
        async with self.device_lock(dev.mac):
            await client.async_command(f"OtaUrl {url}")
            started = dt_util.utcnow()
            try:
                answer = await client.async_command("Upgrade 1")
            except TasmotaAuthError:
                raise
            except TasmotaError as err:
                # The answer may be lost while the device starts downloading.
                _LOGGER.debug("Upgrade on %s: no answer (%s)", dev.name, err)
            else:
                _LOGGER.debug("Upgrade on %s: %s", dev.name, answer.get("Upgrade"))

        while (elapsed := dt_util.utcnow() - started) < OTA_TIMEOUT:
            await asyncio.sleep(OTA_POLL_SECONDS)
            try:
                info = parse_status0(await client.async_status0())
            except TasmotaAuthError:
                raise
            except TasmotaError:
                continue  # downloading or rebooting
            restarted = info.uptime_sec is not None and info.uptime_sec < elapsed.total_seconds()
            # tasmota-minimal is only the stepping stone to the full image.
            if info.version == version and "minimal" not in (info.variant or ""):
                return
            if not restarted and elapsed >= OTA_RESTART_TIMEOUT:
                raise TasmotaError(f"still running {info.version}, no restart")
        raise TasmotaError(f"no answer with {version} within {OTA_TIMEOUT}")
