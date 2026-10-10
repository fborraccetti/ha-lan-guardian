"""Network scan coordinator: ping sweep, ARP table, inventory, issues and notifications."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Network, ip_network
import logging
import time
from typing import TYPE_CHECKING, Any

from homeassistant.components import zeroconf
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from ..const import (
    CONF_CRITICAL_OFFLINE_MINUTES,
    CONF_DNS_SERVERS,
    CONF_GATEWAY,
    CONF_PING_CONCURRENCY,
    CONF_RANDOM_MAC_MODE,
    CONF_SCAN_INTERVAL,
    CONF_SUBNET,
    DOMAIN,
)
from ..inventory import STATUS_KNOWN, STATUS_NEW, Device, Inventory, Observation, ScanChanges
from ..issues import (
    ISSUE_CRITICAL_OFFLINE,
    ISSUE_GATEWAY_MAC_CHANGED,
    ISSUE_MAC_MULTIPLE_IPS,
    ISSUE_NEW_DEVICE,
    issue_id,
    mac_key,
    sync_issues,
)
from ..net.arp import read_arp_table
from ..net.icmp import ProbeMode, async_detect_probe_mode, async_ping_hosts
from ..net.mac import async_load_vendors, is_randomized, vendor_for
from ..net.names import async_reverse_lookup, mdns_names
from ..notifier import (
    EVENT_BASELINE,
    EVENT_CRITICAL_OFFLINE,
    EVENT_CRITICAL_ONLINE,
    EVENT_GATEWAY_MAC_CHANGED,
    EVENT_IP_MAC_CHANGED,
    EVENT_MAC_MULTIPLE_IPS,
    EVENT_NEW_DEVICE,
    Notifier,
)

if TYPE_CHECKING:
    from .. import LanGuardianConfigEntry

_LOGGER = logging.getLogger(__name__)

# After the sweep, give the kernel time to fail ARP for hosts that left, so stale
# entries do not count as online (delay_first_probe 5 s + 3 probes of 1 s).
ARP_SETTLE_SECONDS = 6.0


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Summary of the last scan."""

    online: int
    random_online: int
    scanned: int
    duration: float
    probe_mode: str
    finished: datetime


class ScanCoordinator(DataUpdateCoordinator[ScanResult]):
    """Scan the subnet periodically and keep the inventory in sync."""

    config_entry: LanGuardianConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: LanGuardianConfigEntry,
        options: dict[str, Any],
        inventory: Inventory,
        notifier: Notifier,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} scan",
            update_interval=timedelta(minutes=int(options[CONF_SCAN_INTERVAL])),
        )
        self.options = options
        self.inventory = inventory
        self.notifier = notifier
        subnet = ip_network(entry.data[CONF_SUBNET])
        assert isinstance(subnet, IPv4Network)
        self.subnet = subnet
        self.gateway: str = entry.data[CONF_GATEWAY]
        self.probe_mode = ProbeMode.ARP_ONLY
        self._lock = asyncio.Lock()

    async def async_prepare(self) -> None:
        """Load inventory and vendor DB, detect ICMP permissions. Fast: no network I/O."""
        await self.inventory.async_load()
        await async_load_vendors()
        self.probe_mode = await async_detect_probe_mode()
        _LOGGER.debug("Probe mode: %s", self.probe_mode)

    async def _async_update_data(self) -> ScanResult:
        async with self._lock:
            return await self._async_scan()

    async def _async_scan(self) -> ScanResult:
        start = time.monotonic()
        hosts = [str(host) for host in self.subnet.hosts()]
        pings = await async_ping_hosts(
            hosts, self.probe_mode, concurrency=int(self.options[CONF_PING_CONCURRENCY])
        )
        await asyncio.sleep(ARP_SETTLE_SECONDS)
        arp = await self.hass.async_add_executor_job(read_arp_table, self.subnet)

        alive = {ip for ip, result in pings.items() if result.alive}
        # A complete ARP entry after the settle time means the host answered ARP,
        # even if it drops ICMP (Windows firewall, sleeping phones).
        online_ips = alive | arp.keys()

        names = await self._async_names(arp)
        observations = [
            Observation(
                mac=mac,
                ip=ip,
                hostname=names.get(ip),
                vendor=vendor_for(mac),
                randomized=is_randomized(mac),
            )
            for ip, mac in sorted(arp.items())
        ]
        changes = self.inventory.apply_scan(
            observations,
            gateway_ip=self.gateway,
            random_mode=str(self.options[CONF_RANDOM_MAC_MODE]),
            critical_offline_after=timedelta(
                minutes=int(self.options[CONF_CRITICAL_OFFLINE_MINUTES])
            ),
        )
        await self._async_handle_changes(changes)
        self.inventory.async_schedule_save()

        return ScanResult(
            online=len(online_ips),
            random_online=changes.random_online,
            scanned=len(hosts),
            duration=round(time.monotonic() - start, 1),
            probe_mode=self.probe_mode.value,
            finished=dt_util.utcnow(),
        )

    async def _async_names(self, arp: dict[str, str]) -> dict[str, str]:
        """mDNS cache for everything, reverse DNS only where we have no name yet."""
        names: dict[str, str] = {}
        try:
            aiozc = await zeroconf.async_get_async_instance(self.hass)
            names.update(mdns_names(aiozc.zeroconf.cache))
        except Exception:
            _LOGGER.debug("mDNS cache not available", exc_info=True)

        missing = [
            ip
            for ip, mac in arp.items()
            if ip not in names
            and ((dev := self.inventory.devices.get(mac)) is None or not dev.hostname)
        ]
        if missing:
            servers = [self.gateway, *self.options[CONF_DNS_SERVERS]]
            names.update(await async_reverse_lookup(missing, list(dict.fromkeys(servers))))
        return names

    async def _async_handle_changes(self, changes: ScanChanges) -> None:
        inv = self.inventory
        notify = self.notifier

        if changes.baseline:
            await notify.async_notify(EVENT_BASELINE, "baseline", {"count": len(changes.baseline)})
        for dev in changes.new_devices:
            await notify.async_notify(EVENT_NEW_DEVICE, dev.mac, _placeholders(dev))
        sync_issues(
            self.hass,
            ISSUE_NEW_DEVICE,
            {
                issue_id(ISSUE_NEW_DEVICE, mac_key(dev.mac)): _placeholders(dev)
                for dev in inv.by_status(STATUS_NEW)
            },
            severity=ir.IssueSeverity.WARNING,
            is_fixable=True,
            data={
                issue_id(ISSUE_NEW_DEVICE, mac_key(dev.mac)): {"mac": dev.mac}
                for dev in inv.by_status(STATUS_NEW)
            },
        )

        for dev in changes.critical_offline:
            await notify.async_notify(EVENT_CRITICAL_OFFLINE, dev.mac, _placeholders(dev))
        for dev in changes.critical_online:
            notify.dismiss(EVENT_CRITICAL_OFFLINE, dev.mac)
            await notify.async_notify(EVENT_CRITICAL_ONLINE, dev.mac, _placeholders(dev))
        sync_issues(
            self.hass,
            ISSUE_CRITICAL_OFFLINE,
            {
                issue_id(ISSUE_CRITICAL_OFFLINE, mac_key(dev.mac)): _placeholders(dev)
                for dev in inv.devices.values()
                if dev.critical and dev.status == STATUS_KNOWN and dev.offline_alerted
            },
            severity=ir.IssueSeverity.ERROR,
            is_fixable=False,
        )

        multi: dict[str, dict[str, str]] = {}
        for mac, ips in changes.multi_ip.items():
            owner = inv.devices.get(mac)
            placeholders = {
                "mac": mac,
                "name": owner.display_name if owner else mac,
                "ips": ", ".join(ips),
            }
            multi[issue_id(ISSUE_MAC_MULTIPLE_IPS, mac_key(mac))] = placeholders
            await notify.async_notify(EVENT_MAC_MULTIPLE_IPS, mac, placeholders)
        sync_issues(
            self.hass,
            ISSUE_MAC_MULTIPLE_IPS,
            multi,
            severity=ir.IssueSeverity.WARNING,
            is_fixable=False,
        )

        for ip, previous, current in changes.ip_mac_changed:
            await notify.async_notify(
                EVENT_IP_MAC_CHANGED, ip, {"ip": ip, "previous": previous, "current": current}
            )

        gateway_issue: dict[str, dict[str, str]] = {}
        if changes.gateway_mac_changed is not None:
            previous, current = changes.gateway_mac_changed
            gateway_issue[ISSUE_GATEWAY_MAC_CHANGED] = {
                "ip": self.gateway,
                "previous": previous,
                "current": current,
            }
            await notify.async_notify(
                EVENT_GATEWAY_MAC_CHANGED, current, gateway_issue[ISSUE_GATEWAY_MAC_CHANGED]
            )
        # Also clears the issue if the original MAC comes back.
        sync_issues(
            self.hass,
            ISSUE_GATEWAY_MAC_CHANGED,
            gateway_issue,
            severity=ir.IssueSeverity.CRITICAL,
            is_fixable=True,
            data={iid: {"mac": p["current"]} for iid, p in gateway_issue.items()},
        )


def _placeholders(dev: Device) -> dict[str, str]:
    return {
        "name": dev.display_name,
        "mac": dev.mac,
        "ip": dev.ip or "?",
        "vendor": dev.vendor or "?",
        "hostname": dev.hostname or "?",
        "last_seen": dt_util.as_local(datetime.fromisoformat(dev.last_seen)).strftime(
            "%Y-%m-%d %H:%M"
        ),
    }
