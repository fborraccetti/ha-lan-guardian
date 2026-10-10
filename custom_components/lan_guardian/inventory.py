"""Persistent device inventory and change detection."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import DOMAIN, RANDOM_MAC_GROUP, RANDOM_MAC_TRACK

STORAGE_VERSION = 1
STORAGE_KEY = f"{DOMAIN}.inventory"
SAVE_DELAY = 10
_OWNER_HISTORY = 4

STATUS_KNOWN = "known"
STATUS_IGNORED = "ignored"
STATUS_NEW = "new"
STATUSES = [STATUS_KNOWN, STATUS_IGNORED, STATUS_NEW]

CATEGORIES = [
    "network",
    "server",
    "computer",
    "phone",
    "media",
    "camera",
    "tasmota",
    "shelly",
    "iot",
    "other",
]


@dataclass(slots=True)
class Device:
    """One network device, keyed by MAC."""

    mac: str
    ip: str | None
    status: str
    first_seen: str
    last_seen: str
    name: str | None = None
    category: str = "other"
    critical: bool = False
    hostname: str | None = None
    vendor: str | None = None
    randomized: bool = False
    online: bool = False
    offline_alerted: bool = False

    @property
    def display_name(self) -> str:
        """Best human-readable label."""
        # Reverse DNS gives "sensore-gas.fritz.box": the first label is enough.
        short_host = self.hostname.split(".")[0] if self.hostname else None
        return self.name or short_host or self.vendor or self.mac

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Device:
        """Build from stored data, ignoring unknown keys."""
        known = {key: value for key, value in data.items() if key in cls.__dataclass_fields__}
        return cls(**known)


@dataclass(frozen=True, slots=True)
class Observation:
    """A host seen in this scan."""

    mac: str
    ip: str
    hostname: str | None = None
    vendor: str | None = None
    randomized: bool = False


@dataclass(slots=True)
class ScanChanges:
    """What the inventory noticed in one scan."""

    baseline: list[Device] = field(default_factory=list)
    new_devices: list[Device] = field(default_factory=list)
    critical_offline: list[Device] = field(default_factory=list)
    critical_online: list[Device] = field(default_factory=list)
    multi_ip: dict[str, list[str]] = field(default_factory=dict)  # mac -> ips
    ip_mac_changed: list[tuple[str, str, str]] = field(default_factory=list)  # ip, prev, now
    gateway_mac_changed: tuple[str, str] | None = None  # old, new
    random_online: int = 0


class Inventory:
    """Device inventory backed by a Store."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize an empty inventory."""
        self._store: Store[dict[str, Any]] = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self.devices: dict[str, Device] = {}
        self.gateway_mac: str | None = None
        self.baseline_done = False
        # IP -> recent distinct owners (oldest first), to spot an address flapping.
        self._owner_history: dict[str, list[str]] = {}

    async def async_load(self) -> None:
        """Load the inventory from disk."""
        data = await self._store.async_load()
        if not data:
            return
        self.devices = {dev["mac"]: Device.from_dict(dev) for dev in data.get("devices", [])}
        self.gateway_mac = data.get("gateway_mac")
        self.baseline_done = bool(data.get("baseline_done", False))

    def async_schedule_save(self) -> None:
        """Save shortly, coalescing bursts of changes."""
        self._store.async_delay_save(self._data_to_save, SAVE_DELAY)

    async def async_save(self) -> None:
        """Save now."""
        await self._store.async_save(self._data_to_save())

    def _data_to_save(self) -> dict[str, Any]:
        return {
            "devices": [asdict(dev) for dev in self.devices.values()],
            "gateway_mac": self.gateway_mac,
            "baseline_done": self.baseline_done,
        }

    def by_status(self, status: str) -> list[Device]:
        """Devices with the given status."""
        return [dev for dev in self.devices.values() if dev.status == status]

    def apply_scan(
        self,
        observations: list[Observation],
        *,
        gateway_ip: str,
        random_mode: str,
        critical_offline_after: timedelta,
        now: datetime | None = None,
    ) -> ScanChanges:
        """Merge one scan into the inventory and return what changed."""
        now = now or dt_util.utcnow()
        stamp = now.isoformat()
        changes = ScanChanges()
        baseline = not self.baseline_done

        ips_by_mac: dict[str, list[str]] = defaultdict(list)
        for obs in observations:
            ips_by_mac[obs.mac].append(obs.ip)
        # The trusted gateway may own several addresses (the FRITZ!Box answers on two);
        # someone spoofing it shows up as a gateway MAC change instead.
        changes.multi_ip = {
            mac: sorted(ips)
            for mac, ips in ips_by_mac.items()
            if len(ips) > 1 and mac != self.gateway_mac
        }

        seen: set[str] = set()
        owner: dict[str, str] = {}
        for obs in observations:
            owner[obs.ip] = obs.mac
            if obs.randomized and random_mode != RANDOM_MAC_TRACK:
                if random_mode == RANDOM_MAC_GROUP:
                    changes.random_online += 1
                continue
            seen.add(obs.mac)
            dev = self.devices.get(obs.mac)
            if dev is None:
                dev = Device(
                    mac=obs.mac,
                    ip=obs.ip,
                    status=STATUS_KNOWN if baseline else STATUS_NEW,
                    first_seen=stamp,
                    last_seen=stamp,
                    hostname=obs.hostname,
                    vendor=obs.vendor,
                    randomized=obs.randomized,
                    online=True,
                )
                self.devices[obs.mac] = dev
                (changes.baseline if baseline else changes.new_devices).append(dev)
                continue
            dev.ip = obs.ip
            dev.last_seen = stamp
            dev.online = True
            dev.hostname = obs.hostname or dev.hostname
            dev.vendor = obs.vendor or dev.vendor
            if dev.offline_alerted:
                dev.offline_alerted = False
                if dev.critical and dev.status == STATUS_KNOWN:
                    changes.critical_online.append(dev)

        for dev in self.devices.values():
            if dev.mac in seen:
                continue
            dev.online = False
            if (
                dev.critical
                and dev.status == STATUS_KNOWN
                and not dev.offline_alerted
                and now - datetime.fromisoformat(dev.last_seen) >= critical_offline_after
            ):
                dev.offline_alerted = True
                changes.critical_offline.append(dev)

        # DHCP reuse moves an IP to a new MAC once. An IP that flips back to a MAC it had a
        # few scans ago (A, B, A) is answered by two hosts: address conflict or ARP spoofing.
        for ip, mac in owner.items():
            history = self._owner_history.setdefault(ip, [])
            if history and history[-1] != mac and mac in history[:-1]:
                changes.ip_mac_changed.append((ip, history[-1], mac))
            if not history or history[-1] != mac:
                history.append(mac)
                del history[:-_OWNER_HISTORY]

        if (gw_mac := owner.get(gateway_ip)) is not None:
            if self.gateway_mac is None:
                self.gateway_mac = gw_mac
            elif gw_mac != self.gateway_mac:
                changes.gateway_mac_changed = (self.gateway_mac, gw_mac)

        self.baseline_done = True
        return changes

    def update_device(self, mac: str, **fields: Any) -> Device:
        """Change user-editable fields of a device."""
        dev = self.devices[mac]
        for key in ("name", "category", "critical", "status"):
            if key in fields and fields[key] is not None:
                setattr(dev, key, fields[key])
        if not dev.critical:
            dev.offline_alerted = False
        return dev

    def forget(self, mac: str) -> Device | None:
        """Remove a device; if it shows up again it will be new."""
        return self.devices.pop(mac, None)

    def accept_gateway_mac(self, mac: str) -> None:
        """Trust a new gateway MAC (router replaced)."""
        self.gateway_mac = mac
