"""Per-device connectivity binary sensors."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import LanGuardianConfigEntry
from .coordinator.health import HealthCoordinator
from .coordinator.scan import ScanCoordinator
from .entity import (
    async_add_known_device_entities,
    network_device_info,
    service_device_info,
)
from .inventory import Device


async def async_setup_entry(
    hass: HomeAssistant,
    entry: LanGuardianConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Add one connectivity sensor per known device, and new ones as they get approved."""
    async_add_known_device_entities(
        entry, async_add_entities, lambda scan, dev: [DeviceConnectivity(scan, dev)]
    )

    health = entry.runtime_data.health
    async_add_entities(
        [
            InternetConnectivity(health, entry),
            AdblockActive(health, entry),
            *(DnsServerConnectivity(health, entry, server) for server in health.dns_servers),
        ]
    )


class DeviceConnectivity(CoordinatorEntity[ScanCoordinator], BinarySensorEntity):
    """Whether a device answered the last scan.

    Created for every known device, enabled by default only for critical ones.
    """

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, coordinator: ScanCoordinator, dev: Device) -> None:
        """Initialize from the inventory entry."""
        super().__init__(coordinator)
        self.mac = dev.mac
        self._attr_unique_id = f"{dev.mac}_connectivity"
        self._attr_entity_registry_enabled_default = dev.critical
        self._attr_device_info = network_device_info(coordinator.config_entry, dev.mac)

    @property
    def _device(self) -> Device | None:
        return self.coordinator.inventory.devices.get(self.mac)

    @property
    def available(self) -> bool:
        """Unavailable until the first scan, or once the device is forgotten."""
        return super().available and self.coordinator.data is not None and self._device is not None

    @property
    def is_on(self) -> bool | None:
        """Online in the last scan."""
        dev = self._device
        return dev.online if dev else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Inventory details."""
        dev = self._device
        if dev is None:
            return {}
        return {
            "mac": dev.mac,
            "ip": dev.ip,
            "hostname": dev.hostname,
            "category": dev.category,
            "critical": dev.critical,
            "last_seen": dev.last_seen,
        }


class _HealthBinary(CoordinatorEntity[HealthCoordinator], BinarySensorEntity):
    _attr_has_entity_name = True

    def __init__(
        self, coordinator: HealthCoordinator, entry: LanGuardianConfigEntry, key: str
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._attr_device_info = service_device_info(entry)


class InternetConnectivity(_HealthBinary):
    """The Internet target answers to ping."""

    _attr_translation_key = "internet"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, coordinator: HealthCoordinator, entry: LanGuardianConfigEntry) -> None:
        """Initialize."""
        super().__init__(coordinator, entry, "internet")

    @property
    def is_on(self) -> bool | None:
        """None without ICMP permissions."""
        data = self.coordinator.data
        return data.internet.alive if data and data.internet else None


class AdblockActive(_HealthBinary):
    """Pi-hole blocks the test ad domain."""

    _attr_translation_key = "adblock"

    def __init__(self, coordinator: HealthCoordinator, entry: LanGuardianConfigEntry) -> None:
        """Initialize."""
        super().__init__(coordinator, entry, "adblock")

    @property
    def is_on(self) -> bool | None:
        """None if the check is disabled or the server did not answer."""
        data = self.coordinator.data
        return data.adblock_active if data else None


class DnsServerConnectivity(_HealthBinary):
    """One DNS server answers queries."""

    _attr_translation_key = "dns_server"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(
        self, coordinator: HealthCoordinator, entry: LanGuardianConfigEntry, server: str
    ) -> None:
        """Initialize for one server."""
        super().__init__(coordinator, entry, f"dns_{server}")
        self.server = server
        self._attr_translation_placeholders = {"server": server}

    @property
    def is_on(self) -> bool | None:
        """Answered the last query."""
        data = self.coordinator.data
        check = data.dns.get(self.server) if data else None
        return check.ok if check else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Last error and answer."""
        data = self.coordinator.data
        check = data.dns.get(self.server) if data else None
        if check is None:
            return {}
        return {"time_ms": check.time_ms, "error": check.error, "addresses": list(check.addresses)}
