"""Shared entity helpers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

from homeassistant.core import callback
from homeassistant.helpers.device_registry import (
    CONNECTION_NETWORK_MAC,
    DeviceEntryType,
    DeviceInfo,
)
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .inventory import STATUS_KNOWN, Device

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

    from . import LanGuardianConfigEntry
    from .coordinator.scan import ScanCoordinator
    from .coordinator.tasmota import TasmotaCoordinator, TasmotaDevice


def service_device_info(entry: ConfigEntry) -> DeviceInfo:
    """The LAN Guardian service device that groups the integration-wide entities."""
    return DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name="LAN Guardian",
        manufacturer="LAN Guardian",
        entry_type=DeviceEntryType.SERVICE,
    )


def network_device_info(entry: LanGuardianConfigEntry, mac: str) -> DeviceInfo:
    """Device of one LAN host, shared by its connectivity sensor and Tasmota entities.

    Since HA 2026.9 devices are scoped to their config entry, so this is LAN Guardian's
    own device even when Tasmota or FRITZ! registered the same MAC. The name is chosen
    here only, so the platforms never fight over it.
    """
    data = entry.runtime_data
    inv = data.scan.inventory.devices.get(mac)
    tas = data.tasmota.devices.get(mac)
    info = tas.info if tas else None
    name = (
        (inv.name if inv else None)
        or (info.name if info else None)
        or (inv.display_name if inv else None)
        or mac
    )
    return DeviceInfo(
        connections={(CONNECTION_NETWORK_MAC, mac)},
        name=name,
        manufacturer="Tasmota" if tas else (inv.vendor if inv else None),
        model=info.hardware if info else None,
        sw_version=info.version if info else None,
    )


class TasmotaEntity(CoordinatorEntity["TasmotaCoordinator"]):
    """Base for entities of one Tasmota device."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: TasmotaCoordinator, mac: str, key: str) -> None:
        """Initialize for one device."""
        super().__init__(coordinator)
        self.mac = mac
        self._attr_unique_id = f"{mac}_tasmota_{key}"
        self._attr_device_info = network_device_info(coordinator.config_entry, mac)

    @property
    def device(self) -> TasmotaDevice:
        """Current state of the device."""
        return self.coordinator.devices[self.mac]

    @property
    def available(self) -> bool:
        """Reachable at the last poll."""
        return super().available and self.device.available


class InventoryEntity(CoordinatorEntity["ScanCoordinator"]):
    """Base for the entities that show or edit one inventory entry."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: ScanCoordinator, mac: str, key: str) -> None:
        """Initialize for one device."""
        super().__init__(coordinator)
        self.mac = mac
        self._attr_unique_id = f"{mac}_{key}"
        self._attr_device_info = network_device_info(coordinator.config_entry, mac)

    @property
    def inventory_device(self) -> Device | None:
        """The inventory entry, None once forgotten."""
        return self.coordinator.inventory.devices.get(self.mac)

    @property
    def available(self) -> bool:
        """Unavailable once the device is forgotten."""
        return super().available and self.inventory_device is not None


def async_add_known_device_entities(
    entry: LanGuardianConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
    factory: Callable[[ScanCoordinator, Device], Iterable[Entity]],
) -> None:
    """Add entities for every known device, now and whenever one gets approved.

    A forgotten device is dropped from the bookkeeping, so it gets its entities
    back if it is approved again.
    """
    coordinator = entry.runtime_data.scan
    added: set[str] = set()

    @callback
    def add_new() -> None:
        devices = coordinator.inventory.devices
        added.intersection_update(devices)
        new = [
            dev for dev in devices.values() if dev.status == STATUS_KNOWN and dev.mac not in added
        ]
        added.update(dev.mac for dev in new)
        if new:
            async_add_entities([entity for dev in new for entity in factory(coordinator, dev)])

    add_new()
    entry.async_on_unload(coordinator.async_add_listener(add_new))
