"""Critical-device switch for each known device."""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import LanGuardianConfigEntry
from .coordinator.scan import ScanCoordinator
from .entity import InventoryEntity, async_add_known_device_entities
from .services import async_update_inventory_device


async def async_setup_entry(
    hass: HomeAssistant,
    entry: LanGuardianConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Add a switch per known device."""
    async_add_known_device_entities(
        entry, async_add_entities, lambda scan, dev: [CriticalSwitch(scan, dev.mac)]
    )


class CriticalSwitch(InventoryEntity, SwitchEntity):
    """Alert when the device goes offline."""

    _attr_translation_key = "critical"

    def __init__(self, coordinator: ScanCoordinator, mac: str) -> None:
        """Initialize."""
        super().__init__(coordinator, mac, "critical")

    @property
    def is_on(self) -> bool | None:
        """Critical in the inventory."""
        dev = self.inventory_device
        return dev.critical if dev else None

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Mark as critical."""
        async_update_inventory_device(
            self.hass, self.coordinator.config_entry, self.mac, critical=True
        )

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Mark as not critical."""
        async_update_inventory_device(
            self.hass, self.coordinator.config_entry, self.mac, critical=False
        )
