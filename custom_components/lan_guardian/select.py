"""Category and status selects for each known device."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.select import SelectEntity, SelectEntityDescription
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import LanGuardianConfigEntry
from .coordinator.scan import ScanCoordinator
from .entity import InventoryEntity, async_add_known_device_entities
from .inventory import CATEGORIES, STATUSES
from .services import async_update_inventory_device


@dataclass(frozen=True, kw_only=True)
class InventorySelectDescription(SelectEntityDescription):
    """An inventory field edited through a select; the key is the field name."""


INVENTORY_SELECTS: tuple[InventorySelectDescription, ...] = (
    InventorySelectDescription(
        key="category", translation_key="category", options=list(CATEGORIES)
    ),
    InventorySelectDescription(key="status", translation_key="status", options=list(STATUSES)),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: LanGuardianConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Add the selects of every known device."""
    async_add_known_device_entities(
        entry,
        async_add_entities,
        lambda scan, dev: [InventorySelect(scan, dev.mac, desc) for desc in INVENTORY_SELECTS],
    )


class InventorySelect(InventoryEntity, SelectEntity):
    """One editable inventory field."""

    entity_description: InventorySelectDescription

    def __init__(
        self, coordinator: ScanCoordinator, mac: str, description: InventorySelectDescription
    ) -> None:
        """Initialize."""
        super().__init__(coordinator, mac, description.key)
        self.entity_description = description

    @property
    def current_option(self) -> str | None:
        """Value in the inventory."""
        dev = self.inventory_device
        return getattr(dev, self.entity_description.key) if dev else None

    async def async_select_option(self, option: str) -> None:
        """Store the new value."""
        async_update_inventory_device(
            self.hass,
            self.coordinator.config_entry,
            self.mac,
            **{self.entity_description.key: option},
        )
