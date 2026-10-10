"""Buttons: back up and secure each Tasmota, forget any known device."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import LanGuardianConfigEntry
from .const import DOMAIN
from .coordinator.scan import ScanCoordinator
from .coordinator.tasmota import TasmotaCoordinator
from .entity import InventoryEntity, TasmotaEntity, async_add_known_device_entities
from .services import async_forget_device


async def async_setup_entry(
    hass: HomeAssistant,
    entry: LanGuardianConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Add the Tasmota buttons, including devices discovered later, and the forget buttons."""
    coordinator = entry.runtime_data.tasmota
    added: set[str] = set()

    @callback
    def add_new() -> None:
        new = [mac for mac in coordinator.devices if mac not in added]
        added.update(new)
        if new:
            async_add_entities(
                button
                for mac in new
                for button in (
                    BackupButton(coordinator, mac),
                    ApplyPasswordButton(coordinator, mac),
                )
            )

    add_new()
    entry.async_on_unload(coordinator.async_add_listener(add_new))

    async_add_known_device_entities(
        entry, async_add_entities, lambda scan, dev: [ForgetButton(scan, dev.mac)]
    )


class BackupButton(TasmotaEntity, ButtonEntity):
    """Download the configuration now."""

    _attr_translation_key = "backup_now"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: TasmotaCoordinator, mac: str) -> None:
        """Initialize."""
        super().__init__(coordinator, mac, "backup_now")

    async def async_press(self) -> None:
        """Back up; errors surface in the UI as HomeAssistantError."""
        await self.coordinator.async_backup(self.mac)


class ApplyPasswordButton(TasmotaEntity, ButtonEntity):
    """Set the stored WebPassword on this device."""

    _attr_translation_key = "apply_password"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: TasmotaCoordinator, mac: str) -> None:
        """Initialize."""
        super().__init__(coordinator, mac, "apply_password")

    async def async_press(self) -> None:
        """Apply, the password itself never leaves the config entry."""
        result = await self.coordinator.async_apply_password([self.mac])
        if result.failed:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="password_failed",
                translation_placeholders={"devices": ", ".join(result.failed)},
            )


class ForgetButton(InventoryEntity, ButtonEntity):
    """Drop the device from the inventory, with its device page."""

    _attr_translation_key = "forget"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: ScanCoordinator, mac: str) -> None:
        """Initialize."""
        super().__init__(coordinator, mac, "forget")

    async def async_press(self) -> None:
        """Forget."""
        async_forget_device(self.hass, self.coordinator.config_entry, self.mac)
