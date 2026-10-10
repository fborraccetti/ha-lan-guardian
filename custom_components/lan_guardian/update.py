"""Firmware update entity for each Tasmota device."""

from __future__ import annotations

from typing import Any

from homeassistant.components.update import UpdateEntity, UpdateEntityFeature
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import LanGuardianConfigEntry
from .coordinator.tasmota import TasmotaCoordinator
from .entity import TasmotaEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: LanGuardianConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Add an update entity per Tasmota, including devices discovered later."""
    coordinator = entry.runtime_data.tasmota
    added: set[str] = set()

    @callback
    def add_new() -> None:
        new = [mac for mac in coordinator.devices if mac not in added]
        added.update(new)
        if new:
            async_add_entities(FirmwareUpdate(coordinator, mac) for mac in new)

    add_new()
    entry.async_on_unload(coordinator.async_add_listener(add_new))


class FirmwareUpdate(TasmotaEntity, UpdateEntity):
    """Tasmota firmware against the latest release on GitHub."""

    _attr_translation_key = "firmware"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_title = "Tasmota"

    def __init__(self, coordinator: TasmotaCoordinator, mac: str) -> None:
        """Initialize."""
        super().__init__(coordinator, mac, "firmware")

    @property
    def available(self) -> bool:
        """Stay available while the device reboots into the new firmware."""
        return self.device.updating or super().available

    @property
    def installed_version(self) -> str | None:
        """Running version."""
        info = self.device.info
        return info.version if info else None

    @property
    def latest_version(self) -> str | None:
        """Latest release; the installed one when it cannot be updated from here.

        Development and self-built firmware are never replaced with a release.
        """
        release = self.coordinator.release
        if release is None or self.coordinator.ota_target(self.mac) is None:
            return self.installed_version
        return release.version

    @property
    def release_url(self) -> str | None:
        """GitHub release page."""
        release = self.coordinator.release
        return release.url if release else None

    @property
    def supported_features(self) -> UpdateEntityFeature:
        """Install only with an official image to install."""
        if self.coordinator.ota_target(self.mac) is None:
            return UpdateEntityFeature(0)
        features = UpdateEntityFeature.INSTALL | UpdateEntityFeature.BACKUP
        if self.coordinator.release and self.coordinator.release.notes:
            features |= UpdateEntityFeature.RELEASE_NOTES
        return features

    @property
    def in_progress(self) -> bool:
        """OTA running."""
        return self.device.updating

    async def async_release_notes(self) -> str | None:
        """GitHub release notes, markdown."""
        release = self.coordinator.release
        return release.notes if release else None

    async def async_install(self, version: str | None, backup: bool, **kwargs: Any) -> None:
        """Back up the configuration if asked, then OTA the latest release."""
        await self.coordinator.async_upgrade(self.mac, backup=backup)
