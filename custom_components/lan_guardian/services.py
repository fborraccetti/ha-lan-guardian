"""LAN Guardian services."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import ATTR_DEVICE_ID
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import (
    config_validation as cv,
    device_registry as dr,
    entity_registry as er,
)
import voluptuous as vol

from .const import DOMAIN
from .inventory import CATEGORIES, STATUS_KNOWN, STATUSES
from .net.mac import normalize_mac

if TYPE_CHECKING:
    from . import LanGuardianConfigEntry

SERVICE_SCAN_NOW = "scan_now"
SERVICE_UPDATE_DEVICE = "update_device"
SERVICE_FORGET_DEVICE = "forget_device"
SERVICE_BACKUP_TASMOTA = "backup_tasmota"
SERVICE_APPLY_TASMOTA_PASSWORD = "apply_tasmota_password"

ATTR_MAC = "mac"


def _mac(value: Any) -> str:
    mac = normalize_mac(cv.string(value))
    if mac is None:
        raise vol.Invalid("invalid MAC address")
    return mac


UPDATE_DEVICE_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_MAC): _mac,
        vol.Optional("name"): cv.string,
        vol.Optional("category"): vol.In(CATEGORIES),
        vol.Optional("critical"): cv.boolean,
        vol.Optional("status"): vol.In(STATUSES),
    }
)
FORGET_DEVICE_SCHEMA = vol.Schema({vol.Required(ATTR_MAC): _mac})
BACKUP_TASMOTA_SCHEMA = vol.Schema(
    {vol.Optional(ATTR_DEVICE_ID, default=[]): vol.All(cv.ensure_list, [cv.string])}
)


def macs_for_devices(hass: HomeAssistant, device_ids: list[str]) -> list[str]:
    """MAC addresses of the given device registry ids."""
    registry = dr.async_get(hass)
    macs: list[str] = []
    for device_id in device_ids:
        device = registry.async_get(device_id)
        found = [
            dr.format_mac(value)
            for kind, value in getattr(device, "connections", ())
            if kind == dr.CONNECTION_NETWORK_MAC
        ]
        if not found:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="not_a_tasmota",
                translation_placeholders={"device_id": device_id},
            )
        macs.extend(found)
    return macs


def loaded_entry(hass: HomeAssistant) -> LanGuardianConfigEntry:
    """The single loaded LAN Guardian entry."""
    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.state is ConfigEntryState.LOADED:
            return entry
    raise ServiceValidationError(translation_domain=DOMAIN, translation_key="not_loaded")


def sync_connectivity_entity(hass: HomeAssistant, mac: str, critical: bool) -> None:
    """Enable the connectivity entity for critical devices, disable it for the others.

    Only touches entities that we disabled ourselves, never a user choice.
    """
    registry = er.async_get(hass)
    entity_id = registry.async_get_entity_id("binary_sensor", DOMAIN, f"{mac}_connectivity")
    if entity_id is None or (entry := registry.async_get(entity_id)) is None:
        return
    if critical and entry.disabled_by is er.RegistryEntryDisabler.INTEGRATION:
        registry.async_update_entity(entity_id, disabled_by=None)
    elif not critical and entry.disabled_by is None:
        registry.async_update_entity(entity_id, disabled_by=er.RegistryEntryDisabler.INTEGRATION)


def _unknown_device(mac: str) -> ServiceValidationError:
    return ServiceValidationError(
        translation_domain=DOMAIN,
        translation_key="unknown_device",
        translation_placeholders={"mac": mac},
    )


@callback
def async_update_inventory_device(
    hass: HomeAssistant, entry: LanGuardianConfigEntry, mac: str, **fields: Any
) -> None:
    """Change user-editable fields of a device, from the service or its entities."""
    coordinator = entry.runtime_data.scan
    if mac not in coordinator.inventory.devices:
        raise _unknown_device(mac)
    dev = coordinator.inventory.update_device(mac, **fields)
    coordinator.inventory.async_schedule_save()
    sync_connectivity_entity(hass, mac, dev.critical and dev.status == STATUS_KNOWN)
    coordinator.async_update_listeners()


@callback
def async_forget_device(hass: HomeAssistant, entry: LanGuardianConfigEntry, mac: str) -> None:
    """Drop a device from the inventory together with its device page and entities.

    If it shows up again it is a new device; a Tasmota gets its entities back on reload.
    """
    coordinator = entry.runtime_data.scan
    if coordinator.inventory.forget(mac) is None:
        raise _unknown_device(mac)
    coordinator.inventory.async_schedule_save()
    entities = er.async_get(hass)
    if entity_id := entities.async_get_entity_id("binary_sensor", DOMAIN, f"{mac}_connectivity"):
        entities.async_remove(entity_id)
    devices = dr.async_get(hass)
    for device in dr.async_entries_for_config_entry(devices, entry.entry_id):
        if (dr.CONNECTION_NETWORK_MAC, mac) in device.connections:
            # Removing our entry from the device also removes our entities on it.
            devices.async_update_device(device.id, remove_config_entry_id=entry.entry_id)
    coordinator.async_update_listeners()


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Register the domain services."""

    async def scan_now(call: ServiceCall) -> None:
        await loaded_entry(hass).runtime_data.scan.async_request_refresh()

    async def update_device(call: ServiceCall) -> None:
        fields = {
            key: call.data[key]
            for key in ("name", "category", "critical", "status")
            if key in call.data
        }
        async_update_inventory_device(hass, loaded_entry(hass), call.data[ATTR_MAC], **fields)

    async def forget_device(call: ServiceCall) -> None:
        async_forget_device(hass, loaded_entry(hass), call.data[ATTR_MAC])

    async def backup_tasmota(call: ServiceCall) -> None:
        coordinator = loaded_entry(hass).runtime_data.tasmota
        macs = macs_for_devices(hass, call.data[ATTR_DEVICE_ID]) or None
        if macs is not None and (unknown := [m for m in macs if m not in coordinator.devices]):
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="tasmota_unknown",
                translation_placeholders={"mac": ", ".join(unknown)},
            )
        failures = await coordinator.async_backup_many(macs)
        if failures:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="backups_failed",
                translation_placeholders={"count": str(len(failures))},
            )

    async def apply_tasmota_password(call: ServiceCall) -> None:
        # Deliberately no password field: service data ends up in the recorder,
        # traces and logbook. The stored global password is used.
        coordinator = loaded_entry(hass).runtime_data.tasmota
        macs = macs_for_devices(hass, call.data[ATTR_DEVICE_ID]) or None
        result = await coordinator.async_apply_password(macs)
        if result.failed:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="password_failed",
                translation_placeholders={"devices": ", ".join(result.failed)},
            )

    hass.services.async_register(DOMAIN, SERVICE_SCAN_NOW, scan_now)
    hass.services.async_register(
        DOMAIN,
        SERVICE_APPLY_TASMOTA_PASSWORD,
        apply_tasmota_password,
        schema=BACKUP_TASMOTA_SCHEMA,  # same shape: optional device_id list
    )
    hass.services.async_register(
        DOMAIN, SERVICE_BACKUP_TASMOTA, backup_tasmota, schema=BACKUP_TASMOTA_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_UPDATE_DEVICE, update_device, schema=UPDATE_DEVICE_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_FORGET_DEVICE, forget_device, schema=FORGET_DEVICE_SCHEMA
    )
