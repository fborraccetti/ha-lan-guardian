"""LAN Guardian sensors: inventory, network health, security."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    EntityCategory,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import LanGuardianConfigEntry
from .coordinator.health import HealthCoordinator, HealthResult
from .coordinator.scan import ScanCoordinator
from .coordinator.security import SecurityCoordinator
from .coordinator.tasmota import TasmotaCoordinator, TasmotaDevice
from .entity import (
    InventoryEntity,
    TasmotaEntity,
    async_add_known_device_entities,
    service_device_info,
)
from .inventory import STATUS_IGNORED, STATUS_KNOWN, STATUS_NEW, Device


async def async_setup_entry(
    hass: HomeAssistant,
    entry: LanGuardianConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the sensors."""
    data = entry.runtime_data
    entities: list[SensorEntity] = [
        DevicesOnlineSensor(data.scan, entry),
        UnknownDevicesSensor(data.scan, entry),
        TasmotaOpenSensor(data.security, entry),
        ShellyOpenSensor(data.security, entry),
    ]
    entities += [HealthSensor(data.health, entry, desc) for desc in HEALTH_SENSORS]
    entities += [DnsTimeSensor(data.health, entry, server) for server in data.health.dns_servers]
    async_add_entities(entities)

    tasmota = data.tasmota
    added: set[str] = set()

    @callback
    def add_tasmota() -> None:
        new = [mac for mac in tasmota.devices if mac not in added]
        added.update(new)
        if new:
            async_add_entities(
                TasmotaSensor(tasmota, mac, desc) for mac in new for desc in TASMOTA_SENSORS
            )

    add_tasmota()
    entry.async_on_unload(tasmota.async_add_listener(add_tasmota))

    async_add_known_device_entities(
        entry,
        async_add_entities,
        lambda scan, dev: [InventorySensor(scan, dev.mac, desc) for desc in INVENTORY_SENSORS],
    )


class _ScanSensor(CoordinatorEntity[ScanCoordinator], SensorEntity):
    _attr_has_entity_name = True
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: ScanCoordinator, entry: LanGuardianConfigEntry) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_{self._attr_translation_key}"
        self._attr_device_info = service_device_info(entry)


class DevicesOnlineSensor(_ScanSensor):
    """Hosts that answered the last scan."""

    _attr_translation_key = "devices_online"

    @property
    def native_value(self) -> int | None:
        """Online hosts."""
        return self.coordinator.data.online if self.coordinator.data else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Breakdown of the online hosts."""
        data = self.coordinator.data
        if data is None:
            return {}
        online = [d for d in self.coordinator.inventory.devices.values() if d.online]
        return {
            "known": sum(d.status == STATUS_KNOWN for d in online),
            "new": sum(d.status == STATUS_NEW for d in online),
            "ignored": sum(d.status == STATUS_IGNORED for d in online),
            "randomized_mac": data.random_online,
            "scanned_hosts": data.scanned,
            "scan_duration_s": data.duration,
            "probe_mode": data.probe_mode,
            "last_scan": data.finished.isoformat(),
        }


class UnknownDevicesSensor(_ScanSensor):
    """Devices waiting for approval."""

    _attr_translation_key = "unknown_devices"

    @property
    def native_value(self) -> int:
        """Devices with status new."""
        return len(self.coordinator.inventory.by_status(STATUS_NEW))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """The pending devices."""
        return {
            "devices": [
                {"mac": d.mac, "ip": d.ip, "vendor": d.vendor, "hostname": d.hostname}
                for d in self.coordinator.inventory.by_status(STATUS_NEW)
            ]
        }


class ShellyOpenSensor(CoordinatorEntity[SecurityCoordinator], SensorEntity):
    """Shelly devices reachable without authentication."""

    _attr_has_entity_name = True
    _attr_translation_key = "shelly_without_password"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: SecurityCoordinator, entry: LanGuardianConfigEntry) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_shelly_without_password"
        self._attr_device_info = service_device_info(entry)

    @property
    def native_value(self) -> int | None:
        """Number of unprotected Shelly devices."""
        data = self.coordinator.data
        return len(data.open_shelly_macs) if data else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Which devices, and how many Shelly were found in total."""
        data = self.coordinator.data
        if data is None:
            return {}
        inventory = self.coordinator.scan.inventory
        return {
            "shelly_found": len(data.shelly),
            "devices": [
                {
                    "name": dev.display_name if (dev := inventory.devices.get(mac)) else mac,
                    "ip": data.shelly[mac].ip,
                    "generation": data.shelly[mac].gen,
                    "model": data.shelly[mac].model,
                }
                for mac in data.open_shelly_macs
            ],
        }


@dataclass(frozen=True, kw_only=True)
class HealthSensorDescription(SensorEntityDescription):
    """A value read from the health result."""

    value_fn: Callable[[HealthResult], float | None]


def _loss(ping: Any) -> float | None:
    return round(ping.packet_loss * 100, 1) if ping is not None else None


def _rtt(ping: Any, attr: str) -> float | None:
    value = getattr(ping, attr, None) if ping is not None else None
    return round(value, 1) if value is not None else None


def _pct(key: str, value_fn: Callable[[HealthResult], float | None]) -> HealthSensorDescription:
    return HealthSensorDescription(
        key=key,
        value_fn=value_fn,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
    )


def _ms(key: str, value_fn: Callable[[HealthResult], float | None]) -> HealthSensorDescription:
    return HealthSensorDescription(
        key=key,
        value_fn=value_fn,
        native_unit_of_measurement=UnitOfTime.MILLISECONDS,
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
    )


HEALTH_SENSORS: tuple[HealthSensorDescription, ...] = (
    _pct("gateway_packet_loss", lambda r: _loss(r.gateway)),
    _ms("gateway_latency", lambda r: _rtt(r.gateway, "avg_rtt")),
    _ms("gateway_latency_max", lambda r: _rtt(r.gateway, "max_rtt")),
    _pct("internet_packet_loss", lambda r: _loss(r.internet)),
    _ms("internet_latency", lambda r: _rtt(r.internet, "avg_rtt")),
    _ms("internet_latency_max", lambda r: _rtt(r.internet, "max_rtt")),
)


class HealthSensor(CoordinatorEntity[HealthCoordinator], SensorEntity):
    """Gateway / Internet loss and latency."""

    _attr_has_entity_name = True
    entity_description: HealthSensorDescription

    def __init__(
        self,
        coordinator: HealthCoordinator,
        entry: LanGuardianConfigEntry,
        description: HealthSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_translation_key = description.key
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = service_device_info(entry)

    @property
    def native_value(self) -> float | None:
        """Value from the last check; None without ICMP."""
        data = self.coordinator.data
        return self.entity_description.value_fn(data) if data else None


class DnsTimeSensor(CoordinatorEntity[HealthCoordinator], SensorEntity):
    """Resolution time on one DNS server."""

    _attr_has_entity_name = True
    _attr_translation_key = "dns_resolve_time"
    _attr_native_unit_of_measurement = UnitOfTime.MILLISECONDS
    _attr_device_class = SensorDeviceClass.DURATION
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 1

    def __init__(
        self, coordinator: HealthCoordinator, entry: LanGuardianConfigEntry, server: str
    ) -> None:
        super().__init__(coordinator)
        self.server = server
        self._attr_translation_placeholders = {"server": server}
        self._attr_unique_id = f"{entry.entry_id}_dns_{server}_time"
        self._attr_device_info = service_device_info(entry)

    @property
    def native_value(self) -> float | None:
        """Milliseconds, None when the server did not answer."""
        data = self.coordinator.data
        check = data.dns.get(self.server) if data else None
        return check.time_ms if check and check.ok else None


class TasmotaOpenSensor(CoordinatorEntity[SecurityCoordinator], SensorEntity):
    """Tasmota devices reachable without WebPassword."""

    _attr_has_entity_name = True
    _attr_translation_key = "tasmota_without_password"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: SecurityCoordinator, entry: LanGuardianConfigEntry) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_tasmota_without_password"
        self._attr_device_info = service_device_info(entry)

    @property
    def native_value(self) -> int | None:
        """Number of unprotected Tasmota devices."""
        data = self.coordinator.data
        return len(data.open_macs) if data else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Which devices, and how many Tasmota were found in total."""
        data = self.coordinator.data
        if data is None:
            return {}
        inventory = self.coordinator.scan.inventory
        return {
            "tasmota_found": len(data.tasmota),
            "devices": [
                {
                    "name": dev.display_name if (dev := inventory.devices.get(mac)) else mac,
                    "ip": data.tasmota[mac].ip,
                }
                for mac in data.open_macs
            ],
        }


@dataclass(frozen=True, kw_only=True)
class TasmotaSensorDescription(SensorEntityDescription):
    """A value read from a Tasmota device."""

    value_fn: Callable[[TasmotaDevice], float | int | str | datetime | None]
    available_offline: bool = False  # e.g. last backup stays meaningful when offline


TASMOTA_SENSORS: tuple[TasmotaSensorDescription, ...] = (
    TasmotaSensorDescription(
        key="wifi_signal",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.info.signal if d.info else None,
    ),
    TasmotaSensorDescription(
        key="wifi_rssi",
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda d: d.info.rssi if d.info else None,
    ),
    TasmotaSensorDescription(
        key="last_restart",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.last_restart,
    ),
    TasmotaSensorDescription(
        key="restart_reason",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.info.restart_reason if d.info else None,
    ),
    TasmotaSensorDescription(
        key="restarts_24h",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: len(d.restarts),
    ),
    TasmotaSensorDescription(
        key="last_backup",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        available_offline=True,
        value_fn=lambda d: d.last_backup,
    ),
)


class TasmotaSensor(TasmotaEntity, SensorEntity):
    """Diagnostic sensor of one Tasmota device."""

    entity_description: TasmotaSensorDescription

    def __init__(
        self, coordinator: TasmotaCoordinator, mac: str, description: TasmotaSensorDescription
    ) -> None:
        super().__init__(coordinator, mac, description.key)
        self.entity_description = description
        self._attr_translation_key = f"tasmota_{description.key}"

    @property
    def available(self) -> bool:
        """Some values stay meaningful while the device is offline."""
        if self.entity_description.available_offline:
            return self.coordinator.last_update_success
        return super().available

    @property
    def native_value(self) -> float | int | str | datetime | None:
        """Value from the last poll."""
        return self.entity_description.value_fn(self.device)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Backup error next to the last backup time."""
        if self.entity_description.key == "last_backup":
            return {"error": self.device.last_backup_error}
        return None


@dataclass(frozen=True, kw_only=True)
class InventorySensorDescription(SensorEntityDescription):
    """A value read from the inventory entry of one device."""

    value_fn: Callable[[Device], str | datetime | None]


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)


INVENTORY_SENSORS: tuple[InventorySensorDescription, ...] = (
    InventorySensorDescription(key="ip", translation_key="ip", value_fn=lambda d: d.ip),
    InventorySensorDescription(
        key="last_seen",
        translation_key="last_seen",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda d: _timestamp(d.last_seen),
    ),
    InventorySensorDescription(
        key="first_seen",
        translation_key="first_seen",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda d: _timestamp(d.first_seen),
    ),
    InventorySensorDescription(
        key="hostname", translation_key="hostname", value_fn=lambda d: d.hostname
    ),
    InventorySensorDescription(key="vendor", translation_key="vendor", value_fn=lambda d: d.vendor),
)


class InventorySensor(InventoryEntity, SensorEntity):
    """Network details of one device, from the scans."""

    entity_description: InventorySensorDescription

    def __init__(
        self, coordinator: ScanCoordinator, mac: str, description: InventorySensorDescription
    ) -> None:
        """Initialize."""
        super().__init__(coordinator, mac, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> str | datetime | None:
        """Current value."""
        dev = self.inventory_device
        return self.entity_description.value_fn(dev) if dev else None
