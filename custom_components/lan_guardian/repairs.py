"""Fix flows for LAN Guardian repair issues."""

from __future__ import annotations

from typing import Any

from homeassistant.components.repairs import ConfirmRepairFlow, RepairsFlow, RepairsFlowResult
from homeassistant.core import HomeAssistant
from homeassistant.helpers import selector
import voluptuous as vol

from .const import CONF_TASMOTA_PASSWORD
from .inventory import CATEGORIES, STATUS_IGNORED, STATUS_KNOWN
from .issues import ISSUE_GATEWAY_MAC_CHANGED, ISSUE_NEW_DEVICE, ISSUE_TASMOTA_NO_PASSWORD
from .services import loaded_entry, sync_connectivity_entity


class NewDeviceRepairFlow(RepairsFlow):
    """Approve (with name, category, critical) or ignore a new device."""

    def __init__(self, mac: str) -> None:
        """Initialize for one MAC."""
        self.mac = mac

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> RepairsFlowResult:
        """Choose what to do."""
        coordinator = loaded_entry(self.hass).runtime_data.scan
        if (dev := coordinator.inventory.devices.get(self.mac)) is None:
            return self.async_abort(reason="device_gone")
        return self.async_show_menu(
            step_id="init",
            menu_options=["approve", "ignore"],
            description_placeholders={
                "mac": dev.mac,
                "ip": dev.ip or "?",
                "vendor": dev.vendor or "?",
                "hostname": dev.hostname or "?",
            },
        )

    async def async_step_approve(
        self, user_input: dict[str, Any] | None = None
    ) -> RepairsFlowResult:
        """Name the device and mark it known."""
        coordinator = loaded_entry(self.hass).runtime_data.scan
        dev = coordinator.inventory.devices.get(self.mac)
        if dev is None:
            return self.async_abort(reason="device_gone")
        if user_input is not None:
            coordinator.inventory.update_device(
                self.mac,
                name=user_input["name"].strip() or None,
                category=user_input["category"],
                critical=user_input["critical"],
                status=STATUS_KNOWN,
            )
            await coordinator.inventory.async_save()
            coordinator.async_update_listeners()
            sync_connectivity_entity(self.hass, self.mac, user_input["critical"])
            return self.async_create_entry(data={})

        schema = vol.Schema(
            {
                vol.Required("name", default=dev.hostname or ""): str,
                vol.Required("category", default=dev.category): selector.SelectSelector(
                    selector.SelectSelectorConfig(options=CATEGORIES, translation_key="category")
                ),
                vol.Required("critical", default=False): bool,
            }
        )
        return self.async_show_form(
            step_id="approve",
            data_schema=schema,
            description_placeholders={
                "mac": dev.mac,
                "ip": dev.ip or "?",
                "vendor": dev.vendor or "?",
            },
        )

    async def async_step_ignore(
        self, user_input: dict[str, Any] | None = None
    ) -> RepairsFlowResult:
        """Ignore the device: no more issues or alerts for this MAC."""
        coordinator = loaded_entry(self.hass).runtime_data.scan
        if self.mac not in coordinator.inventory.devices:
            return self.async_abort(reason="device_gone")
        coordinator.inventory.update_device(self.mac, status=STATUS_IGNORED)
        await coordinator.inventory.async_save()
        coordinator.async_update_listeners()
        return self.async_create_entry(data={})


class GatewayMacRepairFlow(ConfirmRepairFlow):
    """Accept the new gateway MAC (router replaced)."""

    def __init__(self, mac: str) -> None:
        """Initialize with the new MAC."""
        super().__init__()
        self.mac = mac

    async def async_step_confirm(
        self, user_input: dict[str, str] | None = None
    ) -> RepairsFlowResult:
        """Trust the new MAC once the user confirms."""
        if user_input is not None:
            coordinator = loaded_entry(self.hass).runtime_data.scan
            coordinator.inventory.accept_gateway_mac(self.mac)
            await coordinator.inventory.async_save()
        return await super().async_step_confirm(user_input)


class TasmotaPasswordRepairFlow(RepairsFlow):
    """Apply the stored global WebPassword to every Tasmota without one."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> RepairsFlowResult:
        """Check a password is stored, then ask for confirmation."""
        options = loaded_entry(self.hass).runtime_data.options
        if not options.get(CONF_TASMOTA_PASSWORD):
            return self.async_abort(reason="no_password")
        return await self.async_step_confirm()

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> RepairsFlowResult:
        """Apply on confirmation; the outcome arrives as a notification."""
        data = loaded_entry(self.hass).runtime_data
        open_macs = data.security.data.open_macs if data.security.data else []
        if user_input is not None:
            await data.tasmota.async_apply_password(open_macs)
            return self.async_create_entry(data={})
        names = [
            dev.display_name if (dev := data.scan.inventory.devices.get(mac)) else mac
            for mac in open_macs
        ]
        return self.async_show_form(
            step_id="confirm",
            data_schema=vol.Schema({}),
            description_placeholders={"count": str(len(names)), "devices": ", ".join(names)},
        )


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    data: dict[str, str | int | float | None] | None,
) -> RepairsFlow:
    """Create the fix flow for an issue."""
    mac = str((data or {}).get("mac", ""))
    if issue_id.startswith(f"{ISSUE_NEW_DEVICE}_"):
        return NewDeviceRepairFlow(mac)
    if issue_id == ISSUE_GATEWAY_MAC_CHANGED:
        return GatewayMacRepairFlow(mac)
    if issue_id == ISSUE_TASMOTA_NO_PASSWORD:
        return TasmotaPasswordRepairFlow()
    return ConfirmRepairFlow()
