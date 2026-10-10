"""Repair issue helpers."""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir

from .const import DOMAIN

ISSUE_NEW_DEVICE = "new_device"
ISSUE_CRITICAL_OFFLINE = "critical_offline"
ISSUE_MAC_MULTIPLE_IPS = "mac_multiple_ips"
ISSUE_GATEWAY_MAC_CHANGED = "gateway_mac_changed"
ISSUE_DNS_PRIMARY_DOWN = "dns_primary_down"
ISSUE_GATEWAY_PACKET_LOSS = "gateway_packet_loss"
ISSUE_ADBLOCK_INACTIVE = "adblock_inactive"
ISSUE_TASMOTA_NO_PASSWORD = "tasmota_no_password"
ISSUE_TASMOTA_SIGNAL_DROP = "tasmota_signal_drop"
ISSUE_TASMOTA_RESTARTS = "tasmota_frequent_restarts"
ISSUE_TASMOTA_AUTH = "tasmota_auth_failed"


def mac_key(mac: str) -> str:
    """MAC as an issue-id-safe suffix."""
    return mac.replace(":", "")


def issue_id(kind: str, suffix: str | None = None) -> str:
    """Build an issue id like new_device_aabbccddeeff."""
    return f"{kind}_{suffix}" if suffix else kind


def active_issue_ids(hass: HomeAssistant, kind: str) -> set[str]:
    """Ids of our open issues of one kind."""
    registry = ir.async_get(hass)
    return {
        iid
        for (domain, iid) in registry.issues
        if domain == DOMAIN and (iid == kind or iid.startswith(f"{kind}_"))
    }


def sync_issues(
    hass: HomeAssistant,
    kind: str,
    wanted: dict[str, dict[str, str]],
    *,
    severity: ir.IssueSeverity,
    is_fixable: bool,
    data: dict[str, dict[str, str | int | float | None]] | None = None,
    learn_more_url: str | None = None,
) -> None:
    """Create the wanted issues of one kind (id -> placeholders) and delete the others."""
    for iid in active_issue_ids(hass, kind) - wanted.keys():
        ir.async_delete_issue(hass, DOMAIN, iid)
    for iid, placeholders in wanted.items():
        ir.async_create_issue(
            hass,
            DOMAIN,
            iid,
            is_fixable=is_fixable,
            severity=severity,
            translation_key=kind,
            translation_placeholders=placeholders,
            data=(data or {}).get(iid),
            learn_more_url=learn_more_url,
        )
