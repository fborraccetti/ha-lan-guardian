"""Notifications: persistent, notify entities/action, HA event, with dedup and cooldown."""

from __future__ import annotations

from datetime import datetime, timedelta
import logging
from typing import Any, Final

from homeassistant.components import persistent_notification
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util import dt as dt_util

from .const import (
    CONF_NOTIFY_COOLDOWN_MINUTES,
    CONF_NOTIFY_ENTITIES,
    CONF_NOTIFY_PERSISTENT,
    CONF_NOTIFY_SERVICE,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

EVENT_NAME: Final = f"{DOMAIN}_event"

EVENT_BASELINE: Final = "baseline"
EVENT_NEW_DEVICE: Final = "new_device"
EVENT_CRITICAL_OFFLINE: Final = "critical_offline"
EVENT_CRITICAL_ONLINE: Final = "critical_online"
EVENT_MAC_MULTIPLE_IPS: Final = "mac_multiple_ips"
EVENT_IP_MAC_CHANGED: Final = "ip_mac_changed"
EVENT_GATEWAY_MAC_CHANGED: Final = "gateway_mac_changed"
EVENT_DNS_DOWN: Final = "dns_down"
EVENT_DNS_UP: Final = "dns_up"
EVENT_GATEWAY_LOSS: Final = "gateway_loss"
EVENT_INTERNET_DOWN: Final = "internet_down"
EVENT_INTERNET_UP: Final = "internet_up"
EVENT_ADBLOCK_OFF: Final = "adblock_off"
EVENT_TASMOTA_NO_PASSWORD: Final = "tasmota_no_password"
EVENT_TASMOTA_SIGNAL_DROP: Final = "tasmota_signal_drop"
EVENT_TASMOTA_RESTARTS: Final = "tasmota_frequent_restarts"
EVENT_TASMOTA_AUTH: Final = "tasmota_auth_failed"
EVENT_BACKUP_FAILED: Final = "backup_failed"
EVENT_PASSWORD_APPLIED: Final = "tasmota_password_applied"
EVENT_FIRMWARE_UPDATED: Final = "tasmota_firmware_updated"
EVENT_FIRMWARE_FAILED: Final = "tasmota_firmware_failed"

# Recovery messages must always go out, otherwise "offline" would never be followed by "online".
# Firmware results answer an explicit request, so each one is reported.
_NO_COOLDOWN: Final = {
    EVENT_CRITICAL_ONLINE,
    EVENT_DNS_UP,
    EVENT_INTERNET_UP,
    EVENT_FIRMWARE_UPDATED,
    EVENT_FIRMWARE_FAILED,
}

MESSAGES: Final[dict[str, dict[str, tuple[str, str]]]] = {
    "en": {
        EVENT_BASELINE: (
            "LAN Guardian: inventory created",
            "{count} devices found on the first scan were saved as known. "
            "From now on every new MAC address raises a repair issue.",
        ),
        EVENT_NEW_DEVICE: (
            "LAN Guardian: new device",
            "New device on the network: {name} ({ip}, {mac}, {vendor}). "
            "Open Settings → Repairs to approve or ignore it.",
        ),
        EVENT_CRITICAL_OFFLINE: (
            "LAN Guardian: critical device offline",
            "{name} ({ip}) has not answered since {last_seen}.",
        ),
        EVENT_CRITICAL_ONLINE: (
            "LAN Guardian: critical device back online",
            "{name} ({ip}) is reachable again.",
        ),
        EVENT_MAC_MULTIPLE_IPS: (
            "LAN Guardian: MAC on several IPs",
            "{mac} ({name}) answers on {ips}. Possible ARP spoofing or a bridging device.",
        ),
        EVENT_IP_MAC_CHANGED: (
            "LAN Guardian: IP address conflict",
            "{ip} keeps switching between {previous} and {current}. "
            "Possible address conflict or ARP spoofing.",
        ),
        EVENT_GATEWAY_MAC_CHANGED: (
            "LAN Guardian: gateway MAC changed",
            "The gateway {ip} now answers with {current} instead of {previous}. "
            "If the router was not replaced this may be ARP spoofing.",
        ),
        EVENT_DNS_DOWN: (
            "LAN Guardian: DNS server not answering",
            "DNS server {server} does not answer ({error}).",
        ),
        EVENT_DNS_UP: (
            "LAN Guardian: DNS server back",
            "DNS server {server} answers again ({time_ms} ms).",
        ),
        EVENT_GATEWAY_LOSS: (
            "LAN Guardian: packet loss to the gateway",
            "{loss}% packet loss towards the gateway {ip} (threshold {threshold}%).",
        ),
        EVENT_INTERNET_DOWN: (
            "LAN Guardian: Internet unreachable",
            "{target} does not answer to ping.",
        ),
        EVENT_INTERNET_UP: (
            "LAN Guardian: Internet back",
            "{target} answers again ({latency} ms).",
        ),
        EVENT_ADBLOCK_OFF: (
            "LAN Guardian: ad blocking not active",
            "{server} resolves {domain} to {addresses}: Pi-hole is not blocking.",
        ),
        EVENT_TASMOTA_NO_PASSWORD: (
            "LAN Guardian: Tasmota without password",
            "{count} Tasmota devices have no WebPassword: {devices}.",
        ),
        EVENT_TASMOTA_SIGNAL_DROP: (
            "LAN Guardian: Wi-Fi signal dropped",
            "Tasmota whose signal dropped by {threshold} points or more: {devices}.",
        ),
        EVENT_TASMOTA_RESTARTS: (
            "LAN Guardian: Tasmota restarting often",
            "{name} ({ip}) restarted {count} times in 24 hours. Last reason: {reason}.",
        ),
        EVENT_TASMOTA_AUTH: (
            "LAN Guardian: Tasmota password rejected",
            "Wrong or missing WebPassword for: {devices}.",
        ),
        EVENT_BACKUP_FAILED: (
            "LAN Guardian: Tasmota backup failed",
            "Backup failed for: {devices}.",
        ),
        EVENT_PASSWORD_APPLIED: (
            "LAN Guardian: Tasmota WebPassword",
            "Password set on: {applied}.\nAlready set: {already}.\n"
            "Protected by another password (skipped): {other}.\n"
            "Offline (try again later): {offline}.\nErrors: {failed}.",
        ),
        EVENT_FIRMWARE_UPDATED: (
            "LAN Guardian: Tasmota updated",
            "{name} ({ip}) updated from {previous} to {version}.",
        ),
        EVENT_FIRMWARE_FAILED: (
            "LAN Guardian: Tasmota update failed",
            "Update of {name} ({ip}) from {previous} to {version} failed: {error}.",
        ),
    },
    "it": {
        EVENT_BASELINE: (
            "LAN Guardian: inventario creato",
            "{count} dispositivi trovati alla prima scansione sono stati salvati come noti. "
            "Da ora ogni nuovo indirizzo MAC apre una segnalazione in Riparazioni.",
        ),
        EVENT_NEW_DEVICE: (
            "LAN Guardian: nuovo dispositivo",
            "Nuovo dispositivo in rete: {name} ({ip}, {mac}, {vendor}). "
            "Apri Impostazioni → Riparazioni per approvarlo o ignorarlo.",
        ),
        EVENT_CRITICAL_OFFLINE: (
            "LAN Guardian: dispositivo critico offline",
            "{name} ({ip}) non risponde dalle {last_seen}.",
        ),
        EVENT_CRITICAL_ONLINE: (
            "LAN Guardian: dispositivo critico di nuovo online",
            "{name} ({ip}) è di nuovo raggiungibile.",
        ),
        EVENT_MAC_MULTIPLE_IPS: (
            "LAN Guardian: MAC su più IP",
            "{mac} ({name}) risponde su {ips}. Possibile ARP spoofing o dispositivo bridge.",
        ),
        EVENT_IP_MAC_CHANGED: (
            "LAN Guardian: conflitto di indirizzo IP",
            "{ip} continua a passare da {previous} a {current}. "
            "Possibile conflitto di indirizzi o ARP spoofing.",
        ),
        EVENT_GATEWAY_MAC_CHANGED: (
            "LAN Guardian: MAC del gateway cambiato",
            "Il gateway {ip} ora risponde con {current} invece di {previous}. "
            "Se il router non è stato sostituito potrebbe essere ARP spoofing.",
        ),
        EVENT_DNS_DOWN: (
            "LAN Guardian: server DNS non risponde",
            "Il server DNS {server} non risponde ({error}).",
        ),
        EVENT_DNS_UP: (
            "LAN Guardian: server DNS di nuovo attivo",
            "Il server DNS {server} risponde di nuovo ({time_ms} ms).",
        ),
        EVENT_GATEWAY_LOSS: (
            "LAN Guardian: perdita di pacchetti verso il gateway",
            "Perdita del {loss}% verso il gateway {ip} (soglia {threshold}%).",
        ),
        EVENT_INTERNET_DOWN: (
            "LAN Guardian: Internet non raggiungibile",
            "{target} non risponde al ping.",
        ),
        EVENT_INTERNET_UP: (
            "LAN Guardian: Internet di nuovo raggiungibile",
            "{target} risponde di nuovo ({latency} ms).",
        ),
        EVENT_ADBLOCK_OFF: (
            "LAN Guardian: blocco pubblicità non attivo",
            "{server} risolve {domain} in {addresses}: Pi-hole non sta bloccando.",
        ),
        EVENT_TASMOTA_NO_PASSWORD: (
            "LAN Guardian: Tasmota senza password",
            "{count} dispositivi Tasmota non hanno WebPassword: {devices}.",
        ),
        EVENT_TASMOTA_SIGNAL_DROP: (
            "LAN Guardian: segnale Wi-Fi calato",
            "Tasmota con segnale calato di {threshold} punti o più: {devices}.",
        ),
        EVENT_TASMOTA_RESTARTS: (
            "LAN Guardian: Tasmota si riavvia spesso",
            "{name} ({ip}) si è riavviato {count} volte in 24 ore. Ultimo motivo: {reason}.",
        ),
        EVENT_TASMOTA_AUTH: (
            "LAN Guardian: password Tasmota rifiutata",
            "WebPassword errata o mancante per: {devices}.",
        ),
        EVENT_BACKUP_FAILED: (
            "LAN Guardian: backup Tasmota fallito",
            "Backup non riuscito per: {devices}.",
        ),
        EVENT_PASSWORD_APPLIED: (
            "LAN Guardian: WebPassword Tasmota",
            "Password impostata su: {applied}.\nGià impostata: {already}.\n"
            "Protetti da un'altra password (saltati): {other}.\n"
            "Offline (riprova più tardi): {offline}.\nErrori: {failed}.",
        ),
        EVENT_FIRMWARE_UPDATED: (
            "LAN Guardian: Tasmota aggiornato",
            "{name} ({ip}) aggiornato da {previous} a {version}.",
        ),
        EVENT_FIRMWARE_FAILED: (
            "LAN Guardian: aggiornamento Tasmota fallito",
            "Aggiornamento di {name} ({ip}) da {previous} a {version} non riuscito: {error}.",
        ),
    },
}


class Notifier:
    """Send LAN Guardian notifications with per-event cooldown."""

    def __init__(self, hass: HomeAssistant, options: dict[str, Any]) -> None:
        """Initialize with the merged entry options."""
        self.hass = hass
        self._persistent: bool = bool(options[CONF_NOTIFY_PERSISTENT])
        self._entities: list[str] = list(options[CONF_NOTIFY_ENTITIES])
        self._service: str = str(options[CONF_NOTIFY_SERVICE])
        self._cooldown = timedelta(minutes=int(options[CONF_NOTIFY_COOLDOWN_MINUTES]))
        self._last_sent: dict[tuple[str, str], datetime] = {}

    def _text(self, event_type: str, placeholders: dict[str, Any]) -> tuple[str, str]:
        language = "it" if self.hass.config.language.startswith("it") else "en"
        title, body = MESSAGES[language][event_type]
        return title, body.format_map(_Defaults(placeholders))

    async def async_notify(
        self, event_type: str, key: str, placeholders: dict[str, Any] | None = None
    ) -> bool:
        """Fire the HA event and notify, unless the same event/key is in cooldown.

        Returns True when notifications were sent.
        """
        placeholders = placeholders or {}
        self.hass.bus.async_fire(EVENT_NAME, {"type": event_type, "key": key, **placeholders})

        now = dt_util.utcnow()
        last = self._last_sent.get((event_type, key))
        if event_type not in _NO_COOLDOWN and last is not None and now - last < self._cooldown:
            _LOGGER.debug("Notification %s/%s suppressed by cooldown", event_type, key)
            return False
        self._last_sent[(event_type, key)] = now

        title, message = self._text(event_type, placeholders)
        if self._persistent:
            persistent_notification.async_create(
                self.hass, message, title, notification_id=f"{DOMAIN}_{event_type}_{key}"
            )
        if self._entities:
            await self._async_call(
                "notify",
                "send_message",
                {"entity_id": self._entities, "title": title, "message": message},
            )
        if self._service:
            domain, service = self._service.split(".", 1)
            await self._async_call(domain, service, {"title": title, "message": message})
        return True

    def dismiss(self, event_type: str, key: str) -> None:
        """Remove the persistent notification and reset the cooldown for a resolved event."""
        self._last_sent.pop((event_type, key), None)
        persistent_notification.async_dismiss(self.hass, f"{DOMAIN}_{event_type}_{key}")

    async def _async_call(self, domain: str, service: str, data: dict[str, Any]) -> None:
        try:
            await self.hass.services.async_call(domain, service, data, blocking=True)
        except (HomeAssistantError, ValueError) as err:
            _LOGGER.warning("Notification via %s.%s failed: %s", domain, service, err)


class _Defaults(dict[str, Any]):
    """format_map helper: unknown placeholders render as '?' instead of raising."""

    def __missing__(self, key: str) -> str:
        return "?"
