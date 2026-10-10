"""Network health coordinator: gateway/Internet loss and latency, DNS servers, Pi-hole blocking."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from ..const import (
    CONF_ADBLOCK_TEST_DOMAIN,
    CONF_DNS_SERVERS,
    CONF_DNS_TEST_DOMAIN,
    CONF_GATEWAY,
    CONF_HEALTH_INTERVAL,
    CONF_INTERNET_TARGET,
    CONF_LOSS_THRESHOLD,
    DOMAIN,
)
from ..issues import (
    ISSUE_ADBLOCK_INACTIVE,
    ISSUE_DNS_PRIMARY_DOWN,
    ISSUE_GATEWAY_PACKET_LOSS,
    sync_issues,
)
from ..net.dns import DnsCheck, async_resolve, is_blocked
from ..net.icmp import PingResult, ProbeMode, async_ping_target
from ..notifier import (
    EVENT_ADBLOCK_OFF,
    EVENT_DNS_DOWN,
    EVENT_DNS_UP,
    EVENT_GATEWAY_LOSS,
    EVENT_INTERNET_DOWN,
    EVENT_INTERNET_UP,
    Notifier,
)

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry

_LOGGER = logging.getLogger(__name__)

# Consecutive bad checks before raising an alert: one lost burst is not an outage.
FAILURES_BEFORE_ALERT = 2


@dataclass(frozen=True, slots=True)
class HealthResult:
    """One round of health checks."""

    gateway: PingResult | None
    internet: PingResult | None
    dns: dict[str, DnsCheck] = field(default_factory=dict)
    adblock: DnsCheck | None = None

    @property
    def adblock_active(self) -> bool | None:
        """Whether Pi-hole blocked the test domain (None if unknown)."""
        return is_blocked(self.adblock) if self.adblock else None


class _Streak:
    """Count consecutive failures and report transitions once."""

    def __init__(self) -> None:
        self.failures = 0
        self.alerted = False

    def update(self, failed: bool) -> str | None:
        """Return 'down' or 'up' on a state change, else None."""
        self.failures = self.failures + 1 if failed else 0
        if self.failures >= FAILURES_BEFORE_ALERT and not self.alerted:
            self.alerted = True
            return "down"
        if not failed and self.alerted:
            self.alerted = False
            return "up"
        return None


class HealthCoordinator(DataUpdateCoordinator[HealthResult]):
    """Run the network health checks."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        options: dict[str, Any],
        notifier: Notifier,
        probe_mode: Callable[[], ProbeMode],
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} health",
            update_interval=timedelta(minutes=int(options[CONF_HEALTH_INTERVAL])),
        )
        self.options = options
        self.notifier = notifier
        self._probe_mode = probe_mode
        self.gateway: str = entry.data[CONF_GATEWAY]
        self.internet_target = str(options[CONF_INTERNET_TARGET])
        self.dns_servers: list[str] = list(options[CONF_DNS_SERVERS]) or [self.gateway]
        self.loss_threshold = int(options[CONF_LOSS_THRESHOLD])
        self._dns_streaks = {server: _Streak() for server in self.dns_servers}
        self._gateway_streak = _Streak()
        self._internet_streak = _Streak()

    async def _async_update_data(self) -> HealthResult:
        mode = self._probe_mode()
        test_domain = str(self.options[CONF_DNS_TEST_DOMAIN])
        adblock_domain = str(self.options.get(CONF_ADBLOCK_TEST_DOMAIN) or "")

        gateway, internet = await asyncio.gather(
            async_ping_target(self.gateway, mode),
            async_ping_target(self.internet_target, mode),
        )
        adblock, *dns = await asyncio.gather(
            self._async_adblock(adblock_domain),
            *(async_resolve(server, test_domain) for server in self.dns_servers),
        )
        result = HealthResult(
            gateway=gateway,
            internet=internet,
            dns={check.server: check for check in dns if check is not None},
            adblock=adblock,
        )
        await self._async_alerts(result, adblock_domain)
        return result

    async def _async_adblock(self, domain: str) -> DnsCheck | None:
        if not domain or not self.dns_servers:
            return None
        return await async_resolve(self.dns_servers[0], domain)

    async def _async_alerts(self, result: HealthResult, adblock_domain: str) -> None:
        notify = self.notifier

        for server, check in result.dns.items():
            change = self._dns_streaks[server].update(not check.ok)
            if change == "down":
                await notify.async_notify(
                    EVENT_DNS_DOWN, server, {"server": server, "error": check.error or "timeout"}
                )
            elif change == "up":
                notify.dismiss(EVENT_DNS_DOWN, server)
                await notify.async_notify(
                    EVENT_DNS_UP, server, {"server": server, "time_ms": check.time_ms}
                )
        primary = self.dns_servers[0] if self.dns_servers else None
        sync_issues(
            self.hass,
            ISSUE_DNS_PRIMARY_DOWN,
            {ISSUE_DNS_PRIMARY_DOWN: {"server": primary}}
            if primary and self._dns_streaks[primary].alerted
            else {},
            severity=ir.IssueSeverity.ERROR,
            is_fixable=False,
        )

        if result.gateway is not None:
            loss = round(result.gateway.packet_loss * 100)
            change = self._gateway_streak.update(loss >= self.loss_threshold)
            placeholders = {
                "ip": self.gateway,
                "loss": str(loss),
                "threshold": str(self.loss_threshold),
            }
            if change == "down":
                await notify.async_notify(EVENT_GATEWAY_LOSS, self.gateway, placeholders)
            elif change == "up":
                notify.dismiss(EVENT_GATEWAY_LOSS, self.gateway)
            sync_issues(
                self.hass,
                ISSUE_GATEWAY_PACKET_LOSS,
                {ISSUE_GATEWAY_PACKET_LOSS: placeholders} if self._gateway_streak.alerted else {},
                severity=ir.IssueSeverity.WARNING,
                is_fixable=False,
            )

        if result.internet is not None:
            change = self._internet_streak.update(not result.internet.alive)
            target = self.internet_target
            if change == "down":
                await notify.async_notify(EVENT_INTERNET_DOWN, target, {"target": target})
            elif change == "up":
                notify.dismiss(EVENT_INTERNET_DOWN, target)
                await notify.async_notify(
                    EVENT_INTERNET_UP,
                    target,
                    {"target": target, "latency": result.internet.avg_rtt},
                )

        # Unknown (server down) keeps the previous state: the DNS alert covers it.
        if (active := result.adblock_active) is not None and result.adblock is not None:
            placeholders = {
                "server": result.adblock.server,
                "domain": adblock_domain,
                "addresses": ", ".join(result.adblock.addresses),
            }
            if not active:
                await notify.async_notify(EVENT_ADBLOCK_OFF, result.adblock.server, placeholders)
            else:
                notify.dismiss(EVENT_ADBLOCK_OFF, result.adblock.server)
            sync_issues(
                self.hass,
                ISSUE_ADBLOCK_INACTIVE,
                {} if active else {ISSUE_ADBLOCK_INACTIVE: placeholders},
                severity=ir.IssueSeverity.WARNING,
                is_fixable=False,
            )
