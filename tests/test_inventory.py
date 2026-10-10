"""Tests for the inventory logic."""

from __future__ import annotations

from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util
import pytest

from custom_components.lan_guardian.const import (
    RANDOM_MAC_GROUP,
    RANDOM_MAC_IGNORE,
    RANDOM_MAC_TRACK,
)
from custom_components.lan_guardian.inventory import (
    STATUS_IGNORED,
    STATUS_KNOWN,
    STATUS_NEW,
    Inventory,
    Observation,
)

GW = "192.168.1.1"
GW_MAC = "3c:a6:2f:00:00:01"
GAS = Observation(mac="a4:cf:12:00:02:48", ip="192.168.1.248", hostname="sensore-gas")
PHONE = Observation(mac="da:a1:19:00:00:01", ip="192.168.1.120", randomized=True)
ROUTER = Observation(mac=GW_MAC, ip=GW)


def _scan(inv: Inventory, obs: list[Observation], minutes: int = 0, **kwargs: object):
    return inv.apply_scan(
        obs,
        gateway_ip=GW,
        random_mode=kwargs.get("random_mode", RANDOM_MAC_GROUP),  # type: ignore[arg-type]
        critical_offline_after=timedelta(minutes=15),
        now=dt_util.utcnow() + timedelta(minutes=minutes),
    )


async def test_baseline_then_new(hass: HomeAssistant) -> None:
    """First scan imports everything as known; later MACs are new."""
    inv = Inventory(hass)
    changes = _scan(inv, [ROUTER, GAS])
    assert [d.mac for d in changes.baseline] == [GW_MAC, GAS.mac]
    assert not changes.new_devices
    assert inv.devices[GAS.mac].status == STATUS_KNOWN
    assert inv.gateway_mac == GW_MAC

    newcomer = Observation(mac="aa:bb:cc:00:00:99", ip="192.168.1.99", vendor="Acme")
    changes = _scan(inv, [ROUTER, GAS, newcomer], minutes=10)
    assert [d.mac for d in changes.new_devices] == [newcomer.mac]
    assert inv.devices[newcomer.mac].status == STATUS_NEW
    assert inv.devices[newcomer.mac].display_name == "Acme"

    # Seen again: no new event.
    assert not _scan(inv, [ROUTER, newcomer], minutes=20).new_devices
    assert not inv.devices[GAS.mac].online


@pytest.mark.parametrize(
    ("mode", "stored", "counted"),
    [(RANDOM_MAC_GROUP, False, 1), (RANDOM_MAC_IGNORE, False, 0), (RANDOM_MAC_TRACK, True, 0)],
)
async def test_random_mac_modes(hass: HomeAssistant, mode: str, stored: bool, counted: int) -> None:
    """Randomized MACs are grouped, ignored or tracked."""
    inv = Inventory(hass)
    _scan(inv, [ROUTER])
    changes = _scan(inv, [ROUTER, PHONE], random_mode=mode)
    assert (PHONE.mac in inv.devices) is stored
    assert bool(changes.new_devices) is stored
    assert changes.random_online == counted


async def test_critical_offline_and_back(hass: HomeAssistant) -> None:
    """A critical device alerts once after the threshold and once on recovery."""
    inv = Inventory(hass)
    _scan(inv, [ROUTER, GAS])
    inv.update_device(GAS.mac, critical=True, name="Sensore gas")

    assert not _scan(inv, [ROUTER], minutes=10).critical_offline  # below threshold
    changes = _scan(inv, [ROUTER], minutes=16)
    assert [d.mac for d in changes.critical_offline] == [GAS.mac]
    assert not _scan(inv, [ROUTER], minutes=30).critical_offline  # alerted once

    changes = _scan(inv, [ROUTER, GAS], minutes=40)
    assert [d.mac for d in changes.critical_online] == [GAS.mac]
    assert not inv.devices[GAS.mac].offline_alerted


async def test_ignored_and_non_critical_never_alert(hass: HomeAssistant) -> None:
    """Only known critical devices raise offline alerts."""
    inv = Inventory(hass)
    _scan(inv, [ROUTER, GAS])
    inv.update_device(GAS.mac, critical=True, status=STATUS_IGNORED)
    assert not _scan(inv, [ROUTER], minutes=60).critical_offline


async def test_conflicts(hass: HomeAssistant) -> None:
    """MAC on several IPs, IP flapping between MACs, gateway MAC change."""
    inv = Inventory(hass)
    _scan(inv, [ROUTER, GAS])

    # The router answering on two addresses is not an alert.
    router_alias = Observation(mac=GW_MAC, ip="192.168.1.202")
    assert not _scan(inv, [ROUTER, router_alias, GAS]).multi_ip

    spoof = Observation(mac=GAS.mac, ip="192.168.1.250")
    assert _scan(inv, [ROUTER, GAS, spoof]).multi_ip == {
        GAS.mac: ["192.168.1.248", "192.168.1.250"]
    }

    # DHCP reuse (A -> B) is fine, flipping back (B -> A) is a conflict.
    other = Observation(mac="aa:bb:cc:00:00:01", ip=GAS.ip)
    assert not _scan(inv, [ROUTER, other]).ip_mac_changed
    assert _scan(inv, [ROUTER, GAS]).ip_mac_changed == [(GAS.ip, other.mac, GAS.mac)]

    attacker = Observation(mac="aa:bb:cc:00:00:66", ip=GW)
    changes = _scan(inv, [attacker, GAS])
    assert changes.gateway_mac_changed == (GW_MAC, attacker.mac)
    inv.accept_gateway_mac(attacker.mac)
    assert _scan(inv, [attacker, GAS]).gateway_mac_changed is None


async def test_persistence(hass: HomeAssistant, hass_storage: dict[str, object]) -> None:
    """Inventory round-trips through the Store."""
    inv = Inventory(hass)
    _scan(inv, [ROUTER, GAS])
    inv.update_device(GAS.mac, name="Sensore gas", category="tasmota", critical=True)
    await inv.async_save()

    loaded = Inventory(hass)
    await loaded.async_load()
    dev = loaded.devices[GAS.mac]
    assert (dev.name, dev.category, dev.critical, dev.hostname) == (
        "Sensore gas",
        "tasmota",
        True,
        "sensore-gas",
    )
    assert loaded.baseline_done
    assert loaded.gateway_mac == GW_MAC
    assert loaded.forget(GAS.mac) is not None
    assert loaded.forget(GAS.mac) is None
