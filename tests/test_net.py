"""Tests for the network helpers."""

from __future__ import annotations

from ipaddress import IPv4Network
from types import SimpleNamespace
from unittest.mock import patch

from icmplib.exceptions import SocketPermissionError
import pytest

from custom_components.lan_guardian.net import icmp
from custom_components.lan_guardian.net.arp import parse_arp_table
from custom_components.lan_guardian.net.mac import is_randomized, normalize_mac
from custom_components.lan_guardian.net.names import mdns_names

ARP_TABLE = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         3C:A6:2F:00:00:01     *        enp0s18
192.168.1.248    0x1         0x2         a4:cf:12:00:02:48     *        enp0s18
192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        enp0s18
192.168.1.78     0x1         0x0         aa:bb:cc:00:00:78     *        enp0s18
172.30.32.1      0x1         0x2         02:42:ac:1e:20:01     *        hassio
garbage line
"""


def test_parse_arp_table() -> None:
    """Only complete entries inside the subnet survive, MACs normalized."""
    table = parse_arp_table(ARP_TABLE.splitlines(), IPv4Network("192.168.1.0/24"))
    assert table == {
        "192.168.1.1": "3c:a6:2f:00:00:01",
        "192.168.1.248": "a4:cf:12:00:02:48",
    }


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("A4-CF-12-00-02-48", "a4:cf:12:00:02:48"),
        ("a4cf.1200.0248", "a4:cf:12:00:02:48"),
        ("00:00:00:00:00:00", None),
        ("ff:ff:ff:ff:ff:ff", None),
        ("01:00:5e:00:00:fb", None),  # multicast
        ("nope", None),
    ],
)
def test_normalize_mac(raw: str, expected: str | None) -> None:
    """MACs are normalized; zero, broadcast and multicast are rejected."""
    assert normalize_mac(raw) == expected


def test_is_randomized() -> None:
    """Locally administered bit."""
    assert is_randomized("da:a1:19:00:00:01")
    assert is_randomized("02:42:ac:1e:20:01")
    assert not is_randomized("a4:cf:12:00:02:48")
    assert not is_randomized("bc:24:11:00:00:09")  # Proxmox VM


def test_mdns_names() -> None:
    """A records from the zeroconf cache become ip -> host name."""
    records = {
        "tasmota-1a2b.local.": [
            SimpleNamespace(type=1, address=bytes([192, 168, 1, 50]), name="tasmota-1a2b.local."),
            SimpleNamespace(type=28, address=b"\x00" * 16, name="tasmota-1a2b.local."),
        ],
        "_http._tcp.local.": [SimpleNamespace(type=12, name="_http._tcp.local.")],
    }
    cache = SimpleNamespace(
        names=lambda: list(records), async_entries_with_name=lambda name: records[name]
    )
    assert mdns_names(cache) == {"192.168.1.50": "tasmota-1a2b"}


@pytest.mark.parametrize(
    ("failures", "expected"),
    [
        (set(), icmp.ProbeMode.PRIVILEGED),
        ({True}, icmp.ProbeMode.UNPRIVILEGED),
        ({True, False}, icmp.ProbeMode.ARP_ONLY),
    ],
)
async def test_detect_probe_mode(failures: set[bool], expected: icmp.ProbeMode) -> None:
    """Privileged first, then unprivileged, then ARP only."""

    async def fake_ping(*args: object, privileged: bool, **kwargs: object) -> None:
        if privileged in failures:
            raise SocketPermissionError(privileged)

    with patch.object(icmp, "async_ping", side_effect=fake_ping):
        assert await icmp.async_detect_probe_mode() is expected


async def test_ping_hosts_maps_results() -> None:
    """icmplib Host objects become PingResult; ARP-only mode returns nothing."""
    hosts = [
        SimpleNamespace(
            address="192.168.1.1", is_alive=True, packet_loss=0.5, avg_rtt=2.0, max_rtt=3.0
        ),
        SimpleNamespace(
            address="192.168.1.2", is_alive=False, packet_loss=1.0, avg_rtt=0.0, max_rtt=0.0
        ),
    ]
    with patch.object(icmp, "async_multiping", return_value=hosts) as multiping:
        result = await icmp.async_ping_hosts(
            ["192.168.1.1", "192.168.1.2"], icmp.ProbeMode.PRIVILEGED, concurrency=8
        )
    assert multiping.call_args.kwargs["privileged"] is True
    assert multiping.call_args.kwargs["concurrent_tasks"] == 8
    assert result["192.168.1.1"].alive
    assert result["192.168.1.1"].avg_rtt == 2.0
    assert result["192.168.1.2"].avg_rtt is None

    with patch.object(icmp, "_async_udp_probe") as probe:
        assert (
            await icmp.async_ping_hosts(["192.168.1.1"], icmp.ProbeMode.ARP_ONLY, concurrency=1)
            == {}
        )
    probe.assert_awaited_once()
