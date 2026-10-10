"""Read the kernel neighbour (ARP) table."""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from .mac import normalize_mac

PROC_ARP = Path("/proc/net/arp")
# ATF_COM: the entry is complete (the host answered the ARP request).
_ATF_COM = 0x2


def parse_arp_table(lines: Iterable[str], subnet: IPv4Network) -> dict[str, str]:
    """Parse /proc/net/arp content into {ip: mac}, keeping complete entries inside the subnet."""
    table: dict[str, str] = {}
    for line in lines:
        fields = line.split()
        if len(fields) < 6 or fields[0] == "IP":
            continue
        ip, _hw_type, flags, hw_addr = fields[:4]
        try:
            if not int(flags, 16) & _ATF_COM or IPv4Address(ip) not in subnet:
                continue
        except ValueError:
            continue
        if (mac := normalize_mac(hw_addr)) is not None:
            table[ip] = mac
    return table


def read_arp_table(subnet: IPv4Network) -> dict[str, str]:
    """Blocking read of /proc/net/arp; run it in an executor."""
    try:
        content = PROC_ARP.read_text(encoding="ascii", errors="replace")
    except OSError:
        return {}
    return parse_arp_table(content.splitlines(), subnet)
