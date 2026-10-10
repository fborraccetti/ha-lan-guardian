"""Ping sweep with icmplib, plus a no-privilege fallback."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import StrEnum
import logging
import socket

from icmplib import async_multiping, async_ping
from icmplib.exceptions import ICMPLibError, SocketPermissionError

_LOGGER = logging.getLogger(__name__)

# Discard service: the datagram is dropped, but sending it makes the kernel resolve ARP.
_UDP_PROBE_PORT = 9


class ProbeMode(StrEnum):
    """How hosts are probed."""

    PRIVILEGED = "privileged"  # raw ICMP socket (HA OS: core runs privileged as root)
    UNPRIVILEGED = "unprivileged"  # ICMP datagram socket (needs ping_group_range)
    ARP_ONLY = "arp_only"  # no ICMP: UDP probes trigger ARP, liveness comes from the ARP table


@dataclass(frozen=True, slots=True)
class PingResult:
    """Outcome of pinging one host."""

    ip: str
    alive: bool
    packet_loss: float  # 0..1
    avg_rtt: float | None  # ms
    max_rtt: float | None  # ms


async def async_detect_probe_mode() -> ProbeMode:
    """Same check the core ping integration does, without depending on its private helper."""
    for privileged, mode in ((True, ProbeMode.PRIVILEGED), (False, ProbeMode.UNPRIVILEGED)):
        try:
            await async_ping("127.0.0.1", count=0, timeout=0, privileged=privileged)
        except SocketPermissionError:
            continue
        except ICMPLibError as err:
            _LOGGER.debug("ICMP self-test failed (privileged=%s): %s", privileged, err)
            continue
        return mode
    return ProbeMode.ARP_ONLY


async def async_ping_hosts(
    hosts: list[str],
    mode: ProbeMode,
    *,
    concurrency: int,
    count: int = 2,
    interval: float = 0.5,
    timeout: float = 1.5,  # noqa: ASYNC109 - per-request timeout of the library
) -> dict[str, PingResult]:
    """Ping every host; a host is alive if at least one reply arrives."""
    if mode is ProbeMode.ARP_ONLY:
        await _async_udp_probe(hosts)
        return {}
    results = await async_multiping(
        hosts,
        count=count,
        interval=interval,
        timeout=timeout,
        concurrent_tasks=concurrency,
        privileged=mode is ProbeMode.PRIVILEGED,
    )
    return {
        host.address: PingResult(
            ip=host.address,
            alive=host.is_alive,
            packet_loss=host.packet_loss,
            avg_rtt=host.avg_rtt if host.is_alive else None,
            max_rtt=host.max_rtt if host.is_alive else None,
        )
        for host in results
    }


async def async_ping_target(
    target: str,
    mode: ProbeMode,
    *,
    count: int = 10,
    interval: float = 0.2,
    timeout: float = 1.0,  # noqa: ASYNC109 - per-request timeout of the library
) -> PingResult | None:
    """Ping one host or name for loss/latency stats; None without ICMP or on resolve errors."""
    if mode is ProbeMode.ARP_ONLY:
        return None
    try:
        host = await async_ping(
            target,
            count=count,
            interval=interval,
            timeout=timeout,
            privileged=mode is ProbeMode.PRIVILEGED,
        )
    except ICMPLibError as err:
        _LOGGER.debug("Ping %s failed: %s", target, err)
        return PingResult(ip=target, alive=False, packet_loss=1.0, avg_rtt=None, max_rtt=None)
    return PingResult(
        ip=host.address,
        alive=host.is_alive,
        packet_loss=host.packet_loss,
        avg_rtt=host.avg_rtt if host.is_alive else None,
        max_rtt=host.max_rtt if host.is_alive else None,
    )


async def _async_udp_probe(hosts: list[str]) -> None:
    """Send one UDP datagram per host so the kernel fills the ARP table."""
    loop = asyncio.get_running_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        for host in hosts:
            try:
                await loop.sock_sendto(sock, b"", (host, _UDP_PROBE_PORT))
            except OSError:
                continue
