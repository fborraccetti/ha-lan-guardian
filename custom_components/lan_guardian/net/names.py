"""Host name lookup: reverse DNS and the mDNS cache."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from ipaddress import IPv4Address

import aiodns
from aiodns.error import DNSError

# zeroconf record type for A records.
_TYPE_A = 1


async def async_reverse_lookup(
    ips: Iterable[str],
    nameservers: list[str],
    *,
    timeout: float = 2.0,  # noqa: ASYNC109 - per-query timeout passed to c-ares
    concurrency: int = 16,
) -> dict[str, str]:
    """PTR lookup for each IP; missing entries are simply left out."""
    resolver = aiodns.DNSResolver(nameservers=nameservers or None, timeout=timeout, tries=1)
    semaphore = asyncio.Semaphore(concurrency)

    async def lookup(ip: str) -> tuple[str, str | None]:
        async with semaphore:
            try:
                result = await resolver.gethostbyaddr(ip)
            except DNSError:
                return ip, None
            return ip, result.name.rstrip(".") or None

    try:
        pairs = await asyncio.gather(*(lookup(ip) for ip in ips))
    finally:
        await resolver.close()
    return {ip: name for ip, name in pairs if name}


def mdns_names(cache: object) -> dict[str, str]:
    """Map IPv4 address to mDNS host name from a zeroconf DNSCache, without sending queries."""
    names: dict[str, str] = {}
    for name in cache.names():  # type: ignore[attr-defined]
        for record in cache.async_entries_with_name(name):  # type: ignore[attr-defined]
            if getattr(record, "type", None) != _TYPE_A:
                continue
            address = getattr(record, "address", b"")
            if len(address) != 4:
                continue
            host = str(getattr(record, "name", "")).rstrip(".")
            names[str(IPv4Address(address))] = host.removesuffix(".local")
    return names
