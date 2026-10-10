"""DNS health checks."""

from __future__ import annotations

from dataclasses import dataclass
import time

import aiodns
from aiodns.error import DNSError
import pycares

# Pi-hole answers blocked domains with 0.0.0.0 / :: (NULL mode) or NXDOMAIN.
_BLOCKED_ADDRESSES = {"0.0.0.0", "::"}
_NOT_FOUND = {pycares.errno.ARES_ENOTFOUND, pycares.errno.ARES_ENODATA}


@dataclass(frozen=True, slots=True)
class DnsCheck:
    """Result of resolving one name on one server."""

    server: str
    ok: bool
    time_ms: float | None
    addresses: tuple[str, ...] = ()
    error: str | None = None


async def async_resolve(
    server: str,
    name: str,
    *,
    timeout: float = 3.0,  # noqa: ASYNC109 - per-query timeout passed to c-ares
) -> DnsCheck:
    """Resolve an A record directly on one server, timing it.

    NXDOMAIN counts as a working server (it answered), with no addresses.
    """
    resolver = aiodns.DNSResolver(nameservers=[server], timeout=timeout, tries=1)
    start = time.perf_counter()
    try:
        result = await resolver.query_dns(name, "A")
    except DNSError as err:
        elapsed = (time.perf_counter() - start) * 1000
        code = err.args[0] if err.args else None
        if code in _NOT_FOUND:
            return DnsCheck(server=server, ok=True, time_ms=round(elapsed, 1))
        return DnsCheck(server=server, ok=False, time_ms=None, error=str(err.args[-1]))
    finally:
        await resolver.close()
    elapsed = (time.perf_counter() - start) * 1000
    addresses = tuple(
        record.data.addr for record in result.answer if isinstance(record.data, pycares.ARecordData)
    )
    return DnsCheck(server=server, ok=True, time_ms=round(elapsed, 1), addresses=addresses)


def is_blocked(check: DnsCheck) -> bool | None:
    """Whether a sinkhole blocked the name; None if the server did not answer."""
    if not check.ok:
        return None
    return not check.addresses or set(check.addresses) <= _BLOCKED_ADDRESSES
