"""Detect Tasmota devices and whether their web UI is password protected."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import logging
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)


class WebAuth(StrEnum):
    """Web UI protection of a Tasmota device."""

    OPEN = "open"  # no WebPassword: anyone on the LAN can run any command
    PROTECTED = "protected"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """A Tasmota device answered on this IP."""

    ip: str
    auth: WebAuth
    status: dict[str, Any] | None = None  # Status response when open


async def async_probe_tasmota(
    session: aiohttp.ClientSession,
    ip: str,
    *,
    timeout: float = 4.0,  # noqa: ASYNC109 - aiohttp per-request timeout
) -> ProbeResult | None:
    """Ask /cm?cmnd=Status without credentials.

    Tasmota answers 200 with JSON when it has no WebPassword and 401 with
    {"WARNING":"Need user=..."} when it has one. Anything else is not Tasmota.
    No Referer header is sent: Tasmota rejects foreign referers.
    """
    try:
        async with session.get(
            f"http://{ip}/cm",
            params={"cmnd": "Status"},
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            server = resp.headers.get("Server", "")
            body = await resp.text(errors="replace")
            if resp.status == 401 and ("Need user=" in body or server.startswith("Tasmota")):
                return ProbeResult(ip=ip, auth=WebAuth.PROTECTED)
            if resp.status != 200:
                return None
            try:
                data = await resp.json(content_type=None)
            except ValueError:
                return None
    except (aiohttp.ClientError, TimeoutError) as err:
        _LOGGER.debug("No HTTP Tasmota on %s: %s", ip, err.__class__.__name__)
        return None
    if isinstance(data, dict) and isinstance(data.get("Status"), dict):
        return ProbeResult(ip=ip, auth=WebAuth.OPEN, status=data)
    return None
