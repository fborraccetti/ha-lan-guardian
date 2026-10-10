"""Detect Shelly devices and whether their local API is password protected."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any

import aiohttp

from ..tasmota.probe import WebAuth

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ShellyProbe:
    """A Shelly device answered on this IP."""

    ip: str
    auth: WebAuth
    gen: int
    model: str | None = None
    firmware: str | None = None


async def _async_get(
    session: aiohttp.ClientSession,
    url: str,
    timeout: float,  # noqa: ASYNC109 - aiohttp per-request timeout
) -> tuple[int, Any]:
    async with session.get(
        url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=timeout)
    ) as resp:
        if resp.status != 200:
            return resp.status, None
        try:
            return resp.status, await resp.json(content_type=None)
        except ValueError:
            return resp.status, None


async def async_probe_shelly(
    session: aiohttp.ClientSession,
    ip: str,
    *,
    timeout: float = 4.0,  # noqa: ASYNC109 - aiohttp per-request timeout
) -> ShellyProbe | None:
    """Identify a Shelly with /shelly, then verify its protection on a guarded endpoint.

    /shelly never needs credentials. Gen1 reports "auth", Gen2+ "gen" and "auth_en".
    The flag is then checked for real: Gen1 /settings and Gen2+ /rpc/Sys.GetConfig
    answer 401 when a password is set and 200 when anyone can change the device.
    """
    try:
        status, info = await _async_get(session, f"http://{ip}/shelly", timeout)
    except (aiohttp.ClientError, TimeoutError) as err:
        _LOGGER.debug("No HTTP Shelly on %s: %s", ip, err.__class__.__name__)
        return None
    if status != 200 or not isinstance(info, dict):
        return None

    if isinstance(gen := info.get("gen"), int) and gen >= 2 and "auth_en" in info:
        claimed = bool(info["auth_en"])
        guarded = f"http://{ip}/rpc/Sys.GetConfig"
        model, firmware = info.get("model") or info.get("app"), info.get("ver")
    elif "type" in info and "auth" in info:
        gen, claimed = 1, bool(info["auth"])
        guarded = f"http://{ip}/settings"
        model, firmware = info.get("type"), info.get("fw")
    else:
        return None

    auth = WebAuth.PROTECTED if claimed else WebAuth.OPEN
    try:
        status, _ = await _async_get(session, guarded, timeout)
    except (aiohttp.ClientError, TimeoutError) as err:
        # The device answered /shelly a moment ago: keep what it claims.
        _LOGGER.debug("Shelly %s: auth check failed: %s", ip, err.__class__.__name__)
    else:
        if status == 401:
            auth = WebAuth.PROTECTED
        elif status == 200:
            auth = WebAuth.OPEN

    return ShellyProbe(
        ip=ip,
        auth=auth,
        gen=gen,
        model=str(model) if model else None,
        firmware=str(firmware) if firmware else None,
    )
