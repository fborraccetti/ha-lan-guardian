"""Set and check the password of a Shelly's local API."""

from __future__ import annotations

import hashlib

import aiohttp

from .probe import guarded_url

USER = "admin"  # fixed on Gen2+; on Gen1 any name works, we always use this one
TIMEOUT = 8.0


class ShellyError(Exception):
    """The device did not answer, or refused the request."""


def ha1(device_id: str, password: str) -> str:
    """Gen2+ stores sha256("admin:<realm>:<password>"), the realm being the device id."""
    return hashlib.sha256(f"{USER}:{device_id}:{password}".encode()).hexdigest()


async def async_guarded_status(
    session: aiohttp.ClientSession,
    ip: str,
    gen: int,
    password: str | None,
    *,
    timeout: float = TIMEOUT,  # noqa: ASYNC109 - aiohttp per-request timeout
) -> int:
    """HTTP status of the guarded endpoint, anonymous or with the password.

    Gen1 takes HTTP Basic, Gen2+ Digest with SHA-256.
    """
    kwargs: dict[str, object] = {}
    if password is not None:
        if gen == 1:
            kwargs["headers"] = {"Authorization": aiohttp.encode_basic_auth(USER, password)}
        else:
            kwargs["middlewares"] = (aiohttp.DigestAuthMiddleware(USER, password),)
    try:
        async with session.get(
            guarded_url(ip, gen),
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
            **kwargs,  # type: ignore[arg-type]
        ) as resp:
            return resp.status
    except (aiohttp.ClientError, TimeoutError) as err:
        raise ShellyError(f"{ip}: {err.__class__.__name__}") from err


async def async_set_password(
    session: aiohttp.ClientSession,
    ip: str,
    gen: int,
    device_id: str | None,
    password: str,
    *,
    timeout: float = TIMEOUT,  # noqa: ASYNC109 - aiohttp per-request timeout
) -> None:
    """Enable authentication on a device that has none (no credentials needed for that).

    Gen1: /settings/login. Gen2+: Shelly.SetAuth, which takes the hash, not the password.
    """
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    try:
        if gen == 1:
            request = session.get(
                f"http://{ip}/settings/login",
                params={"enabled": "1", "username": USER, "password": password},
                allow_redirects=False,
                timeout=client_timeout,
            )
        else:
            if not device_id:
                raise ShellyError(f"{ip}: device id unknown")
            request = session.post(
                f"http://{ip}/rpc",
                json={
                    "id": 1,
                    "method": "Shelly.SetAuth",
                    "params": {"user": USER, "realm": device_id, "ha1": ha1(device_id, password)},
                },
                allow_redirects=False,
                timeout=client_timeout,
            )
        async with request as resp:
            if resp.status != 200:
                raise ShellyError(f"{ip}: HTTP {resp.status}")
    except (aiohttp.ClientError, TimeoutError) as err:
        raise ShellyError(f"{ip}: {err.__class__.__name__}") from err
