"""Async HTTP client for one Tasmota device.

Credentials travel only as HTTP Basic auth (user admin), never in the URL, so they
cannot end up in logs or exception messages.
"""

from __future__ import annotations

import asyncio
from email.message import Message
import logging
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

USER = "admin"
DEFAULT_TIMEOUT = 10.0
# The config dump is 4 KiB on ESP8266, a few more on ESP32 with file system settings.
BACKUP_TIMEOUT = 30.0
MIN_BACKUP_SIZE = 4096
MAX_BACKUP_SIZE = 256 * 1024


class TasmotaError(Exception):
    """Base error."""


class TasmotaConnectionError(TasmotaError):
    """Device unreachable or answered garbage."""


class TasmotaAuthError(TasmotaError):
    """WebPassword missing or wrong."""


class TasmotaClient:
    """Talk to one device over its web API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        password: str | None,
        semaphore: asyncio.Semaphore,
    ) -> None:
        """Initialize; the semaphore is shared by all devices to spare the Wi-Fi."""
        self._session = session
        self.host = host
        self._headers = (
            {"Authorization": aiohttp.encode_basic_auth(USER, password)} if password else {}
        )
        self._semaphore = semaphore

    async def async_command(
        self,
        command: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,  # noqa: ASYNC109 - aiohttp per-request timeout
    ) -> dict[str, Any]:
        """Run a console command and return its JSON answer."""
        async with self._semaphore:
            try:
                async with self._session.get(
                    f"http://{self.host}/cm",
                    params={"cmnd": command},
                    headers=self._headers,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    if resp.status == 401:
                        raise TasmotaAuthError(self.host)
                    if resp.status != 200:
                        raise TasmotaConnectionError(f"{self.host}: HTTP {resp.status}")
                    data = await resp.json(content_type=None)
            except (aiohttp.ClientError, TimeoutError, ValueError) as err:
                raise TasmotaConnectionError(f"{self.host}: {err.__class__.__name__}") from err
        if not isinstance(data, dict):
            raise TasmotaConnectionError(f"{self.host}: unexpected answer")
        return data

    async def async_status0(self) -> dict[str, Any]:
        """All status sections at once."""
        return await self.async_command("Status 0")

    async def async_download_config(self) -> tuple[bytes, str | None]:
        """Download the binary settings dump (/dl) and its suggested file name.

        /dl only accepts Basic auth. No Referer is sent: Tasmota rejects foreign ones.
        """
        async with self._semaphore:
            try:
                async with self._session.get(
                    f"http://{self.host}/dl",
                    headers=self._headers,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=BACKUP_TIMEOUT),
                ) as resp:
                    if resp.status == 401:
                        raise TasmotaAuthError(self.host)
                    content_type = resp.headers.get("Content-Type", "")
                    if resp.status != 200 or "octet-stream" not in content_type:
                        # WebServer 1 (user mode) or tasmota-minimal answer with an HTML page.
                        raise TasmotaConnectionError(
                            f"{self.host}: no config dump (HTTP {resp.status}, {content_type})"
                        )
                    data = await _read_all(resp, self.host)
                    filename = _filename(resp.headers.get("Content-Disposition"))
            except (aiohttp.ClientError, TimeoutError) as err:
                raise TasmotaConnectionError(f"{self.host}: {err.__class__.__name__}") from err
        # Every Tasmota dump holds at least the 4 KiB TSettings block.
        if len(data) < MIN_BACKUP_SIZE:
            raise TasmotaConnectionError(f"{self.host}: truncated config dump ({len(data)} bytes)")
        return data, filename


async def _read_all(resp: aiohttp.ClientResponse, host: str) -> bytes:
    """Read the whole body, chunk by chunk, up to MAX_BACKUP_SIZE.

    StreamReader.read(n) returns as soon as some data is there (one TCP segment from
    an ESP8266), so it must not be used to read a full body.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.content.iter_chunked(16 * 1024):
        total += len(chunk)
        if total > MAX_BACKUP_SIZE:
            raise TasmotaConnectionError(f"{host}: config dump larger than {MAX_BACKUP_SIZE}")
        chunks.append(chunk)
    data = b"".join(chunks)
    expected = resp.headers.get("Content-Length")
    if expected is not None and expected.isdigit() and int(expected) != len(data):
        raise TasmotaConnectionError(
            f"{host}: config dump of {len(data)} bytes, expected {expected}"
        )
    return data


def _filename(disposition: str | None) -> str | None:
    if not disposition:
        return None
    msg = Message()
    msg["content-disposition"] = disposition
    name = msg.get_param("filename", header="content-disposition")
    return name if isinstance(name, str) else None
