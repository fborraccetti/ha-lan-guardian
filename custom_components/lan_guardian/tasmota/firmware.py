"""Tasmota firmware: latest release on GitHub and the official OTA image of a device."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any
from urllib.parse import urlsplit

import aiohttp

from .models import TasmotaInfo

_LOGGER = logging.getLogger(__name__)

RELEASES_URL = "https://api.github.com/repos/arendst/Tasmota/releases/latest"
RELEASE_TIMEOUT = 20.0
OTA_HOST = "ota.tasmota.com"
MAX_OTA_URL = 100  # OtaUrl is a 100-character setting


class FirmwareError(Exception):
    """Release information unavailable."""


@dataclass(frozen=True, slots=True)
class Release:
    """A published Tasmota release."""

    version: str  # "15.6.0"
    url: str | None  # GitHub release page
    notes: str | None  # markdown


async def async_fetch_latest_release(session: aiohttp.ClientSession) -> Release:
    """Latest stable release; GitHub allows 60 anonymous requests per hour."""
    try:
        async with session.get(
            RELEASES_URL,
            headers={"Accept": "application/vnd.github+json"},
            timeout=aiohttp.ClientTimeout(total=RELEASE_TIMEOUT),
        ) as resp:
            if resp.status != 200:
                raise FirmwareError(f"GitHub HTTP {resp.status}")
            data = await resp.json(content_type=None)
    except (aiohttp.ClientError, TimeoutError, ValueError) as err:
        raise FirmwareError(f"GitHub: {err.__class__.__name__}") from err
    return parse_release(data)


def parse_release(data: Any) -> Release:
    """Release from a GitHub releases API answer."""
    if not isinstance(data, dict) or not isinstance(data.get("tag_name"), str):
        raise FirmwareError("GitHub: unexpected answer")
    version = data["tag_name"].strip().removeprefix("v")
    if not version[:1].isdigit():
        raise FirmwareError(f"GitHub: unexpected tag {data['tag_name']}")
    notes = data.get("body")
    url = data.get("html_url")
    return Release(
        version=version,
        url=url if isinstance(url, str) else None,
        notes=notes if isinstance(notes, str) and notes else None,
    )


def _image_name(info: TasmotaInfo) -> str | None:
    """Official image file name of the running build."""
    if info.chip is None or info.variant is None:
        return None
    # Devices report the image without its prefix, e.g. "sensors" for tasmota-sensors.
    variant = info.variant
    if info.chip == "esp8266":
        name = variant if variant.startswith("tasmota") else f"tasmota-{variant}"
        return f"{name}.bin.gz"
    name = variant if variant.startswith("tasmota32") else f"tasmota32-{variant}"
    return f"{name}.bin"


def ota_url(info: TasmotaInfo) -> str | None:
    """Release image on ota.tasmota.com matching the running build, None if unknown.

    The device's own OtaUrl wins when it already points to the official server: its
    file name is the exact image (the version string drops the "tasmota-" prefix).
    A custom OtaUrl means a self-built firmware, which must not be replaced.
    """
    if info.chip is None:
        return None
    folder = "tasmota" if info.chip == "esp8266" else "tasmota32"
    name: str | None
    if info.ota_url:
        parts = urlsplit(info.ota_url)
        if parts.hostname != OTA_HOST:
            return None
        name = parts.path.rsplit("/", 1)[-1] or None
        if name is not None and not name.endswith((".bin", ".bin.gz")):
            name = None
    else:
        name = None
    name = name or _image_name(info)
    if name is None:
        return None
    url = f"http://{OTA_HOST}/{folder}/release/{name}"
    return url if len(url) <= MAX_OTA_URL else None
