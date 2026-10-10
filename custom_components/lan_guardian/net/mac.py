"""MAC address helpers."""

from __future__ import annotations

import re

import aiooui

_HEX_RE = re.compile(r"[^0-9a-f]")


def normalize_mac(mac: str) -> str | None:
    """Return the MAC as lowercase aa:bb:cc:dd:ee:ff, or None if it is not a usable unicast MAC."""
    digits = _HEX_RE.sub("", mac.lower())
    if len(digits) != 12 or digits in ("000000000000", "ffffffffffff"):
        return None
    if int(digits[1], 16) & 0x1:  # multicast
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def is_randomized(mac: str) -> bool:
    """Locally administered bit set: phones and laptops use this for private MACs."""
    return bool(int(mac[1], 16) & 0x2)


async def async_load_vendors() -> None:
    """Load the offline OUI database (mmap in an executor)."""
    if not aiooui.is_loaded():
        await aiooui.async_load()


def vendor_for(mac: str) -> str | None:
    """Vendor name from the OUI database; None for randomized or unknown MACs."""
    if is_randomized(mac) or not aiooui.is_loaded():
        return None
    return aiooui.get_vendor(mac)
