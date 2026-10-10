"""Tasmota configuration backups on disk, with rotation and de-duplication.

Layout: <config>/lan_guardian/backups/<mac without colons>/
    <UTC timestamp>_<tasmota hostname>.dmp   binary settings dump (/dl)
    <UTC timestamp>_<tasmota hostname>.json  device identity, backup info, Status 0
    device.json                              identity of the device, latest backup
Everything here is blocking file I/O: call it from an executor.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

SETTINGS_SIZE = 4096
DEVICE_FILE = "device.json"
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
# ESP32 dumps with extra driver settings start with a 16-byte header before TSettings.
_EXTENDED_HEADER = 16

# Fields of TSettings (tasmota/include/tasmota_types.h) that change without any
# configuration change. Masked before hashing so a restart, a relay toggle or Wi-Fi
# roaming between mesh repeaters does not produce a "new" backup. The XOR obfuscation
# is per byte position, so masking positions works on the raw dump.
_VOLATILE_RANGES = (
    (0x004, 4),  # save_flag: incremented on every settings save
    (0x00C, 4),  # bootcount + cfg_crc
    (0x2E8, 4),  # power: relay state
    (0xF09, 7),  # wifi_channel + wifi_bssid: last access point
    (0xFD4, 4),  # bootcount_reset_time
    (0xFF8, 8),  # cfg_timestamp + cfg_crc32
)


@dataclass(frozen=True, slots=True)
class BackupResult:
    """Outcome of storing one backup."""

    saved: bool  # False: identical to the latest one, nothing written
    path: Path  # the new .dmp, or the existing identical one
    digest: str


def config_digest(dump: bytes) -> str:
    """SHA-256 of the dump with volatile fields zeroed."""
    data = bytearray(dump)
    base = _EXTENDED_HEADER if len(data) > SETTINGS_SIZE else 0
    for offset, length in _VOLATILE_RANGES:
        start = base + offset
        if start + length <= len(data):
            data[start : start + length] = bytes(length)
    return hashlib.sha256(data).hexdigest()


def _safe(value: Any) -> str | None:
    """A host name usable in a file name."""
    if not value:
        return None
    return _UNSAFE.sub("_", str(value)).strip("._")[:48] or None


class BackupStore:
    """Backups of all devices under one directory."""

    def __init__(self, root: Path) -> None:
        """Initialize with <config>/lan_guardian/backups."""
        self.root = root

    def device_dir(self, mac: str) -> Path:
        """Directory of one device."""
        return self.root / mac.replace(":", "").lower()

    def list_backups(self, mac: str) -> list[Path]:
        """The device .dmp files, oldest first (names are sortable timestamps)."""
        directory = self.device_dir(mac)
        if not directory.is_dir():
            return []
        return sorted(directory.glob("*.dmp"))

    def latest(self, mac: str) -> Path | None:
        """Most recent .dmp."""
        backups = self.list_backups(mac)
        return backups[-1] if backups else None

    def save(
        self,
        mac: str,
        dump: bytes,
        status: dict[str, Any],
        *,
        identity: dict[str, Any],
        now: datetime,
        retention: int,
        tasmota_filename: str | None = None,
    ) -> BackupResult:
        """Write <ts>_<host>.dmp and .json unless the config equals the latest backup.

        `identity` (MAC, IP, names, Tasmota hostname...) goes into the .json and into
        device.json, so a backup can always be traced back to its device, even when
        the files are copied somewhere else.
        """
        digest = config_digest(dump)
        directory = self.device_dir(mac)
        latest = self.latest(mac)
        if latest is not None and config_digest(latest.read_bytes()) == digest:
            self._write_device_file(directory, identity, latest, now)
            return BackupResult(saved=False, path=latest, digest=digest)

        directory.mkdir(parents=True, exist_ok=True)
        stem = now.strftime("%Y%m%dT%H%M%SZ")
        if host := _safe(identity.get("hostname")):
            stem = f"{stem}_{host}"
        dmp = directory / f"{stem}.dmp"
        tmp = dmp.with_suffix(".tmp")
        tmp.write_bytes(dump)
        tmp.replace(dmp)  # never leave a truncated .dmp behind
        record = {
            "lan_guardian_backup": 1,
            "device": identity,
            "backup": {
                "created": now.isoformat(),
                "file": dmp.name,
                "size": len(dump),
                "sha256": hashlib.sha256(dump).hexdigest(),
                "config_digest": digest,
                "tasmota_filename": tasmota_filename,
            },
            "status0": status,
        }
        dmp.with_suffix(".json").write_text(
            json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        self._write_device_file(directory, identity, dmp, now)
        self.rotate(mac, retention)
        return BackupResult(saved=True, path=dmp, digest=digest)

    @staticmethod
    def _write_device_file(
        directory: Path, identity: dict[str, Any], latest: Path, now: datetime
    ) -> None:
        """device.json: who this directory belongs to, as of the last backup run."""
        (directory / DEVICE_FILE).write_text(
            json.dumps(
                {**identity, "latest_backup": latest.name, "checked": now.isoformat()},
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    def rotate(self, mac: str, retention: int) -> list[Path]:
        """Keep the newest `retention` backups; return the removed .dmp files."""
        backups = self.list_backups(mac)
        removed = backups[: max(len(backups) - retention, 0)]
        for dmp in removed:
            dmp.unlink(missing_ok=True)
            dmp.with_suffix(".json").unlink(missing_ok=True)
        return removed
