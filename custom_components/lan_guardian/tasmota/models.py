"""Parse Tasmota status answers."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from ..net.mac import normalize_mac

# Prefix is "release-" or the git hash of a development build; the rest is the variant.
_VERSION_RE = re.compile(r"^(\d+\.\d+\.\d+(?:\.\d+)?)\((?:release-|[0-9a-f]{7,}-)?([^)]+)\)")
_DEV_BUILD_RE = re.compile(r"\([0-9a-f]{7,}-")


def parse_version(raw: str) -> tuple[str, str | None]:
    """'14.3.0(release-tasmota-sensors)' -> ('14.3.0', 'tasmota-sensors').

    Development builds look like '15.0.1.2(85cff52-tasmota32)'.
    """
    match = _VERSION_RE.match(raw.strip())
    if match is None:
        return raw.split("(", maxsplit=1)[0].strip(), None
    return match.group(1), match.group(2)


def chip_from_hardware(hardware: str) -> str | None:
    """'ESP8266EX' -> 'esp8266', 'ESP32-C3 v0.4' -> 'esp32c3', 'ESP32-D0WD-V3 v3.1' -> 'esp32'."""
    hw = hardware.upper()
    if hw.startswith(("ESP8266", "ESP8285")):
        return "esp8266"
    if not hw.startswith("ESP32"):
        return None
    for suffix in ("C2", "C3", "C5", "C6", "H2", "P4", "S2", "S3"):
        if hw.startswith(f"ESP32-{suffix}"):
            return f"esp32{suffix.lower()}"
    return "esp32"


@dataclass(frozen=True, slots=True)
class TasmotaInfo:
    """The parts of Status 0 LAN Guardian cares about."""

    mac: str | None
    ip: str | None
    hostname: str | None
    device_name: str | None
    friendly_name: str | None
    topic: str | None
    version: str
    variant: str | None
    release: bool  # official release build, not a development one
    hardware: str | None
    chip: str | None
    core: str | None
    restart_reason: str | None
    boot_count: int | None
    ota_url: str | None
    uptime_sec: int | None
    rssi: int | None  # dBm
    signal: int | None  # quality 0-100 %
    link_count: int | None
    wifi_downtime: str | None
    program_size_kb: int | None
    free_kb: int | None
    flash_size_kb: int | None

    @property
    def name(self) -> str | None:
        """DeviceName, else the first FriendlyName."""
        return self.device_name or self.friendly_name


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except TypeError, ValueError:
        return None


def _str(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def parse_status0(data: dict[str, Any]) -> TasmotaInfo:
    """Build TasmotaInfo from a Status 0 answer; missing sections become None."""
    status = data.get("Status") or {}
    prm = data.get("StatusPRM") or {}
    fwr = data.get("StatusFWR") or {}
    mem = data.get("StatusMEM") or {}
    net = data.get("StatusNET") or {}
    sts = data.get("StatusSTS") or {}
    wifi = sts.get("Wifi") or {}

    friendly = status.get("FriendlyName")
    if isinstance(friendly, list):
        friendly = friendly[0] if friendly else None
    raw_version = str(fwr.get("Version", ""))
    version, variant = parse_version(raw_version)
    hardware = _str(fwr.get("Hardware"))
    return TasmotaInfo(
        mac=normalize_mac(str(net.get("Mac", ""))),
        ip=_str(net.get("IPAddress")),
        hostname=_str(net.get("Hostname")),
        device_name=_str(status.get("DeviceName")),
        friendly_name=_str(friendly),
        topic=_str(status.get("Topic")),
        version=version,
        variant=variant,
        # Older releases have no "release-" prefix; development builds carry a git hash.
        release=bool(raw_version) and _DEV_BUILD_RE.search(raw_version) is None,
        hardware=hardware,
        chip=chip_from_hardware(hardware) if hardware else None,
        core=_str(fwr.get("Core")),
        restart_reason=_str(prm.get("RestartReason")),
        boot_count=_int(prm.get("BootCount")),
        ota_url=_str(prm.get("OtaUrl")),
        uptime_sec=_int(sts.get("UptimeSec")),
        # Tasmota's naming is inverted: "RSSI" is the 0-100 quality, "Signal" the dBm
        # (support_tasmota.ino: WifiGetRssiAsQuality(rssi), rssi).
        rssi=_int(wifi.get("Signal")),
        signal=_int(wifi.get("RSSI")),
        link_count=_int(wifi.get("LinkCount")),
        wifi_downtime=_str(wifi.get("Downtime")),
        program_size_kb=_int(mem.get("ProgramSize")),
        free_kb=_int(mem.get("Free")),
        flash_size_kb=_int(mem.get("FlashSize")),
    )
