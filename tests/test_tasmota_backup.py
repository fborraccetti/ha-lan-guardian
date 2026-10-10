"""Tests for Tasmota status parsing and the backup store."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

import pytest

from custom_components.lan_guardian.tasmota.backup import (
    BackupResult,
    BackupStore,
    config_digest,
)
from custom_components.lan_guardian.tasmota.models import (
    chip_from_hardware,
    parse_status0,
    parse_version,
)

from .conftest import load_fixture, make_dump

MAC = "a4:cf:12:00:02:48"
T0 = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("14.3.0(release-tasmota)", ("14.3.0", "tasmota")),
        ("14.3.0(release-tasmota-sensors)", ("14.3.0", "tasmota-sensors")),
        # As seen on the real devices (2026-10-09): image name without "tasmota-".
        ("14.3.0(release-sensors)", ("14.3.0", "sensors")),
        ("13.1.0(tasmota)", ("13.1.0", "tasmota")),
        ("15.0.1(release-tasmota32)", ("15.0.1", "tasmota32")),
        ("15.3.0.2(85cff52-tasmota32c3)", ("15.3.0.2", "tasmota32c3")),
        ("13.1.0(tasmota-lite)", ("13.1.0", "tasmota-lite")),
        ("15.0.1(release-tasmota32solo1)single-core", ("15.0.1", "tasmota32solo1")),
        ("garbage", ("garbage", None)),
    ],
)
def test_parse_version(raw: str, expected: tuple[str, str | None]) -> None:
    """Version and build variant from StatusFWR.Version."""
    assert parse_version(raw) == expected


@pytest.mark.parametrize(
    ("hardware", "chip"),
    [
        ("ESP8266EX", "esp8266"),
        ("ESP8285N08", "esp8266"),
        ("ESP32-D0WD-V3 v3.1", "esp32"),
        ("ESP32-C3 v0.4", "esp32c3"),
        ("ESP32-S3", "esp32s3"),
        ("ESP32-S2", "esp32s2"),
        ("RP2040", None),
    ],
)
def test_chip_from_hardware(hardware: str, chip: str | None) -> None:
    """Chip family from StatusFWR.Hardware."""
    assert chip_from_hardware(hardware) == chip


def test_parse_fixtures() -> None:
    """Both real-shaped Status 0 answers parse, with Tasmota's inverted Wi-Fi naming."""
    esp8266 = parse_status0(load_fixture("status0_esp8266.json"))
    assert (esp8266.mac, esp8266.version, esp8266.variant, esp8266.chip) == (
        MAC,
        "14.3.0",
        "sensors",
        "esp8266",
    )
    assert (esp8266.signal, esp8266.rssi) == (22, -89)
    assert esp8266.boot_count == 41
    assert esp8266.name == "sensore_gas"

    esp32 = parse_status0(load_fixture("status0_esp32.json"))
    assert (esp32.variant, esp32.chip, esp32.signal) == ("tasmota32", "esp32", 64)
    assert esp32.ota_url == "http://ota.tasmota.com/tasmota32/release/tasmota32.bin"

    empty = parse_status0({})
    assert empty.mac is None
    assert empty.signal is None


def test_digest_ignores_volatile_fields() -> None:
    """Boot counter, relay state and roaming do not change the digest; settings do."""
    base = bytearray(make_dump())
    digest = config_digest(bytes(base))
    for offset in (0x004, 0x00C, 0x00E, 0x2E8, 0xF0A, 0xFD4, 0xFFC):
        changed = bytearray(base)
        changed[offset] ^= 0xFF
        assert config_digest(bytes(changed)) == digest, hex(offset)
    changed = bytearray(base)
    changed[0x100] ^= 0xFF  # e.g. a GPIO template byte
    assert config_digest(bytes(changed)) != digest


def test_digest_extended_esp32_dump() -> None:
    """With extra driver settings the TSettings block starts after a 16-byte header."""
    dump = bytearray(make_dump(size=4096 + 16 + 512))
    digest = config_digest(bytes(dump))
    dump[16 + 0x004] ^= 0xFF
    assert config_digest(bytes(dump)) == digest
    dump[0x004] ^= 0xFF  # header byte, not save_flag here
    assert config_digest(bytes(dump)) != digest


IDENTITY = {
    "mac": MAC,
    "ip": "192.168.1.248",
    "name": "Sensore gas",
    "device_name": "sensore_gas",
    "hostname": "tasmota-000248-0584",
}


def test_store_dedup_and_rotation(tmp_path: Path) -> None:
    """Identical configs are skipped; only the newest N pairs are kept."""
    store = BackupStore(tmp_path)
    status = load_fixture("status0_esp8266.json")
    directory = tmp_path / "a4cf12000248"

    def save(seed: int | bytes, when: datetime) -> BackupResult:
        dump = seed if isinstance(seed, bytes) else make_dump(seed)
        return store.save(
            MAC,
            dump,
            status,
            identity=IDENTITY,
            now=when,
            retention=2,
            tasmota_filename="Config_sensore_gas_15.0.1.dmp",
        )

    first = save(1, T0)
    assert first.saved
    assert first.path == directory / "20261009T120000Z_tasmota-000248-0584.dmp"
    record = json.loads(first.path.with_suffix(".json").read_text())
    assert record["device"] == IDENTITY
    assert record["backup"]["file"] == first.path.name
    assert record["backup"]["size"] == 4096
    assert record["backup"]["tasmota_filename"] == "Config_sensore_gas_15.0.1.dmp"
    assert record["status0"]["StatusNET"]["Mac"] == "A4:CF:12:00:02:48"
    device = json.loads((directory / "device.json").read_text())
    assert device["hostname"] == "tasmota-000248-0584"
    assert device["latest_backup"] == first.path.name

    # Same settings after a reboot: not written again, but device.json is refreshed.
    rebooted = bytearray(make_dump(1))
    rebooted[0x00C] += 1
    again = save(bytes(rebooted), T0 + timedelta(hours=1))
    assert not again.saved
    assert again.path == first.path
    device = json.loads((directory / "device.json").read_text())
    assert device["checked"] == (T0 + timedelta(hours=1)).isoformat()

    for i in (2, 3, 4):
        assert save(i, T0 + timedelta(days=i)).saved
    assert sorted(p.name for p in directory.iterdir()) == [
        "20261012T120000Z_tasmota-000248-0584.dmp",
        "20261012T120000Z_tasmota-000248-0584.json",
        "20261013T120000Z_tasmota-000248-0584.dmp",
        "20261013T120000Z_tasmota-000248-0584.json",
        "device.json",
    ]
    assert store.latest("00:00:00:00:00:01") is None


def test_store_without_hostname_and_unsafe_names(tmp_path: Path) -> None:
    """No hostname: timestamp only; odd characters never reach the file name."""
    store = BackupStore(tmp_path)
    plain = store.save(MAC, make_dump(), {}, identity={"mac": MAC}, now=T0, retention=5)
    assert plain.path.name == "20261009T120000Z.dmp"
    odd = store.save(
        MAC,
        make_dump(9),
        {},
        identity={"mac": MAC, "hostname": "../Cucina luce/1"},
        now=T0 + timedelta(minutes=1),
        retention=5,
    )
    assert odd.path.name == "20261009T120100Z_Cucina_luce_1.dmp"
    assert odd.path.parent == plain.path.parent
