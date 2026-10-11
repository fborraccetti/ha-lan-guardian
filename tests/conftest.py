"""Shared fixtures."""

from __future__ import annotations

from collections.abc import Generator
import copy
import dataclasses
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lan_guardian.const import (
    CONF_DNS_SERVERS,
    CONF_GATEWAY,
    CONF_SUBNET,
    DOMAIN,
)
from custom_components.lan_guardian.net.dns import DnsCheck
from custom_components.lan_guardian.net.icmp import PingResult, ProbeMode
from custom_components.lan_guardian.shelly.auth import ShellyError
from custom_components.lan_guardian.shelly.probe import ShellyProbe
from custom_components.lan_guardian.tasmota.client import TasmotaAuthError, TasmotaConnectionError
from custom_components.lan_guardian.tasmota.firmware import FirmwareError, Release
from custom_components.lan_guardian.tasmota.probe import ProbeResult, WebAuth


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(
    enable_custom_integrations: None,
) -> None:
    """Load custom_components/ in every test."""


@pytest.fixture
def mock_adapters() -> Generator[None]:
    """Pretend HA sees a single LAN adapter on 192.168.1.3/24."""
    adapters = [
        {
            "name": "eth0",
            "index": 2,
            "enabled": True,
            "auto": True,
            "default": True,
            "ipv4": [{"address": "192.168.1.3", "network_prefix": 24}],
            "ipv6": [],
        }
    ]
    with patch(
        "custom_components.lan_guardian.config_flow.network.async_get_adapters",
        return_value=adapters,
    ):
        yield


@pytest.fixture
def config_entry() -> MockConfigEntry:
    """A configured LAN Guardian entry."""
    return MockConfigEntry(
        domain=DOMAIN,
        title="LAN Guardian (192.168.1.0/24)",
        data={CONF_SUBNET: "192.168.1.0/24", CONF_GATEWAY: "192.168.1.1"},
        options={CONF_DNS_SERVERS: ["192.168.1.9", "192.168.1.1"]},
    )


FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict[str, Any]:
    """A JSON fixture, fresh copy each time."""
    return json.loads((FIXTURES / name).read_text())


def make_dump(seed: int = 1, size: int = 4096) -> bytes:
    """A fake config dump."""
    return bytes((seed + i) % 256 for i in range(size))


class FakeTasmotaClient:
    """Stands in for TasmotaClient, backed by FakeNetwork."""

    net: FakeNetwork

    def __init__(self, session: object, host: str, password: str | None, semaphore: object) -> None:
        self.host = host
        self.password = password

    def _check(self, what: str) -> None:
        self.net.tasmota_calls.append((self.host, what, self.password))
        if self.host not in self.net.tasmota_status:
            raise TasmotaConnectionError(self.host)
        expected = self.net.tasmota_passwords.get(self.host)
        if expected is not None and self.password != expected:
            raise TasmotaAuthError(self.host)

    async def async_status0(self) -> dict[str, Any]:
        self._check("status0")
        return copy.deepcopy(self.net.tasmota_status[self.host])

    async def async_command(self, command: str, **kwargs: object) -> dict[str, Any]:
        self._check(command)
        return self.net.tasmota_commands(self.host, command)

    async def async_download_config(self) -> tuple[bytes, str | None]:
        self._check("dl")
        if self.net.tasmota_flaky.get(self.host, 0) > 0:
            self.net.tasmota_flaky[self.host] -= 1
            raise TasmotaConnectionError(f"{self.host}: ClientPayloadError")
        return self.net.tasmota_dumps[self.host], "Config_x_14.3.0.dmp"


class FakeNetwork:
    """A LAN the tests can edit between scans."""

    def __init__(self) -> None:
        """Start with router, Home Assistant peer and a Tasmota."""
        self.arp: dict[str, str] = {
            "192.168.1.1": "3c:a6:2f:00:00:01",
            "192.168.1.9": "bc:24:11:00:00:09",
            "192.168.1.248": "a4:cf:12:00:02:48",
        }
        self.no_icmp: set[str] = set()  # hosts that answer ARP but drop ping
        self.ptr: dict[str, str] = {"192.168.1.248": "sensore-gas.fritz.box"}
        self.vendors: dict[str, str] = {"a4:cf:12:00:02:48": "Espressif Inc."}
        self.gateway_loss = 0.0
        self.internet_alive = True
        self.dns_down: set[str] = set()
        self.adblock_addresses: tuple[str, ...] = ("0.0.0.0",)
        self.tasmota: dict[str, WebAuth] = {"192.168.1.248": WebAuth.OPEN}
        self.shelly: dict[str, ShellyProbe] = {}
        self.shelly_passwords: dict[str, str] = {}
        self.shelly_ignore_password: set[str] = set()  # accepts the request, stays open
        self.shelly_calls: list[tuple[str, str]] = []  # host, what
        # HTTP API of the Tasmota devices: Status 0 answers, WebPasswords, config dumps.
        self.tasmota_status: dict[str, dict[str, Any]] = {
            "192.168.1.248": load_fixture("status0_esp8266.json")
        }
        self.tasmota_passwords: dict[str, str] = {}
        self.tasmota_dumps: dict[str, bytes] = {"192.168.1.248": make_dump()}
        self.tasmota_calls: list[tuple[str, str, str | None]] = []  # host, what, password
        self.tasmota_flaky: dict[str, int] = {}  # host -> failures before /dl works
        self.tasmota_ignore_password: set[str] = set()  # accepts WebPassword2, stays open
        self.tasmota_drop_password_answer: set[str] = set()  # sets it, answer is lost
        self.tasmota_lose_answer: set[str] = set()  # WebPassword2 applied, answer lost
        self.tasmota_ignore_password: set[str] = set()  # WebPassword2 has no effect
        # Firmware: latest GitHub release (None: GitHub unreachable) and OTA behaviour.
        self.release: Release | None = Release(
            version="15.6.0",
            url="https://github.com/arendst/Tasmota/releases/tag/v15.6.0",
            notes="## Changed\n- Everything",
        )
        self.release_checks = 0
        self.tasmota_ota_fail: set[str] = set()  # Upgrade 1 accepted, download fails
        self.tasmota_ota_urls: dict[str, str] = {}

    def tasmota_commands(self, host: str, command: str) -> dict[str, Any]:
        """Console commands the fake devices understand."""
        if command.startswith("WebPassword2 "):
            if host in self.tasmota_lose_answer:
                self.tasmota_passwords[host] = command.split(" ", 1)[1]
                raise TasmotaConnectionError(f"{host}: ClientPayloadError")
            if host not in self.tasmota_ignore_password:
                self.tasmota_passwords[host] = command.split(" ", 1)[1]
            return {"WebPassword": "****"}
        if command == "Status":
            return {"Status": self.tasmota_status[host]["Status"]}
        if command.startswith("OtaUrl "):
            self.tasmota_ota_urls[host] = command.split(" ", 1)[1]
            return {"OtaUrl": self.tasmota_ota_urls[host]}
        if command == "Upgrade 1":
            if host not in self.tasmota_ota_fail and self.release is not None:
                status = self.tasmota_status[host]
                build = status["StatusFWR"]["Version"].split("(", 1)[1]
                status["StatusFWR"]["Version"] = f"{self.release.version}({build}"
                status["StatusSTS"]["UptimeSec"] = 0
            return {"Upgrade": "Version 15.6.0 from ..."}
        return {}

    def ping_target(self, target: str) -> PingResult:
        if target == "192.168.1.1":
            return PingResult(
                ip=target,
                alive=self.gateway_loss < 1,
                packet_loss=self.gateway_loss,
                avg_rtt=1.0,
                max_rtt=4.0,
            )
        if not self.internet_alive:
            return PingResult(ip=target, alive=False, packet_loss=1.0, avg_rtt=None, max_rtt=None)
        return PingResult(ip=target, alive=True, packet_loss=0.0, avg_rtt=12.0, max_rtt=20.0)

    def resolve(self, server: str, name: str) -> DnsCheck:
        if server in self.dns_down:
            return DnsCheck(
                server=server, ok=False, time_ms=None, error="Timeout while contacting DNS servers"
            )
        if name == "doubleclick.net":
            return DnsCheck(server=server, ok=True, time_ms=1.0, addresses=self.adblock_addresses)
        return DnsCheck(server=server, ok=True, time_ms=8.5, addresses=("142.250.180.68",))

    def ping(self, hosts: list[str]) -> dict[str, PingResult]:
        return {
            ip: PingResult(ip=ip, alive=True, packet_loss=0.0, avg_rtt=3.0, max_rtt=5.0)
            for ip in self.arp
            if ip in hosts and ip not in self.no_icmp
        }


@pytest.fixture(autouse=True)
def fake_network() -> Generator[FakeNetwork]:
    """Replace ICMP, ARP, DNS and mDNS with an in-memory network."""
    net = FakeNetwork()
    scan = "custom_components.lan_guardian.coordinator.scan"
    health = "custom_components.lan_guardian.coordinator.health"
    security = "custom_components.lan_guardian.coordinator.security"
    tasmota = "custom_components.lan_guardian.coordinator.tasmota"
    client_cls = type("BoundFakeTasmotaClient", (FakeTasmotaClient,), {"net": net})

    async def ping_hosts(hosts: list[str], mode: object, **kwargs: object) -> dict[str, PingResult]:
        return net.ping(hosts)

    async def ping_target(target: str, mode: object, **kwargs: object) -> PingResult:
        return net.ping_target(target)

    async def resolve(server: str, name: str, **kwargs: object) -> DnsCheck:
        return net.resolve(server, name)

    async def probe(session: object, ip: str, **kwargs: object) -> ProbeResult | None:
        auth = net.tasmota.get(ip)
        if auth and ip in net.tasmota_passwords:
            auth = WebAuth.PROTECTED
        return ProbeResult(ip=ip, auth=auth) if auth else None

    async def probe_shelly(session: object, ip: str, **kwargs: object) -> ShellyProbe | None:
        found = net.shelly.get(ip)
        if found and ip in net.shelly_passwords:
            return dataclasses.replace(found, auth=WebAuth.PROTECTED)
        return found

    async def shelly_status(
        session: object, ip: str, gen: int, password: str | None, **kwargs: object
    ) -> int:
        net.shelly_calls.append((ip, "status"))
        if ip not in net.shelly:
            raise ShellyError(f"{ip}: ClientConnectorError")
        expected = net.shelly_passwords.get(ip)
        return 200 if expected is None or password == expected else 401

    async def shelly_set(
        session: object, ip: str, gen: int, device_id: str | None, password: str, **kwargs: object
    ) -> None:
        net.shelly_calls.append((ip, "set"))
        if ip not in net.shelly:
            raise ShellyError(f"{ip}: ClientConnectorError")
        if ip in net.shelly_passwords:
            raise ShellyError(f"{ip}: HTTP 401")
        if ip not in net.shelly_ignore_password:
            net.shelly_passwords[ip] = password

    async def latest_release(session: object) -> Release:
        net.release_checks += 1
        if net.release is None:
            raise FirmwareError("GitHub: ClientConnectorError")
        return net.release

    async def reverse(ips: list[str], servers: list[str], **kwargs: object) -> dict[str, str]:
        return {ip: net.ptr[ip] for ip in ips if ip in net.ptr}

    with (
        patch(f"{scan}.async_detect_probe_mode", return_value=ProbeMode.PRIVILEGED),
        patch(f"{scan}.async_load_vendors"),
        patch(f"{scan}.async_ping_hosts", side_effect=ping_hosts),
        patch(f"{scan}.read_arp_table", side_effect=lambda subnet: dict(net.arp)),
        patch(f"{scan}.async_reverse_lookup", side_effect=reverse),
        patch(f"{scan}.vendor_for", side_effect=net.vendors.get),
        patch(f"{scan}.zeroconf.async_get_async_instance", side_effect=RuntimeError),
        patch(f"{scan}.ARP_SETTLE_SECONDS", 0),
        patch(f"{health}.async_ping_target", side_effect=ping_target),
        patch(f"{health}.async_resolve", side_effect=resolve),
        patch(f"{security}.async_probe_tasmota", side_effect=probe),
        patch(f"{security}.async_probe_shelly", side_effect=probe_shelly),
        patch(f"{security}.async_guarded_status", side_effect=shelly_status),
        patch(f"{security}.async_set_password", side_effect=shelly_set),
        patch(f"{tasmota}.TasmotaClient", client_cls),
        patch(f"{tasmota}.BACKUP_RETRY_DELAY", 0),
        patch(f"{tasmota}.async_fetch_latest_release", side_effect=latest_release),
        patch(f"{tasmota}.OTA_POLL_SECONDS", 0),
    ):
        yield net
