"""Tests for the Tasmota HTTP probe and the DNS check."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from aiodns.error import DNSError
import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import pycares
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.lan_guardian.net import dns
from custom_components.lan_guardian.tasmota.probe import WebAuth, async_probe_tasmota

URL = "http://192.168.1.248/cm"


async def test_probe_open(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    """200 with a Status object: Tasmota without password."""
    aioclient_mock.get(URL, json={"Status": {"Module": 1, "DeviceName": "sensore_gas"}})
    result = await async_probe_tasmota(async_get_clientsession(hass), "192.168.1.248")
    assert result is not None
    assert result.auth is WebAuth.OPEN
    assert result.status == {"Status": {"Module": 1, "DeviceName": "sensore_gas"}}
    assert aioclient_mock.mock_calls[0][1].query == {"cmnd": "Status"}


async def test_probe_protected(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    """401 with Tasmota's warning: protected."""
    aioclient_mock.get(
        URL, status=401, text='{"WARNING":"Need user=<username>&password=<password>"}'
    )
    result = await async_probe_tasmota(async_get_clientsession(hass), "192.168.1.248")
    assert result is not None
    assert result.auth is WebAuth.PROTECTED


async def test_probe_not_tasmota(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    """Other web servers, garbage, and network errors are not Tasmota."""
    session = async_get_clientsession(hass)
    aioclient_mock.get(URL, status=401, text="Unauthorized")
    assert await async_probe_tasmota(session, "192.168.1.248") is None

    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, text="<html>camera</html>")
    assert await async_probe_tasmota(session, "192.168.1.248") is None

    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, json={"other": 1})
    assert await async_probe_tasmota(session, "192.168.1.248") is None

    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, status=404)
    assert await async_probe_tasmota(session, "192.168.1.248") is None

    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, exc=aiohttp.ClientConnectionError())
    assert await async_probe_tasmota(session, "192.168.1.248") is None

    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, exc=TimeoutError())
    assert await async_probe_tasmota(session, "192.168.1.248") is None


def _resolver(result: object = None, error: DNSError | None = None) -> AsyncMock:
    resolver = AsyncMock()
    if error is not None:
        resolver.query_dns.side_effect = error
    else:
        resolver.query_dns.return_value = result
    return resolver


async def test_resolve_answer_and_block_detection() -> None:
    """A records are collected; 0.0.0.0 and empty answers mean blocked."""
    answer = SimpleNamespace(
        answer=[
            SimpleNamespace(data=pycares.CNAMERecordData(cname="x.example")),
            SimpleNamespace(data=pycares.ARecordData(addr="142.250.180.68")),
        ]
    )
    with patch.object(dns.aiodns, "DNSResolver", return_value=_resolver(answer)):
        check = await dns.async_resolve("192.168.1.9", "www.google.com")
    assert check.ok
    assert check.addresses == ("142.250.180.68",)
    assert dns.is_blocked(check) is False
    assert dns.is_blocked(dns.DnsCheck("s", True, 1.0, ("0.0.0.0",))) is True
    assert dns.is_blocked(dns.DnsCheck("s", True, 1.0, ())) is True
    assert dns.is_blocked(dns.DnsCheck("s", False, None)) is None


async def test_resolve_errors() -> None:
    """NXDOMAIN is an answer (blocked); a timeout is a failure."""
    nx = DNSError(pycares.errno.ARES_ENOTFOUND, "Domain name not found")
    with patch.object(dns.aiodns, "DNSResolver", return_value=_resolver(error=nx)):
        check = await dns.async_resolve("192.168.1.9", "doubleclick.net")
    assert check.ok
    assert dns.is_blocked(check) is True

    timeout = DNSError(pycares.errno.ARES_ETIMEOUT, "Timeout while contacting DNS servers")
    with patch.object(dns.aiodns, "DNSResolver", return_value=_resolver(error=timeout)):
        check = await dns.async_resolve("192.168.1.9", "www.google.com")
    assert not check.ok
    assert check.error == "Timeout while contacting DNS servers"
