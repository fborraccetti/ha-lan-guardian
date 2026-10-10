"""Tests for the real Tasmota HTTP client."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from unittest.mock import MagicMock

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import pytest
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.lan_guardian.tasmota.client import (
    TasmotaAuthError,
    TasmotaClient,
    TasmotaConnectionError,
)

from .conftest import load_fixture, make_dump

HOST = "192.168.1.248"
SECRET = "s3cret-Pw!"


def _client(hass: HomeAssistant, password: str | None = SECRET) -> TasmotaClient:
    return TasmotaClient(async_get_clientsession(hass), HOST, password, asyncio.Semaphore(1))


async def test_command_sends_basic_auth(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Credentials go in the Authorization header, never in the URL."""
    aioclient_mock.get(f"http://{HOST}/cm", json=load_fixture("status0_esp8266.json"))
    data = await _client(hass).async_status0()
    assert data["StatusNET"]["Mac"] == "A4:CF:12:00:02:48"

    _method, url, _data, headers = aioclient_mock.mock_calls[0]
    assert url.query == {"cmnd": "Status 0"}
    assert SECRET not in str(url)
    assert headers["Authorization"].startswith("Basic ")
    assert SECRET not in headers["Authorization"]  # base64, not plain text


async def test_command_errors(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    """401 is an auth error; everything else a connection error without the password."""
    aioclient_mock.get(f"http://{HOST}/cm", status=401)
    with pytest.raises(TasmotaAuthError):
        await _client(hass).async_status0()

    for kwargs in (
        {"status": 500},
        {"text": "not json"},
        {"json": ["a", "list"]},
        {"exc": aiohttp.ClientConnectionError()},
        {"exc": TimeoutError()},
    ):
        aioclient_mock.clear_requests()
        aioclient_mock.get(f"http://{HOST}/cm", **kwargs)
        with pytest.raises(TasmotaConnectionError) as err:
            await _client(hass).async_status0()
        assert SECRET not in str(err.value)


async def test_download_config(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    """The dump comes back with Tasmota's suggested file name."""
    dump = make_dump()
    aioclient_mock.get(
        f"http://{HOST}/dl",
        content=dump,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Disposition": "attachment; filename=Config_sensore_gas_14.3.0.dmp",
        },
    )
    data, filename = await _client(hass).async_download_config()
    assert data == dump
    assert filename == "Config_sensore_gas_14.3.0.dmp"


async def test_download_config_errors(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """HTML instead of a dump (WebServer 1, minimal build), 401, empty or huge bodies."""
    url = f"http://{HOST}/dl"
    aioclient_mock.get(url, status=401)
    with pytest.raises(TasmotaAuthError):
        await _client(hass).async_download_config()

    for kwargs in (
        {"text": "<html>Tasmota</html>", "headers": {"Content-Type": "text/html"}},
        {"content": b"", "headers": {"Content-Type": "application/octet-stream"}},
        {"content": b"x" * 300_000, "headers": {"Content-Type": "application/octet-stream"}},
        {"exc": aiohttp.ClientConnectionError()},
    ):
        aioclient_mock.clear_requests()
        aioclient_mock.get(url, **kwargs)
        with pytest.raises(TasmotaConnectionError):
            await _client(hass).async_download_config()


async def test_auth_header_value(hass: HomeAssistant) -> None:
    """The client builds admin:<password> Basic auth, and none without a password."""
    expected = "Basic " + base64.b64encode(f"admin:{SECRET}".encode()).decode()
    assert _client(hass)._headers == {"Authorization": expected}
    assert _client(hass, None)._headers == {}


class _ChunkedContent:
    """Body arriving in TCP-sized pieces, like a real ESP8266."""

    def __init__(self, data: bytes, size: int = 1460) -> None:
        self._chunks = [data[i : i + size] for i in range(0, len(data), size)]

    async def iter_chunked(self, _n: int) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


class _Response:
    def __init__(self, data: bytes, content_length: int | None) -> None:
        self.status = 200
        self.headers = {"Content-Type": "application/octet-stream"}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)
        self.content = _ChunkedContent(data)

    async def __aenter__(self) -> _Response:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


@pytest.mark.parametrize(
    ("body", "content_length", "ok"),
    [
        (make_dump(), 4096, True),  # three segments: must be joined
        (make_dump(), None, True),
        (make_dump()[:1460], 4096, False),  # connection closed early
        (make_dump()[:1460], None, False),  # shorter than a TSettings block
    ],
)
async def test_download_reads_every_segment(
    body: bytes, content_length: int | None, ok: bool
) -> None:
    """Regression: the first real run kept only the first 1460-byte segment."""
    session = MagicMock()
    session.get = MagicMock(return_value=_Response(body, content_length))
    client = TasmotaClient(session, HOST, None, asyncio.Semaphore(1))
    if ok:
        data, _ = await client.async_download_config()
        assert data == body
    else:
        with pytest.raises(TasmotaConnectionError):
            await client.async_download_config()
