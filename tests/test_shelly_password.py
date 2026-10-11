"""Tests for setting the global password on Shelly devices."""

from __future__ import annotations

import base64
from collections.abc import AsyncGenerator
import hashlib
import secrets

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer
from homeassistant.components import persistent_notification
from homeassistant.components.repairs import repairs_flow_manager
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import entity_registry as er, issue_registry as ir
from homeassistant.setup import async_setup_component
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_capture_events

from custom_components.lan_guardian.const import CONF_TASMOTA_PASSWORD, DOMAIN
from custom_components.lan_guardian.notifier import EVENT_NAME
from custom_components.lan_guardian.shelly import auth
from custom_components.lan_guardian.shelly.auth import ShellyError
from custom_components.lan_guardian.shelly.probe import ShellyProbe
from custom_components.lan_guardian.tasmota.probe import WebAuth

from .conftest import FakeNetwork

PASSWORD = "Example-Pass-2026"
DEVICE_ID = "shellyplus1-a0a3b3000051"
OPEN_IP = "192.168.1.50"
OPEN_MAC = "a0:a3:b3:00:00:50"
GEN1_IP = "192.168.1.52"
GEN1_MAC = "a4:cf:12:00:00:52"
OTHER_IP = "192.168.1.51"
OTHER_MAC = "a0:a3:b3:00:00:51"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class FakeShelly:
    """Just enough of a Shelly's HTTP API: Gen1 Basic, Gen2+ Digest SHA-256."""

    def __init__(self, gen: int) -> None:
        self.gen = gen
        self.password: str | None = None  # Gen1
        self.ha1: str | None = None  # Gen2+
        self.nonce = secrets.token_hex(8)
        app = web.Application()
        app.router.add_get("/settings", self.settings)
        app.router.add_get("/settings/login", self.login)
        app.router.add_get("/rpc/Sys.GetConfig", self.get_config)
        app.router.add_post("/rpc", self.rpc)
        self.app = app

    async def settings(self, request: web.Request) -> web.Response:
        if self.password is not None:
            expected = base64.b64encode(f"admin:{self.password}".encode()).decode()
            if request.headers.get("Authorization") != f"Basic {expected}":
                return web.Response(status=401)
        return web.json_response({"device": {}})

    async def login(self, request: web.Request) -> web.Response:
        if self.password is not None:
            return web.Response(status=401)
        assert request.query["enabled"] == "1"
        assert request.query["username"] == "admin"
        self.password = request.query["password"]
        return web.json_response({"enabled": True, "username": "admin"})

    def _digest_ok(self, request: web.Request) -> bool:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Digest "):
            return False
        fields = dict(part.strip().split("=", 1) for part in header[len("Digest ") :].split(","))
        fields = {k: v.strip('"') for k, v in fields.items()}
        ha2 = _sha256(f"{request.method}:{fields['uri']}")
        expected = _sha256(
            f"{self.ha1}:{fields['nonce']}:{fields['nc']}:{fields['cnonce']}:{fields['qop']}:{ha2}"
        )
        return fields["realm"] == DEVICE_ID and fields["response"] == expected

    async def get_config(self, request: web.Request) -> web.Response:
        if self.ha1 is not None and not self._digest_ok(request):
            challenge = (
                f'Digest qop="auth", realm="{DEVICE_ID}", nonce="{self.nonce}", algorithm=SHA-256'
            )
            return web.Response(status=401, headers={"WWW-Authenticate": challenge})
        return web.json_response({"device": {}})

    async def rpc(self, request: web.Request) -> web.Response:
        if self.ha1 is not None:
            return web.Response(status=401)
        body = await request.json()
        assert body["method"] == "Shelly.SetAuth"
        params = body["params"]
        assert (params["user"], params["realm"]) == ("admin", DEVICE_ID)
        self.ha1 = params["ha1"]
        return web.json_response({"id": 1, "result": None})


@pytest.fixture
async def http_session(socket_enabled: None) -> AsyncGenerator[aiohttp.ClientSession]:
    """A real client session (the tests talk to a local server)."""
    async with aiohttp.ClientSession() as session:
        yield session


async def _serve(shelly: FakeShelly) -> TestServer:
    server = TestServer(shelly.app, host="127.0.0.1")
    await server.start_server()
    return server


@pytest.mark.parametrize("gen", [1, 2])
async def test_client_sets_and_checks_password(
    http_session: aiohttp.ClientSession, gen: int
) -> None:
    """Open device: set the password, then only the right credentials get in."""
    shelly = FakeShelly(gen)
    server = await _serve(shelly)
    host = f"127.0.0.1:{server.port}"
    try:
        assert await auth.async_guarded_status(http_session, host, gen, None) == 200
        await auth.async_set_password(http_session, host, gen, DEVICE_ID, PASSWORD)
        if gen == 1:
            assert shelly.password == PASSWORD
        else:
            # Gen2+ only receives the hash, never the password.
            assert shelly.ha1 == _sha256(f"admin:{DEVICE_ID}:{PASSWORD}")
        assert await auth.async_guarded_status(http_session, host, gen, None) == 401
        assert await auth.async_guarded_status(http_session, host, gen, "wrong-pass") == 401
        assert await auth.async_guarded_status(http_session, host, gen, PASSWORD) == 200
        # A protected device refuses a new password without credentials.
        with pytest.raises(ShellyError):
            await auth.async_set_password(http_session, host, gen, DEVICE_ID, "another-one")
    finally:
        await server.close()


async def test_client_errors(http_session: aiohttp.ClientSession) -> None:
    """Unreachable devices and a Gen2 without id raise ShellyError."""
    with pytest.raises(ShellyError):
        await auth.async_guarded_status(http_session, "127.0.0.1:9", 2, None, timeout=1)
    with pytest.raises(ShellyError, match="device id"):
        await auth.async_set_password(http_session, "127.0.0.1:9", 2, None, PASSWORD)


# -- integration ---------------------------------------------------------------------


def _add_shelly(net: FakeNetwork, ip: str, mac: str, gen: int = 2) -> None:
    net.arp[ip] = mac
    net.shelly[ip] = ShellyProbe(
        ip=ip,
        auth=WebAuth.OPEN,
        gen=gen,
        model="SNSW-001X16EU",
        device_id=DEVICE_ID if gen >= 2 else None,
    )


async def _setup(hass: HomeAssistant, entry: MockConfigEntry, password: str | None) -> None:
    await async_setup_component(hass, "repairs", {})
    entry.add_to_hass(hass)
    if password:
        hass.config_entries.async_update_entry(entry, options={CONF_TASMOTA_PASSWORD: password})
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)


async def test_apply_to_all(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    fake_network: FakeNetwork,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Open Shelly devices get the password; others are reported; the secret stays hidden."""
    caplog.set_level("DEBUG")
    _add_shelly(fake_network, OPEN_IP, OPEN_MAC)
    _add_shelly(fake_network, GEN1_IP, GEN1_MAC, gen=1)
    _add_shelly(fake_network, OTHER_IP, OTHER_MAC)
    fake_network.shelly_passwords[OTHER_IP] = "someone-elses"
    await _setup(hass, config_entry, PASSWORD)
    events = async_capture_events(hass, EVENT_NAME)
    assert ir.async_get(hass).async_get_issue(DOMAIN, "shelly_no_password") is not None

    await hass.services.async_call(DOMAIN, "apply_shelly_password", {}, blocking=True)
    await hass.async_block_till_done(wait_background_tasks=True)

    assert fake_network.shelly_passwords[OPEN_IP] == PASSWORD
    assert fake_network.shelly_passwords[GEN1_IP] == PASSWORD
    assert fake_network.shelly_passwords[OTHER_IP] == "someone-elses"
    [applied] = [e.data for e in events if e.data["type"] == "shelly_password_applied"]
    assert len(applied["applied"].split(", ")) == 2
    assert applied["other"] != "-"
    assert ir.async_get(hass).async_get_issue(DOMAIN, "shelly_no_password") is None
    state = hass.states.get("sensor.lan_guardian_shelly_without_password")
    assert state is not None
    assert state.state == "0"
    # The Tasmota devices are left alone.
    assert "192.168.1.248" not in fake_network.tasmota_passwords

    notifications = persistent_notification._async_get_or_create_notifications(hass)
    visible = " ".join([caplog.text, repr([e.data for e in events]), repr(notifications)])
    assert PASSWORD not in visible

    # Second run: everything already done, nothing re-sent.
    fake_network.shelly_calls.clear()
    await hass.services.async_call(DOMAIN, "apply_shelly_password", {}, blocking=True)
    assert not any(what == "set" for _ip, what in fake_network.shelly_calls)


async def test_offline_and_unverified(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """A device that stays open raises; an offline one is reported, not failed."""
    _add_shelly(fake_network, OPEN_IP, OPEN_MAC)
    _add_shelly(fake_network, OTHER_IP, OTHER_MAC)
    await _setup(hass, config_entry, PASSWORD)
    events = async_capture_events(hass, EVENT_NAME)
    fake_network.shelly_ignore_password.add(OPEN_IP)
    del fake_network.shelly[OTHER_IP]
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(DOMAIN, "apply_shelly_password", {}, blocking=True)
    [applied] = [e.data for e in events if e.data["type"] == "shelly_password_applied"]
    assert applied["failed"] != "-"
    assert applied["offline"] != "-"
    assert applied["applied"] == "-"


async def test_button_targets_one_device(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """The button on the device page secures that Shelly only."""
    _add_shelly(fake_network, OPEN_IP, OPEN_MAC)
    _add_shelly(fake_network, GEN1_IP, GEN1_MAC, gen=1)
    await _setup(hass, config_entry, PASSWORD)
    entity_id = er.async_get(hass).async_get_entity_id(
        "button", DOMAIN, f"{OPEN_MAC}_shelly_apply_password"
    )
    assert entity_id is not None
    await hass.services.async_call("button", "press", {"entity_id": entity_id}, blocking=True)
    assert fake_network.shelly_passwords == {OPEN_IP: PASSWORD}


async def test_no_stored_password(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """Without a stored password the action refuses and the repair aborts."""
    _add_shelly(fake_network, OPEN_IP, OPEN_MAC)
    await _setup(hass, config_entry, None)
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(DOMAIN, "apply_shelly_password", {}, blocking=True)
    manager = repairs_flow_manager(hass)
    assert manager is not None
    result = await manager.async_init(DOMAIN, data={"issue_id": "shelly_no_password"})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_password"
    assert not fake_network.shelly_passwords


async def test_not_a_shelly(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """The action refuses devices that are not known Shelly devices."""
    _add_shelly(fake_network, OPEN_IP, OPEN_MAC)
    await _setup(hass, config_entry, PASSWORD)
    tasmota_button = er.async_get(hass).async_get_entity_id(
        "button", DOMAIN, "a4:cf:12:00:02:48_tasmota_apply_password"
    )
    assert tasmota_button is not None
    entity = er.async_get(hass).async_get(tasmota_button)
    assert entity is not None
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(
            DOMAIN, "apply_shelly_password", {"device_id": entity.device_id}, blocking=True
        )
    assert not fake_network.shelly_passwords


async def test_repair_flow_applies(
    hass: HomeAssistant, config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """The issue's fix flow lists the open devices and applies the password on confirm."""
    _add_shelly(fake_network, OPEN_IP, OPEN_MAC)
    await _setup(hass, config_entry, PASSWORD)
    manager = repairs_flow_manager(hass)
    assert manager is not None
    result = await manager.async_init(DOMAIN, data={"issue_id": "shelly_no_password"})
    assert result["step_id"] == "confirm"
    assert result["description_placeholders"]["count"] == "1"
    result = await manager.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done(wait_background_tasks=True)
    assert fake_network.shelly_passwords[OPEN_IP] == PASSWORD
    assert ir.async_get(hass).async_get_issue(DOMAIN, "shelly_no_password") is None
