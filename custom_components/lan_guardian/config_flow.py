"""Config and options flow for LAN Guardian."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
import re
from typing import Any

from homeassistant.components import network
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import selector
import voluptuous as vol

from . import merged_options
from .const import (
    CONF_ADBLOCK_TEST_DOMAIN,
    CONF_BACKUP_INTERVAL_DAYS,
    CONF_BACKUP_RETENTION,
    CONF_CRITICAL_OFFLINE_MINUTES,
    CONF_DNS_SERVERS,
    CONF_DNS_TEST_DOMAIN,
    CONF_GATEWAY,
    CONF_HEALTH_INTERVAL,
    CONF_INTERNET_TARGET,
    CONF_LOSS_THRESHOLD,
    CONF_NOTIFY_COOLDOWN_MINUTES,
    CONF_NOTIFY_ENTITIES,
    CONF_NOTIFY_PERSISTENT,
    CONF_NOTIFY_SERVICE,
    CONF_PING_CONCURRENCY,
    CONF_RANDOM_MAC_MODE,
    CONF_SCAN_INTERVAL,
    CONF_SECURITY_INTERVAL_HOURS,
    CONF_SUBNET,
    CONF_TASMOTA_CONCURRENCY,
    CONF_TASMOTA_DEVICE_PASSWORDS,
    CONF_TASMOTA_IMPORT_MQTT,
    CONF_TASMOTA_PASSWORD,
    CONF_TASMOTA_SIGNAL_DROP,
    CONF_TASMOTA_WARN_NO_PASSWORD,
    DEFAULT_SUBNET,
    DOMAIN,
    MIN_PREFIX_LENGTH,
    RANDOM_MAC_MODES,
)
from .tasmota.password import generate_password, password_problem

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
CONF_GENERATE_PASSWORD = "generate_password"
_SERVICE_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")


def _number(minimum: int, maximum: int, unit: str | None = None) -> selector.NumberSelector:
    config = selector.NumberSelectorConfig(
        min=minimum, max=maximum, step=1, mode=selector.NumberSelectorMode.BOX
    )
    if unit is not None:
        config["unit_of_measurement"] = unit
    return selector.NumberSelector(config)


def _is_host(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return bool(_HOSTNAME_RE.match(value))
    return True


def validate_network(subnet: str, gateway: str) -> tuple[dict[str, str], str | None]:
    """Validate subnet and gateway; return errors and the normalized subnet."""
    errors: dict[str, str] = {}
    try:
        net = ip_network(subnet.strip(), strict=False)
    except ValueError:
        return {CONF_SUBNET: "invalid_subnet"}, None
    if not isinstance(net, IPv4Network):
        return {CONF_SUBNET: "invalid_subnet"}, None
    if net.prefixlen < MIN_PREFIX_LENGTH:
        return {CONF_SUBNET: "subnet_too_large"}, None
    try:
        gw = ip_address(gateway.strip())
    except ValueError:
        errors[CONF_GATEWAY] = "invalid_ip"
    else:
        if gw not in net:
            errors[CONF_GATEWAY] = "gateway_outside_subnet"
    return errors, str(net)


async def _async_default_subnet(hass: HomeAssistant) -> str:
    """Guess the LAN subnet from the network integration."""
    for adapter in await network.async_get_adapters(hass):
        if not adapter["enabled"]:
            continue
        for addr in adapter["ipv4"]:
            net = ip_network(f"{addr['address']}/{addr['network_prefix']}", strict=False)
            if not net.is_loopback and net.prefixlen >= MIN_PREFIX_LENGTH:
                return str(net)
    return DEFAULT_SUBNET


def _tasmota_choices(entry: ConfigEntry) -> list[tuple[str, str]]:
    """(mac, label) of the Tasmota devices known to the running integration."""
    data = getattr(entry, "runtime_data", None)
    if data is None:
        return []
    return sorted(
        ((mac, f"{dev.name} ({dev.ip or mac})") for mac, dev in data.tasmota.devices.items()),
        key=lambda item: item[1].lower(),
    )


class LanGuardianConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the initial setup."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Ask for subnet and gateway."""
        errors: dict[str, str] = {}
        if user_input is not None:
            errors, subnet = validate_network(user_input[CONF_SUBNET], user_input[CONF_GATEWAY])
            if not errors and subnet is not None:
                return self.async_create_entry(
                    title=f"LAN Guardian ({subnet})",
                    data={
                        CONF_SUBNET: subnet,
                        CONF_GATEWAY: user_input[CONF_GATEWAY].strip(),
                    },
                )
            default_subnet = user_input[CONF_SUBNET]
            default_gateway = user_input[CONF_GATEWAY]
        else:
            default_subnet = await _async_default_subnet(self.hass)
            net = ip_network(default_subnet)
            default_gateway = str(next(net.hosts(), IPv4Address("192.168.1.1")))

        schema = vol.Schema(
            {
                vol.Required(CONF_SUBNET, default=default_subnet): str,
                vol.Required(CONF_GATEWAY, default=default_gateway): str,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> LanGuardianOptionsFlow:
        """Return the options flow."""
        return LanGuardianOptionsFlow()


class LanGuardianOptionsFlow(OptionsFlowWithReload):
    """Options are grouped in a menu; each step saves its own section."""

    _pending: dict[str, Any]

    def _save(self, user_input: dict[str, Any]) -> ConfigFlowResult:
        # NumberSelector returns floats; every numeric option here is an integer.
        cleaned = {
            key: int(value) if isinstance(value, float) else value
            for key, value in user_input.items()
        }
        return self.async_create_entry(data={**merged_options(self.config_entry), **cleaned})

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Show the options menu."""
        return self.async_show_menu(
            step_id="init",
            menu_options=["scan", "health", "tasmota", "tasmota_device", "notify"],
        )

    async def async_step_scan(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Network scan options."""
        if user_input is not None:
            return self._save(user_input)
        opts = merged_options(self.config_entry)
        schema = vol.Schema(
            {
                vol.Required(CONF_SCAN_INTERVAL, default=opts[CONF_SCAN_INTERVAL]): _number(
                    1, 1440, "min"
                ),
                vol.Required(
                    CONF_RANDOM_MAC_MODE, default=opts[CONF_RANDOM_MAC_MODE]
                ): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=RANDOM_MAC_MODES, translation_key=CONF_RANDOM_MAC_MODE
                    )
                ),
                vol.Required(
                    CONF_CRITICAL_OFFLINE_MINUTES,
                    default=opts[CONF_CRITICAL_OFFLINE_MINUTES],
                ): _number(1, 1440, "min"),
                vol.Required(CONF_PING_CONCURRENCY, default=opts[CONF_PING_CONCURRENCY]): _number(
                    1, 256
                ),
            }
        )
        return self.async_show_form(step_id="scan", data_schema=schema)

    async def async_step_health(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Network health options."""
        errors: dict[str, str] = {}
        opts = merged_options(self.config_entry)
        if user_input is not None:
            if not _is_host(user_input[CONF_INTERNET_TARGET].strip()):
                errors[CONF_INTERNET_TARGET] = "invalid_host"
            servers = [s.strip() for s in user_input[CONF_DNS_SERVERS] if s.strip()]
            for server in servers:
                try:
                    ip_address(server)
                except ValueError:
                    errors[CONF_DNS_SERVERS] = "invalid_ip"
                    break
            if not servers:
                errors[CONF_DNS_SERVERS] = "invalid_ip"
            for key in (CONF_DNS_TEST_DOMAIN, CONF_ADBLOCK_TEST_DOMAIN):
                value = user_input.get(key, "").strip()
                if value and not _HOSTNAME_RE.match(value):
                    errors[key] = "invalid_host"
            if not errors:
                user_input[CONF_DNS_SERVERS] = servers
                return self._save(user_input)
            opts = {**opts, **user_input}

        schema = vol.Schema(
            {
                vol.Required(CONF_HEALTH_INTERVAL, default=opts[CONF_HEALTH_INTERVAL]): _number(
                    1, 60, "min"
                ),
                vol.Required(CONF_INTERNET_TARGET, default=opts[CONF_INTERNET_TARGET]): str,
                vol.Required(CONF_LOSS_THRESHOLD, default=opts[CONF_LOSS_THRESHOLD]): _number(
                    1, 100, "%"
                ),
                vol.Required(
                    CONF_DNS_SERVERS, default=opts[CONF_DNS_SERVERS]
                ): selector.TextSelector(selector.TextSelectorConfig(multiple=True)),
                vol.Required(CONF_DNS_TEST_DOMAIN, default=opts[CONF_DNS_TEST_DOMAIN]): str,
                vol.Optional(
                    CONF_ADBLOCK_TEST_DOMAIN,
                    description={"suggested_value": opts[CONF_ADBLOCK_TEST_DOMAIN]},
                ): str,
                vol.Required(
                    CONF_SECURITY_INTERVAL_HOURS, default=opts[CONF_SECURITY_INTERVAL_HOURS]
                ): _number(1, 168, "h"),
            }
        )
        return self.async_show_form(step_id="health", data_schema=schema, errors=errors)

    async def async_step_tasmota(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Tasmota options."""
        opts = merged_options(self.config_entry)
        errors: dict[str, str] = {}
        if user_input is not None:
            generate = user_input.pop(CONF_GENERATE_PASSWORD, False)
            password = user_input.get(CONF_TASMOTA_PASSWORD, "")
            if generate:
                self._pending = {**user_input, CONF_TASMOTA_PASSWORD: generate_password()}
                return await self.async_step_tasmota_password_generated()
            if not password:
                # An empty field keeps the stored password: the form never shows it back.
                user_input[CONF_TASMOTA_PASSWORD] = opts[CONF_TASMOTA_PASSWORD]
                return self._save(user_input)
            if problem := password_problem(password):
                errors[CONF_TASMOTA_PASSWORD] = problem
            else:
                return self._save(user_input)
        schema = vol.Schema(
            {
                vol.Optional(CONF_TASMOTA_PASSWORD): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                ),
                vol.Optional(CONF_GENERATE_PASSWORD, default=False): bool,
                vol.Required(
                    CONF_TASMOTA_CONCURRENCY, default=opts[CONF_TASMOTA_CONCURRENCY]
                ): _number(1, 10),
                vol.Required(
                    CONF_TASMOTA_SIGNAL_DROP, default=opts[CONF_TASMOTA_SIGNAL_DROP]
                ): _number(5, 100, "%"),
                vol.Required(
                    CONF_BACKUP_INTERVAL_DAYS, default=opts[CONF_BACKUP_INTERVAL_DAYS]
                ): _number(1, 90, "d"),
                vol.Required(CONF_BACKUP_RETENTION, default=opts[CONF_BACKUP_RETENTION]): _number(
                    1, 100
                ),
                vol.Required(
                    CONF_TASMOTA_IMPORT_MQTT, default=opts[CONF_TASMOTA_IMPORT_MQTT]
                ): bool,
                vol.Required(
                    CONF_TASMOTA_WARN_NO_PASSWORD, default=opts[CONF_TASMOTA_WARN_NO_PASSWORD]
                ): bool,
            }
        )
        return self.async_show_form(step_id="tasmota", data_schema=schema, errors=errors)

    async def async_step_tasmota_password_generated(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show the generated password once; saved when the user confirms."""
        if user_input is not None:
            return self._save(self._pending)
        return self.async_show_form(
            step_id="tasmota_password_generated",
            data_schema=vol.Schema({}),
            description_placeholders={"password": self._pending[CONF_TASMOTA_PASSWORD]},
        )

    async def async_step_tasmota_device(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Set or clear the WebPassword of a single Tasmota device."""
        opts = merged_options(self.config_entry)
        passwords: dict[str, str] = dict(opts[CONF_TASMOTA_DEVICE_PASSWORDS])
        if user_input is not None:
            mac = user_input["device"]
            password = user_input.get(CONF_TASMOTA_PASSWORD)
            if password and (problem := password_problem(password)):
                errors = {CONF_TASMOTA_PASSWORD: problem}
            else:
                if password:
                    passwords[mac] = password
                else:
                    passwords.pop(mac, None)
                return self._save({CONF_TASMOTA_DEVICE_PASSWORDS: passwords})

        else:
            errors = {}
        devices = _tasmota_choices(self.config_entry)
        if not devices:
            return self.async_abort(reason="no_tasmota")
        schema = vol.Schema(
            {
                vol.Required("device"): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=[
                            selector.SelectOptionDict(
                                value=mac,
                                label=f"{label}{' 🔑' if mac in passwords else ''}",
                            )
                            for mac, label in devices
                        ],
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                ),
                vol.Optional(CONF_TASMOTA_PASSWORD): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                ),
            }
        )
        return self.async_show_form(step_id="tasmota_device", data_schema=schema, errors=errors)

    async def async_step_notify(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Notification options."""
        errors: dict[str, str] = {}
        opts = merged_options(self.config_entry)
        if user_input is not None:
            service = user_input.get(CONF_NOTIFY_SERVICE, "").strip()
            if service and not _SERVICE_RE.match(service):
                errors[CONF_NOTIFY_SERVICE] = "invalid_service"
            else:
                user_input[CONF_NOTIFY_SERVICE] = service
                user_input.setdefault(CONF_NOTIFY_ENTITIES, [])
                return self._save(user_input)
            opts = {**opts, **user_input}
        schema = vol.Schema(
            {
                vol.Required(CONF_NOTIFY_PERSISTENT, default=opts[CONF_NOTIFY_PERSISTENT]): bool,
                vol.Optional(
                    CONF_NOTIFY_ENTITIES, default=opts[CONF_NOTIFY_ENTITIES]
                ): selector.EntitySelector(
                    selector.EntitySelectorConfig(domain="notify", multiple=True)
                ),
                vol.Optional(
                    CONF_NOTIFY_SERVICE,
                    description={"suggested_value": opts[CONF_NOTIFY_SERVICE]},
                ): str,
                vol.Required(
                    CONF_NOTIFY_COOLDOWN_MINUTES,
                    default=opts[CONF_NOTIFY_COOLDOWN_MINUTES],
                ): _number(0, 10080, "min"),
            }
        )
        return self.async_show_form(step_id="notify", data_schema=schema, errors=errors)
