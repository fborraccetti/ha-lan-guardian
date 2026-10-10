"""Constants for LAN Guardian."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "lan_guardian"

# Config entry data (set once in the config flow).
CONF_SUBNET: Final = "subnet"
CONF_GATEWAY: Final = "gateway"

# Options: network scan.
CONF_SCAN_INTERVAL: Final = "scan_interval"
CONF_RANDOM_MAC_MODE: Final = "random_mac_mode"
CONF_CRITICAL_OFFLINE_MINUTES: Final = "critical_offline_minutes"
CONF_PING_CONCURRENCY: Final = "ping_concurrency"

# Options: network health.
CONF_HEALTH_INTERVAL: Final = "health_interval"
CONF_INTERNET_TARGET: Final = "internet_target"
CONF_LOSS_THRESHOLD: Final = "loss_threshold"
CONF_DNS_SERVERS: Final = "dns_servers"
CONF_DNS_TEST_DOMAIN: Final = "dns_test_domain"
CONF_ADBLOCK_TEST_DOMAIN: Final = "adblock_test_domain"
CONF_SECURITY_INTERVAL_HOURS: Final = "security_interval_hours"
CONF_SHELLY_WARN_NO_PASSWORD: Final = "shelly_warn_no_password"

# Options: Tasmota.
CONF_TASMOTA_PASSWORD: Final = "tasmota_password"
CONF_TASMOTA_CONCURRENCY: Final = "tasmota_concurrency"
CONF_TASMOTA_SIGNAL_DROP: Final = "tasmota_signal_drop"
CONF_BACKUP_INTERVAL_DAYS: Final = "backup_interval_days"
CONF_BACKUP_RETENTION: Final = "backup_retention"
CONF_TASMOTA_IMPORT_MQTT: Final = "tasmota_import_mqtt"
CONF_TASMOTA_WARN_NO_PASSWORD: Final = "tasmota_warn_no_password"
CONF_TASMOTA_DEVICE_PASSWORDS: Final = "tasmota_device_passwords"

# Options: notifications.
CONF_NOTIFY_PERSISTENT: Final = "notify_persistent"
CONF_NOTIFY_ENTITIES: Final = "notify_entities"
CONF_NOTIFY_SERVICE: Final = "notify_service"
CONF_NOTIFY_COOLDOWN_MINUTES: Final = "notify_cooldown_minutes"

RANDOM_MAC_GROUP: Final = "group"
RANDOM_MAC_IGNORE: Final = "ignore"
RANDOM_MAC_TRACK: Final = "track"
RANDOM_MAC_MODES: Final = [RANDOM_MAC_GROUP, RANDOM_MAC_IGNORE, RANDOM_MAC_TRACK]

DEFAULT_SUBNET: Final = "192.168.1.0/24"
# Largest subnet we agree to sweep: /22 is 1022 hosts.
MIN_PREFIX_LENGTH: Final = 22

DEFAULT_OPTIONS: Final[dict[str, object]] = {
    CONF_SCAN_INTERVAL: 10,
    CONF_RANDOM_MAC_MODE: RANDOM_MAC_GROUP,
    CONF_CRITICAL_OFFLINE_MINUTES: 15,
    CONF_PING_CONCURRENCY: 32,
    CONF_HEALTH_INTERVAL: 2,
    CONF_INTERNET_TARGET: "1.1.1.1",
    CONF_LOSS_THRESHOLD: 20,
    CONF_DNS_SERVERS: [],  # empty: the gateway is checked
    CONF_DNS_TEST_DOMAIN: "www.google.com",
    CONF_ADBLOCK_TEST_DOMAIN: "doubleclick.net",
    CONF_SECURITY_INTERVAL_HOURS: 6,
    CONF_SHELLY_WARN_NO_PASSWORD: True,
    CONF_TASMOTA_PASSWORD: "",
    CONF_TASMOTA_CONCURRENCY: 3,
    CONF_TASMOTA_SIGNAL_DROP: 20,
    CONF_BACKUP_INTERVAL_DAYS: 7,
    CONF_BACKUP_RETENTION: 10,
    CONF_TASMOTA_IMPORT_MQTT: True,
    CONF_TASMOTA_WARN_NO_PASSWORD: True,
    CONF_TASMOTA_DEVICE_PASSWORDS: {},
    CONF_NOTIFY_PERSISTENT: True,
    CONF_NOTIFY_ENTITIES: [],
    CONF_NOTIFY_SERVICE: "",
    CONF_NOTIFY_COOLDOWN_MINUTES: 60,
}
