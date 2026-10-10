# LAN Guardian

[![Validate](https://github.com/fborraccetti/ha-lan-guardian/actions/workflows/validate.yml/badge.svg)](https://github.com/fborraccetti/ha-lan-guardian/actions/workflows/validate.yml)
[![Tests](https://github.com/fborraccetti/ha-lan-guardian/actions/workflows/tests.yml/badge.svg)](https://github.com/fborraccetti/ha-lan-guardian/actions/workflows/tests.yml)
[![HACS Custom](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://hacs.xyz/)

A Home Assistant custom integration that watches your home network and manages your
[Tasmota](https://tasmota.github.io/) devices. Everything runs locally: no cloud, no add-on,
no agent on other machines.

- **Device inventory**: every host on the LAN, with vendor, hostname, first/last seen.
- **Intruder alerts**: a repair issue and a notification for every unknown MAC address.
- **Network health**: gateway and Internet packet loss and latency, DNS servers, ad-blocker check.
- **Tasmota manager**: Wi-Fi signal, restarts, configuration backups, firmware updates and
  WebPassword management.

UI and notifications are available in English and Italian.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Entities](#entities)
- [Actions](#actions)
- [Repairs and notifications](#repairs-and-notifications)
- [Privacy and security](#privacy-and-security)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Features

### Network inventory

- Periodic ping sweep of the configured IPv4 subnet (up to /22), plus the kernel ARP table.
- Names from mDNS (Zeroconf) and reverse DNS; vendors from the offline IEEE OUI database.
- Randomized MAC addresses (phones, tablets) can be grouped in one entry, ignored or tracked
  one by one.
- Every known device gets its own Home Assistant device with category, status and a
  *critical* switch: a critical device that stays offline too long raises an issue.
- Detects a MAC address answering on several IPs and a change of the gateway MAC address
  (possible ARP spoofing).

### Network health

- Packet loss, average and maximum latency towards the gateway and an Internet target.
- Resolution time and availability of each DNS server; an issue when the primary DNS stops
  answering.
- Optional ad-blocker check (Pi-hole, AdGuard Home…): a known ad domain must not resolve to a
  real address.

### Tasmota

- Finds Tasmota devices on the LAN over HTTP and, optionally, imports those already known to
  the official Tasmota (MQTT) integration.
- Sensors per device: Wi-Fi signal and RSSI, last restart and its reason, restarts in 24 hours,
  last backup.
- Alerts for a Wi-Fi signal drop compared with the 24-hour average and for frequent restarts.
- **Backups**: scheduled and on-demand download of the configuration (`.dmp`), stored in
  `<config>/lan_guardian/backups/`. Identical backups are not rewritten; old ones are rotated.
- **Firmware updates**: an `update` entity per device compares the installed version with the
  latest Tasmota release on GitHub, shows the release notes and installs the right build from
  `ota.tasmota.com` (backup first, if you ask for it).
- **WebPassword**: flags devices that accept commands without a password, sets a global (or
  per-device) password on them, and can generate a strong one for you.

## Requirements

- Home Assistant **2026.9** or later.
- Home Assistant must be on the same LAN (layer 2) as the devices it watches, so it can read
  their MAC addresses.
  - **Home Assistant OS / Supervised**: works out of the box.
  - **Container (Docker)**: run with `network_mode: host`. For the fastest ping sweep also add
    `cap_add: [NET_RAW]`; without it the integration falls back to unprivileged ICMP, which
    needs `net.ipv4.ping_group_range` to include the container user.
  - **Core (venv)**: same as Container; the Python process must be able to open ICMP sockets.
- Tasmota features need the devices' web server enabled (`Webserver 2`, the default).

## Installation

### Option A: HACS (recommended)

1. Make sure [HACS](https://hacs.xyz/docs/use/download/download/) is installed.
2. In Home Assistant open **HACS**, then the **⋮** menu in the top right corner and choose
   **Custom repositories**.
3. Paste `https://github.com/fborraccetti/ha-lan-guardian`, pick the type **Integration** and click
   **Add**.
4. Search for **LAN Guardian** in HACS, open it and click **Download**.
5. Restart Home Assistant: **Settings → System → ⏻ (top right) → Restart Home Assistant**.

### Option B: manual

1. Download the latest release from the
   [Releases page](https://github.com/fborraccetti/ha-lan-guardian/releases) (or clone the repository).
2. Copy the folder `custom_components/lan_guardian` into the `custom_components` folder of your
   Home Assistant configuration directory (the one containing `configuration.yaml`). Create
   `custom_components` if it does not exist. The result must be:

   ```text
   <config>/custom_components/lan_guardian/manifest.json
   ```

   You can do this with the *Samba share*, *File editor*, *Studio Code Server* or *SSH* add-ons.
3. Restart Home Assistant.

### Add the integration

1. Go to **Settings → Devices & services** and click **+ Add integration**.
2. Search for **LAN Guardian**. (If it does not appear, clear the browser cache or reload the
   page: the restart above is required.)
3. Enter:
   - **Subnet (CIDR)**: the network to watch, for example `192.168.1.0/24`. Pre-filled from
     Home Assistant's network settings. Only IPv4 subnets up to /22 are supported.
   - **Gateway**: the IP address of your router, used for latency and packet loss checks.
4. Click **Submit**. The first scan starts right away: every device found in the first scan is
   considered *known*; from then on each new MAC address raises an alert.

Only one LAN Guardian entry can be configured.

## Configuration

All settings are in **Settings → Devices & services → LAN Guardian → Configure**. The options
are grouped in a menu; each section is saved on its own and the integration reloads.

### Network scan

| Option | Default | Description |
| --- | --- | --- |
| Scan interval | 10 min | How often the subnet is swept. |
| Randomized MAC addresses | Group | `Group` in one entry, `Ignore` or `Track` each one. |
| Critical device offline after | 15 min | Grace time before a critical device raises an issue. |
| Parallel pings | 32 | Lower it on slow hardware. |

### Network health

| Option | Default | Description |
| --- | --- | --- |
| Check interval | 2 min | |
| Internet target | `1.1.1.1` | Host pinged to measure Internet loss and latency. |
| Packet loss alarm threshold | 20 % | |
| DNS servers | *(empty)* | The first is the primary DNS. If empty, the gateway is checked. |
| Domain to resolve | `www.google.com` | Used to time the DNS servers. |
| Ad domain that must be blocked | `doubleclick.net` | Leave empty if you have no ad-blocking DNS. |
| Tasmota security check every | 6 h | Looks for Tasmota devices without WebPassword. |

### Tasmota

| Option | Default | Description |
| --- | --- | --- |
| Global WebPassword | *(empty)* | Used to talk to protected devices (user `admin`) and set on unprotected ones. 8–32 characters, no spaces or `;`. Never logged nor shown again. |
| Generate a random password | off | Creates a strong password and shows it **once**: copy it before confirming. |
| Parallel requests to Tasmota | 3 | |
| Signal drop alarm | 20 % | Percentage points lost against the 24-hour average that raise an alert. |
| Backup every | 7 days | |
| Backups kept per device | 10 | |
| Import Tasmota from the MQTT integration | on | |
| Warn about Tasmota without WebPassword | on | |

**Password of a single Tasmota**: overrides the global password for one device. Leave it empty
to go back to the global one.

### Notifications

Repair issues are always created. In addition you can choose:

| Option | Default | Description |
| --- | --- | --- |
| Persistent notifications | on | Shown in the Home Assistant sidebar. |
| Notification entities | *(none)* | Any `notify` entity (e.g. a Telegram bot), via `notify.send_message`. |
| Notification action | *(none)* | Optional legacy action, e.g. `notify.mobile_app_my_phone`. |
| Minimum pause per event type | 60 min | Avoids repeated notifications for the same event. |

## Entities

**LAN Guardian hub device**

| Entity | Type |
| --- | --- |
| Online devices, Unknown devices | sensor |
| Gateway / Internet packet loss, latency, max latency | sensor |
| DNS resolution time *(per server)* | sensor |
| DNS *(per server)*, Internet, Ad blocking active | binary sensor |
| Tasmota without password | sensor |

**Each network device**

| Entity | Type |
| --- | --- |
| IP address, Hostname, Vendor, First seen, Last seen | sensor |
| Category (network, server, computer, phone, media, camera, Tasmota, IoT, other) | select |
| Status (known, ignored, new) | select |
| Critical | switch |
| Forget device | button |

**Each Tasmota device** (in addition to the above)

| Entity | Type |
| --- | --- |
| Wi-Fi signal, Wi-Fi RSSI, Last restart, Last restart reason, Restarts in 24 hours, Last backup | sensor |
| Back up now, Apply WebPassword | button |
| Firmware | update |

## Actions

| Action | Fields | Description |
| --- | --- | --- |
| `lan_guardian.scan_now` | – | Starts a network scan immediately. |
| `lan_guardian.update_device` | `mac`, `name`, `category`, `critical`, `status` | Edits an inventory entry. |
| `lan_guardian.forget_device` | `mac` | Removes a device; if it comes back it is new again. |
| `lan_guardian.backup_tasmota` | `device_id` *(optional)* | Backs up the chosen Tasmota devices (all if none). |
| `lan_guardian.apply_tasmota_password` | `device_id` *(optional)* | Sets the stored WebPassword on the chosen devices (all if none). The password is never an action parameter. |

Example: name a device and mark it as known.

```yaml
action: lan_guardian.update_device
data:
  mac: "aa:bb:cc:dd:ee:ff"
  name: "Living room speaker"
  category: media
  critical: false
  status: known
```

## Repairs and notifications

Alerts appear in **Settings → System → Repairs** and, if enabled, as notifications. Some can be
fixed directly from the repair dialog (for example: approve a new device with a name and a
category, or set the WebPassword).

- New device on the network
- Critical device offline
- MAC address on several IP addresses
- Gateway MAC address changed
- Primary DNS not answering
- Packet loss towards the gateway
- Ad blocker not blocking
- Tasmota devices without WebPassword
- Tasmota Wi-Fi signal dropped
- Tasmota restarting often
- Tasmota password rejected

## Privacy and security

- All traffic stays on your LAN. The only Internet requests are the ping/DNS health checks
  towards the targets you configure and, for firmware updates, the GitHub releases API and
  `ota.tasmota.com`.
- Tasmota passwords are stored in the config entry options (like any other integration's
  credentials), are never written to logs and never passed as action data.
- Tasmota only supports plain HTTP with Basic authentication: anyone on your LAN can sniff it.
  Keep IoT devices on a trusted network or VLAN.

## Troubleshooting

- **No devices found / no MAC addresses**: Home Assistant is not on the same layer-2 network
  (e.g. Docker without `network_mode: host`, or a different VLAN).
- **Very slow scan**: ICMP is unprivileged; see [Requirements](#requirements).
- **A Tasmota device keeps saying "password rejected"**: set its password under
  *Configure → Password of a single Tasmota*.

Debug logging:

```yaml
logger:
  logs:
    custom_components.lan_guardian: debug
```

Please attach debug logs when opening an
[issue](https://github.com/fborraccetti/ha-lan-guardian/issues).

## Development

Requires Python 3.14 and [uv](https://docs.astral.sh/uv/).

```bash
uv venv -p 3.14 .venv
uv pip install -p .venv -r requirements_test.txt
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy
docker run --rm -v "$PWD":/github/workspace ghcr.io/home-assistant/hassfest
```

Notes on the Home Assistant and Tasmota APIs used are in [docs/research.md](docs/research.md).

## License

[MIT](LICENSE)
