# Note di ricerca (verificate il 2026-10-09)

Riferimento: Home Assistant core tag `2026.9.4`, Tasmota branch `development`.

## Home Assistant 2026.9

- Python richiesto: `>=3.14.2`. Test: `pytest-homeassistant-custom-component==0.13.367` (= HA 2026.9.4).
- **HA OS / Supervisor**: il container core gira `privileged=True`, `network_mode=host`, come root
  (`supervisor/docker/homeassistant.py`). Quindi ICMP privilegiato funziona e `/proc/net/arp`
  mostra la tabella ARP dell'host. Nell'immagine c'è `net-tools` (`arp`), `nmap`; non `iproute2`.
  Nessun add-on companion necessario.
- **icmplib** `3.0.4` (pin dell'integrazione `ping`). La rilevazione privilegi è privata
  (`_can_use_icmp_lib_with_privilege` in `components/ping/__init__.py`): va replicata
  (`async_ping("127.0.0.1", count=0, timeout=0, privileged=True/False)`, cattura `SocketPermissionError`).
- **aiooui** (offline, mmap in executor): `await aiooui.async_load()`, `aiooui.get_vendor(mac)`.
  Core lo usa in `nmap_tracker` (`aiooui==0.1.9`), non è in package_constraints.
- **aiodns** `4.0.4` è dipendenza diretta del core.
- **UpdateEntity**: `UpdateEntityFeature.INSTALL|PROGRESS|BACKUP|RELEASE_NOTES`; impostare
  `_attr_in_progress: bool` e `_attr_update_percentage` separati (int in `in_progress` deprecato).
  `async_install(version, backup, **kwargs)`, `async_release_notes() -> str | None`,
  `release_summary` max 255 caratteri.
- **Repairs**: `ir.async_create_issue(..., data=dict piatto di scalari, is_fixable, severity,
  translation_key, translation_placeholders)`. Piattaforma `repairs.py` con
  `async_create_fix_flow(hass, issue_id, data) -> RepairsFlow`; multi-step con `async_step_<x>`;
  stringhe in `issues.<key>.fix_flow.step.<step>`.
- **Coordinator**: passare `config_entry=` esplicito; `_async_setup()`; `always_update=False` se i
  dati supportano `__eq__`. `type XConfigEntry = ConfigEntry[XData]` per `runtime_data`.
- **Options flow**: `OptionsFlowWithReload` (reload automatico, niente update listener);
  `async_get_options_flow` ritorna l'istanza senza passare `config_entry`.
- CI: `home-assistant/actions/hassfest@master`, `hacs/action@main` con `category: integration`.

## Tasmota

- **Backup**: `GET /dl` → `application/octet-stream`, `Content-Disposition: attachment;
  filename=Config_<host>_<ver>.dmp`; 4096 byte (ESP32 con UFILESYS può essere più grande, file
  `.drvset` accodati). Assente in `tasmota-minimal`.
  Auth **solo HTTP Basic** `admin:<WebPassword>` (niente `?user=&password=` su `/dl`).
  **Non inviare header Referer** (o deve contenere host/IP del dispositivo).
- **`/cm?cmnd=`**: Basic auth oppure `user=admin&password=`. Senza credenziali con password
  impostata: 401 + `{"WARNING":"Need user=<username>&password=<password>"}`.
- **Status 0** sezioni: `Status, StatusPRM, StatusFWR, StatusLOG, StatusMEM, StatusNET, StatusMQT,
  StatusTIM, StatusSNS, StatusSTS`. `StatusPRM.RestartReason`, `StatusPRM.OtaUrl`,
  `StatusFWR.Version` = `"14.3.0(release-tasmota)"` → regex
  `^(\d+\.\d+\.\d+)\((?:release-)?([^)]+)\)`. `StatusFWR.Hardware` = `ESP8266EX` / `ESP32-D0WD-V3 v3.1` / `ESP32-C3 ...`.
  `StatusMEM` in KB (`ProgramSize`, `Free`, `FlashSize`...). `StatusSTS.Wifi.{RSSI,Signal,LinkCount,Downtime}`.
- **OTA**: `OtaUrl <url>` (max 100 caratteri), poi `Upgrade 1`.
  - ESP8266: `http://ota.tasmota.com/tasmota/release/<variant>.bin.gz` (es. `tasmota`,
    `tasmota-sensors`, `tasmota-4M`, `tasmota-lite`, `tasmota-IT`). Spazio insufficiente: Tasmota
    passa da solo a `<name>-minimal.bin.gz` e poi ri-scarica il completo dalla stessa OtaUrl
    (automatico, due riavvii). Solo http su ESP8266.
  - ESP32: `http://ota.tasmota.com/tasmota32/release/<variant>.bin` (`tasmota32`, `tasmota32c3`,
    `tasmota32s3`, `tasmota32solo1`). Con safeboot: due riavvii.
  - Completamento: polling `Status 2` finché risponde con versione nuova; attendere fino a 5 min.
- **GitHub**: `GET /repos/arendst/Tasmota/releases/latest`, `tag_name` `vX.Y.Z`, `body` markdown
  (~10 KB), limite 60 req/h non autenticato. Ultima al 2026-10-09: `v15.6.0`.
- **WebPassword**: usare `WebPassword2 <pw>` (risposta mascherata); `0`/`1` non ammessi come
  password; max 32 caratteri; utente sempre `admin`.
- **Test "senza password"**: `/cm?cmnd=Status` senza credenziali → 200 = nessuna password,
  401 = protetto (più robusto di `/`).

## Shelly

- **`GET /shelly`**: mai protetto, su tutte le generazioni.
  - Gen1: `{"type":"SHSW-1","mac":...,"auth":bool,"fw":...}`.
  - Gen2+: `{"id":...,"mac":...,"model":...,"gen":2|3|4,"ver":...,"app":...,"auth_en":bool,"auth_domain":...}`.
- **Verifica reale**: Gen1 `GET /settings` (HTTP Basic), Gen2+ `GET /rpc/Sys.GetConfig` (Digest
  SHA-256, utente `admin`, realm = id del dispositivo) → 200 = aperto, 401 = protetto.
- Password: Gen1 `/settings/login?enabled=1&username=&password=`; Gen2+ `Shelly.SetAuth` con
  `ha1 = sha256("admin:<id>:<password>")`. Non usate: LAN Guardian solo segnala, perché
  impostare la password richiede di aggiornare le credenziali nell'integrazione Shelly di HA.
