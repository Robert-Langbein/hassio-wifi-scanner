# Installation Guide

## Option A: Home Assistant OS / Supervised

1. Add this repository as add-on repository in Home Assistant.
2. Install add-on `WiFi Presence Scanner`.
3. Configure add-on options:
   - `wifi_interface` (default `wlan0`)
   - `log_level` (`error|warning|info|debug`, default `info`)
   - `scan_interval_sec` (default `30`)
   - `quiet_windows_json` (JSON array, one window per weekday)
4. Start add-on.
5. If update does not appear, use "Reload" on the add-on repository and then upgrade the add-on.
6. Install custom integration (`custom_components/wifi_presence_scanner`) via HACS or manual copy.
7. Add integration from UI and choose mode `auto`.

## Option B: Home Assistant Core / Container

1. Deploy companion agent container from `agent/wifi_presence_scanner_agent`.
2. Ensure Linux capabilities (`NET_ADMIN`, `NET_RAW`) and host/local network access.
3. Set `API_KEY` and bind to `127.0.0.1` if possible.
4. Install custom integration.
5. In integration config choose mode `agent` and set backend URL/API key.

## Quiet window JSON example

```json
[
  {"weekday": "monday", "start": "09:00", "end": "17:00"},
  {"weekday": "tuesday", "start": "09:00", "end": "17:00"}
]
```

## Ignore list examples

- `ignore_ssid_patterns`: `^MyHome$,^Printer-`
- `ignore_bssid_prefixes`: `AA:BB:CC,11:22:33`

## Add-on log output

The add-on prints structured scan lines in Supervisor logs. Example:

`ts=2026-02-21T17:10:00+0000 level=INFO logger=wifi_presence_scanner.scan event=scan_completed run_id=154 interface=wlan0 seen=19 new=2 disappeared=1 rules=1 duration_ms=463 status=ok trigger=scheduled`

## Troubleshooting Supervisor 403

If scan logs show `Supervisor API error 403`:

1. Ensure add-on version is `1.0.4` or newer (`hassio_role: manager`).
2. Reload add-on repository and upgrade to newest version.
3. Restart the add-on after upgrade.
4. Verify `wifi_interface` points to a valid WiFi interface (for example `wlan0`).

Startup logs include preflight checks for `/network/info` and `/network/interface/<iface>/info` plus an accesspoint role note for `/network/interface/<iface>/accesspoints`.

If scans are visible in logs but Ingress UI still shows `404`, update to `1.0.4` or newer.
