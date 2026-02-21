# Installation Guide

## Option A: Home Assistant OS / Supervised

1. Add this repository as add-on repository in Home Assistant.
2. Install add-on `WiFi Presence Scanner`.
3. Configure add-on options:
   - `wifi_interface` (default `wlan0`)
   - `scan_interval_sec` (default `30`)
   - `quiet_windows_json` (JSON array, one window per weekday)
4. Start add-on.
5. Install custom integration (`custom_components/wifi_presence_scanner`) via HACS or manual copy.
6. Add integration from UI and choose mode `auto`.

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
