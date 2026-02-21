# WiFi Presence Scanner Add-on

This add-on continuously scans nearby WiFi access points using the Supervisor network endpoint,
stores observations in SQLite, provides an Ingress UI, and emits events for automations.

## Home Assistant events

- `wifi_presence_scanner_wifi_discovered`
- `wifi_presence_scanner_wifi_disappeared`
- `wifi_presence_scanner_rule_matched`
- `wifi_presence_scanner_health_warning`

## Notes

- One WiFi interface is supported (`wifi_interface`), default `wlan0`.
- Single-interface setups are allowed, but scan stability may improve with a dedicated USB adapter.
- Scan logs are visible in add-on logs. Control verbosity with `log_level` (`error|warning|info|debug`).
