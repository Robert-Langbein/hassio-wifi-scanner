# WiFi Presence Scanner

WiFi presence tracking solution for Home Assistant with support for:

- HA OS / Supervised via Supervisor add-on (`app/supervisor_wifi_presence_scanner`)
- HA Core / Container via companion agent (`agent/wifi_presence_scanner_agent`)
- Home Assistant custom integration (`custom_components/wifi_presence_scanner`)

## Core features

- Configurable scan interval (default: 30 seconds)
- One quiet scan window per weekday
- SQLite persistence with automatic retention cleanup (default: 30 days)
- Structured scan logs in add-on/agent runtime (`log_level`: `error|warning|info|debug`)
- Search/filter list of scanned WiFi networks
- Frequency-band visibility (`2.4/5/6 GHz`) in network and observation tables
- Networks table shows `Max RSSI` (highest observed value in the selected history window)
- Short-repeating network filter for courier-like patterns
- Scan run history with detail drilldown (runs + observations)
- Collapsible `Scan Runs` and `Health JSON` sections with per-browser state persistence
- Rules help panel (`Show help`) with examples for regex/prefix/RSSI/cooldown
- Home Assistant events:
  - `wifi_presence_scanner_wifi_discovered`
  - `wifi_presence_scanner_wifi_disappeared`
  - `wifi_presence_scanner_rule_matched`
  - `wifi_presence_scanner_health_warning`
- Rule engine with regex/prefix/RSSI/repeat constraints and cooldown
- Whitelist/ignore patterns
- Optional BSSID hashing (privacy mode)

## Repository layout

- `src/wifi_presence_backend`: shared backend runtime, DB, scanner engine, REST API
- `app/supervisor_wifi_presence_scanner`: Home Assistant Supervisor add-on
- `agent/wifi_presence_scanner_agent`: companion Docker agent
- `custom_components/wifi_presence_scanner`: HACS-ready custom integration
- `blueprints/automation/wifi_presence_scanner_notify.yaml`: notification blueprint
- `schemas/`: shared JSON schemas

## Quick start

### 1. HA OS / Supervised

1. Build/install add-on from `app/supervisor_wifi_presence_scanner`.
2. If you update from HACS/add-on repository, reload the add-on repository in Home Assistant so the new add-on version is detected.
3. Start add-on.
4. Install integration from `custom_components/wifi_presence_scanner` (or via HACS from this repo).
5. In integration config flow choose mode `auto` (default).

### 2. HA Core / Container

1. Deploy agent from `agent/wifi_presence_scanner_agent` with `API_KEY` and WiFi capabilities.
2. Install integration.
3. In integration config flow choose mode `agent` and set backend URL/API key.

## REST API (App/Agent)

- `GET /v1/health`
- `GET /v1/networks`
- `GET /v1/networks/{bssid}/sessions`
- `GET /v1/rules`
- `POST /v1/rules`
- `PATCH /v1/rules/{id}`
- `DELETE /v1/rules/{id}`
- `GET /v1/scan-runs`
- `GET /v1/scan-runs/{id}`
- `GET /v1/scan-runs/{id}/observations`
- `POST /v1/scan/trigger`
- `GET /v1/stats/short-repeat`
- `POST /v1/history/purge`
- `GET /v1/events`

## Security notes

- Set `API_KEY` for agent mode.
- Prefer `HTTP_HOST=127.0.0.1` for local-only exposure.
- Use private networks/VPN if remote connectivity is needed.
- Optional privacy mode hashes BSSID values before storage.

## Troubleshooting

### Supervisor 403 on scans

If logs contain `Supervisor API error 403`, verify:

1. Add-on is updated to at least `1.0.6` (`hassio_role: manager`).
2. Add-on repository has been reloaded in Home Assistant before update.
3. Add-on was restarted after update.
4. Configured `wifi_interface` exists on host (for example `wlan0`).

At startup, the backend logs supervisor preflight checks for `/network/info` and `/network/interface/<iface>/info`, including a role requirement note for `/network/interface/<iface>/accesspoints`.

If Ingress UI shows `404` in health/network sections while scan logs are successful, update to `1.0.6` or newer.

## Blueprint

Import `blueprints/automation/wifi_presence_scanner_notify.yaml` to create mobile notification automations from scanner events.

## Use Rules In Automations

After creating a rule, use Home Assistant automations with an `Event` trigger:

1. Create a new automation.
2. Add trigger type `Event`.
3. Set event type to `wifi_presence_scanner_rule_matched` (rule-based trigger).
4. Optionally add event-data filters, for example:
   - `rule_name: DHL van nearby`
   - `rule_id: 1`
5. Add your action (mobile notification, light, script, etc.).

Other useful event types:

- `wifi_presence_scanner_wifi_discovered`
- `wifi_presence_scanner_wifi_disappeared`
- `wifi_presence_scanner_health_warning`

Example automation (YAML):

```yaml
alias: Notify on DHL WiFi rule
trigger:
  - platform: event
    event_type: wifi_presence_scanner_rule_matched
    event_data:
      rule_name: DHL van nearby
action:
  - service: notify.mobile_app_your_phone
    data:
      title: Paketdienst erkannt
      message: >-
        SSID={{ trigger.event.data.ssid }},
        BSSID={{ trigger.event.data.bssid }},
        RSSI={{ trigger.event.data.rssi }}
mode: queued
```
