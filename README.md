# WiFi Presence Scanner

WiFi presence tracking solution for Home Assistant with support for:

- HA OS / Supervised via Supervisor add-on (`app/supervisor_wifi_presence_scanner`)
- HA Core / Container via companion agent (`agent/wifi_presence_scanner_agent`)
- Home Assistant custom integration (`custom_components/wifi_presence_scanner`)

## Core features

- Configurable scan interval (default: 30 seconds)
- One quiet scan window per weekday
- SQLite persistence with automatic retention cleanup (default: 30 days)
- Search/filter list of scanned WiFi networks
- Short-repeating network filter for courier-like patterns
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
2. Start add-on.
3. Install integration from `custom_components/wifi_presence_scanner` (or via HACS from this repo).
4. In integration config flow choose mode `auto` (default).

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
- `POST /v1/scan/trigger`
- `GET /v1/stats/short-repeat`
- `POST /v1/history/purge`
- `GET /v1/events`

## Security notes

- Set `API_KEY` for agent mode.
- Prefer `HTTP_HOST=127.0.0.1` for local-only exposure.
- Use private networks/VPN if remote connectivity is needed.
- Optional privacy mode hashes BSSID values before storage.

## Blueprint

Import `blueprints/automation/wifi_presence_scanner_notify.yaml` to create mobile notification automations from scanner events.
