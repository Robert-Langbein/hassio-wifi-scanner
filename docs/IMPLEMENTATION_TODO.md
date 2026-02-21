# WiFi Presence Scanner - Detailed To-Do

## Repository and protocol
- [x] Create repository structure for app, integration, agent, docs, blueprints.
- [x] Create shared JSON schemas for network observation, fingerprint rules, and event payload.

## Backend core
- [x] Implement SQLite database layer with migrations, indices, retention purge, event table.
- [x] Implement sessionization engine for discovered/disappeared logic with missed-scan debounce.
- [x] Implement fingerprint rule engine with cooldown and short-repeat heuristics.
- [x] Implement scheduler with scan interval and quiet windows.
- [x] Implement ignore filters, privacy hash mode, and config validation.
- [x] Implement health state and warning event behavior on scan failures.

## Scanner implementations
- [x] Implement Supervisor scanner using Supervisor network accesspoints endpoint.
- [x] Implement Companion scanner using `iw` command parser.
- [x] Add Supervisor payload compatibility for both legacy list and `data.accesspoints[]` response formats.

## API and UI
- [x] Implement REST API endpoints for health, networks, sessions, rules, short-repeat stats, trigger scan.
- [x] Implement backend static UI with search/filter/rule management.
- [x] Implement Home Assistant fallback panel view and API proxy endpoints.
- [x] Add scan-run log endpoints (`/v1/scan-runs`, detail, observations) and integration proxy routes.
- [x] Redesign Ingress + panel fallback UI to a shared HA-native layout with KPI cards, quick actions, and run details drawer.

## Logging and observability
- [x] Add configurable runtime log level (`error|warning|info|debug`) in add-on options.
- [x] Emit structured scan summary lines for completed/skipped/failed runs.
- [x] Keep HTTP access logs disabled by default and enable in debug mode.
- [x] Add supervisor startup preflight diagnostics for `/network/info` and interface permissions.
- [x] Tag scanner 403 failures as `reason=supervisor_forbidden` in logs and health warnings.
- [x] Tag invalid Supervisor accesspoint payload failures as `reason=supervisor_payload_invalid`.
- [x] Fix ingress UI static asset paths to use ingress-safe relative URLs.
- [x] Fix ingress UI API base path resolution so `/v1` calls stay inside ingress context.
- [x] Harden static file MIME mapping for CSS/JS delivery.
- [x] Add frequency-band presentation in networks and observation tables.
- [x] Add collapsible Scan Runs/Health sections with persisted UI state.
- [x] Add Rules guidance panel in UI and switch visual theme to neutral gray full-width layout.

## Home Assistant integration
- [x] Create custom integration domain `wifi_presence_scanner`.
- [x] Implement config flow and options flow.
- [x] Implement coordinator polling backend health/events and firing HA events.
- [x] Implement services: force_scan, reload_rules, purge_history.
- [x] Implement entities:
  - [x] sensor last scan
  - [x] sensor seen networks
  - [x] binary sensor healthy

## Packaging and distribution
- [x] Create supervisor add-on scaffold and run scripts.
- [x] Create companion agent Dockerfile and compose example.
- [x] Provide HACS structure (`custom_components`) and metadata (`hacs.json`).
- [x] Provide blueprint for notification automations.

## Validation and tests
- [ ] Add full E2E test matrix on HA OS / Supervised / Core+Agent.
- [ ] Add load/performance verification for 30s scan interval over long runtime.
- [ ] Add integration tests with real WLAN hardware capture.
- [ ] Conduct final security hardening pass against deployment-specific exposure.
