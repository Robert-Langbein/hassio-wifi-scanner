# Backend API

Base URL depends on deployment mode:

- Add-on: `http://<addon-host>:8099`
- Agent: `http://<agent-host>:8100`

If `API_KEY` is configured, provide `X-API-Key` header.

## Endpoints

### `GET /v1/health`
Returns scanner health and latest scan metadata.

### `GET /v1/networks`
Query params:

- `query`
- `from`
- `to`
- `rule`
- `short_repeat`
- `limit`
- `offset`

### `GET /v1/networks/{bssid}/sessions`
Returns tracked presence sessions for one BSSID.

### `GET /v1/novel-networks`
Query params:

- `window_hours` (1..168, default `24`)
- `query`
- `limit`
- `offset`

Returns one-time network candidates: BSSIDs with only one session inside the configured time window after first sighting.

### `POST /v1/novel-networks/clear`
Payload options:

- `{ "bssid": "AA:BB:CC:DD:EE:FF" }` clears one entry.
- `{ "clear_all": true, "window_hours": 24, "query": "" }` clears the currently matching set.

### `GET /v1/scan-runs`
Query params:

- `status` (`ok|error|running`)
- `from` (ISO datetime)
- `to` (ISO datetime)
- `limit`
- `offset`

Returns scan run summaries including `seen_total`, `new_count`, `disappeared_count`, and `rule_matches`.

### `GET /v1/scan-runs/{id}`
Returns one scan run with timing and counters.

### `GET /v1/scan-runs/{id}/observations`
Query params:

- `limit`
- `offset`

Returns observations captured in one scan run.

### `GET /v1/rules`
List fingerprint rules.

### `POST /v1/rules`
Create a fingerprint rule.

### `PATCH /v1/rules/{id}`
Update a fingerprint rule.

### `DELETE /v1/rules/{id}`
Delete a fingerprint rule.

### `POST /v1/scan/trigger`
Trigger immediate scan.

### `GET /v1/stats/short-repeat`
Short-repeat analytics.

### `POST /v1/history/purge`
Run immediate retention purge.

### `GET /v1/events`
Query params:

- `after_id`
- `limit`

Returns emitted scanner events for integration polling.
