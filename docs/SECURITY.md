# Security Notes

## Threat model

- Scanner data can reveal nearby devices and behavioral patterns.
- Agent endpoint may expose sensitive WiFi metadata if reachable by untrusted clients.

## Controls implemented

- Companion agent requires `API_KEY` at startup.
- Integration proxy endpoints require Home Assistant authenticated session.
- Optional privacy mode stores BSSID hash (`sha256(salt:bssid)`) in addition to raw logic paths.
- Input validation for scan intervals, retention, regex patterns, and rule payload.
- Static file serving prevents directory traversal.

## Deployment recommendations

- Keep agent host binding on loopback (`127.0.0.1`) whenever possible.
- If remote access is required, restrict with firewall/VPN and strong API key.
- Rotate API keys and privacy salt periodically.
- Exclude scanner DB from public backups.
- Use dedicated WiFi adapter for better scan stability and less impact on main connection.
