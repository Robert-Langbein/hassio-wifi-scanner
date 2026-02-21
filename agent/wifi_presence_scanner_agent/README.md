# WiFi Presence Scanner Companion Agent

Companion scanner service for Home Assistant Core/Container installations.

## Security defaults

- Set `API_KEY` and only expose the service to trusted local networks.
- Keep `HTTP_HOST=127.0.0.1` if integration runs on same host.

## Required Linux capabilities

WiFi scans usually require privileged networking access to execute `iw` scans.

## Minimal docker run

```bash
docker run -d \
  --name wifi-presence-agent \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -e API_KEY='change-me' \
  -e WIFI_INTERFACE='wlan0' \
  -e SCAN_INTERVAL_SEC='30' \
  -v wifi_presence_data:/var/lib/wifi_presence_scanner \
  ghcr.io/Robert-Langbein/wifi-presence-scanner-agent:1.0.0
```
