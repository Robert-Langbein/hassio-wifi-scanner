"""HTTP views for wifi_presence_scanner panel fallback and API proxy."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

from aiohttp.web import Response
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

from .const import DOMAIN


def _pick_coordinator(hass: HomeAssistant):
    domain_data = hass.data.get(DOMAIN, {})
    entries = domain_data.get("entries", {})
    for coordinator in entries.values():
        return coordinator
    return None


class WifiPresencePanelView(HomeAssistantView):
    url = "/api/wifi_presence_scanner/panel"
    name = "api:wifi_presence_scanner:panel"
    requires_auth = True

    async def get(self, request):
        html = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>WiFi Presence Scanner</title>
    <style>
      body { font-family: "IBM Plex Sans", "Segoe UI", sans-serif; margin: 0; padding: 1rem; background: #f4f6f5; color: #123; }
      .shell { display: grid; gap: 1rem; }
      .panel { background: #fff; border: 1px solid #ccd9d3; border-radius: 12px; padding: 1rem; }
      .grid { display: grid; gap: .6rem; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
      input, select, button { padding: .5rem .6rem; border-radius: 8px; border: 1px solid #ccd9d3; }
      button { background: #0a6f4f; color: #fff; border: 0; cursor: pointer; }
      table { width: 100%; border-collapse: collapse; font-size: .9rem; }
      th, td { border-bottom: 1px solid #e2ece8; text-align: left; padding: .45rem; }
      pre { margin: 0; white-space: pre-wrap; }
    </style>
  </head>
  <body>
    <main class="shell">
      <section class="panel">
        <h2>Search</h2>
        <div class="grid">
          <input id="query" placeholder="SSID/BSSID/Vendor" />
          <select id="shortRepeat"><option value="false">No short repeat</option><option value="true">Short repeat only</option></select>
          <input id="limit" type="number" value="100" min="1" max="1000" />
          <button id="refresh">Refresh</button>
        </div>
      </section>
      <section class="panel"><h2>Health</h2><pre id="health"></pre></section>
      <section class="panel"><h2>Networks</h2><table><thead><tr><th>Visible</th><th>SSID</th><th>BSSID</th><th>Seen</th><th>RSSI</th><th>Last</th></tr></thead><tbody id="rows"></tbody></table></section>
    </main>
    <script>
      const query = document.getElementById('query');
      const shortRepeat = document.getElementById('shortRepeat');
      const limit = document.getElementById('limit');
      const refresh = document.getElementById('refresh');
      const health = document.getElementById('health');
      const rows = document.getElementById('rows');

      async function api(path, init) {
        const res = await fetch(path, init);
        if (!res.ok) throw new Error(await res.text());
        return await res.json();
      }

      async function load() {
        const search = new URLSearchParams({ query: query.value, short_repeat: shortRepeat.value, limit: limit.value });
        const [h, n] = await Promise.all([
          api('/api/wifi_presence_scanner/health'),
          api('/api/wifi_presence_scanner/networks?' + search.toString())
        ]);
        health.textContent = JSON.stringify(h, null, 2);
        rows.innerHTML = '';
        for (const item of n.items || []) {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${item.currently_visible ? 'yes' : 'no'}</td><td>${item.ssid || ''}</td><td>${item.bssid}</td><td>${item.seen_count}</td><td>${item.strongest_rssi}</td><td>${item.last_seen}</td>`;
          rows.appendChild(tr);
        }
      }

      refresh.addEventListener('click', () => load().catch((e) => (health.textContent = e.message)));
      load().catch((e) => (health.textContent = e.message));
    </script>
  </body>
</html>
        """
        return Response(text=html, content_type="text/html")


class WifiPresenceProxyView(HomeAssistantView):
    requires_auth = True

    async def _proxy(self, request, *, method: str, suffix: str, payload: dict[str, Any] | None = None):
        coordinator = _pick_coordinator(request.app["hass"])
        if coordinator is None:
            return self.json({"error": "integration_not_loaded"}, status_code=HTTPStatus.SERVICE_UNAVAILABLE)

        client = coordinator.client
        try:
            if method == "GET" and suffix == "health":
                data = await client.health()
            elif method == "GET" and suffix == "networks":
                params = {k: v for k, v in request.query.items()}
                data = await client.list_networks(params=params)
            elif method == "GET" and suffix.startswith("networks/") and suffix.endswith("/sessions"):
                bssid = suffix.removeprefix("networks/").removesuffix("/sessions")
                data = await client.network_sessions(bssid=bssid)
            elif method == "GET" and suffix == "rules":
                data = await client.list_rules()
            elif method == "POST" and suffix == "rules":
                data = await client.create_rule(payload=payload or {})
            elif method == "PATCH" and suffix.startswith("rules/"):
                rule_id = int(suffix.removeprefix("rules/"))
                data = await client.patch_rule(rule_id=rule_id, payload=payload or {})
            elif method == "DELETE" and suffix.startswith("rules/"):
                rule_id = int(suffix.removeprefix("rules/"))
                data = await client.delete_rule(rule_id=rule_id)
            elif method == "POST" and suffix == "scan/trigger":
                data = await client.trigger_scan()
            elif method == "GET" and suffix == "stats/short-repeat":
                params = {k: v for k, v in request.query.items()}
                data = await client.short_repeat_stats(params=params)
            elif method == "POST" and suffix == "history/purge":
                data = await client.purge_history()
            else:
                return self.json({"error": "not_found"}, status_code=HTTPStatus.NOT_FOUND)
        except Exception as err:
            return self.json({"error": str(err)}, status_code=HTTPStatus.BAD_GATEWAY)

        return self.json(data)


class WifiPresenceProxyRootView(WifiPresenceProxyView):
    url = "/api/wifi_presence_scanner/{suffix:.*}"
    name = "api:wifi_presence_scanner:proxy"

    async def get(self, request, suffix: str):
        return await self._proxy(request, method="GET", suffix=suffix)

    async def post(self, request, suffix: str):
        payload = await request.json() if request.can_read_body else {}
        return await self._proxy(request, method="POST", suffix=suffix, payload=payload)

    async def patch(self, request, suffix: str):
        payload = await request.json() if request.can_read_body else {}
        return await self._proxy(request, method="PATCH", suffix=suffix, payload=payload)

    async def delete(self, request, suffix: str):
        return await self._proxy(request, method="DELETE", suffix=suffix)


def async_register_views(hass: HomeAssistant) -> None:
    hass.http.register_view(WifiPresencePanelView)
    hass.http.register_view(WifiPresenceProxyRootView)
