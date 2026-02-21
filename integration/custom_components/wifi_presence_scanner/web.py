"""HTTP views for wifi_presence_scanner panel fallback and API proxy."""

from __future__ import annotations

import mimetypes
from http import HTTPStatus
from pathlib import Path
from typing import Any

from aiohttp.web import Response
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

from .const import DOMAIN

FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"


def _pick_coordinator(hass: HomeAssistant):
    domain_data = hass.data.get(DOMAIN, {})
    entries = domain_data.get("entries", {})
    for coordinator in entries.values():
        return coordinator
    return None


def _serve_frontend_file(path: Path) -> Response:
    mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
    return Response(body=path.read_bytes(), content_type=mime)


class WifiPresencePanelView(HomeAssistantView):
    url = "/api/wifi_presence_scanner/panel"
    name = "api:wifi_presence_scanner:panel"
    requires_auth = True

    async def get(self, request):
        index_path = FRONTEND_DIR / "index.html"
        if not index_path.is_file():
            return Response(status=HTTPStatus.NOT_FOUND, text="panel assets not found")
        return _serve_frontend_file(index_path)


class WifiPresenceAssetView(HomeAssistantView):
    url = "/api/wifi_presence_scanner/assets/{filename:.*}"
    name = "api:wifi_presence_scanner:asset"
    requires_auth = True

    async def get(self, request, filename: str):
        candidate = (FRONTEND_DIR / filename).resolve()
        try:
            candidate.relative_to(FRONTEND_DIR.resolve())
        except ValueError:
            return Response(status=HTTPStatus.FORBIDDEN, text="forbidden")

        if not candidate.is_file():
            return Response(status=HTTPStatus.NOT_FOUND, text="not_found")
        return _serve_frontend_file(candidate)


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
            elif method == "GET" and suffix == "scan-runs":
                params = {k: v for k, v in request.query.items()}
                data = await client.scan_runs(params=params)
            elif method == "GET" and suffix.startswith("scan-runs/") and suffix.endswith("/observations"):
                scan_run_id = int(suffix.removeprefix("scan-runs/").removesuffix("/observations"))
                params = {k: v for k, v in request.query.items()}
                data = await client.scan_run_observations(scan_run_id=scan_run_id, params=params)
            elif method == "GET" and suffix.startswith("scan-runs/"):
                scan_run_id = int(suffix.removeprefix("scan-runs/"))
                data = await client.scan_run_detail(scan_run_id=scan_run_id)
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
    hass.http.register_view(WifiPresenceAssetView)
    hass.http.register_view(WifiPresenceProxyRootView)
