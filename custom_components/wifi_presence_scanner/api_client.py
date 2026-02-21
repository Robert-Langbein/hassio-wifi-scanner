"""Async backend client for wifi_presence_scanner."""

from __future__ import annotations

import asyncio
from typing import Any

from aiohttp import ClientError, ClientSession


class BackendClientError(Exception):
    """Raised when backend requests fail."""


class BackendClient:
    def __init__(
        self,
        *,
        session: ClientSession,
        base_url: str,
        api_key: str | None,
    ) -> None:
        self._session = session
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key

    @property
    def base_url(self) -> str:
        return self._base_url

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        return headers

    async def _request(
        self,
        *,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        try:
            async with self._session.request(
                method,
                url,
                headers=self._headers(),
                params=params,
                json=json_payload,
                timeout=15,
            ) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    raise BackendClientError(f"Backend HTTP {resp.status}: {body}")
                payload = await resp.json(content_type=None)
        except BackendClientError:
            raise
        except (ClientError, asyncio.TimeoutError) as err:
            raise BackendClientError(f"Backend request failed: {err}") from err
        except ValueError as err:
            raise BackendClientError(f"Backend response parse failed: {err}") from err

        if not isinstance(payload, dict):
            raise BackendClientError("Backend response is not an object")
        return payload

    async def health(self) -> dict[str, Any]:
        return await self._request(method="GET", path="/v1/health")

    async def list_events(self, *, after_id: int, limit: int = 200) -> list[dict[str, Any]]:
        payload = await self._request(
            method="GET",
            path="/v1/events",
            params={"after_id": after_id, "limit": limit},
        )
        items = payload.get("items", [])
        if not isinstance(items, list):
            raise BackendClientError("Backend events payload invalid")
        return items

    async def list_networks(self, *, params: dict[str, Any]) -> dict[str, Any]:
        return await self._request(method="GET", path="/v1/networks", params=params)

    async def network_sessions(self, *, bssid: str) -> dict[str, Any]:
        return await self._request(method="GET", path=f"/v1/networks/{bssid}/sessions")

    async def novel_networks(self, *, params: dict[str, Any]) -> dict[str, Any]:
        return await self._request(method="GET", path="/v1/novel-networks", params=params)

    async def clear_novel_network(self, *, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request(method="POST", path="/v1/novel-networks/clear", json_payload=payload)

    async def scan_runs(self, *, params: dict[str, Any]) -> dict[str, Any]:
        return await self._request(method="GET", path="/v1/scan-runs", params=params)

    async def scan_run_detail(self, *, scan_run_id: int) -> dict[str, Any]:
        return await self._request(method="GET", path=f"/v1/scan-runs/{scan_run_id}")

    async def scan_run_observations(
        self,
        *,
        scan_run_id: int,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        return await self._request(
            method="GET",
            path=f"/v1/scan-runs/{scan_run_id}/observations",
            params=params,
        )

    async def list_rules(self) -> dict[str, Any]:
        return await self._request(method="GET", path="/v1/rules")

    async def create_rule(self, *, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request(method="POST", path="/v1/rules", json_payload=payload)

    async def patch_rule(self, *, rule_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request(method="PATCH", path=f"/v1/rules/{rule_id}", json_payload=payload)

    async def delete_rule(self, *, rule_id: int) -> dict[str, Any]:
        return await self._request(method="DELETE", path=f"/v1/rules/{rule_id}")

    async def trigger_scan(self) -> dict[str, Any]:
        return await self._request(method="POST", path="/v1/scan/trigger")

    async def short_repeat_stats(self, *, params: dict[str, Any]) -> dict[str, Any]:
        return await self._request(method="GET", path="/v1/stats/short-repeat", params=params)

    async def purge_history(self) -> dict[str, Any]:
        return await self._request(method="POST", path="/v1/history/purge")
