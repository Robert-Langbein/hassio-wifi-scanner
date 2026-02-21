"""Coordinator for wifi_presence_scanner."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api_client import BackendClient, BackendClientError
from .const import COORDINATOR_INTERVAL

_LOGGER = logging.getLogger(__name__)


class WifiPresenceCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    def __init__(self, hass: HomeAssistant, client: BackendClient) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="wifi_presence_scanner",
            update_interval=COORDINATOR_INTERVAL,
        )
        self.client = client
        self._last_event_id = 0
        self.rules_cache: list[dict[str, Any]] = []

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            health = await self.client.health()
            events = await self.client.list_events(after_id=self._last_event_id)
            if events:
                self._last_event_id = int(events[-1]["id"])

            for event in events:
                event_type = event.get("event_type")
                payload = event.get("payload", {})
                if not isinstance(payload, dict) or not isinstance(event_type, str):
                    continue
                self.hass.bus.async_fire(event_type, payload)

            rules = await self.client.list_rules()
            items = rules.get("items", [])
            self.rules_cache = items if isinstance(items, list) else []

            return {
                "health": health,
                "events_received": len(events),
                "rules_count": len(self.rules_cache),
            }
        except BackendClientError as err:
            raise UpdateFailed(str(err)) from err

    async def async_force_scan(self) -> dict[str, Any]:
        try:
            result = await self.client.trigger_scan()
            await self.async_request_refresh()
            return result
        except BackendClientError as err:
            raise HomeAssistantError(str(err)) from err

    async def async_purge_history(self) -> dict[str, Any]:
        try:
            result = await self.client.purge_history()
            await self.async_request_refresh()
            return result
        except BackendClientError as err:
            raise HomeAssistantError(str(err)) from err
