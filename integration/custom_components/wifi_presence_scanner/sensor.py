"""Sensors for wifi_presence_scanner."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import WifiPresenceCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: WifiPresenceCoordinator = hass.data[DOMAIN]["entries"][entry.entry_id]
    async_add_entities(
        [
            WifiPresenceLastScanSensor(coordinator, entry),
            WifiPresenceSeenNetworksSensor(coordinator, entry),
        ]
    )


class BaseWifiPresenceSensor(CoordinatorEntity[WifiPresenceCoordinator], SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: WifiPresenceCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry = entry

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "WiFi Presence Scanner",
            "manufacturer": "Custom",
            "model": "wifi_presence_scanner",
        }


class WifiPresenceLastScanSensor(BaseWifiPresenceSensor):
    _attr_name = "Last Scan"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_last_scan"

    @property
    def native_value(self) -> str | None:
        health = self.coordinator.data.get("health", {})
        return health.get("last_scan_finished_at")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        health = self.coordinator.data.get("health", {})
        return {
            "last_scan_started_at": health.get("last_scan_started_at"),
            "last_error": health.get("last_error"),
            "backend_url": self.coordinator.client.base_url,
        }


class WifiPresenceSeenNetworksSensor(BaseWifiPresenceSensor):
    _attr_name = "Seen Networks"
    _attr_native_unit_of_measurement = "networks"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_seen_networks"

    @property
    def native_value(self) -> int:
        health = self.coordinator.data.get("health", {})
        return int(health.get("currently_visible", 0))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "rules_count": int(self.coordinator.data.get("rules_count", 0)),
            "events_received_last_poll": int(self.coordinator.data.get("events_received", 0)),
        }
