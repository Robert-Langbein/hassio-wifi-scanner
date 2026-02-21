"""Binary sensor for wifi_presence_scanner health status."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import BinarySensorEntity
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
    async_add_entities([WifiPresenceHealthyBinarySensor(coordinator, entry)])


class WifiPresenceHealthyBinarySensor(
    CoordinatorEntity[WifiPresenceCoordinator],
    BinarySensorEntity,
):
    _attr_has_entity_name = True
    _attr_name = "Healthy"

    def __init__(self, coordinator: WifiPresenceCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry = entry

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_healthy"

    @property
    def is_on(self) -> bool:
        health = self.coordinator.data.get("health", {})
        return bool(health.get("ok", False))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        health = self.coordinator.data.get("health", {})
        return {
            "last_error": health.get("last_error"),
            "source": health.get("source"),
            "interface": health.get("interface"),
        }

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "WiFi Presence Scanner",
            "manufacturer": "Custom",
            "model": "wifi_presence_scanner",
        }
