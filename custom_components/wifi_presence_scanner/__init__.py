"""WiFi Presence Scanner integration."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.frontend import async_register_built_in_panel, async_remove_panel
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api_client import BackendClient, BackendClientError
from .const import (
    CONF_API_KEY,
    CONF_BACKEND_URL,
    CONF_MODE,
    DEFAULT_BACKEND_URL_AGENT,
    DEFAULT_BACKEND_URL_SUPERVISOR,
    DOMAIN,
    MODE_AGENT,
    MODE_AUTO,
    MODE_SUPERVISOR,
    PLATFORMS,
)
from .coordinator import WifiPresenceCoordinator
from .web import async_register_views

_LOGGER = logging.getLogger(__name__)


def _resolve_backend_candidates(entry: ConfigEntry) -> list[str]:
    mode = entry.data.get(CONF_MODE, MODE_AUTO)
    explicit = entry.data.get(CONF_BACKEND_URL, "").strip()
    if explicit:
        return [explicit]

    if mode == MODE_AGENT:
        return [DEFAULT_BACKEND_URL_AGENT]
    if mode == MODE_SUPERVISOR:
        return [DEFAULT_BACKEND_URL_SUPERVISOR]

    return [DEFAULT_BACKEND_URL_SUPERVISOR, DEFAULT_BACKEND_URL_AGENT]


async def _build_working_client(hass: HomeAssistant, entry: ConfigEntry) -> BackendClient:
    session = async_get_clientsession(hass)
    api_key = entry.data.get(CONF_API_KEY)

    last_error: Exception | None = None
    for candidate in _resolve_backend_candidates(entry):
        client = BackendClient(session=session, base_url=candidate, api_key=api_key)
        try:
            await client.health()
            _LOGGER.info("Connected to wifi_presence_scanner backend at %s", candidate)
            return client
        except BackendClientError as err:
            last_error = err
            continue

    raise BackendClientError(str(last_error) if last_error else "No backend candidate reachable")


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN].setdefault("entries", {})
    hass.data[DOMAIN].setdefault("views_registered", False)
    hass.data[DOMAIN].setdefault("services_registered", False)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    if not hass.data[DOMAIN]["views_registered"]:
        try:
            async_register_views(hass)
        except Exception as err:  # pragma: no cover - depends on HA HTTP view lifecycle
            _LOGGER.warning(
                "HTTP view registration failed, continuing without custom panel views: %s",
                err,
            )
        try:
            async_register_built_in_panel(
                hass,
                component_name="iframe",
                frontend_url_path=DOMAIN,
                sidebar_title="WiFi Scanner",
                sidebar_icon="mdi:wifi-marker",
                config={"url": "/api/wifi_presence_scanner/panel"},
                require_admin=False,
            )
        except Exception as err:  # pragma: no cover - depends on HA frontend internals
            _LOGGER.warning(
                "Panel registration failed, continuing without sidebar panel: %s",
                err,
            )
        hass.data[DOMAIN]["views_registered"] = True

    client = await _build_working_client(hass, entry)
    coordinator = WifiPresenceCoordinator(hass=hass, client=client)
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN]["entries"][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    if not hass.data[DOMAIN]["services_registered"]:

        async def async_force_scan(call: ServiceCall) -> None:
            coordinators = hass.data[DOMAIN]["entries"].values()
            for item in coordinators:
                await item.async_force_scan()

        async def async_reload_rules(call: ServiceCall) -> None:
            coordinators = hass.data[DOMAIN]["entries"].values()
            for item in coordinators:
                await item.async_request_refresh()

        async def async_purge_history(call: ServiceCall) -> None:
            coordinators = hass.data[DOMAIN]["entries"].values()
            for item in coordinators:
                await item.async_purge_history()

        hass.services.async_register(DOMAIN, "force_scan", async_force_scan)
        hass.services.async_register(DOMAIN, "reload_rules", async_reload_rules)
        hass.services.async_register(DOMAIN, "purge_history", async_purge_history)

        hass.data[DOMAIN]["services_registered"] = True

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        return False

    hass.data[DOMAIN]["entries"].pop(entry.entry_id, None)
    if not hass.data[DOMAIN]["entries"]:
        try:
            async_remove_panel(hass, DOMAIN)
        except Exception:  # pragma: no cover - panel may not exist
            pass
        if hass.data[DOMAIN].get("services_registered"):
            hass.services.async_remove(DOMAIN, "force_scan")
            hass.services.async_remove(DOMAIN, "reload_rules")
            hass.services.async_remove(DOMAIN, "purge_history")
            hass.data[DOMAIN]["services_registered"] = False
    return True
