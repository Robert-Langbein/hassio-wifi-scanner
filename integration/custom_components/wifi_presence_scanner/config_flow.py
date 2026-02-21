"""Config flow for wifi_presence_scanner."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api_client import BackendClient, BackendClientError
from .const import (
    CONF_API_KEY,
    CONF_BACKEND_URL,
    CONF_DISAPPEAR_MISSED_SCANS,
    CONF_IGNORE_BSSID_PREFIXES,
    CONF_IGNORE_SSID_PATTERNS,
    CONF_MODE,
    CONF_PRIVACY_MODE,
    CONF_PRIVACY_SALT,
    CONF_QUIET_WINDOWS_JSON,
    CONF_RETENTION_DAYS,
    CONF_SCAN_INTERVAL_SEC,
    CONF_WIFI_INTERFACE,
    DEFAULT_BACKEND_URL_AGENT,
    DEFAULT_BACKEND_URL_SUPERVISOR,
    DEFAULT_DISAPPEAR_MISSED_SCANS,
    DEFAULT_RETENTION_DAYS,
    DEFAULT_SCAN_INTERVAL_SEC,
    DOMAIN,
    MODE_AGENT,
    MODE_AUTO,
    MODE_SUPERVISOR,
)


def _build_schema(user_input: dict[str, Any] | None = None) -> vol.Schema:
    data = user_input or {}
    return vol.Schema(
        {
            vol.Required(CONF_MODE, default=data.get(CONF_MODE, MODE_AUTO)): vol.In(
                [MODE_AUTO, MODE_SUPERVISOR, MODE_AGENT]
            ),
            vol.Optional(
                CONF_BACKEND_URL,
                default=data.get(CONF_BACKEND_URL, ""),
            ): str,
            vol.Optional(CONF_API_KEY, default=data.get(CONF_API_KEY, "")): str,
        }
    )


async def _validate_backend(hass, *, base_url: str, api_key: str | None) -> None:
    session = async_get_clientsession(hass)
    client = BackendClient(session=session, base_url=base_url, api_key=api_key)
    await client.health()


def _default_backend_for_mode(mode: str) -> str:
    if mode == MODE_AGENT:
        return DEFAULT_BACKEND_URL_AGENT
    return DEFAULT_BACKEND_URL_SUPERVISOR


class WifiPresenceConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}

        if user_input is not None:
            mode = user_input[CONF_MODE]
            backend_url = user_input.get(CONF_BACKEND_URL, "").strip() or _default_backend_for_mode(mode)
            api_key = user_input.get(CONF_API_KEY, "").strip() or None

            try:
                if mode == MODE_AUTO:
                    last_error: Exception | None = None
                    for candidate in [DEFAULT_BACKEND_URL_SUPERVISOR, DEFAULT_BACKEND_URL_AGENT]:
                        try:
                            await _validate_backend(self.hass, base_url=candidate, api_key=api_key)
                            backend_url = candidate
                            break
                        except BackendClientError as err:
                            last_error = err
                    else:
                        raise BackendClientError(str(last_error) if last_error else "No backend found")
                else:
                    await _validate_backend(self.hass, base_url=backend_url, api_key=api_key)
            except BackendClientError:
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(f"{DOMAIN}:{backend_url}")
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title="WiFi Presence Scanner",
                    data={
                        CONF_MODE: mode,
                        CONF_BACKEND_URL: backend_url,
                        CONF_API_KEY: api_key,
                    },
                    options={
                        CONF_WIFI_INTERFACE: "wlan0",
                        CONF_SCAN_INTERVAL_SEC: DEFAULT_SCAN_INTERVAL_SEC,
                        CONF_DISAPPEAR_MISSED_SCANS: DEFAULT_DISAPPEAR_MISSED_SCANS,
                        CONF_RETENTION_DAYS: DEFAULT_RETENTION_DAYS,
                        CONF_PRIVACY_MODE: False,
                        CONF_PRIVACY_SALT: "",
                        CONF_QUIET_WINDOWS_JSON: "[]",
                        CONF_IGNORE_SSID_PATTERNS: "",
                        CONF_IGNORE_BSSID_PREFIXES: "",
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_build_schema(user_input),
            errors=errors,
        )

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        return WifiPresenceOptionsFlow(config_entry)


class WifiPresenceOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self._entry.options
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_WIFI_INTERFACE,
                    default=options.get(CONF_WIFI_INTERFACE, "wlan0"),
                ): str,
                vol.Required(
                    CONF_SCAN_INTERVAL_SEC,
                    default=options.get(CONF_SCAN_INTERVAL_SEC, DEFAULT_SCAN_INTERVAL_SEC),
                ): vol.All(vol.Coerce(int), vol.Range(min=10, max=3600)),
                vol.Required(
                    CONF_DISAPPEAR_MISSED_SCANS,
                    default=options.get(CONF_DISAPPEAR_MISSED_SCANS, DEFAULT_DISAPPEAR_MISSED_SCANS),
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=20)),
                vol.Required(
                    CONF_RETENTION_DAYS,
                    default=options.get(CONF_RETENTION_DAYS, DEFAULT_RETENTION_DAYS),
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=365)),
                vol.Required(
                    CONF_PRIVACY_MODE,
                    default=options.get(CONF_PRIVACY_MODE, False),
                ): bool,
                vol.Optional(
                    CONF_PRIVACY_SALT,
                    default=options.get(CONF_PRIVACY_SALT, ""),
                ): str,
                vol.Optional(
                    CONF_QUIET_WINDOWS_JSON,
                    default=options.get(CONF_QUIET_WINDOWS_JSON, "[]"),
                ): str,
                vol.Optional(
                    CONF_IGNORE_SSID_PATTERNS,
                    default=options.get(CONF_IGNORE_SSID_PATTERNS, ""),
                ): str,
                vol.Optional(
                    CONF_IGNORE_BSSID_PREFIXES,
                    default=options.get(CONF_IGNORE_BSSID_PREFIXES, ""),
                ): str,
            }
        )

        return self.async_show_form(step_id="init", data_schema=schema)
