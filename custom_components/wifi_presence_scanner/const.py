"""Constants for wifi_presence_scanner integration."""

from __future__ import annotations

from datetime import timedelta

DOMAIN = "wifi_presence_scanner"
PLATFORMS = ["sensor", "binary_sensor"]

CONF_MODE = "mode"
CONF_BACKEND_URL = "backend_url"
CONF_API_KEY = "api_key"
CONF_SCAN_INTERVAL_SEC = "scan_interval_sec"
CONF_DISAPPEAR_MISSED_SCANS = "disappear_missed_scans"
CONF_RETENTION_DAYS = "retention_days"
CONF_PRIVACY_MODE = "privacy_mode"
CONF_PRIVACY_SALT = "privacy_salt"
CONF_QUIET_WINDOWS_JSON = "quiet_windows_json"
CONF_IGNORE_SSID_PATTERNS = "ignore_ssid_patterns"
CONF_IGNORE_BSSID_PREFIXES = "ignore_bssid_prefixes"
CONF_WIFI_INTERFACE = "wifi_interface"

MODE_AUTO = "auto"
MODE_SUPERVISOR = "supervisor"
MODE_AGENT = "agent"

DEFAULT_BACKEND_URL_SUPERVISOR = "http://127.0.0.1:8099"
DEFAULT_BACKEND_URL_AGENT = "http://127.0.0.1:8100"

DEFAULT_SCAN_INTERVAL_SEC = 30
DEFAULT_DISAPPEAR_MISSED_SCANS = 2
DEFAULT_RETENTION_DAYS = 30

COORDINATOR_INTERVAL = timedelta(seconds=15)

EVENT_WIFI_DISCOVERED = "wifi_presence_scanner_wifi_discovered"
EVENT_WIFI_DISAPPEARED = "wifi_presence_scanner_wifi_disappeared"
EVENT_RULE_MATCHED = "wifi_presence_scanner_rule_matched"
EVENT_HEALTH_WARNING = "wifi_presence_scanner_health_warning"
