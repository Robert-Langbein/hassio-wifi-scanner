"""Shared constants for WiFi presence scanner backends."""

DOMAIN = "wifi_presence_scanner"

EVENT_WIFI_DISCOVERED = "wifi_presence_scanner_wifi_discovered"
EVENT_WIFI_DISAPPEARED = "wifi_presence_scanner_wifi_disappeared"
EVENT_RULE_MATCHED = "wifi_presence_scanner_rule_matched"
EVENT_HEALTH_WARNING = "wifi_presence_scanner_health_warning"

DEFAULT_SCAN_INTERVAL_SEC = 30
DEFAULT_DISAPPEAR_MISSED_SCANS = 2
DEFAULT_RETENTION_DAYS = 30
DEFAULT_SHORT_REPEAT_MAX_DURATION_SEC = 120
DEFAULT_SHORT_REPEAT_MIN_REAPPEAR_COUNT = 3
DEFAULT_SHORT_REPEAT_WINDOW_HOURS = 24

MIN_SCAN_INTERVAL_SEC = 10
MAX_SCAN_INTERVAL_SEC = 3600
