from __future__ import annotations

import json
import os
import re
from datetime import datetime, time

from .constants import (
    DEFAULT_DISAPPEAR_MISSED_SCANS,
    DEFAULT_RETENTION_DAYS,
    DEFAULT_SCAN_INTERVAL_SEC,
    MAX_SCAN_INTERVAL_SEC,
    MIN_SCAN_INTERVAL_SEC,
)
from .types import QuietWindow, ScanConfig


WEEKDAY_TO_INDEX = {
    "monday": 0,
    "tuesday": 1,
    "wednesday": 2,
    "thursday": 3,
    "friday": 4,
    "saturday": 5,
    "sunday": 6,
}


def _parse_time(raw: str) -> time:
    parsed = datetime.strptime(raw, "%H:%M")
    return time(hour=parsed.hour, minute=parsed.minute)


def _parse_quiet_windows(raw: str | None) -> list[QuietWindow]:
    if not raw:
        return []

    payload = json.loads(raw)
    if not isinstance(payload, list):
        raise ValueError("QUIET_WINDOWS_JSON must be a JSON list")

    windows: list[QuietWindow] = []
    weekdays_seen: set[int] = set()
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("Each quiet window must be an object")

        weekday_raw = str(item.get("weekday", "")).strip().lower()
        if weekday_raw not in WEEKDAY_TO_INDEX:
            raise ValueError(f"Unsupported weekday: {weekday_raw}")

        weekday = WEEKDAY_TO_INDEX[weekday_raw]
        if weekday in weekdays_seen:
            raise ValueError("Only one quiet window per weekday is supported")
        weekdays_seen.add(weekday)

        start_raw = str(item.get("start", "")).strip()
        end_raw = str(item.get("end", "")).strip()
        if not start_raw or not end_raw:
            raise ValueError("Quiet window requires 'start' and 'end'")

        windows.append(
            QuietWindow(
                weekday=weekday,
                start=_parse_time(start_raw),
                end=_parse_time(end_raw),
            )
        )

    return windows


def _csv_env(name: str) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _validate_scan_interval(scan_interval_sec: int) -> None:
    if scan_interval_sec < MIN_SCAN_INTERVAL_SEC or scan_interval_sec > MAX_SCAN_INTERVAL_SEC:
        raise ValueError(
            f"SCAN_INTERVAL_SEC must be between {MIN_SCAN_INTERVAL_SEC} and {MAX_SCAN_INTERVAL_SEC}"
        )


def _validate_regexes(patterns: list[str]) -> None:
    for pattern in patterns:
        re.compile(pattern)


def load_scan_config(*, source: str, default_interface: str) -> ScanConfig:
    interface = os.getenv("WIFI_INTERFACE", default_interface).strip()
    if not interface:
        raise ValueError("WIFI_INTERFACE must not be empty")

    scan_interval_sec = int(os.getenv("SCAN_INTERVAL_SEC", str(DEFAULT_SCAN_INTERVAL_SEC)))
    _validate_scan_interval(scan_interval_sec)

    disappear_missed_scans = int(
        os.getenv("DISAPPEAR_MISSED_SCANS", str(DEFAULT_DISAPPEAR_MISSED_SCANS))
    )
    if disappear_missed_scans < 1 or disappear_missed_scans > 20:
        raise ValueError("DISAPPEAR_MISSED_SCANS must be between 1 and 20")

    retention_days = int(os.getenv("RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS)))
    if retention_days < 1 or retention_days > 365:
        raise ValueError("RETENTION_DAYS must be between 1 and 365")

    privacy_mode = os.getenv("PRIVACY_MODE", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    privacy_salt = os.getenv("PRIVACY_SALT", "")
    if privacy_mode and not privacy_salt:
        raise ValueError("PRIVACY_SALT is required when PRIVACY_MODE=true")

    quiet_windows = _parse_quiet_windows(os.getenv("QUIET_WINDOWS_JSON"))

    ignore_ssid_patterns = _csv_env("IGNORE_SSID_PATTERNS")
    _validate_regexes(ignore_ssid_patterns)

    ignore_bssid_prefixes = [value.upper() for value in _csv_env("IGNORE_BSSID_PREFIXES")]

    return ScanConfig(
        source=source,
        interface=interface,
        scan_interval_sec=scan_interval_sec,
        disappear_missed_scans=disappear_missed_scans,
        retention_days=retention_days,
        privacy_mode=privacy_mode,
        privacy_salt=privacy_salt,
        quiet_windows=quiet_windows,
        ignore_ssid_patterns=ignore_ssid_patterns,
        ignore_bssid_prefixes=ignore_bssid_prefixes,
    )
