from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time
from typing import Any


@dataclass(slots=True)
class QuietWindow:
    weekday: int
    start: time
    end: time


@dataclass(slots=True)
class ScanConfig:
    source: str
    interface: str
    scan_interval_sec: int
    disappear_missed_scans: int
    retention_days: int
    observation_retention_days: int
    privacy_mode: bool
    privacy_salt: str
    quiet_windows: list[QuietWindow]
    ignore_ssid_patterns: list[str]
    ignore_bssid_prefixes: list[str]


@dataclass(slots=True)
class NetworkObservation:
    scanner_source: str
    interface: str
    ssid: str
    bssid: str
    bssid_hash: str | None
    oui_vendor: str | None
    rssi: int
    channel: int
    frequency_mhz: int
    seen_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanner_source": self.scanner_source,
            "interface": self.interface,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "bssid_hash": self.bssid_hash,
            "oui_vendor": self.oui_vendor,
            "rssi": self.rssi,
            "channel": self.channel,
            "frequency_mhz": self.frequency_mhz,
            "seen_at": self.seen_at.isoformat(),
        }


@dataclass(slots=True)
class FingerprintRule:
    id: int | None
    name: str
    enabled: bool
    ssid_regex: str | None
    bssid_prefix_csv: str | None
    oui_vendor_csv: str | None
    min_rssi: int | None
    max_duration_sec: int | None
    min_reappear_count: int | None
    cooldown_sec: int


@dataclass(slots=True)
class PresenceSession:
    id: int
    ssid: str
    bssid: str
    first_seen: datetime
    last_seen: datetime
    duration_sec: int
    scans_seen: int
    ended_reason: str | None


@dataclass(slots=True)
class RuleMatchEvent:
    event_type: str
    payload: dict[str, Any]


@dataclass(slots=True)
class HealthStatus:
    ok: bool
    source: str
    interface: str
    last_scan_started_at: str | None
    last_scan_finished_at: str | None
    last_error: str | None
    queue_size: int
    db_path: str
