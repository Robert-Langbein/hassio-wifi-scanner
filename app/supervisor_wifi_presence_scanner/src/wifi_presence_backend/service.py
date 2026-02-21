from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any

from .constants import (
    DEFAULT_SHORT_REPEAT_MAX_DURATION_SEC,
    DEFAULT_SHORT_REPEAT_MIN_REAPPEAR_COUNT,
    DEFAULT_SHORT_REPEAT_WINDOW_HOURS,
    EVENT_HEALTH_WARNING,
    EVENT_RULE_MATCHED,
    EVENT_WIFI_DISCOVERED,
    EVENT_WIFI_DISAPPEARED,
)
from .db import Database
from .rules import RuleEngine
from .scanner import ScanSource, to_observation
from .types import ScanConfig


def _utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


class EventPublisher:
    def __init__(
        self,
        *,
        db: Database,
        ha_api_url: str | None,
        ha_token: str | None,
        verify_ssl: bool = True,
    ) -> None:
        self._db = db
        self._ha_api_url = ha_api_url.rstrip("/") if ha_api_url else None
        self._ha_token = ha_token
        self._verify_ssl = verify_ssl

    def emit(self, *, event_type: str, payload: dict[str, Any]) -> int:
        event_id = self._db.record_emitted_event(event_type=event_type, payload=payload)
        if self._ha_api_url and self._ha_token:
            self._try_post_to_home_assistant(event_type=event_type, payload=payload)
        return event_id

    def _try_post_to_home_assistant(self, *, event_type: str, payload: dict[str, Any]) -> None:
        url = f"{self._ha_api_url}/events/{event_type}"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self._ha_token}",
                "Content-Type": "application/json",
            },
        )
        try:
            urllib.request.urlopen(req, timeout=10).read()
        except (urllib.error.URLError, urllib.error.HTTPError):
            # Event is still available through /v1/events polling.
            return


class ScannerService:
    def __init__(
        self,
        *,
        db: Database,
        config: ScanConfig,
        scanner: ScanSource,
        publisher: EventPublisher,
    ) -> None:
        self._db = db
        self._config = config
        self._scanner = scanner
        self._publisher = publisher
        self._rules = RuleEngine(db)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_scan_started_at: str | None = None
        self._last_scan_finished_at: str | None = None
        self._last_error: str | None = None
        self._last_purge_at: datetime | None = None
        self._regex_ignores = [re.compile(item) for item in config.ignore_ssid_patterns]
        self._perform_lock = threading.Lock()

    @property
    def config(self) -> ScanConfig:
        return self._config

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="wifi-scan-loop")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        next_run = time.monotonic()
        while not self._stop.is_set():
            now_mono = time.monotonic()
            if now_mono >= next_run:
                self.perform_scan(trigger="scheduled")
                self._maybe_purge()
                next_run = now_mono + self._config.scan_interval_sec
            wait_sec = max(next_run - time.monotonic(), 0.2)
            self._stop.wait(wait_sec)

    def _maybe_purge(self) -> None:
        now = _utc_now()
        if self._last_purge_at and (now - self._last_purge_at) < timedelta(hours=24):
            return
        self._db.purge_history(retention_days=self._config.retention_days)
        self._last_purge_at = now

    def _is_quiet_window(self, dt: datetime) -> bool:
        weekday = dt.weekday()
        current = dt.time()

        for window in self._config.quiet_windows:
            if window.weekday != weekday:
                continue
            if window.start <= window.end:
                return window.start <= current < window.end
            return current >= window.start or current < window.end
        return False

    def _ignore_network(self, *, ssid: str, bssid: str) -> bool:
        if any(regex.search(ssid or "") for regex in self._regex_ignores):
            return True
        upper = bssid.upper()
        return any(upper.startswith(prefix) for prefix in self._config.ignore_bssid_prefixes)

    def _hash_bssid(self, bssid: str) -> str | None:
        if not self._config.privacy_mode:
            return None
        payload = f"{self._config.privacy_salt}:{bssid.upper()}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _base_payload(self, *, active_record: dict[str, Any]) -> dict[str, Any]:
        return {
            "scanner_source": self._config.source,
            "interface": self._config.interface,
            "ssid": active_record["ssid"],
            "bssid": active_record["bssid"],
            "bssid_hash": active_record.get("bssid_hash"),
            "oui_vendor": active_record.get("oui_vendor"),
            "rssi": active_record.get("last_rssi"),
            "channel": active_record.get("last_channel"),
            "first_seen": active_record["first_seen"],
            "last_seen": active_record["last_seen"],
            "seen_count": int(active_record["seen_count"]),
            "rule_id": None,
            "rule_name": None,
            "confidence": None,
            "reason": None,
        }

    def perform_scan(self, *, trigger: str) -> dict[str, Any]:
        if not self._perform_lock.acquire(blocking=False):
            return {"status": "skipped", "reason": "scan_in_progress"}
        try:
            now = _utc_now()
            if self._is_quiet_window(now):
                return {"status": "skipped", "reason": "quiet_window"}

            self._last_scan_started_at = now.isoformat()
            scan_run_id = self._db.begin_scan_run(
                source=self._config.source,
                interface=self._config.interface,
            )

            try:
                raw_networks = self._scanner.scan(interface=self._config.interface)
                observations = []
                for raw in raw_networks:
                    if self._ignore_network(ssid=raw.ssid, bssid=raw.bssid):
                        continue
                    observations.append(
                        to_observation(
                            source=self._config.source,
                            interface=self._config.interface,
                            network=raw,
                            bssid_hash=self._hash_bssid(raw.bssid),
                        )
                    )

                self._db.insert_observations(scan_run_id=scan_run_id, observations=observations)
                self._handle_presence_and_rules(observations=observations)

                self._db.finish_scan_run(scan_run_id=scan_run_id, status="ok", error=None)
                self._last_scan_finished_at = _utc_now().isoformat()
                self._last_error = None
                return {
                    "status": "ok",
                    "scan_run_id": scan_run_id,
                    "seen": len(observations),
                    "trigger": trigger,
                }
            except Exception as exc:
                err = str(exc)
                self._db.finish_scan_run(scan_run_id=scan_run_id, status="error", error=err)
                self._last_scan_finished_at = _utc_now().isoformat()
                self._last_error = err
                self._publisher.emit(
                    event_type=EVENT_HEALTH_WARNING,
                    payload={
                        "scanner_source": self._config.source,
                        "interface": self._config.interface,
                        "reason": "scan_failed",
                        "error": err,
                        "at": self._last_scan_finished_at,
                    },
                )
                return {"status": "error", "error": err, "scan_run_id": scan_run_id}
        finally:
            self._perform_lock.release()

    def _handle_presence_and_rules(self, *, observations: list[Any]) -> None:
        seen_bssids: set[str] = set()

        for obs in observations:
            seen_bssids.add(obs.bssid)
            is_new, active = self._db.upsert_active_network(
                bssid=obs.bssid,
                ssid=obs.ssid,
                timestamp_iso=obs.seen_at.isoformat(),
                rssi=obs.rssi,
                channel=obs.channel,
                frequency_mhz=obs.frequency_mhz,
                bssid_hash=obs.bssid_hash,
                oui_vendor=obs.oui_vendor,
            )
            if is_new:
                self._publisher.emit(event_type=EVENT_WIFI_DISCOVERED, payload=self._base_payload(active_record=active))

            for rule, result in self._rules.evaluate(observation=obs, active_record=active):
                self._db.record_rule_match(
                    rule_id=rule.id or 0,
                    bssid=obs.bssid,
                    confidence=result.confidence,
                    reason=result.reason,
                )
                payload = self._base_payload(active_record=active)
                payload["rule_id"] = rule.id
                payload["rule_name"] = rule.name
                payload["confidence"] = result.confidence
                payload["reason"] = result.reason
                self._publisher.emit(event_type=EVENT_RULE_MATCHED, payload=payload)

        for active in self._db.get_active_networks():
            bssid = active["bssid"]
            if bssid in seen_bssids:
                continue
            updated = self._db.increment_missed_scans(bssid=bssid)
            if not updated:
                continue
            if int(updated["missed_scans"]) >= self._config.disappear_missed_scans:
                closed = self._db.close_active_network(
                    bssid=bssid,
                    ended_reason="missing_scans",
                )
                if closed:
                    payload = {
                        "scanner_source": self._config.source,
                        "interface": self._config.interface,
                        "ssid": closed["ssid"],
                        "bssid": closed["bssid"],
                        "bssid_hash": updated.get("bssid_hash"),
                        "oui_vendor": updated.get("oui_vendor"),
                        "rssi": updated.get("last_rssi"),
                        "channel": updated.get("last_channel"),
                        "first_seen": closed["first_seen"],
                        "last_seen": closed["last_seen"],
                        "seen_count": int(closed["scans_seen"]),
                        "rule_id": None,
                        "rule_name": None,
                        "confidence": None,
                        "reason": {"ended_reason": "missing_scans"},
                    }
                    self._publisher.emit(event_type=EVENT_WIFI_DISAPPEARED, payload=payload)

    def get_health(self) -> dict[str, Any]:
        latest_scan = self._db.latest_scan_state()
        return {
            "ok": self._last_error is None,
            "source": self._config.source,
            "interface": self._config.interface,
            "scan_interval_sec": self._config.scan_interval_sec,
            "last_scan_started_at": self._last_scan_started_at,
            "last_scan_finished_at": self._last_scan_finished_at,
            "last_error": self._last_error,
            "db_path": self._db.db_path,
            "currently_visible": self._db.count_currently_visible(),
            "latest_scan": latest_scan,
        }

    def list_networks(self, *, params: dict[str, str]) -> dict[str, Any]:
        query = params.get("query")
        from_dt = params.get("from")
        to_dt = params.get("to")
        short_repeat = params.get("short_repeat", "false").lower() in {"1", "true", "yes"}
        limit = max(1, min(int(params.get("limit", "100")), 1000))
        offset = max(0, int(params.get("offset", "0")))
        rule_id: int | None = None
        if "rule" in params and params["rule"]:
            rule_id = int(params["rule"])

        rows = self._db.list_networks(
            query=query,
            from_dt=from_dt,
            to_dt=to_dt,
            rule_id=rule_id,
            short_repeat=short_repeat,
            limit=limit,
            offset=offset,
        )
        return {"items": rows, "limit": limit, "offset": offset}

    def get_network_sessions(self, *, bssid: str) -> dict[str, Any]:
        return {"items": self._db.get_network_sessions(bssid=bssid.upper())}

    def list_rules(self) -> dict[str, Any]:
        rules = [asdict(rule) for rule in self._db.list_rules()]
        return {"items": rules}

    @staticmethod
    def _validate_rule_payload(payload: dict[str, Any]) -> None:
        name = str(payload.get("name", "")).strip()
        if not name:
            raise ValueError("'name' is required")
        if len(name) > 128:
            raise ValueError("'name' is too long")

        ssid_regex = payload.get("ssid_regex")
        if ssid_regex:
            re.compile(str(ssid_regex))

        cooldown_sec = int(payload.get("cooldown_sec", 0))
        if cooldown_sec < 0 or cooldown_sec > 86400:
            raise ValueError("'cooldown_sec' must be between 0 and 86400")

    def create_rule(self, *, payload: dict[str, Any]) -> dict[str, Any]:
        self._validate_rule_payload(payload)
        rule = self._db.create_rule(payload)
        return asdict(rule)

    def patch_rule(self, *, rule_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
        if "ssid_regex" in payload and payload["ssid_regex"]:
            re.compile(str(payload["ssid_regex"]))
        updated = self._db.patch_rule(rule_id=rule_id, patch=payload)
        if not updated:
            return None
        return asdict(updated)

    def delete_rule(self, *, rule_id: int) -> bool:
        return self._db.delete_rule(rule_id=rule_id)

    def trigger_scan(self) -> dict[str, Any]:
        return self.perform_scan(trigger="manual")

    def list_events(self, *, after_id: int, limit: int) -> dict[str, Any]:
        safe_limit = max(1, min(limit, 1000))
        return {"items": self._db.list_emitted_events(after_id=after_id, limit=safe_limit)}

    def short_repeat_stats(self, *, params: dict[str, str]) -> dict[str, Any]:
        max_duration_sec = int(params.get("max_duration_sec", str(DEFAULT_SHORT_REPEAT_MAX_DURATION_SEC)))
        min_reappear_count = int(
            params.get("min_reappear_count", str(DEFAULT_SHORT_REPEAT_MIN_REAPPEAR_COUNT))
        )
        window_hours = int(params.get("window_hours", str(DEFAULT_SHORT_REPEAT_WINDOW_HOURS)))
        items = self._db.short_repeat_stats(
            max_duration_sec=max_duration_sec,
            min_reappear_count=min_reappear_count,
            window_hours=window_hours,
        )
        return {
            "items": items,
            "max_duration_sec": max_duration_sec,
            "min_reappear_count": min_reappear_count,
            "window_hours": window_hours,
        }

    def purge_history(self) -> dict[str, Any]:
        return self._db.purge_history(retention_days=self._config.retention_days)
