import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from wifi_presence_backend.db import Database
from wifi_presence_backend.scanner import ScanRawNetwork
from wifi_presence_backend.service import ScannerService
from wifi_presence_backend.types import NetworkObservation, ScanConfig


class _RecordingPublisher:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def forward(self, *, event_type: str, payload: dict[str, object]) -> None:
        self.events.append((event_type, payload))


class _StaticScanner:
    def __init__(self, networks: list[ScanRawNetwork]) -> None:
        self._networks = networks

    def scan(self, *, interface: str) -> list[ScanRawNetwork]:
        self.last_interface = interface
        return list(self._networks)


class ScannerServiceNovelValidationTests(unittest.TestCase):
    @staticmethod
    def _build_service(db_path: str) -> ScannerService:
        return ScannerService(
            db=Database(db_path),
            config=ScanConfig(
                source="agent",
                interface="wlan0",
                scan_interval_sec=30,
                disappear_missed_scans=2,
                retention_days=30,
                observation_retention_days=3,
                privacy_mode=False,
                privacy_salt="salt",
                quiet_windows=[],
                ignore_ssid_patterns=[],
                ignore_bssid_prefixes=[],
            ),
            scanner=object(),
            publisher=object(),
        )

    def test_list_novel_networks_rejects_invalid_max_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service = self._build_service(f"{tmp}/scanner.db")
            try:
                with self.assertRaisesRegex(ValueError, "max_sessions"):
                    service.list_novel_networks(params={"max_sessions": "0"})
            finally:
                service._db.close()

    def test_clear_novel_networks_rejects_invalid_max_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service = self._build_service(f"{tmp}/scanner.db")
            try:
                with self.assertRaisesRegex(ValueError, "max_sessions"):
                    service.clear_novel_networks(payload={"clear_all": True, "max_sessions": "0"})
            finally:
                service._db.close()

    def test_scan_run_observations_expire_by_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service = self._build_service(f"{tmp}/scanner.db")
            try:
                service._config.observation_retention_days = 1
                old_seen_at = datetime.now(tz=timezone.utc) - timedelta(days=2)
                recent_seen_at = datetime.now(tz=timezone.utc) - timedelta(hours=2)

                def record_run(*, at: datetime, bssid: str) -> int:
                    scan_id = service._db.begin_scan_run(source="agent", interface="wlan0", trigger="manual")
                    service._db.insert_observations(
                        scan_run_id=scan_id,
                        observations=[
                            NetworkObservation(
                                scanner_source="agent",
                                interface="wlan0",
                                ssid="Tracked",
                                bssid=bssid,
                                bssid_hash=None,
                                oui_vendor=None,
                                rssi=-55,
                                channel=1,
                                frequency_mhz=2412,
                                seen_at=at,
                            )
                        ],
                    )
                    service._db.finish_scan_run(
                        scan_run_id=scan_id,
                        status="ok",
                        error=None,
                        seen_total=1,
                        new_count=1,
                        disappeared_count=0,
                        rule_matches=0,
                    )
                    with service._db.transaction() as conn:
                        conn.execute(
                            "UPDATE scan_runs SET started_at = ?, finished_at = ? WHERE id = ?",
                            (at.isoformat(), at.isoformat(), scan_id),
                        )
                    return scan_id

                old_scan_id = record_run(at=old_seen_at, bssid="AA:BB:CC:11:22:33")
                recent_scan_id = record_run(at=recent_seen_at, bssid="AA:BB:CC:11:22:44")

                old_detail = service.get_scan_run_detail(scan_run_id=old_scan_id)
                recent_detail = service.get_scan_run_detail(scan_run_id=recent_scan_id)

                self.assertFalse(old_detail["raw_observations_available"])
                self.assertTrue(recent_detail["raw_observations_available"])
                self.assertEqual(
                    service.list_scan_run_observations(scan_run_id=old_scan_id, params={})["items"],
                    [],
                )
                self.assertEqual(
                    len(service.list_scan_run_observations(scan_run_id=recent_scan_id, params={})["items"]),
                    1,
                )
            finally:
                service._db.close()

    def test_repeated_scans_keep_stable_network_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            publisher = _RecordingPublisher()
            scanner = _StaticScanner(
                [
                    ScanRawNetwork(
                        ssid="Stable",
                        bssid="AA:BB:CC:44:55:66",
                        rssi=-51,
                        channel=1,
                        frequency_mhz=2412,
                        oui_vendor="Vendor",
                    )
                ]
            )
            service = ScannerService(
                db=Database(f"{tmp}/scanner.db"),
                config=ScanConfig(
                    source="agent",
                    interface="wlan0",
                    scan_interval_sec=30,
                    disappear_missed_scans=2,
                    retention_days=30,
                    observation_retention_days=3,
                    privacy_mode=False,
                    privacy_salt="salt",
                    quiet_windows=[],
                    ignore_ssid_patterns=[],
                    ignore_bssid_prefixes=[],
                ),
                scanner=scanner,
                publisher=publisher,
            )
            try:
                first = service.perform_scan(trigger="manual")
                second = service.perform_scan(trigger="manual")

                self.assertEqual(first["new_count"], 1)
                self.assertEqual(second["new_count"], 0)
                self.assertEqual(second["disappeared_count"], 0)
                self.assertEqual(scanner.last_interface, "wlan0")
                network = service.list_networks(params={"query": "Stable"})["items"][0]
                self.assertEqual(network["seen_count"], 2)
                self.assertEqual(len([event for event in publisher.events if event[0] == "wifi_presence_scanner_wifi_discovered"]), 1)
            finally:
                service._db.close()


if __name__ == "__main__":
    unittest.main()
