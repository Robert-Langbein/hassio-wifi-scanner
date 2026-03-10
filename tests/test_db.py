import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from wifi_presence_backend.db import Database
from wifi_presence_backend.types import NetworkObservation


class DatabaseTests(unittest.TestCase):
    def test_observation_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f"{tmp}/scanner.db")
            scan_id = db.begin_scan_run(source="agent", interface="wlan0", trigger="scheduled")
            obs = NetworkObservation(
                scanner_source="agent",
                interface="wlan0",
                ssid="Test",
                bssid="AA:BB:CC:11:22:33",
                bssid_hash=None,
                oui_vendor=None,
                rssi=-55,
                channel=1,
                frequency_mhz=2412,
                seen_at=datetime.now(tz=timezone.utc),
            )
            db.insert_observations(scan_run_id=scan_id, observations=[obs])
            db.finish_scan_run(
                scan_run_id=scan_id,
                status="ok",
                error=None,
                seen_total=1,
                new_count=1,
                disappeared_count=0,
                rule_matches=0,
            )
            items = db.list_networks(
                query="Test",
                from_dt=None,
                to_dt=None,
                rule_id=None,
                short_repeat=False,
                limit=10,
                offset=0,
            )
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["bssid"], "AA:BB:CC:11:22:33")
            runs = db.list_scan_runs(
                status=None,
                from_dt=None,
                to_dt=None,
                limit=10,
                offset=0,
            )
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["seen_total"], 1)
            db.close()

    def test_novel_networks_window_and_clear(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f"{tmp}/scanner.db")

            old = datetime.now(tz=timezone.utc) - timedelta(hours=30)
            old_plus_twenty_six = old + timedelta(hours=26)
            recent = datetime.now(tz=timezone.utc) - timedelta(hours=2)

            def record_single_session(
                *,
                bssid: str,
                ssid: str,
                at: datetime,
                frequency_mhz: int,
                channel: int,
                rssi: int,
            ) -> None:
                scan_id = db.begin_scan_run(source="agent", interface="wlan0", trigger="manual")
                db.insert_observations(
                    scan_run_id=scan_id,
                    observations=[
                        NetworkObservation(
                            scanner_source="agent",
                            interface="wlan0",
                            ssid=ssid,
                            bssid=bssid,
                            bssid_hash=None,
                            oui_vendor=None,
                            rssi=rssi,
                            channel=channel,
                            frequency_mhz=frequency_mhz,
                            seen_at=at,
                        )
                    ],
                )
                db.finish_scan_run(
                    scan_run_id=scan_id,
                    status="ok",
                    error=None,
                    seen_total=1,
                    new_count=1,
                    disappeared_count=1,
                    rule_matches=0,
                )
                db.upsert_active_network(
                    bssid=bssid,
                    ssid=ssid,
                    timestamp_iso=at.isoformat(),
                    rssi=rssi,
                    channel=channel,
                    frequency_mhz=frequency_mhz,
                    bssid_hash=None,
                    oui_vendor=None,
                )
                db.close_active_network(bssid=bssid, ended_reason="test")

            # Should be included: one session, older than window.
            record_single_session(
                bssid="AA:BB:CC:11:22:33",
                ssid="Novel-One",
                at=old,
                frequency_mhz=2412,
                channel=1,
                rssi=-54,
            )

            # Should be excluded for max_sessions=1, even though the repeat is after the window.
            record_single_session(
                bssid="AA:BB:CC:11:22:44",
                ssid="Repeat-After-Window",
                at=old,
                frequency_mhz=2412,
                channel=1,
                rssi=-60,
            )
            record_single_session(
                bssid="AA:BB:CC:11:22:44",
                ssid="Repeat-After-Window",
                at=old_plus_twenty_six,
                frequency_mhz=2412,
                channel=1,
                rssi=-63,
            )

            # Should be excluded: not old enough for classification.
            record_single_session(
                bssid="AA:BB:CC:11:22:55",
                ssid="Too-Recent",
                at=recent,
                frequency_mhz=5180,
                channel=36,
                rssi=-72,
            )

            # Should be included for max_sessions=2.
            record_single_session(
                bssid="AA:BB:CC:11:22:77",
                ssid="Rare-Two-Sessions",
                at=old,
                frequency_mhz=2462,
                channel=11,
                rssi=-58,
            )
            record_single_session(
                bssid="AA:BB:CC:11:22:77",
                ssid="Rare-Two-Sessions",
                at=old_plus_twenty_six,
                frequency_mhz=2462,
                channel=11,
                rssi=-59,
            )

            novel = db.list_novel_networks(
                window_hours=24,
                max_sessions=1,
                query=None,
                limit=50,
                offset=0,
            )
            self.assertEqual(len(novel), 1)
            self.assertEqual(novel[0]["bssid"], "AA:BB:CC:11:22:33")

            rare_two_sessions = db.list_novel_networks(
                window_hours=24,
                max_sessions=2,
                query="Rare-Two-Sessions",
                limit=50,
                offset=0,
            )
            self.assertEqual(len(rare_two_sessions), 1)
            self.assertEqual(rare_two_sessions[0]["bssid"], "AA:BB:CC:11:22:77")
            repeated_after_window = db.list_novel_networks(
                window_hours=24,
                max_sessions=1,
                query="Repeat-After-Window",
                limit=50,
                offset=0,
            )
            self.assertEqual(len(repeated_after_window), 0)

            db.clear_novel_network(bssid="AA:BB:CC:11:22:33")
            after_single_clear = db.list_novel_networks(
                window_hours=24,
                max_sessions=1,
                query=None,
                limit=50,
                offset=0,
            )
            self.assertEqual(len(after_single_clear), 0)

            # Re-create another candidate and clear via bulk mode with query.
            record_single_session(
                bssid="AA:BB:CC:11:22:66",
                ssid="Novel-Bulk",
                at=old,
                frequency_mhz=2417,
                channel=2,
                rssi=-51,
            )
            record_single_session(
                bssid="AA:BB:CC:11:22:88",
                ssid="Novel-Bulk-Two",
                at=old,
                frequency_mhz=2422,
                channel=3,
                rssi=-50,
            )
            record_single_session(
                bssid="AA:BB:CC:11:22:88",
                ssid="Novel-Bulk-Two",
                at=old_plus_twenty_six,
                frequency_mhz=2422,
                channel=3,
                rssi=-52,
            )
            cleared = db.clear_novel_networks(window_hours=24, max_sessions=1, query="Novel-Bulk")
            self.assertGreaterEqual(cleared, 1)

            after_bulk_clear = db.list_novel_networks(
                window_hours=24,
                max_sessions=1,
                query="Novel-Bulk",
                limit=50,
                offset=0,
            )
            self.assertEqual(len(after_bulk_clear), 0)
            remaining_bulk_two = db.list_novel_networks(
                window_hours=24,
                max_sessions=2,
                query="Novel-Bulk",
                limit=50,
                offset=0,
            )
            self.assertEqual(len(remaining_bulk_two), 1)
            self.assertEqual(remaining_bulk_two[0]["bssid"], "AA:BB:CC:11:22:88")
            db.close()


if __name__ == "__main__":
    unittest.main()
