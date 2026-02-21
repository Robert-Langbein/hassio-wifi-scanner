import tempfile
import unittest
from datetime import datetime, timezone

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


if __name__ == "__main__":
    unittest.main()
