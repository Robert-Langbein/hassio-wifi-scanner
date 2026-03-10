import tempfile
import unittest

from wifi_presence_backend.db import Database
from wifi_presence_backend.service import ScannerService
from wifi_presence_backend.types import ScanConfig


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


if __name__ == "__main__":
    unittest.main()
