import json
import os
import unittest

from wifi_presence_backend.config import load_scan_config


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._backup = dict(os.environ)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._backup)

    def test_default_config(self) -> None:
        cfg = load_scan_config(source="agent", default_interface="wlan0")
        self.assertEqual(cfg.interface, "wlan0")
        self.assertEqual(cfg.scan_interval_sec, 30)
        self.assertEqual(cfg.observation_retention_days, 3)

    def test_quiet_window_single_per_weekday(self) -> None:
        os.environ["QUIET_WINDOWS_JSON"] = json.dumps(
            [
                {"weekday": "monday", "start": "09:00", "end": "10:00"},
                {"weekday": "monday", "start": "11:00", "end": "12:00"},
            ]
        )
        with self.assertRaises(ValueError):
            load_scan_config(source="agent", default_interface="wlan0")

    def test_observation_retention_must_not_exceed_retention(self) -> None:
        os.environ["RETENTION_DAYS"] = "2"
        os.environ["OBSERVATION_RETENTION_DAYS"] = "3"
        with self.assertRaises(ValueError):
            load_scan_config(source="agent", default_interface="wlan0")


if __name__ == "__main__":
    unittest.main()
