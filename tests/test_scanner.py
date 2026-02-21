import unittest

from wifi_presence_backend.scanner import IWScanner, SupervisorApiError, SupervisorApiScanner


class _StubSupervisorScanner(SupervisorApiScanner):
    def __init__(self, payload: dict[str, object] | list[object]) -> None:
        super().__init__(base_url="http://supervisor", supervisor_token="token")
        self._payload = payload

    def _request(self, *, path: str) -> dict[str, object] | list[object]:
        self._last_path = path
        return self._payload


class ScannerParserTests(unittest.TestCase):
    def test_parse_iw_output(self) -> None:
        raw = """
BSS aa:bb:cc:11:22:33(on wlan0)
    freq: 2412
    signal: -54.00 dBm
    SSID: DHL-VAN
BSS 11:22:33:44:55:66(on wlan0)
    freq: 5180
    signal: -71.00 dBm
    SSID: HOME
        """
        items = IWScanner._parse_iw_output(raw)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].bssid, "AA:BB:CC:11:22:33")
        self.assertEqual(items[0].channel, 1)
        self.assertEqual(items[1].channel, 36)

    def test_supervisor_scan_legacy_payload(self) -> None:
        scanner = _StubSupervisorScanner(
            [
                {
                    "ssid": "DHL-VAN",
                    "bssid": "aa:bb:cc:11:22:33",
                    "signal": "-55.0",
                    "frequency": 2412,
                }
            ]
        )
        items = scanner.scan(interface="wlan0")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].bssid, "AA:BB:CC:11:22:33")
        self.assertEqual(items[0].channel, 1)
        self.assertEqual(items[0].rssi, -55)

    def test_supervisor_scan_accesspoints_payload(self) -> None:
        scanner = _StubSupervisorScanner(
            {
                "accesspoints": [
                    {
                        "ssid": "DHL-VAN",
                        "mac": "11:22:33:44:55:66",
                        "signal": -64,
                        "frequency": 5180,
                    }
                ]
            }
        )
        items = scanner.scan(interface="wlan0")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].bssid, "11:22:33:44:55:66")
        self.assertEqual(items[0].channel, 36)
        self.assertEqual(items[0].rssi, -64)

    def test_supervisor_scan_invalid_payload(self) -> None:
        scanner = _StubSupervisorScanner({"interfaces": []})
        with self.assertRaises(SupervisorApiError):
            scanner.scan(interface="wlan0")


if __name__ == "__main__":
    unittest.main()
