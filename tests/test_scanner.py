import unittest

from wifi_presence_backend.scanner import IWScanner


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


if __name__ == "__main__":
    unittest.main()
