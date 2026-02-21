from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from .types import NetworkObservation

BSSID_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


@dataclass(slots=True)
class ScanRawNetwork:
    ssid: str
    bssid: str
    rssi: int
    channel: int
    frequency_mhz: int
    oui_vendor: str | None


class SupervisorApiError(RuntimeError):
    def __init__(self, *, status_code: int | None, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


class ScanSource:
    def scan(self, *, interface: str) -> list[ScanRawNetwork]:
        raise NotImplementedError


def _frequency_to_channel(frequency_mhz: int) -> int:
    if frequency_mhz == 2484:
        return 14
    if 2412 <= frequency_mhz <= 2472:
        return (frequency_mhz - 2407) // 5
    if 5000 <= frequency_mhz <= 5900:
        return (frequency_mhz - 5000) // 5
    return 0


class SupervisorApiScanner(ScanSource):
    def __init__(self, *, base_url: str, supervisor_token: str, timeout_sec: int = 15) -> None:
        self._base_url = base_url.rstrip("/")
        self._supervisor_token = supervisor_token
        self._timeout_sec = timeout_sec

    def _request(self, *, path: str) -> dict[str, object] | list[object]:
        url = f"{self._base_url}{path}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self._supervisor_token}",
                "Content-Type": "application/json",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_sec) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise SupervisorApiError(
                status_code=exc.code,
                message=f"Supervisor API error {exc.code}: {body}",
            ) from exc
        except urllib.error.URLError as exc:
            raise SupervisorApiError(
                status_code=None,
                message=f"Supervisor API unreachable: {exc.reason}",
            ) from exc
        if not isinstance(payload, dict):
            raise SupervisorApiError(
                status_code=None,
                message="Supervisor API returned invalid payload",
            )
        data = payload.get("data")
        if data is None:
            raise SupervisorApiError(
                status_code=None,
                message="Supervisor API returned payload without data",
            )
        if not isinstance(data, (dict, list)):
            raise SupervisorApiError(
                status_code=None,
                message="Supervisor API returned invalid data payload",
            )
        return data

    def get_network_info(self) -> dict[str, object]:
        data = self._request(path="/network/info")
        if not isinstance(data, dict):
            raise SupervisorApiError(
                status_code=None,
                message="Supervisor API returned invalid network info payload",
            )
        return data

    def get_interface_info(self, *, interface: str) -> dict[str, object]:
        data = self._request(path=f"/network/interface/{interface}/info")
        if not isinstance(data, dict):
            raise SupervisorApiError(
                status_code=None,
                message="Supervisor API returned invalid interface payload",
            )
        return data

    @staticmethod
    def _extract_accesspoints_payload(data: dict[str, object] | list[object]) -> list[object]:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            accesspoints = data.get("accesspoints")
            if isinstance(accesspoints, list):
                return accesspoints
        raise SupervisorApiError(
            status_code=None,
            message="Supervisor API returned invalid accesspoints payload",
        )

    def scan(self, *, interface: str) -> list[ScanRawNetwork]:
        data = self._request(path=f"/network/interface/{interface}/accesspoints")
        accesspoints = self._extract_accesspoints_payload(data)

        results: list[ScanRawNetwork] = []
        for entry in accesspoints:
            if not isinstance(entry, dict):
                continue
            bssid_raw = entry.get("bssid") or entry.get("mac") or ""
            bssid = str(bssid_raw).strip().upper()
            if not BSSID_RE.match(bssid):
                continue
            ssid = str(entry.get("ssid", "")).strip()
            try:
                frequency = int(float(entry.get("frequency") or entry.get("frequency_mhz") or 0))
            except (TypeError, ValueError):
                frequency = 0
            try:
                channel = int(float(entry.get("channel")))
            except (TypeError, ValueError):
                channel = _frequency_to_channel(frequency)
            try:
                rssi = int(float(entry.get("signal") or entry.get("rssi") or -100))
            except (TypeError, ValueError):
                rssi = -100
            results.append(
                ScanRawNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    rssi=rssi,
                    channel=channel,
                    frequency_mhz=frequency,
                    oui_vendor=None,
                )
            )
        return results


class IWScanner(ScanSource):
    def __init__(self, *, timeout_sec: int = 20) -> None:
        self._timeout_sec = timeout_sec

    def scan(self, *, interface: str) -> list[ScanRawNetwork]:
        cmd = ["iw", "dev", interface, "scan"]
        try:
            proc = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self._timeout_sec,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip()
            raise RuntimeError(f"iw scan failed: {stderr}") from exc
        except FileNotFoundError as exc:
            raise RuntimeError("iw command not available") from exc

        return self._parse_iw_output(proc.stdout)

    @staticmethod
    def _parse_iw_output(raw: str) -> list[ScanRawNetwork]:
        blocks = re.split(r"\nBSS ", raw)
        parsed: list[ScanRawNetwork] = []

        for block in blocks:
            lines = block.strip().splitlines()
            if not lines:
                continue

            first = lines[0].strip()
            bssid = first.split("(")[0].strip().upper()
            if not BSSID_RE.match(bssid):
                continue

            ssid = ""
            signal = -100
            frequency = 0

            for line in lines[1:]:
                clean = line.strip()
                if clean.startswith("SSID:"):
                    ssid = clean.removeprefix("SSID:").strip()
                elif clean.startswith("signal:"):
                    value = clean.removeprefix("signal:").strip().split(" ")[0]
                    try:
                        signal = int(float(value))
                    except ValueError:
                        pass
                elif clean.startswith("freq:"):
                    value = clean.removeprefix("freq:").strip()
                    try:
                        frequency = int(value)
                    except ValueError:
                        pass

            parsed.append(
                ScanRawNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    rssi=signal,
                    channel=_frequency_to_channel(frequency),
                    frequency_mhz=frequency,
                    oui_vendor=None,
                )
            )

        return parsed


def to_observation(
    *,
    source: str,
    interface: str,
    network: ScanRawNetwork,
    bssid_hash: str | None,
) -> NetworkObservation:
    return NetworkObservation(
        scanner_source=source,
        interface=interface,
        ssid=network.ssid,
        bssid=network.bssid,
        bssid_hash=bssid_hash,
        oui_vendor=network.oui_vendor,
        rssi=network.rssi,
        channel=network.channel,
        frequency_mhz=network.frequency_mhz,
        seen_at=datetime.now(tz=timezone.utc),
    )
