from __future__ import annotations

import os
import signal
import threading
from pathlib import Path

from .api_server import ApiServer
from .config import load_scan_config
from .db import Database
from .scanner import IWScanner, SupervisorApiScanner
from .service import EventPublisher, ScannerService


def build_scanner(*, source: str):
    if source == "supervisor":
        supervisor_token = os.getenv("SUPERVISOR_TOKEN", "").strip()
        if not supervisor_token:
            raise RuntimeError("SUPERVISOR_TOKEN is required for supervisor source")
        base_url = os.getenv("SUPERVISOR_URL", "http://supervisor")
        return SupervisorApiScanner(base_url=base_url, supervisor_token=supervisor_token)
    if source == "agent":
        return IWScanner()
    raise RuntimeError(f"Unsupported source: {source}")


def run_backend(*, source: str) -> None:
    default_interface = "wlan0"
    config = load_scan_config(source=source, default_interface=default_interface)

    db_path = os.getenv("DB_PATH", f"/data/{source}_wifi_presence_scanner.db")
    if source == "agent" and db_path.startswith("/data/"):
        db_path = os.getenv("DB_PATH", "/var/lib/wifi_presence_scanner/wifi_presence_scanner.db")

    db = Database(db_path=db_path)
    scanner = build_scanner(source=source)
    publisher = EventPublisher(
        db=db,
        ha_api_url=os.getenv("HA_API_URL"),
        ha_token=os.getenv("HA_API_TOKEN"),
    )
    service = ScannerService(db=db, config=config, scanner=scanner, publisher=publisher)

    if source == "agent" and not os.getenv("API_KEY", "").strip():
        raise RuntimeError("API_KEY is required for agent source")

    default_host = "127.0.0.1" if source == "agent" else "0.0.0.0"
    host = os.getenv("HTTP_HOST", default_host)
    port = int(os.getenv("HTTP_PORT", "8099" if source == "supervisor" else "8100"))
    api_key = os.getenv("API_KEY")
    static_dir_raw = os.getenv("STATIC_DIR", "")
    static_dir = Path(static_dir_raw) if static_dir_raw else None

    api = ApiServer(
        service=service,
        host=host,
        port=port,
        api_key=api_key,
        static_dir=static_dir,
    )

    stop_event = threading.Event()

    def _stop(*_args: object) -> None:
        stop_event.set()
        api.shutdown()
        service.stop()
        db.close()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    service.start()
    try:
        api.serve_forever()
    finally:
        _stop()
