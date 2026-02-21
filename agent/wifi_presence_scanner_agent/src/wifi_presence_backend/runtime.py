from __future__ import annotations

import logging
import os
import signal
import threading
from http import HTTPStatus
from pathlib import Path

from .api_server import ApiServer
from .config import load_scan_config
from .db import Database
from .scanner import IWScanner, SupervisorApiError, SupervisorApiScanner
from .service import EventPublisher, ScannerService

_RUNTIME_LOGGER = logging.getLogger("wifi_presence_scanner.runtime")


def configure_logging() -> str:
    raw_level = os.getenv("LOG_LEVEL", "info").strip().upper()
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    level = level_map.get(raw_level, logging.INFO)

    logging.basicConfig(
        level=level,
        format="ts=%(asctime)s level=%(levelname)s logger=%(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        force=True,
    )
    return logging.getLevelName(level).lower()


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


def _run_supervisor_preflight(*, scanner: SupervisorApiScanner, interface: str) -> None:
    try:
        network_info = scanner.get_network_info()
        interfaces = network_info.get("interfaces")
        interfaces_count = len(interfaces) if isinstance(interfaces, list) else 0
        _RUNTIME_LOGGER.info(
            "event=supervisor_preflight_ok endpoint=/network/info interface_count=%s",
            interfaces_count,
        )
    except SupervisorApiError as exc:
        if exc.status_code == HTTPStatus.FORBIDDEN:
            _RUNTIME_LOGGER.error(
                "event=supervisor_preflight_forbidden endpoint=/network/info interface=%s "
                "reason=supervisor_forbidden hint=requires_hassio_role_manager_and_restart message=%s",
                interface,
                str(exc),
            )
        else:
            _RUNTIME_LOGGER.error(
                "event=supervisor_preflight_failed endpoint=/network/info interface=%s message=%s",
                interface,
                str(exc),
            )
        return

    try:
        interface_info = scanner.get_interface_info(interface=interface)
        if_name = str(interface_info.get("interface") or interface)
        _RUNTIME_LOGGER.info(
            "event=supervisor_preflight_ok endpoint=/network/interface/%s/info interface=%s",
            interface,
            if_name,
        )
    except SupervisorApiError as exc:
        if exc.status_code == HTTPStatus.FORBIDDEN:
            _RUNTIME_LOGGER.error(
                "event=supervisor_preflight_forbidden endpoint=/network/interface/%s/info interface=%s "
                "reason=supervisor_forbidden hint=requires_hassio_role_manager_and_restart message=%s",
                interface,
                interface,
                str(exc),
            )
            return
        _RUNTIME_LOGGER.error(
            "event=supervisor_preflight_failed endpoint=/network/interface/%s/info interface=%s message=%s",
            interface,
            interface,
            str(exc),
        )
        return

    _RUNTIME_LOGGER.info(
        "event=supervisor_preflight_note endpoint=/network/interface/%s/accesspoints requirement=hassio_role_manager",
        interface,
    )


def run_backend(*, source: str) -> None:
    configured_log_level = configure_logging()
    _RUNTIME_LOGGER.info("event=backend_start source=%s log_level=%s", source, configured_log_level)

    default_interface = "wlan0"
    config = load_scan_config(source=source, default_interface=default_interface)

    db_path = os.getenv("DB_PATH", f"/data/{source}_wifi_presence_scanner.db")
    if source == "agent" and db_path.startswith("/data/"):
        db_path = os.getenv("DB_PATH", "/var/lib/wifi_presence_scanner/wifi_presence_scanner.db")

    db = Database(db_path=db_path)
    scanner = build_scanner(source=source)
    if source == "supervisor" and isinstance(scanner, SupervisorApiScanner):
        _run_supervisor_preflight(scanner=scanner, interface=config.interface)
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
        enable_access_logs=configured_log_level == "debug",
    )

    stop_event = threading.Event()

    def _stop(*_args: object) -> None:
        stop_event.set()
        _RUNTIME_LOGGER.info("event=backend_stop source=%s", source)
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
