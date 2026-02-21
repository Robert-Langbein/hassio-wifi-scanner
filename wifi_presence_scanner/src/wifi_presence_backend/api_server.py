from __future__ import annotations

import json
import logging
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .service import ScannerService

_API_LOGGER = logging.getLogger("wifi_presence_scanner.api")


class ApiServer:
    def __init__(
        self,
        *,
        service: ScannerService,
        host: str,
        port: int,
        api_key: str | None,
        static_dir: Path | None = None,
        enable_access_logs: bool = False,
    ) -> None:
        self._service = service
        self._host = host
        self._port = port
        self._api_key = api_key
        self._static_dir = static_dir
        self._enable_access_logs = enable_access_logs
        self._httpd = ThreadingHTTPServer((host, port), self._build_handler())

    def _build_handler(self) -> type[BaseHTTPRequestHandler]:
        service = self._service
        api_key = self._api_key
        static_dir = self._static_dir
        enable_access_logs = self._enable_access_logs

        class Handler(BaseHTTPRequestHandler):
            server_version = "wifi-presence-scanner/1.0"

            def _is_authorized(self) -> bool:
                if not api_key:
                    return True
                header = self.headers.get("X-API-Key", "")
                if header == api_key:
                    return True
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Bearer ") and auth.removeprefix("Bearer ") == api_key:
                    return True
                return False

            def _read_json(self) -> dict[str, Any]:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0:
                    return {}
                body = self.rfile.read(length)
                payload = json.loads(body.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("JSON body must be an object")
                return payload

            def _write_json(self, *, status: int, payload: dict[str, Any]) -> None:
                encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(encoded)

            def _write_file(self, file_path: Path) -> None:
                data = file_path.read_bytes()
                mime, _ = mimetypes.guess_type(str(file_path))
                suffix = file_path.suffix.lower()
                if suffix == ".css":
                    mime = "text/css"
                elif suffix == ".js":
                    mime = "application/javascript"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", mime or "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _serve_static(self, request_path: str) -> bool:
                if not static_dir:
                    return False
                if request_path == "/":
                    index = static_dir / "index.html"
                    if index.exists():
                        self._write_file(index)
                        return True
                if request_path.startswith("/ui/"):
                    local = request_path.removeprefix("/ui/")
                    candidate = (static_dir / local).resolve()
                    try:
                        candidate.relative_to(static_dir.resolve())
                    except ValueError:
                        self._write_json(status=HTTPStatus.FORBIDDEN, payload={"error": "forbidden"})
                        return True
                    if candidate.is_file():
                        self._write_file(candidate)
                        return True
                return False

            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                query = {key: values[-1] for key, values in parse_qs(parsed.query).items()}

                if self._serve_static(parsed.path):
                    return

                if parsed.path == "/v1/health":
                    self._write_json(status=HTTPStatus.OK, payload=service.get_health())
                    return

                if not self._is_authorized():
                    self._write_json(status=HTTPStatus.UNAUTHORIZED, payload={"error": "unauthorized"})
                    return

                try:
                    if parsed.path == "/v1/networks":
                        self._write_json(status=HTTPStatus.OK, payload=service.list_networks(params=query))
                        return
                    if parsed.path.startswith("/v1/networks/") and parsed.path.endswith("/sessions"):
                        bssid = unquote(parsed.path.removeprefix("/v1/networks/").removesuffix("/sessions")).upper()
                        self._write_json(
                            status=HTTPStatus.OK,
                            payload=service.get_network_sessions(bssid=bssid),
                        )
                        return
                    if parsed.path == "/v1/novel-networks":
                        self._write_json(status=HTTPStatus.OK, payload=service.list_novel_networks(params=query))
                        return
                    if parsed.path == "/v1/rules":
                        self._write_json(status=HTTPStatus.OK, payload=service.list_rules())
                        return
                    if parsed.path == "/v1/stats/short-repeat":
                        self._write_json(status=HTTPStatus.OK, payload=service.short_repeat_stats(params=query))
                        return
                    if parsed.path == "/v1/events":
                        after_id = int(query.get("after_id", "0"))
                        limit = int(query.get("limit", "200"))
                        self._write_json(
                            status=HTTPStatus.OK,
                            payload=service.list_events(after_id=after_id, limit=limit),
                        )
                        return
                    if parsed.path == "/v1/scan-runs":
                        self._write_json(status=HTTPStatus.OK, payload=service.list_scan_runs(params=query))
                        return
                    if parsed.path.startswith("/v1/scan-runs/"):
                        suffix = parsed.path.removeprefix("/v1/scan-runs/")
                        if suffix.endswith("/observations"):
                            scan_run_id = int(suffix.removesuffix("/observations"))
                            self._write_json(
                                status=HTTPStatus.OK,
                                payload=service.list_scan_run_observations(
                                    scan_run_id=scan_run_id,
                                    params=query,
                                ),
                            )
                            return
                        scan_run_id = int(suffix)
                        self._write_json(
                            status=HTTPStatus.OK,
                            payload=service.get_scan_run_detail(scan_run_id=scan_run_id),
                        )
                        return

                    self._write_json(status=HTTPStatus.NOT_FOUND, payload={"error": "not_found"})
                except ValueError as exc:
                    self._write_json(status=HTTPStatus.BAD_REQUEST, payload={"error": str(exc)})
                except Exception as exc:
                    _API_LOGGER.exception("event=request_failed method=GET path=%s", parsed.path)
                    self._write_json(status=HTTPStatus.INTERNAL_SERVER_ERROR, payload={"error": str(exc)})

            def do_POST(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if not self._is_authorized():
                    self._write_json(status=HTTPStatus.UNAUTHORIZED, payload={"error": "unauthorized"})
                    return

                try:
                    if parsed.path == "/v1/rules":
                        payload = self._read_json()
                        created = service.create_rule(payload=payload)
                        self._write_json(status=HTTPStatus.CREATED, payload=created)
                        return
                    if parsed.path == "/v1/scan/trigger":
                        self._write_json(status=HTTPStatus.ACCEPTED, payload=service.trigger_scan())
                        return
                    if parsed.path == "/v1/history/purge":
                        self._write_json(status=HTTPStatus.OK, payload=service.purge_history())
                        return
                    if parsed.path == "/v1/novel-networks/clear":
                        payload = self._read_json()
                        self._write_json(status=HTTPStatus.OK, payload=service.clear_novel_networks(payload=payload))
                        return
                    self._write_json(status=HTTPStatus.NOT_FOUND, payload={"error": "not_found"})
                except ValueError as exc:
                    self._write_json(status=HTTPStatus.BAD_REQUEST, payload={"error": str(exc)})
                except Exception as exc:
                    _API_LOGGER.exception("event=request_failed method=POST path=%s", parsed.path)
                    self._write_json(status=HTTPStatus.INTERNAL_SERVER_ERROR, payload={"error": str(exc)})

            def do_PATCH(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if not self._is_authorized():
                    self._write_json(status=HTTPStatus.UNAUTHORIZED, payload={"error": "unauthorized"})
                    return
                if not parsed.path.startswith("/v1/rules/"):
                    self._write_json(status=HTTPStatus.NOT_FOUND, payload={"error": "not_found"})
                    return
                try:
                    rule_id = int(parsed.path.removeprefix("/v1/rules/"))
                    patched = service.patch_rule(rule_id=rule_id, payload=self._read_json())
                    if not patched:
                        self._write_json(status=HTTPStatus.NOT_FOUND, payload={"error": "not_found"})
                        return
                    self._write_json(status=HTTPStatus.OK, payload=patched)
                except ValueError as exc:
                    self._write_json(status=HTTPStatus.BAD_REQUEST, payload={"error": str(exc)})
                except Exception as exc:
                    _API_LOGGER.exception("event=request_failed method=PATCH path=%s", parsed.path)
                    self._write_json(status=HTTPStatus.INTERNAL_SERVER_ERROR, payload={"error": str(exc)})

            def do_DELETE(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if not self._is_authorized():
                    self._write_json(status=HTTPStatus.UNAUTHORIZED, payload={"error": "unauthorized"})
                    return
                if not parsed.path.startswith("/v1/rules/"):
                    self._write_json(status=HTTPStatus.NOT_FOUND, payload={"error": "not_found"})
                    return
                try:
                    rule_id = int(parsed.path.removeprefix("/v1/rules/"))
                    deleted = service.delete_rule(rule_id=rule_id)
                    if not deleted:
                        self._write_json(status=HTTPStatus.NOT_FOUND, payload={"error": "not_found"})
                        return
                    self._write_json(status=HTTPStatus.OK, payload={"deleted": True})
                except ValueError as exc:
                    self._write_json(status=HTTPStatus.BAD_REQUEST, payload={"error": str(exc)})
                except Exception as exc:
                    _API_LOGGER.exception("event=request_failed method=DELETE path=%s", parsed.path)
                    self._write_json(status=HTTPStatus.INTERNAL_SERVER_ERROR, payload={"error": str(exc)})

            def log_message(self, format: str, *args: object) -> None:
                if not enable_access_logs:
                    return
                _API_LOGGER.debug(
                    "event=http_access client=%s message=%s",
                    self.address_string(),
                    format % args,
                )

        return Handler

    def serve_forever(self) -> None:
        self._httpd.serve_forever(poll_interval=0.5)

    def shutdown(self) -> None:
        self._httpd.shutdown()
