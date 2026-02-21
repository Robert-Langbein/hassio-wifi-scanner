FROM python:3.12-alpine

RUN apk add --no-cache iw

WORKDIR /opt/wifi_presence_scanner
COPY agent/wifi_presence_scanner_agent/src /opt/wifi_presence_scanner/src

ENV PYTHONPATH=/opt/wifi_presence_scanner/src \
    HTTP_HOST=0.0.0.0 \
    HTTP_PORT=8100 \
    DB_PATH=/var/lib/wifi_presence_scanner/wifi_presence_scanner.db \
    WIFI_INTERFACE=wlan0 \
    SCAN_INTERVAL_SEC=30 \
    DISAPPEAR_MISSED_SCANS=2 \
    RETENTION_DAYS=30

VOLUME ["/var/lib/wifi_presence_scanner"]
EXPOSE 8100

CMD ["python", "-m", "wifi_presence_backend.agent_main"]
