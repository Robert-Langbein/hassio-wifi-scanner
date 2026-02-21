ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base:3.22
FROM ${BUILD_FROM}

SHELL ["/bin/ash", "-o", "pipefail", "-c"]

RUN apk add --no-cache python3

COPY rootfs /
COPY src /opt/wifi_presence_scanner/src
RUN chmod a+x /etc/services.d/wifi_presence_scanner/run
