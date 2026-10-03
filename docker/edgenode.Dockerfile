# DoIP EdgeNode image
# Build context = ../doip_edgenode
# Debian base + apt-installed Python deps (no pip — proxy-friendly).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-yaml \
        python3-scapy \
        python3-cryptography \
        libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Dedicated non-root user. /app/logs is a plain container-internal directory
# (not bind-mounted), so there's nothing on the host to chown at startup --
# `docker logs doip-edgenode` already gets everything via the logger's
# stdout handler, and the file copy under /app/logs is just a bonus that
# lives and dies with the container.
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd -g "$APP_GID" doip \
    && useradd -u "$APP_UID" -g "$APP_GID" -M -s /usr/sbin/nologin doip

WORKDIR /app

COPY . /app/
RUN mkdir -p /app/logs && chown -R doip:doip /app

USER doip

# Tester-facing DoIP: plain 13400 / TLS 3496 (TCP) + 13400 (UDP discovery)
EXPOSE 13400/tcp 3496/tcp 13400/udp

CMD ["python3", "main.py", "--config", "/app/config.yaml", "--log-level", "INFO"]
