# DoIP Echo ECU image (pure stdlib, IPv6 listener)
# Build context = ../echo_ecu
# Debian base + apt-installed Python deps (no pip — proxy-friendly).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-yaml \
    && rm -rf /var/lib/apt/lists/*

# Dedicated non-root user -- config.yaml is mounted :ro and this image never
# writes to disk at runtime, so no chown-on-startup dance is needed here.
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd -g "$APP_GID" doip \
    && useradd -u "$APP_UID" -g "$APP_GID" -M -s /usr/sbin/nologin doip

WORKDIR /app

COPY . /app/
RUN chown -R doip:doip /app

USER doip

EXPOSE 13400/tcp 13400/udp

CMD ["python3", "echo_ecu.py", "--config", "/app/config.yaml", "--log-level", "INFO"]
