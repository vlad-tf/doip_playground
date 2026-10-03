# DoIP TestEcu image — extensible UDS ECU simulator (pure stdlib + PyYAML)
# Build context = ../test_ecu
# Debian base + apt-installed Python deps (no pip — proxy-friendly).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-yaml \
    && rm -rf /var/lib/apt/lists/*

# Dedicated non-root user. config.yaml and plugins/ are both mounted :ro and
# PYTHONDONTWRITEBYTECODE below means this image never writes to disk at
# runtime, so no chown-on-startup dance is needed here.
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd -g "$APP_GID" doip \
    && useradd -u "$APP_UID" -g "$APP_GID" -M -s /usr/sbin/nologin doip

WORKDIR /app

COPY . /app/
RUN chown -R doip:doip /app

# `COPY . /app/` puts the package at /app/testecu, so `python3 -m testecu` works
# with no packaging step.  PYTHONPATH makes that true regardless of the CWD a
# user picks with `docker compose exec`.
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

USER doip

EXPOSE 13400/tcp 13400/udp

CMD ["python3", "-m", "testecu", "--config", "/app/config.yaml", "--log-level", "INFO"]
