# DoIP PC Tester image (interactive REPL, pure stdlib)
# Build context = ../pc_tester
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

# Interactive tester. It auto-sends Routing Activation on connect,
# then drops into the "doip>" REPL. Attach a terminal to interact:
#   docker attach doip-pc-tester
CMD ["python3", "tester.py", "--config", "/app/config.yaml"]
