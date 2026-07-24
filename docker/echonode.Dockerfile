# DoIP Echo ECU image (pure stdlib, IPv6 listener)
# Build context = ../echo_ecu
# Debian base + apt-installed Python deps (no pip — proxy-friendly).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-yaml \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app/

EXPOSE 13400/tcp 13400/udp

CMD ["python3", "echo_ecu.py", "--config", "/app/config.yaml", "--log-level", "INFO"]
