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

WORKDIR /app

COPY . /app/
RUN mkdir -p /app/logs

# Tester-facing DoIP: plain 13400 / TLS 3496 (TCP) + 13400 (UDP discovery)
EXPOSE 13400/tcp 3496/tcp 13400/udp

CMD ["python3", "main.py", "--config", "/app/config.yaml", "--log-level", "INFO"]
