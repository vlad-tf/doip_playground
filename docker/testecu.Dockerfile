# DoIP TestEcu image — extensible UDS ECU simulator (pure stdlib + PyYAML)
# Build context = ../test_ecu
# Debian base + apt-installed Python deps (no pip — proxy-friendly).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-yaml \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app/

# `COPY . /app/` puts the package at /app/testecu, so `python3 -m testecu` works
# with no packaging step.  PYTHONPATH makes that true regardless of the CWD a
# user picks with `docker compose exec`.
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 13400/tcp 13400/udp

CMD ["python3", "-m", "testecu", "--config", "/app/config.yaml", "--log-level", "INFO"]
