# DoIP PC Tester image (interactive REPL, pure stdlib)
# Build context = ../pc_tester
# Debian base + apt-installed Python deps (no pip — proxy-friendly).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-yaml \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app/

# Interactive tester. It auto-sends Routing Activation on connect,
# then drops into the "doip>" REPL. Attach a terminal to interact:
#   docker attach doip-pc-tester
CMD ["python3", "tester.py", "--config", "/app/config.yaml"]
