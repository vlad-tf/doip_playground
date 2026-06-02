"""
DoIP EdgeNode — entry point.

Usage:
    python3 main.py [--config config.yaml] [--log-level INFO]

Known limitations (PoC scope):
    - Single tester connection only; second connection is rejected immediately.
    - TLS fault injection is not functional; TLSFaultPolicy fields are placeholders.
    - No certificate revocation check (CRL/OCSP).
    - Config changes require restart (no SIGHUP hot-reload).
    - OEM-specific routing activation types (0x02+) are passed through without
      interpretation.
    - TLS server-side handshake via TLSBridge is a TODO placeholder; port 3496
      currently accepts plaintext connections.
"""

import argparse
import asyncio
import logging
import os
import sys

# Allow running as: python3 main.py from the doip_edgenode/ directory
sys.path.insert(0, os.path.dirname(__file__))

from config import load_config, ConfigError
from server import DoIPServer


def main() -> None:
    parser = argparse.ArgumentParser(description="DoIP EdgeNode")
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to config.yaml (default: config.yaml)"
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity (default: INFO)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        logging.critical("Configuration error: %s", exc)
        sys.exit(1)

    server = DoIPServer(config)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("Shutting down.")
        sys.exit(0)


if __name__ == "__main__":
    main()
