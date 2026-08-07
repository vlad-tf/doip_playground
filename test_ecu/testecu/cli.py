# Copyright 2026 Vladislav Vostrykh, Technica Engineering GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Command line entry point for TestEcu."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import List, Optional

from testecu.config import ConfigError, EcuConfig, PluginSpec, load_config
from testecu.core import EcuCore
from testecu.server import TestEcuServer

logger = logging.getLogger("testecu")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="testecu",
        description="TestEcu — an extensible DoIP/UDS ECU simulator",
    )
    parser.add_argument("--config", default="config.yaml",
                        help="path to the YAML config (default: config.yaml)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--host", help="override listen.host")
    parser.add_argument("--port", type=int, help="override listen.port")
    parser.add_argument("--interface",
                        help="override listen.interface (use \"\" for none)")
    parser.add_argument("--no-udp", action="store_true",
                        help="skip the UDP announcer (needed on macOS: joining "
                             "ff02::1 on lo0 fails)")
    parser.add_argument("--plugin", action="append", default=[], metavar="PATH",
                        help="load an extra plugin file; repeatable")
    parser.add_argument("--check", action="store_true",
                        help="load the config and plugins, print the resolved hook "
                             "table, and exit")
    return parser


def apply_overrides(config: EcuConfig, args: argparse.Namespace) -> EcuConfig:
    if args.host is not None:
        config.listen.host = args.host
    if args.port is not None:
        config.listen.port = args.port
    if args.interface is not None:
        config.listen.interface = args.interface
    if args.no_udp:
        config.udp.enabled = False
    for index, path in enumerate(args.plugin):
        resolved = path if os.path.isabs(path) else os.path.join(config.base_dir, path)
        config.plugins.specs.append(
            PluginSpec(label="--plugin %s" % path, file=resolved,
                       priority=-1000 - index)
        )
    return config


def _print_check(ecu: EcuCore) -> int:
    print("TestEcu configuration check")
    print("=" * 60)
    for line in ecu.describe():
        print(line)
    print("=" * 60)
    print("OK")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    try:
        config = apply_overrides(load_config(args.config), args)
        ecu = EcuCore(config)
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        return 2
    except Exception:
        logger.exception("Failed to start")
        return 2

    if args.check:
        return _print_check(ecu)

    server = TestEcuServer(ecu)
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\nShutting down.")
    except OSError as exc:
        logger.error("Cannot listen on [%s]:%d — %s",
                     config.listen.host, config.listen.port, exc)
        return 1
    return 0


if __name__ == "__main__":       # pragma: no cover
    sys.exit(main())
