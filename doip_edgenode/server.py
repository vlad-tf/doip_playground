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

"""
DoIP EdgeNode — asyncio TCP server.

Accepts one connection at a time (PoC scope).  A second incoming
connection is immediately closed if one session is already active.

Starts:
  - Plain TCP server on config.ports.doip_plain (typically 13400)
  - TLS TCP server on config.ports.doip_tls (typically 3496)
  - UDPAnnouncer

Layer bindings for Scapy are registered once at module import time.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from config import AppConfig, MiddlewareConfig
from routing import RoutingTable
from middleware import Middleware, MiddlewareChain
from session import DoIPSession
from session_registry import SessionRegistry
from udp_announcer import UDPAnnouncer

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scapy layer bindings — must run at import time, before any sockets
# ---------------------------------------------------------------------------

def _register_layer_bindings() -> None:
    """Register DoIP and TLS on their respective TCP ports."""
    try:
        from scapy.layers.inet import TCP  # type: ignore[import]
        from scapy.layers.tls.record import TLS  # type: ignore[import]
        from scapy.contrib.automotive.doip import DoIP  # type: ignore[import]
        from scapy.packet import bind_layers  # type: ignore[import]

        bind_layers(TCP, TLS,  dport=3496)
        bind_layers(TCP, TLS,  sport=3496)
        bind_layers(TCP, DoIP, dport=13400)
        bind_layers(TCP, DoIP, sport=13400)
        logger.debug("server: Scapy layer bindings registered")
    except ImportError:
        logger.warning("server: Scapy not available; layer bindings skipped")


_register_layer_bindings()


# ---------------------------------------------------------------------------
# Middleware factory
# ---------------------------------------------------------------------------

def _build_middleware(mw_configs: list[MiddlewareConfig]) -> list[Middleware]:
    """Instantiate middleware classes from config objects."""
    from middleware.logger import LoggerMiddleware
    from middleware.drop import DropMiddleware
    from middleware.delay import DelayMiddleware
    from middleware.corrupt import CorruptMiddleware
    from middleware.replay import ReplayMiddleware
    from middleware.address import AddressMiddleware
    from middleware.header_fault import HeaderFaultMiddleware
    from middleware.tls_fault import TLSFaultMiddleware

    _CLASS_MAP = {
        "LoggerMiddleware":      LoggerMiddleware,
        "DropMiddleware":        DropMiddleware,
        "DelayMiddleware":       DelayMiddleware,
        "CorruptMiddleware":     CorruptMiddleware,
        "ReplayMiddleware":      ReplayMiddleware,
        "AddressMiddleware":     AddressMiddleware,
        "HeaderFaultMiddleware": HeaderFaultMiddleware,
        "TLSFaultMiddleware":    TLSFaultMiddleware,
    }

    instances: list[Middleware] = []
    for mw in mw_configs:
        cls = _CLASS_MAP.get(mw.type)
        if cls is None:
            logger.warning("server: unknown middleware type %r — skipping", mw.type)
            continue
        obj = cls(**mw.params)
        obj.enabled = mw.enabled
        instances.append(obj)
        logger.debug("server: loaded middleware %s (enabled=%s)", mw.type, mw.enabled)
    return instances


# ---------------------------------------------------------------------------
# DoIPServer
# ---------------------------------------------------------------------------


class DoIPServer:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._routing_table = RoutingTable(config.routing_table)
        self._middleware_chain = MiddlewareChain(
            _build_middleware(config.middleware)
        )
        self._executor = ThreadPoolExecutor(
            max_workers=8, thread_name_prefix="doip-tls"
        )
        self._loop: asyncio.AbstractEventLoop | None = None
        self._registry = SessionRegistry()
        self._udp_announcer = UDPAnnouncer(config)

    async def start(self) -> None:
        """Start all servers and run until cancelled."""
        self._loop = asyncio.get_running_loop()

        # Plain TCP server
        plain_server = await asyncio.start_server(
            lambda r, w: self._handle_connection(r, w, use_tls=False),
            host=self._config.network.tester_ipv4,
            port=self._config.ports.doip_plain,
        )
        logger.info(
            "DoIPServer: plain TCP listening on %s:%d",
            self._config.network.tester_ipv4,
            self._config.ports.doip_plain,
        )

        # TLS TCP server
        tls_server = await asyncio.start_server(
            lambda r, w: self._handle_connection(r, w, use_tls=True),
            host=self._config.network.tester_ipv4,
            port=self._config.ports.doip_tls,
        )
        logger.info(
            "DoIPServer: TLS TCP listening on %s:%d",
            self._config.network.tester_ipv4,
            self._config.ports.doip_tls,
        )

        # UDP announcer
        await self._udp_announcer.start()

        async with plain_server, tls_server:
            await asyncio.gather(
                plain_server.serve_forever(),
                tls_server.serve_forever(),
            )

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        use_tls: bool,
    ) -> None:
        """Called by asyncio for each new incoming TCP connection."""
        peer = writer.get_extra_info("peername")
        logger.info("DoIPServer: new connection from %s (use_tls=%s)", peer, use_tls)

        if use_tls:
            # Perform TLS handshake before creating the DoIPSession.
            # On failure, close and return (TLS layer sends the alert).
            tls_ok = await self._do_tls_handshake(reader, writer)
            if not tls_ok:
                return

        session = DoIPSession(
            reader=reader,
            writer=writer,
            config=self._config,
            routing_table=self._routing_table,
            middleware_chain=self._middleware_chain,
            loop=self._loop,
            executor=self._executor,
            registry=self._registry,
        )
        await session.run()

    async def _do_tls_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> bool:
        """
        Perform server-side TLS handshake via TLSBridge.

        Returns True on success, False on failure.

        NOTE: In the PoC, the asyncio streams (reader/writer) handed to us
        by asyncio.start_server are plain TCP.  For TLS, we would need to
        intercept at the socket level.  The current implementation logs a
        warning and passes through without TLS — a full TLS integration
        requires creating the server socket manually and wrapping it with
        TLSBridge before handing to the session.

        # TODO: implement full TLS server handshake using TLSBridge.
        #       This requires:
        #       1. Create a raw socket server (not asyncio.start_server)
        #       2. Accept raw socket
        #       3. Instantiate TLSBridge(sock, TLSServerAutomaton, ...)
        #       4. Await bridge.handshake()
        #       5. Wrap bridge in stream-like interface for DoIPSession
        #       See requirements §TLS bridge for the two-executor-task pattern.
        """
        logger.warning(
            "DoIPServer: TLS handshake on port %d is a TODO placeholder — "
            "accepting connection as plaintext for now",
            self._config.ports.doip_tls,
        )
        return True
