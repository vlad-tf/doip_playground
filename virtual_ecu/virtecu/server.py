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
The TCP listener.

Port of ``echo_ecu.EchoECUServer``: the socket is built by hand so that
``IPV6_V6ONLY`` can be set and a link-local address can be bound with its
interface scope id.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from typing import Optional

from virtecu.core import EcuCore
from virtecu.session import EcuSession, SessionRegistry
from virtecu.udp import run_announcer

logger = logging.getLogger("virtecu.server")


class VirtualEcuServer:
    """Accepts tester connections and hands each one to an ``EcuSession``."""

    __test__ = False

    def __init__(self, ecu: EcuCore, backlog: int = 8) -> None:
        self._ecu = ecu
        self._registry = SessionRegistry()
        self._backlog = backlog
        self._udp_task: Optional[asyncio.Task] = None
        self.port: int = ecu.config.listen.port

    # -----------------------------------------------------------------------

    def _build_socket(self) -> socket.socket:
        listen = self._ecu.config.listen
        if listen.family == "ipv4":
            host = listen.host if listen.host not in ("", "::") else "0.0.0.0"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, listen.port))
            sock.listen(self._backlog)
            return sock

        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Single-family IPv6 listens on v6 only; ``dual`` leaves V6ONLY off so
        # the same socket also accepts v4-mapped connections (ListenConfig's
        # "family" default is ipv6).
        if listen.family != "dual":
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except (AttributeError, OSError):
                pass  # not available everywhere

        scope_id = 0
        if listen.interface:
            try:
                scope_id = socket.if_nametoindex(listen.interface)
            except OSError as exc:
                logger.warning("Cannot get scope_id for interface %r: %s  (using 0)",
                               listen.interface, exc)

        # The sockaddr_in6 scope/zone field is meaningful for link-local and
        # multicast addresses. Global/ULA unicast addresses must use scope 0;
        # Windows rejects a non-zero scope there with WSAEADDRNOTAVAIL.
        try:
            address = ipaddress.IPv6Address(listen.host.split("%", 1)[0])
        except ipaddress.AddressValueError:
            address = None
        if address is None or not (address.is_link_local or address.is_multicast):
            scope_id = 0

        sock.bind((listen.host, listen.port, 0, scope_id))
        sock.listen(self._backlog)
        return sock

    async def start(self, serve_forever: bool = True) -> asyncio.AbstractServer:
        """
        Bring the ECU up: run plugin ``setup()``, bind, and start the announcer.

        With ``serve_forever=False`` the bound server is returned immediately so
        tests can drive it and shut it down themselves.
        """
        await self._ecu.startup()

        sock = self._build_socket()
        server = await asyncio.start_server(self._handle_connection, sock=sock)

        bound = sock.getsockname()
        self.port = bound[1]
        listen = self._ecu.config.listen
        logger.info("VirtualEcu listening on [%s]:%d  (interface=%s)",
                    bound[0], bound[1], listen.interface or "any")

        for line in self._ecu.describe():
            logger.info("  %s", line)

        if self._ecu.config.udp.enabled:
            self._udp_task = asyncio.ensure_future(run_announcer(
                self._ecu.config, registry=self._registry,
                max_sockets=self._ecu.config.doip.max_concurrent_sessions,
                doip_hooks=self._ecu.doip_hooks,
            ))
        else:
            logger.info("UDP announcer disabled")

        if not serve_forever:
            return server

        print("VirtualEcu ready — listening on [%s]:%d" % (bound[0], bound[1]))
        print("Press Ctrl+C to stop.\n")
        try:
            async with server:
                await server.serve_forever()
        finally:
            await self.stop()
        return server

    async def stop(self) -> None:
        if self._udp_task is not None and not self._udp_task.done():
            self._udp_task.cancel()
            try:
                await self._udp_task
            except (asyncio.CancelledError, Exception):
                pass
            self._udp_task = None
        await self._ecu.shutdown()

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter) -> None:
        await EcuSession(reader, writer, self._ecu, self._registry).run()
