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
from typing import Optional, Set

from virtecu.core import EcuCore
from virtecu.netutil import resolve_if_index
from virtecu.session import EcuSession, SessionRegistry
from virtecu.udp import run_announcer

logger = logging.getLogger("virtecu.server")

#: Upper bounds for ``stop()``: a peer that never lets its session unwind, or a
#: platform whose ``wait_closed()`` does not return promptly, must not be able
#: to hang shutdown.
_SESSION_DRAIN_TIMEOUT = 5.0
_LISTENER_CLOSE_TIMEOUT = 2.0


class VirtualEcuServer:
    """Accepts tester connections and hands each one to an ``EcuSession``."""

    __test__ = False

    def __init__(self, ecu: EcuCore, backlog: int = 8) -> None:
        self._ecu = ecu
        self._registry = SessionRegistry()
        self._backlog = backlog
        self._udp_task: Optional[asyncio.Task] = None
        self._server: Optional[asyncio.AbstractServer] = None
        self._sessions: Set[asyncio.Task] = set()
        self.port: int = ecu.config.listen.port

    # -----------------------------------------------------------------------

    def _build_socket(self) -> socket.socket:
        listen = self._ecu.config.listen
        family = socket.AF_INET if listen.family == "ipv4" else socket.AF_INET6
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            self._bind_listen(sock, listen)
        except BaseException:
            sock.close()      # never hand back (or leak) a half-set-up socket
            raise
        return sock

    def _bind_listen(self, sock: socket.socket, listen) -> None:
        if listen.family == "ipv4":
            host = listen.host if listen.host not in ("", "::") else "0.0.0.0"
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, listen.port))
            sock.listen(self._backlog)
            return

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Single-family IPv6 listens on v6 only; ``dual`` leaves V6ONLY off so
        # the same socket also accepts v4-mapped connections (ListenConfig's
        # "family" default is ipv6).
        if listen.family != "dual":
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except (AttributeError, OSError):
                pass  # not available everywhere

        scope_id = resolve_if_index(listen.interface, "TCP")

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

    async def start(self, serve_forever: bool = True) -> asyncio.AbstractServer:
        """
        Bring the ECU up: run plugin ``setup()``, bind, and start the announcer.

        With ``serve_forever=False`` the bound server is returned immediately so
        tests can drive it and shut it down themselves.
        """
        await self._ecu.startup()

        # Anything acquired from here on is released again, in reverse order,
        # if a later step fails or the start is cancelled; the original
        # exception then propagates unchanged.
        sock: Optional[socket.socket] = None
        try:
            sock = self._build_socket()
            server = await asyncio.start_server(self._handle_connection, sock=sock)
            self._server = server
            bound = sock.getsockname()
            sock = None                   # the server owns the socket now
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
        except BaseException:
            if sock is not None:
                sock.close()
            try:
                await self.stop()
            except Exception:
                logger.exception("rollback after a failed start also failed")
            raise

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
        """
        Release everything ``start()`` acquired; safe to call more than once.

        Order: stop accepting, end live sessions, wait for the listener to
        close, stop the announcer, then shut the ECU core down (which closes
        the retained per-tester state).
        """
        server, self._server = self._server, None
        if server is not None:
            server.close()
            # Let a connection accepted just before close() start its handler
            # so it is tracked (and cancelled) below.
            await asyncio.sleep(0)
        await self._drain_sessions()
        if server is not None:
            try:
                await asyncio.wait_for(server.wait_closed(), _LISTENER_CLOSE_TIMEOUT)
            except Exception:
                logger.warning("listener did not finish closing within %.1fs",
                               _LISTENER_CLOSE_TIMEOUT)
        if self._udp_task is not None and not self._udp_task.done():
            self._udp_task.cancel()
            try:
                await self._udp_task
            except (asyncio.CancelledError, Exception):
                pass
            self._udp_task = None
        await self._ecu.shutdown()

    async def _drain_sessions(self) -> None:
        """Cancel every live session task and wait (bounded) for it to unwind."""
        current = asyncio.current_task()
        tasks = [task for task in self._sessions if task is not current]
        for task in tasks:
            task.cancel()
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=_SESSION_DRAIN_TIMEOUT)
            if pending:
                logger.warning("%d session task(s) still running %.1fs after cancel",
                               len(pending), _SESSION_DRAIN_TIMEOUT)

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._sessions.add(task)
            task.add_done_callback(self._sessions.discard)
        await EcuSession(reader, writer, self._ecu, self._registry).run()
