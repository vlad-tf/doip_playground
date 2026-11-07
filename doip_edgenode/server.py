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

Accepts up to the configured tester capacity concurrently.  An additional
reserve socket is admitted for pre-routing-activation setup.

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

from config import AppConfig, ConfigError, MiddlewareConfig
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

def _build_middleware(mw_configs: list[MiddlewareConfig], *, sink_owner=None) -> list[Middleware]:
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
    try:
        for mw in mw_configs:
            cls = _CLASS_MAP.get(mw.type)
            if cls is None:
                raise ConfigError(f"middleware: unknown type {mw.type!r}")
            if cls is LoggerMiddleware:
                # Internal lifecycle arguments must not be overridden by config.
                params = {k: v for k, v in mw.params.items()
                          if k not in ("_sink_owner", "_open_sink")}
                obj = cls(**params, _sink_owner=sink_owner, _open_sink=mw.enabled)
            else:
                obj = cls(**mw.params)
            obj.enabled = mw.enabled
            instances.append(obj)
            logger.debug("server: loaded middleware %s (enabled=%s)", mw.type, mw.enabled)
    except BaseException:
        for obj in instances:
            if isinstance(obj, LoggerMiddleware):
                obj.close()
        raise
    return instances


# ---------------------------------------------------------------------------
# DoIPServer
# ---------------------------------------------------------------------------


class DoIPServer:
    def __init__(self, config: AppConfig) -> None:
        from middleware.logger import LogSinkOwner

        self._config = config
        self._routing_table = RoutingTable(config.routing_table)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._registry = SessionRegistry(config.doip.max_connections)
        self._udp_announcer = UDPAnnouncer(config, self._registry)
        self._listeners: set[asyncio.AbstractServer] = set()
        self._connection_tasks: set[asyncio.Task] = set()
        self._connection_writers: dict[asyncio.Task, asyncio.StreamWriter] = {}
        self._sessions: set[DoIPSession] = set()
        self._started = False
        self._cleanup_task: asyncio.Task | None = None
        self._executor_shutdown = False
        self._closing = False
        self._startup_task: asyncio.Task | None = None
        self._serve_tasks: set[asyncio.Task] = set()
        self._log_sink_owner = LogSinkOwner()
        try:
            # Validate startup parameters; connections borrow these server sinks.
            _build_middleware(config.middleware, sink_owner=self._log_sink_owner)
            self._executor = ThreadPoolExecutor(
                max_workers=8, thread_name_prefix="doip-tls"
            )
        except BaseException:
            self._log_sink_owner.close()
            raise

    async def start(self) -> None:
        """Start all servers and run until cancelled."""
        if self._started or self._closing:
            raise RuntimeError("DoIPServer is single-use and already started or stopped")
        self._started = True
        self._loop = asyncio.get_running_loop()
        self._startup_task = asyncio.create_task(self._start_resources())
        try:
            await self._startup_task
            if self._closing:
                return
            self._serve_tasks.update(
                asyncio.create_task(listener.serve_forever())
                for listener in self._listeners
            )
            await asyncio.gather(*self._serve_tasks)
        finally:
            await self.stop()

    async def _start_resources(self) -> None:
        """Acquire startup resources, recording each one before suspension."""
        plain_server = await asyncio.start_server(
            lambda r, w: self._accept_connection(r, w, False),
            host=self._config.network.tester_ipv4,
            port=self._config.ports.doip_plain,
        )
        self._listeners.add(plain_server)
        logger.info("DoIPServer: plain TCP listening on %s:%d",
                    self._config.network.tester_ipv4, self._config.ports.doip_plain)
        tls_server = await asyncio.start_server(
            lambda r, w: self._accept_connection(r, w, True),
            host=self._config.network.tester_ipv4,
            port=self._config.ports.doip_tls,
        )
        self._listeners.add(tls_server)
        logger.info("DoIPServer: TLS TCP listening on %s:%d",
                    self._config.network.tester_ipv4, self._config.ports.doip_tls)
        await self._udp_announcer.start()

    def _accept_connection(self, reader, writer, use_tls: bool) -> None:
        if self._closing:
            try:
                writer.close()
            except Exception:
                logger.debug("DoIPServer: late accept close failed", exc_info=True)
            return
        task = asyncio.create_task(self._handle_connection(reader, writer, use_tls))
        self._connection_tasks.add(task)
        self._connection_writers[task] = writer
        def finished(done):
            self._connection_tasks.discard(done)
            self._connection_writers.pop(done, None)
            if not done.cancelled():
                error = done.exception()
                if error is not None:
                    logger.error("DoIPServer: connection handler failed: %s", error)
        task.add_done_callback(finished)

    async def stop(self) -> None:
        """Idempotently stop, shielding shared cleanup from caller cancellation."""
        self._closing = True
        # Accepted callbacks can precede the first handler step. Closing here
        # also releases capacity before listener/UDP teardown can suspend.
        for writer in tuple(self._connection_writers.values()):
            try:
                writer.close()
            except Exception:
                logger.debug("DoIPServer: accepted writer close failed", exc_info=True)
            self._registry.release(writer)
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup())
        cancelled = False
        while not self._cleanup_task.done():
            try:
                await asyncio.shield(self._cleanup_task)
            except asyncio.CancelledError:
                cancelled = True
        self._cleanup_task.result()
        if cancelled:
            raise asyncio.CancelledError

    async def _cleanup(self) -> None:
        self._closing = True
        startup = self._startup_task
        if startup is not None and not startup.done():
            startup.cancel()
        if startup is not None:
            await asyncio.gather(startup, return_exceptions=True)
        serve_tasks = tuple(self._serve_tasks)
        self._serve_tasks.clear()
        for task in serve_tasks:
            task.cancel()
        if serve_tasks:
            await asyncio.gather(*serve_tasks, return_exceptions=True)
        listeners = tuple(self._listeners)
        self._listeners.clear()
        for listener in listeners:
            try:
                listener.close()
            except Exception:
                logger.debug("DoIPServer: listener close failed", exc_info=True)
        await asyncio.gather(*(listener.wait_closed() for listener in listeners),
                              return_exceptions=True)
        try:
            await self._udp_announcer.stop()
        finally:
            tasks = tuple(self._connection_tasks)
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            sessions = tuple(self._sessions)
            self._sessions.clear()
            if sessions:
                await asyncio.gather(*(session.close() for session in sessions),
                                     return_exceptions=True)
            try:
                if not self._executor_shutdown:
                    self._executor_shutdown = True
                    self._executor.shutdown(wait=True)
            finally:
                self._log_sink_owner.close()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        use_tls: bool,
    ) -> None:
        """Reserve capacity before handshake/setup; overflow gets no DoIP response."""
        if self._closing:
            try:
                writer.close()
            finally:
                self._registry.release(writer)
            return
        if not self._registry.reserve(writer):
            try:
                writer.close()
            except Exception:
                logger.debug("DoIPServer: overflow writer cleanup failed", exc_info=True)
            return
        try:
            await self._run_connection(reader, writer, use_tls)
        finally:
            # Release synchronously even if session teardown is interrupted.
            try:
                writer.close()
            except Exception:
                logger.debug("DoIPServer: writer cleanup failed", exc_info=True)
                self._registry.release(writer)
            else:
                self._registry.release(writer)
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                except Exception:
                    logger.debug("DoIPServer: writer cleanup failed", exc_info=True)

    async def _run_connection(self, reader, writer, use_tls: bool) -> None:
        peer = writer.get_extra_info("peername")
        logger.info("DoIPServer: new connection from %s (use_tls=%s)", peer, use_tls)

        if use_tls:
            # Perform TLS handshake before creating the DoIPSession.
            # On failure, close and return (TLS layer sends the alert).
            tls_ok = await self._do_tls_handshake(reader, writer)
            if not tls_ok:
                return

        try:
            middleware_chain = MiddlewareChain(
                _build_middleware(self._config.middleware, sink_owner=self._log_sink_owner)
            )
        except Exception:
            logger.exception("DoIPServer: middleware setup failed for %s", peer)
            return

        session = DoIPSession(
            reader=reader,
            writer=writer,
            config=self._config,
            routing_table=self._routing_table,
            middleware_chain=middleware_chain,
            loop=self._loop,
            executor=self._executor,
            registry=self._registry,
        )
        self._sessions.add(session)
        try:
            await session.run()
        finally:
            await session.close()
            self._sessions.discard(session)

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