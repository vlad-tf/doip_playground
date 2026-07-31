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
DoIP EdgeNode — TLS bridge.

Wraps a Scapy TLS automaton (TLSServerAutomaton or TLSClientAutomaton)
in a thread-pool executor and exposes async send() / recv() to the
asyncio layer.

Two concurrent executor tasks prevent the deadlock that arises when a
single blocking run_in_executor call blocks waiting for a response while
the asyncio layer is also trying to write:

  asyncio event loop
    ├── writer_task (executor thread A)
    │     loop: get bytes from tx_queue → write to TLS automaton socket
    └── reader_task (executor thread B)
          loop: read decrypted bytes from TLS automaton → put into rx_queue
                use loop.call_soon_threadsafe(rx_queue.put_nowait, data)

The automaton itself runs in a third executor thread (its own run() call).

TLSFaultPolicy is a placeholder.  All fields default to no-fault.
Future implementation will wire these into Scapy automaton callbacks.

# TODO: verify TLSServerAutomaton / TLSClientAutomaton constructor
#       signatures on Raspberry Pi:
#
#   python3 -c "
#   from scapy.layers.tls.automaton_srv import TLSServerAutomaton
#   from scapy.layers.tls.automaton_cli import TLSClientAutomaton
#   import inspect
#   print(inspect.signature(TLSServerAutomaton.__init__))
#   print(inspect.signature(TLSClientAutomaton.__init__))
#   "
#
# Parameter names vary between Scapy 2.5.x and 2.6.x.  The bridge below
# uses keyword-argument dictionaries so you only need to update the
# _build_server_kwargs() / _build_client_kwargs() helpers.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TLS fault policy placeholder
# ---------------------------------------------------------------------------


@dataclass
class TLSFaultPolicy:
    """
    Placeholder: hook point for TLS-layer fault injection.
    Pass an instance to TLSBridge.  All fields default to no-fault.
    Future implementation will wire these into Scapy automaton callbacks.
    """

    wrong_cipher: bool = False
    expired_cert: bool = False
    bad_mac: bool = False
    no_cert: bool = False
    tls_version_downgrade: bool = False


# ---------------------------------------------------------------------------
# Helpers to build automaton keyword-argument dicts
# ---------------------------------------------------------------------------
# These functions are isolated so the rest of TLSBridge doesn't need to
# change when Scapy API differences are found on the Raspberry Pi.

def _build_server_kwargs(tls_config, mycert_path: str, mykey_path: str) -> dict:
    """
    Build kwargs for TLSServerAutomaton.__init__.

    # TODO: verify parameter names on Raspberry Pi.
    # Common parameter names seen in Scapy 2.5.x:
    #   mycert, mykey, client_auth, require_client_auth
    # Scapy 2.6.x may use:
    #   server_certs, server_key, client_cert_required
    """
    return {
        "mycert": mycert_path,
        "mykey": mykey_path,
        "client_auth": tls_config.mutual_tls,
        # TLS 1.3 only: Scapy uses 'tls_version' or 'version' to constrain.
        # TODO: verify exact parameter name; update if needed.
        # "tls_version": 0x0304,   # TLS 1.3
    }


def _build_client_kwargs(
    tls_config,
    mycert_path: str,
    mykey_path: str,
    server_name: str | None,
) -> dict:
    """
    Build kwargs for TLSClientAutomaton.__init__.

    # TODO: verify parameter names on Raspberry Pi.
    """
    kwargs: dict = {
        "mycert": mycert_path,
        "mykey": mykey_path,
        # TODO: verify TLS version constraint parameter name
        # "tls_version": 0x0304,
    }
    if server_name:
        # SNI extension
        kwargs["server_name"] = server_name
    return kwargs


# ---------------------------------------------------------------------------
# TLSBridge
# ---------------------------------------------------------------------------


class TLSBridge:
    """
    Async wrapper around a blocking Scapy TLS automaton.

    Usage (server side):
        bridge = TLSBridge(sock, TLSServerAutomaton, tls_config, policy, loop, executor)
        await bridge.handshake()
        data = await bridge.recv()
        await bridge.send(data)
        await bridge.close()
    """

    def __init__(
        self,
        sock: socket.socket,
        automaton_cls,
        tls_config,
        fault_policy: TLSFaultPolicy,
        loop: asyncio.AbstractEventLoop,
        executor: ThreadPoolExecutor,
        is_server: bool = True,
        server_name: str | None = None,
    ) -> None:
        self._sock = sock
        self._automaton_cls = automaton_cls
        self._tls_config = tls_config
        self._fault_policy = fault_policy
        self._loop = loop
        self._executor = executor
        self._is_server = is_server
        self._server_name = server_name

        self._rx_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._tx_queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._automaton = None
        self._closed = False
        self._handshake_done = asyncio.Event()
        self._handshake_error: Exception | None = None

        # Internal pipe for the automaton ↔ bridge data exchange
        # The automaton operates on self._inner_sock;
        # the bridge reads/writes on self._outer_sock.
        self._inner_sock, self._outer_sock = socket.socketpair()

    def _run_automaton(self) -> None:
        """
        Run the TLS automaton in its own thread.
        Signals handshake_done (or records an exception) when ready.
        """
        try:
            if self._is_server:
                from scapy.layers.tls.automaton_srv import TLSServerAutomaton  # type: ignore[import]
                kwargs = _build_server_kwargs(
                    self._tls_config,
                    mycert_path=self._tls_config.server_cert,
                    mykey_path=self._tls_config.server_key,
                )
                automaton = TLSServerAutomaton(sock=self._inner_sock, **kwargs)
            else:
                from scapy.layers.tls.automaton_cli import TLSClientAutomaton  # type: ignore[import]
                kwargs = _build_client_kwargs(
                    self._tls_config,
                    mycert_path=self._tls_config.client_cert,
                    mykey_path=self._tls_config.client_key,
                    server_name=self._server_name if self._server_name else None,
                )
                automaton = TLSClientAutomaton(sock=self._inner_sock, **kwargs)

            self._automaton = automaton
            # TODO: Fix handshake_done timing.
            # The event must be signalled AFTER the TLS handshake completes,
            # not before automaton.run() is called.  The correct approach is to
            # override the automaton's post-handshake state callback (e.g. the
            # CONNECTED / ESTABLISHED state) and call
            #   self._loop.call_soon_threadsafe(self._handshake_done.set)
            # from inside that callback.  The exact state name depends on the
            # Scapy version; verify with inspect.getmembers(TLSServerAutomaton)
            # on the Raspberry Pi before wiring this up.
            #
            # Current behaviour: event fires immediately, so handshake() returns
            # before TLS negotiation has happened.  This is harmless while
            # _do_tls_handshake() in server.py is still a TODO placeholder, but
            # MUST be fixed before port 3496 TLS is enabled.
            self._loop.call_soon_threadsafe(self._handshake_done.set)
            automaton.run()
        except Exception as exc:
            self._handshake_error = exc
            logger.error("TLSBridge: automaton error: %s", exc, exc_info=True)
            self._loop.call_soon_threadsafe(self._handshake_done.set)

    def _reader_thread(self) -> None:
        """
        Thread B: read decrypted bytes from the outer socket and push into
        rx_queue via call_soon_threadsafe (asyncio-safe).
        """
        try:
            while not self._closed:
                try:
                    data = self._outer_sock.recv(65536)
                except OSError:
                    break
                if not data:
                    break
                self._loop.call_soon_threadsafe(self._rx_queue.put_nowait, data)
        except Exception as exc:
            logger.debug("TLSBridge reader thread exiting: %s", exc)

    def _writer_thread(self) -> None:
        """
        Thread A: drain tx_queue and write bytes to the outer socket.
        A None sentinel causes the thread to exit.
        """
        import queue as _queue

        # We need a synchronous queue for the thread; use a threading.Queue
        # fed by the asyncio tx_queue via a bridge.
        # NOTE: Because asyncio Queues are not thread-safe, we use a separate
        # threading.Queue here and have the asyncio side put into it.
        # The _send() coroutine puts into self._sync_tx_queue instead.
        try:
            while True:
                data = self._sync_tx_queue.get()
                if data is None:
                    break
                try:
                    self._outer_sock.sendall(data)
                except OSError as exc:
                    logger.debug("TLSBridge writer thread socket error: %s", exc)
                    break
        except Exception as exc:
            logger.debug("TLSBridge writer thread exiting: %s", exc)

    async def handshake(self) -> None:
        """
        Start the TLS automaton and complete the handshake.
        Raises on version mismatch or cert failure.
        """
        import queue as _queue

        self._sync_tx_queue: _queue.Queue = _queue.Queue()

        # Start automaton thread
        self._executor.submit(self._run_automaton)

        # Start reader thread
        self._executor.submit(self._reader_thread)

        # Start writer thread
        self._executor.submit(self._writer_thread)

        # Wait for automaton to signal handshake completion
        await self._handshake_done.wait()

        if self._handshake_error is not None:
            raise self._handshake_error

        logger.info("TLSBridge: handshake complete (is_server=%s)", self._is_server)

    async def send(self, data: bytes) -> None:
        """Send encrypted data.  Puts bytes into the sync queue for the writer thread."""
        if self._closed:
            return
        self._sync_tx_queue.put(data)

    async def recv(self) -> bytes:
        """Receive decrypted data from the rx queue."""
        return await self._rx_queue.get()

    async def close(self) -> None:
        """Shut down the bridge cleanly."""
        self._closed = True
        try:
            self._sync_tx_queue.put(None)  # sentinel to stop writer thread
        except Exception:
            pass
        try:
            self._inner_sock.close()
            self._outer_sock.close()
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass
