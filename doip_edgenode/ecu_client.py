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
DoIP EdgeNode — ECU connection.

Manages a single IPv6 TCP connection to one ECU.
TLS is used when the ECU port matches config.ports.doip_tls; otherwise
plain asyncio streams are used.

IPv6 link-local addresses require an interface scope index for connect().
The scope_id is obtained via socket.if_nametoindex().

After TCP (and optional TLS) is established, connect() performs a DoIP
Routing Activation handshake toward the ECU before returning.  The source
logical address used in the RA Request is the tester's logical address
(transparent proxy: the ECU sees the original tester address).
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from concurrent.futures import ThreadPoolExecutor

from config import RoutingEntry, TLSConfig
from tls_bridge import TLSBridge, TLSFaultPolicy

logger = logging.getLogger(__name__)

# DoIP frame constants used for the ECU-facing Routing Activation
_DOIP_VER            = 0x02
_PT_RA_REQUEST       = 0x0005
_PT_RA_RESPONSE      = 0x0006
_PT_ALIVE_CHECK_REQ  = 0x0007
_PT_ALIVE_CHECK_RESP = 0x0008

_RECV_TERMINAL = object()

_RA_RESPONSE_CODES = {
    0x00: "Denied — unknown source address",
    0x01: "Denied — all sockets registered and active",
    0x02: "Denied — SA different from already registered SA",
    0x03: "Denied — SA already registered on different socket",
    0x04: "Denied — authentication missing",
    0x05: "Denied — confirmation rejected",
    0x06: "Denied — unsupported routing activation type",
    0x10: "Successfully activated",
    0x11: "Activated, confirmation pending",
}


def _build_doip_frame(payload_type: int, payload: bytes) -> bytes:
    inv = 0xFF ^ _DOIP_VER
    return struct.pack("!BBHI", _DOIP_VER, inv, payload_type, len(payload)) + payload


def _build_ra_request(src_addr: int) -> bytes:
    """
    Routing Activation Request (0x0005) sent by EdgeNode → ECU.
    Payload: source_address (2) + activation_type (1, 0x00=default) + reserved (4)
    """
    payload = struct.pack("!HB", src_addr, 0x00) + b"\x00\x00\x00\x00"
    return _build_doip_frame(_PT_RA_REQUEST, payload)


class ECUConnection:
    """Single IPv6 TCP connection to one ECU.  Manages TLS if configured."""

    def __init__(
        self,
        entry: RoutingEntry,
        tls_config: TLSConfig,
        loop: asyncio.AbstractEventLoop,
        executor: ThreadPoolExecutor,
        use_tls: bool = False,
        fault_policy: TLSFaultPolicy | None = None,
        max_payload_bytes: int = 4096,
    ) -> None:
        self._entry = entry
        self._tls_config = tls_config
        self._loop = loop
        self._executor = executor
        self._use_tls = use_tls
        self._fault_policy = fault_policy or TLSFaultPolicy()
        self._max_payload_bytes = max_payload_bytes
        self._connecting = False

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._tls_bridge: TLSBridge | None = None
        self._connected = False

        # Background reader: handles unsolicited Alive Check Requests from ECU;
        # all other frames go onto _recv_queue for recv() to consume.
        self._recv_queue: asyncio.Queue[bytes | object] = asyncio.Queue()
        self._terminal_error: BaseException | None = None
        self._reader_task: asyncio.Task | None = None
        # Logical address used in Alive Check Responses sent to the ECU
        self._tester_logical_addr: int = 0x0E00

    @property
    def connected(self) -> bool:
        """Whether this leg can still send; terminal instances are not reusable."""
        return self._connected

    def _mark_terminal(self, cause: BaseException, *, discard: bool = False) -> None:
        """Publish EOF after queued frames, or discard them on explicit close.

        State change and queue publication are synchronous on the event loop.
        A single persistent marker wakes all current and future receivers.
        """
        self._connected = False
        first = self._terminal_error is None
        if first:
            self._terminal_error = cause
        if discard:
            while not self._recv_queue.empty():
                self._recv_queue.get_nowait()
        if first or discard:
            self._recv_queue.put_nowait(_RECV_TERMINAL)

    def _raise_terminal(self) -> None:
        raise ConnectionError("ECU connection terminated") from self._terminal_error

    async def connect(self, tester_logical_addr: int = 0x0E00) -> None:
        """
        Establish TCP + optional TLS connection to the ECU, then perform
        DoIP Routing Activation toward the ECU.

        tester_logical_addr — the source address used in the RA Request.
            The EdgeNode forwards the tester's own logical address so the ECU
            sees the original tester identity (transparent proxy).

        IPv6 link-local scope_id is mandatory; without it the connect() call
        will fail on most kernels.
        """
        if self._terminal_error is not None:
            self._raise_terminal()  # recovery requires a fresh connection object
        if self._connected or self._connecting:
            raise RuntimeError("ECUConnection.connect() called during an existing connection")
        self._connecting = True
        sock = None
        try:
            entry = self._entry
            port = entry.ecu_port_tls if self._use_tls else entry.ecu_port_plain
            try:
                scope_id = socket.if_nametoindex(entry.ecu_interface)
            except OSError as exc:
                raise OSError(
                    f"Cannot get interface index for {entry.ecu_interface!r}: {exc}"
                ) from exc

            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setblocking(False)
            logger.info(
                "ECUConnection: connecting to [%s%%%s]:%d (use_tls=%s)",
                entry.ecu_ipv6, entry.ecu_interface, port, self._use_tls,
            )
            await self._loop.sock_connect(sock, (entry.ecu_ipv6, port, 0, scope_id))
            if self._use_tls:
                from scapy.layers.tls.automaton_cli import TLSClientAutomaton  # type: ignore[import]

                self._tls_bridge = TLSBridge(
                    sock=sock,
                    automaton_cls=TLSClientAutomaton,
                    tls_config=self._tls_config,
                    fault_policy=self._fault_policy,
                    loop=self._loop,
                    executor=self._executor,
                    is_server=False,
                    server_name=entry.ecu_sni or None,
                )
                sock = None  # bridge owns the socket, even if handshake fails
                await self._tls_bridge.handshake()
            else:
                self._reader, self._writer = await asyncio.open_connection(sock=sock)
                sock = None  # ownership transferred to the stream transport

            if self._terminal_error is not None:
                self._raise_terminal()
            # Internal send() is needed during RA; failed setup revokes this state.
            self._connected = True
            self._tester_logical_addr = tester_logical_addr
            await self._do_routing_activation(tester_logical_addr)
            if self._terminal_error is not None:
                self._raise_terminal()
            self._reader_task = asyncio.get_running_loop().create_task(
                self._background_reader(), name="ecu-reader"
            )
        except BaseException as exc:
            self._mark_terminal(exc, discard=True)
            if sock is not None:
                try:
                    sock.close()
                except OSError as close_error:
                    logger.debug("ECUConnection: raw socket close error: %s", close_error)
            # Cancellation (including repeated cancellation) must not abandon
            # the stream close or replace the original setup failure.
            cleanup = asyncio.create_task(self._close_failed_setup())
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    pass
            cleanup.result()
            raise
        finally:
            self._connecting = False

    async def _close_failed_setup(self) -> None:
        """Close owned transports promptly, bounding asynchronous close waits."""
        try:
            await asyncio.wait_for(self.close(), timeout=2.0)
        except Exception as exc:
            logger.debug("ECUConnection: setup cleanup error: %s", exc)

    async def _read_frame(self) -> bytes:
        """Read a bounded, structurally valid ECU frame without sending errors."""
        assert self._reader is not None
        header = await self._reader.readexactly(8)
        version, inverse, ptype, payload_len = struct.unpack("!BBHI", header)
        if version not in (0x02, 0x03) or inverse != (version ^ 0xFF):
            raise RuntimeError("ECUConnection: invalid DoIP version pattern")
        if payload_len > self._max_payload_bytes:
            raise RuntimeError("ECUConnection: DoIP payload exceeds configured limit")
        fixed_lengths = {
            0x0000: (1,), _PT_RA_RESPONSE: (9, 13),
            _PT_ALIVE_CHECK_REQ: (0,), _PT_ALIVE_CHECK_RESP: (2,),
            0x4002: (3, 7), 0x4004: (1,),
        }
        if ptype in fixed_lengths:
            valid_length = payload_len in fixed_lengths[ptype]
        elif ptype in (0x8001, 0x8002, 0x8003):
            valid_length = payload_len >= 5
        else:
            raise RuntimeError(f"ECUConnection: unsupported ECU payload type 0x{ptype:04X}")
        if not valid_length:
            raise RuntimeError(f"ECUConnection: invalid payload length for 0x{ptype:04X}")
        payload = await self._reader.readexactly(payload_len)
        return header + payload

    async def _do_routing_activation(self, tester_logical_addr: int) -> None:
        """
        Send Routing Activation Request to the ECU and validate the response.

        Raises RuntimeError if the ECU denies activation.
        Handles an Alive Check Request from the ECU if it arrives before the
        RA Response (some ECUs probe first).
        """
        logger.info(
            "ECUConnection: sending Routing Activation Request to ECU "
            "(src=0x%04X)", tester_logical_addr,
        )
        await self.send(_build_ra_request(tester_logical_addr))

        # Read responses until we get the RA Response; handle Alive Check inline
        for _ in range(3):  # at most 3 frames before giving up
            raw = await asyncio.wait_for(self._read_frame(), timeout=5.0)
            ptype = struct.unpack("!H", raw[2:4])[0]

            if ptype == _PT_ALIVE_CHECK_REQ:
                # Compatibility: some ECUs probe before returning the RA result.
                logger.debug("ECUConnection: received early Alive Check Request")
                await self._send_alive_check_response(tester_logical_addr)
                continue

            if ptype != _PT_RA_RESPONSE:
                raise RuntimeError(
                    f"ECUConnection: expected Routing Activation Response "
                    f"(0x{_PT_RA_RESPONSE:04X}), got 0x{ptype:04X}"
                )

            payload = raw[8:]
            if len(payload) not in (9, 13):
                raise RuntimeError("ECUConnection: invalid RA Response payload length")
            echoed_tester, entity_addr = struct.unpack("!HH", payload[:4])
            if echoed_tester != tester_logical_addr:
                raise RuntimeError("ECUConnection: RA Response tester address mismatch")
            if entity_addr != self._entry.ecu_logical_addr:
                raise RuntimeError("ECUConnection: RA Response ECU address mismatch")
            code = payload[4]
            desc = _RA_RESPONSE_CODES.get(code, f"unknown (0x{code:02X})")

            if code == 0x10:
                logger.info(
                    "ECUConnection: Routing Activation successful (ECU src=0x%04X)",
                    tester_logical_addr,
                )
                return
            else:
                raise RuntimeError(
                    f"ECUConnection: Routing Activation denied by ECU — {desc}"
                )

        raise RuntimeError("ECUConnection: no Routing Activation Response received from ECU")

    async def _send_alive_check_response(self, tester_addr: int) -> None:
        """Use the client identity for both early and registered ECU probes."""
        await self.send(_build_doip_frame(_PT_ALIVE_CHECK_RESP, struct.pack("!H", tester_addr)))

    async def _background_reader(self) -> None:
        """
        Continuously read frames from the ECU after routing activation.

        - Alive Check Request (0x0007) from ECU → reply immediately with
          Alive Check Response (0x0008) containing the tester's logical address.
          This is the ECU's SA-conflict probe: if we don't reply, the ECU
          considers this connection dead and evicts it in favour of a new one.

        - All other frames → enqueued for recv() to consume.
        """
        cause: BaseException = ConnectionError("ECU reader stopped")
        try:
            while True:
                raw = await self._read_frame()
                ptype = struct.unpack("!H", raw[2:4])[0]

                if ptype == _PT_ALIVE_CHECK_REQ:
                    logger.debug(
                        "ECUConnection: received Alive Check Request from ECU — replying"
                    )
                    await self._send_alive_check_response(self._tester_logical_addr)
                else:
                    await self._recv_queue.put(raw)

        except asyncio.IncompleteReadError as exc:
            cause = exc
            logger.info("ECUConnection: ECU closed the connection")
        except asyncio.CancelledError as exc:
            cause = exc
        except Exception as exc:
            cause = exc
            logger.debug("ECUConnection: background reader error: %s", exc)
        finally:
            self._mark_terminal(cause)
            # Do not call close() here: it waits for this very reader task.
            if self._writer is not None:
                self._writer.close()

    async def send(self, data: bytes) -> None:
        if self._terminal_error is not None:
            self._raise_terminal()
        if not self._connected:
            raise RuntimeError("ECUConnection.send() called before connect()")
        if self._tls_bridge:
            await self._tls_bridge.send(data)
        else:
            assert self._writer is not None
            self._writer.write(data)
            await self._writer.drain()

    async def recv(self) -> bytes:
        if not self._connected and self._terminal_error is None:
            raise RuntimeError("ECUConnection.recv() called before connect()")
        if self._tls_bridge:
            if self._terminal_error is not None:
                self._raise_terminal()
            return await self._tls_bridge.recv()
        else:
            raw = await self._recv_queue.get()
            if raw is _RECV_TERMINAL:
                # No await between removal and reinsertion: cancellation cannot
                # consume the sole marker and strand another waiter.
                self._recv_queue.put_nowait(_RECV_TERMINAL)
                self._raise_terminal()
            assert isinstance(raw, bytes)
            return raw

    async def close(self) -> None:
        self._mark_terminal(ConnectionError("ECU connection closed"), discard=True)
        if (self._reader_task and not self._reader_task.done()
                and self._reader_task is not asyncio.current_task()):
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._tls_bridge:
            await self._tls_bridge.close()
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
