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
    ) -> None:
        self._entry = entry
        self._tls_config = tls_config
        self._loop = loop
        self._executor = executor
        self._use_tls = use_tls
        self._fault_policy = fault_policy or TLSFaultPolicy()

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._tls_bridge: TLSBridge | None = None
        self._connected = False

        # Background reader: handles unsolicited Alive Check Requests from ECU;
        # all other frames go onto _recv_queue for recv() to consume.
        self._recv_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._reader_task: asyncio.Task | None = None
        # Logical address used in Alive Check Responses sent to the ECU
        self._tester_logical_addr: int = 0x0E00

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
        entry = self._entry
        port = entry.ecu_port_tls if self._use_tls else entry.ecu_port_plain

        # IPv6 link-local scope_id
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
            entry.ecu_ipv6,
            entry.ecu_interface,
            port,
            self._use_tls,
        )

        await self._loop.sock_connect(sock, (entry.ecu_ipv6, port, 0, scope_id))

        if self._use_tls:
            from scapy.layers.tls.automaton_cli import TLSClientAutomaton  # type: ignore[import]

            sni = entry.ecu_sni if entry.ecu_sni else None
            self._tls_bridge = TLSBridge(
                sock=sock,
                automaton_cls=TLSClientAutomaton,
                tls_config=self._tls_config,
                fault_policy=self._fault_policy,
                loop=self._loop,
                executor=self._executor,
                is_server=False,
                server_name=sni,
            )
            await self._tls_bridge.handshake()
            logger.info("ECUConnection: TLS handshake complete")
        else:
            self._reader, self._writer = await asyncio.open_connection(sock=sock)

        # Must set _connected before calling send/recv helpers below
        self._connected = True
        self._tester_logical_addr = tester_logical_addr

        # Perform Routing Activation toward the ECU
        await self._do_routing_activation(tester_logical_addr)

        # Start background reader AFTER routing activation is complete.
        # From this point the ECU may send unsolicited Alive Check Requests
        # (e.g. when a competing EdgeNode connection tries to register the
        # same SA); the background reader must reply immediately.
        self._reader_task = asyncio.get_running_loop().create_task(
            self._background_reader(), name="ecu-reader"
        )

    async def _read_frame(self) -> bytes:
        """Read one complete DoIP frame directly from the stream (no _connected guard)."""
        assert self._reader is not None
        header = await self._reader.readexactly(8)
        payload_len = int.from_bytes(header[4:8], "big")
        if payload_len == 0:
            return header
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
                # ECU is checking we're alive before responding — answer it
                logger.debug("ECUConnection: received Alive Check Request from ECU, responding")
                await self.send(_build_doip_frame(_PT_ALIVE_CHECK_RESP, b""))
                continue

            if ptype != _PT_RA_RESPONSE:
                raise RuntimeError(
                    f"ECUConnection: expected Routing Activation Response "
                    f"(0x{_PT_RA_RESPONSE:04X}), got 0x{ptype:04X}"
                )

            # Parse RA Response payload (min 5 bytes: 2+2+1)
            payload = raw[8:]
            if len(payload) < 5:
                raise RuntimeError(
                    f"ECUConnection: RA Response payload too short ({len(payload)} bytes)"
                )
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

    async def _background_reader(self) -> None:
        """
        Continuously read frames from the ECU after routing activation.

        - Alive Check Request (0x0007) from ECU → reply immediately with
          Alive Check Response (0x0008) containing the tester's logical address.
          This is the ECU's SA-conflict probe: if we don't reply, the ECU
          considers this connection dead and evicts it in favour of a new one.

        - All other frames → enqueued for recv() to consume.
        """
        try:
            while True:
                raw = await self._read_frame()
                ptype = struct.unpack("!H", raw[2:4])[0]

                if ptype == _PT_ALIVE_CHECK_REQ:
                    logger.debug(
                        "ECUConnection: received Alive Check Request from ECU — replying"
                    )
                    payload = struct.pack("!H", self._tester_logical_addr)
                    await self.send(_build_doip_frame(_PT_ALIVE_CHECK_RESP, payload))
                else:
                    await self._recv_queue.put(raw)

        except asyncio.IncompleteReadError:
            logger.info("ECUConnection: ECU closed the connection")
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("ECUConnection: background reader error: %s", exc)

    async def send(self, data: bytes) -> None:
        if not self._connected:
            raise RuntimeError("ECUConnection.send() called before connect()")
        if self._tls_bridge:
            await self._tls_bridge.send(data)
        else:
            assert self._writer is not None
            self._writer.write(data)
            await self._writer.drain()

    async def recv(self) -> bytes:
        if not self._connected:
            raise RuntimeError("ECUConnection.recv() called before connect()")
        if self._tls_bridge:
            return await self._tls_bridge.recv()
        else:
            # Consume from the queue fed by _background_reader.
            # The background reader handles Alive Check Requests transparently;
            # everything else (diagnostic responses, etc.) arrives here.
            return await self._recv_queue.get()

    async def close(self) -> None:
        self._connected = False
        if self._reader_task and not self._reader_task.done():
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
