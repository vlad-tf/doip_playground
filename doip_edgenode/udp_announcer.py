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
DoIP EdgeNode — UDP Vehicle Announcement and Discovery.

On startup: sends announce_count Vehicle Announcement messages
(payload type 0x0004) at announce_interval_ms intervals.

Ongoing: validates UDP discovery datagrams, answers unqualified or matching
EID/VIN-qualified identification requests, and reports configured power mode.
Optional entity status awaits truthful socket accounting.

Uses asyncio.DatagramProtocol so it runs inside the event loop.

Vehicle Identification Response / Announcement payload structure (33 bytes):
  bytes  0-16: VIN (17 ASCII bytes)
  bytes 17-18: node logical address (2 bytes)
  bytes 19-24: EID (6 bytes, from config hex string)
  bytes 25-30: GID (6 bytes, from config hex string)
  byte  31:    further action required (0x00 = none)
  byte  32:    VIN/GID sync status     (0x00 = synchronized)
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Tuple

from config import AppConfig

logger = logging.getLogger(__name__)

DOIP_UDP_PORT = 13400

# Payload type codes used for UDP
PT_HEADER_NACK = 0x0000
PT_VEHICLE_ID_REQUEST = 0x0001
PT_VEHICLE_ID_REQUEST_EID = 0x0002
PT_VEHICLE_ID_REQUEST_VIN = 0x0003
PT_VEHICLE_ID_RESPONSE = 0x0004
PT_POWER_MODE_REQUEST = 0x4003
PT_POWER_MODE_RESPONSE = 0x4004

# Types accepted on the discovery listener, including broadcast announcements
# and received NACKs that are validated but never answered.
_UDP_PAYLOAD_LENGTHS = {
    PT_HEADER_NACK: (1,),
    PT_VEHICLE_ID_REQUEST: (0,),
    PT_VEHICLE_ID_REQUEST_EID: (6,),
    PT_VEHICLE_ID_REQUEST_VIN: (17,),
    # The final synchronization-status byte is optional on received messages.
    PT_VEHICLE_ID_RESPONSE: (32, 33),
    PT_POWER_MODE_REQUEST: (0,),
}
_DISCOVERY_REQUESTS = {
    PT_VEHICLE_ID_REQUEST, PT_VEHICLE_ID_REQUEST_EID, PT_VEHICLE_ID_REQUEST_VIN,
}


def _build_frame(payload_type: int, payload: bytes, version: int = 0x02) -> bytes:
    """Build a raw 8-byte DoIP header + payload."""
    inv = 0xFF ^ version
    return (
        bytes([version, inv])
        + payload_type.to_bytes(2, "big")
        + len(payload).to_bytes(4, "big")
        + payload
    )


def _announcement_payload(config: AppConfig) -> bytes:
    """
    Build the 33-byte Vehicle Identification Response / Announcement payload.

    ISO 13400-2 Table 24 field order:
      bytes  0-16 : VIN             (17 bytes)
      bytes 17-18 : logical address  (2 bytes)  ← node's own logical address
      bytes 19-24 : EID              (6 bytes)
      bytes 25-30 : GID              (6 bytes)
      byte  31    : further action required (0x00 = none)
      byte  32    : VIN/GID sync status     (0x00 = synchronized)
    """
    import struct
    vin_bytes    = config.doip.vin.encode("ascii")        # 17 bytes
    logical_addr = struct.pack("!H", config.doip.node_logical_addr)  # 2 bytes
    eid_bytes    = bytes.fromhex(config.doip.eid)         #  6 bytes
    gid_bytes    = bytes.fromhex(config.doip.gid)         #  6 bytes
    return vin_bytes + logical_addr + eid_bytes + gid_bytes + b"\x00\x00"


class _UDPProtocol(asyncio.DatagramProtocol):
    """Validate and dispatch requests received by the shared discovery listener."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._transport: asyncio.DatagramTransport | None = None
        self._payload = _announcement_payload(config)

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def _send(self, payload_type: int, payload: bytes, addr: Tuple[str, int]) -> None:
        if self._transport is None:
            return
        try:
            self._transport.sendto(_build_frame(payload_type, payload), addr)
        except OSError as exc:
            logger.warning("UDPAnnouncer: failed to send to %s: %s", addr, exc)

    def _reject(self, code: int, addr: Tuple[str, int]) -> None:
        # UDP has no per-peer connection to close. Discard this datagram, not
        # the shared listener used by every tester; no stream drain is needed.
        logger.warning("UDPAnnouncer: rejecting datagram from %s with code 0x%02X", addr, code)
        self._send(PT_HEADER_NACK, bytes([code]), addr)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        if len(data) < 8:
            # Insufficient header to identify a complete DoIP message.
            return

        version, inverse = data[:2]
        payload_type = int.from_bytes(data[2:4], "big")
        default_discovery = version == 0xFF and payload_type in _DISCOVERY_REQUESTS
        if (
            inverse != (version ^ 0xFF)
            or (version not in (0x02, 0x03) and not default_discovery)
        ):
            self._reject(0x00, addr)
            return
        lengths = _UDP_PAYLOAD_LENGTHS.get(payload_type)
        if lengths is None:
            # Optional entity status is unsupported until capacity/socket
            # accounting can provide truthful values; TCP-only types are not
            # requests on this listener either.
            self._reject(0x01, addr)
            return
        payload_length = int.from_bytes(data[4:8], "big")
        if payload_length > self._config.doip.max_payload_bytes:
            self._reject(0x02, addr)
            return
        if payload_length not in lengths or len(data) != 8 + payload_length:
            self._reject(0x04, addr)
            return

        if payload_type in (PT_HEADER_NACK, PT_VEHICLE_ID_RESPONSE):
            return  # never answer received NACKs or broadcast announcements
        if payload_type == PT_VEHICLE_ID_REQUEST_EID and data[8:] != self._payload[19:25]:
            return
        if payload_type == PT_VEHICLE_ID_REQUEST_VIN and data[8:] != self._payload[:17]:
            return
        logger.debug("UDPAnnouncer: received request 0x%04X from %s", payload_type, addr)
        if payload_type == PT_POWER_MODE_REQUEST:
            self._send(PT_POWER_MODE_RESPONSE, bytes([self._config.doip.power_mode]), addr)
        else:
            self._send(PT_VEHICLE_ID_RESPONSE, self._payload, addr)

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDPAnnouncer: UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        self._transport = None
        logger.debug("UDPAnnouncer: UDP transport closed: %s", exc)


class UDPAnnouncer:
    """
    Handles Vehicle Announcement on startup and Vehicle Identification
    Request/Response ongoing.
    """

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _UDPProtocol | None = None

    async def start(self) -> None:
        """
        Send announce_count announcements, then start listening for requests.
        """
        loop = asyncio.get_event_loop()

        # Bind UDP socket on 0.0.0.0:13400 with SO_BROADCAST
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass  # not available on all platforms
        sock.bind(("0.0.0.0", DOIP_UDP_PORT))

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self._config),
            sock=sock,
        )
        self._transport = transport  # type: ignore[assignment]
        self._protocol = protocol  # type: ignore[assignment]

        # Send initial announcements
        await self._send_announcements()

        logger.info(
            "UDPAnnouncer: listening on 0.0.0.0:%d", DOIP_UDP_PORT
        )

    async def _send_announcements(self) -> None:
        """Broadcast Vehicle Announcement count times."""
        payload = _announcement_payload(self._config)
        frame = _build_frame(PT_VEHICLE_ID_RESPONSE, payload)
        count = self._config.udp.announce_count
        interval_s = self._config.udp.announce_interval_ms / 1000.0

        for i in range(count):
            if self._transport:
                self._transport.sendto(frame, ("255.255.255.255", DOIP_UDP_PORT))
                logger.info(
                    "UDPAnnouncer: sent Vehicle Announcement %d/%d", i + 1, count
                )
            if i < count - 1:
                await asyncio.sleep(interval_s)

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()
