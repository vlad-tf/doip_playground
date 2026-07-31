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

Ongoing: listens for Vehicle Identification Requests (0x0001) and
responds with a Vehicle Identification Response (0x0004).

Uses asyncio.DatagramProtocol so it runs inside the event loop.

Vehicle Identification Response / Announcement payload structure
(ISO 13400-2, 33 bytes):
  bytes  0-16: VIN (17 ASCII bytes)
  bytes 17-22: EID (6 bytes, from config hex string)
  bytes 23-28: GID (6 bytes, from config hex string)
  byte  29:    further action required (0x00 = none)
  byte  30:    VIN/GID sync status     (0x00 = synchronized)
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
PT_VEHICLE_ID_REQUEST = 0x0001
PT_VEHICLE_ID_RESPONSE = 0x0004


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
    """asyncio.DatagramProtocol that responds to Vehicle Identification Requests."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._transport: asyncio.DatagramTransport | None = None
        self._payload = _announcement_payload(config)

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        if len(data) < 8:
            return

        payload_type = int.from_bytes(data[2:4], "big")
        if payload_type != PT_VEHICLE_ID_REQUEST:
            return

        logger.debug(
            "UDPAnnouncer: received Vehicle Identification Request from %s", addr
        )
        frame = _build_frame(PT_VEHICLE_ID_RESPONSE, self._payload)

        if self._transport:
            # Unicast response to the requester
            self._transport.sendto(frame, addr)
            logger.debug(
                "UDPAnnouncer: sent Vehicle Identification Response to %s", addr
            )

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDPAnnouncer: UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
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
