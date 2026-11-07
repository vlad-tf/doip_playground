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

On startup: waits a random 0–500 ms, then sends announce_count Vehicle
Announcement messages (payload type 0x0004) at announce_interval_ms intervals.
Matching identification responses use independent random 0–500 ms waits.
Wildcard IPv4 reception is portable; announcement/reply egress follows OS routing.

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
import ipaddress
import logging
import random
import socket
from typing import Tuple

from config import AppConfig
from session_registry import SessionRegistry

logger = logging.getLogger(__name__)

DOIP_UDP_PORT = 13400

# Payload type codes used for UDP
PT_HEADER_NACK = 0x0000
PT_VEHICLE_ID_REQUEST = 0x0001
PT_VEHICLE_ID_REQUEST_EID = 0x0002
PT_VEHICLE_ID_REQUEST_VIN = 0x0003
PT_VEHICLE_ID_RESPONSE = 0x0004
PT_ENTITY_STATUS_REQUEST = 0x4001
PT_ENTITY_STATUS_RESPONSE = 0x4002
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
    PT_ENTITY_STATUS_REQUEST: (0,),
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


# Bound discovery scheduling independently of peer count and request rate.
_MAX_PENDING_RESPONSES = 256


def _create_udp_socket() -> socket.socket:
    """Create a portable wildcard listener; outgoing traffic follows OS routing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Do not enable address/port reuse: Windows permits overlapping UDP binds.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setblocking(False)
        sock.bind(("0.0.0.0", DOIP_UDP_PORT))
        return sock
    except BaseException:
        sock.close()
        raise


class _UDPProtocol(asyncio.DatagramProtocol):
    """Validate and dispatch requests received by the shared discovery listener."""

    def __init__(self, config: AppConfig, registry: SessionRegistry | None = None) -> None:
        self._config = config
        self._registry = registry if registry is not None else SessionRegistry(config.doip.max_connections)
        self._transport: asyncio.DatagramTransport | None = None
        self._payload = _announcement_payload(config)
        self._pending_responses: set[asyncio.TimerHandle] = set()

    def cancel_pending(self) -> None:
        """Release scheduled replies without sending after transport teardown."""
        for handle in self._pending_responses:
            handle.cancel()
        self._pending_responses.clear()

    def _source_allowed(self, address: str) -> bool:
        try:
            source = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError:
            return False
        if source.is_unspecified or source.is_multicast or int(source) == 0xFFFFFFFF:
            return False
        # Directed broadcasts require interface netmasks, not available here.
        return True

    def _schedule_discovery(self, addr: Tuple[str, int]) -> None:
        if self._transport is None or len(self._pending_responses) >= _MAX_PENDING_RESPONSES:
            return
        transport = self._transport
        logger.debug("UDPAnnouncer: scheduling identification response to %s", addr)
        loop = asyncio.get_running_loop()

        def reply() -> None:
            if handle not in self._pending_responses:
                return
            self._pending_responses.discard(handle)
            if self._transport is transport:
                self._send(PT_VEHICLE_ID_RESPONSE, self._payload, addr)

        handle = loop.call_later(random.uniform(0.0, 0.5), reply)
        self._pending_responses.add(handle)

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
        if not self._source_allowed(addr[0]) or len(data) < 8:
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
            # Response-only and TCP-only types are unsupported on this listener.
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
        if payload_type == PT_ENTITY_STATUS_REQUEST:
            self._send(PT_ENTITY_STATUS_RESPONSE,
                       self._registry.status_payload(self._config), addr)
        elif payload_type == PT_POWER_MODE_REQUEST:
            logger.debug("UDPAnnouncer: received power request from %s", addr)
            self._send(PT_POWER_MODE_RESPONSE, bytes([self._config.doip.power_mode]), addr)
        else:
            self._schedule_discovery(addr)

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDPAnnouncer: UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        self.cancel_pending()
        self._transport = None
        logger.debug("UDPAnnouncer: UDP transport closed: %s", exc)


class UDPAnnouncer:
    """
    Handles Vehicle Announcement on startup and Vehicle Identification
    Request/Response ongoing.
    """

    def __init__(self, config: AppConfig, registry: SessionRegistry | None = None) -> None:
        self._config = config
        self._registry = registry if registry is not None else SessionRegistry(config.doip.max_connections)
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _UDPProtocol | None = None

    async def start(self) -> None:
        """Start the portable wildcard listener before announcing."""
        if self._transport is not None:
            raise RuntimeError("UDPAnnouncer is already started")
        loop = asyncio.get_running_loop()
        sock = _create_udp_socket()
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(self._config, self._registry), sock=sock,
            )
        except BaseException:
            sock.close()
            raise
        self._transport = transport  # type: ignore[assignment]
        self._protocol = protocol  # type: ignore[assignment]
        try:
            await self._send_announcements()
        except BaseException:
            await self.stop()
            raise
        logger.info("UDPAnnouncer: listening on 0.0.0.0:%d (all IPv4 interfaces; "
                    "egress follows OS routing)", DOIP_UDP_PORT)

    async def _send_announcements(self) -> None:
        """Broadcast Vehicle Announcement count times."""
        payload = _announcement_payload(self._config)
        frame = _build_frame(PT_VEHICLE_ID_RESPONSE, payload)
        count = self._config.udp.announce_count
        interval_s = self._config.udp.announce_interval_ms / 1000.0

        await asyncio.sleep(random.uniform(0.0, 0.5))
        for i in range(count):
            if self._transport:
                self._transport.sendto(frame, ("255.255.255.255", DOIP_UDP_PORT))
                logger.info(
                    "UDPAnnouncer: sent Vehicle Announcement %d/%d", i + 1, count
                )
            if i < count - 1:
                await asyncio.sleep(interval_s)

    async def stop(self) -> None:
        transport, protocol = self._transport, self._protocol
        self._transport = None
        self._protocol = None
        if protocol is not None:
            protocol.cancel_pending()
            protocol._transport = None
        if transport is not None:
            transport.close()
