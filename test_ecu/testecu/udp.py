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
Vehicle Announcement / Vehicle Identification over UDP (ISO 13400-2).

Port of ``echo_ecu.py`` lines 111-246, retyped against ``EcuConfig``.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Optional

from testecu.config import EcuConfig
from testecu.doip import (
    DOIP_MCAST_ADDR,
    PT_VEHICLE_ID_REQUEST,
    PT_VEHICLE_ID_RESPONSE,
    build_frame,
)

logger = logging.getLogger("testecu.udp")


def build_announcement_payload(config: EcuConfig) -> bytes:
    """
    Vehicle Identification Response / Announcement payload (33 bytes).

      bytes  0-16 : VIN          (17 ASCII bytes)
      bytes 17-18 : logical addr (2 bytes)
      bytes 19-24 : EID          (6 bytes)
      bytes 25-30 : GID          (6 bytes)
      byte  31    : further action required (0x00 = none)
      byte  32    : VIN/GID sync status     (0x00 = synchronized)
    """
    doip = config.doip
    vin = doip.vin.encode("ascii")[:17].ljust(17, b"\x00")
    eid = bytes.fromhex(doip.eid)
    gid = bytes.fromhex(doip.gid)
    return (
        vin
        + struct.pack("!H", doip.ecu_logical_addr)
        + eid
        + gid
        + b"\x00"   # further action
        + b"\x00"   # sync status
    )


class _UDPProtocol(asyncio.DatagramProtocol):
    """Answers Vehicle Identification Requests and sends announcements."""

    def __init__(self, config: EcuConfig, if_index: int) -> None:
        self._payload = build_announcement_payload(config)
        self._if_index = if_index
        self._port = config.listen.port
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if len(data) < 8:
            return
        pt = struct.unpack("!H", data[2:4])[0]
        if pt != PT_VEHICLE_ID_REQUEST:
            return
        logger.debug("UDP: Vehicle Identification Request from %s", addr)
        if self._transport:
            self._transport.sendto(build_frame(PT_VEHICLE_ID_RESPONSE, self._payload), addr)
            logger.debug("UDP: sent Vehicle Identification Response to %s", addr)

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDP: error: %s", exc)

    def send_announcement(self) -> None:
        """Send one Vehicle Announcement to the DoIP multicast group."""
        if not self._transport:
            return
        frame = build_frame(PT_VEHICLE_ID_RESPONSE, self._payload)
        dest = (DOIP_MCAST_ADDR, self._port, 0, self._if_index)
        try:
            self._transport.sendto(frame, dest)
        except Exception as exc:
            logger.warning("UDP: announcement send failed: %s", exc)


async def run_announcer(config: EcuConfig) -> None:
    """
    Bind UDP/IPv6, join the DoIP multicast group, send the configured number of
    announcements, then keep listening for Vehicle Identification Requests.

    Every step that depends on the interface is best-effort: on a developer
    machine there is no ``eth0`` and no multicast on loopback, and that must not
    stop the TCP side from coming up.
    """
    interface = config.listen.interface
    port = config.listen.port

    if_index = 0
    if interface:
        try:
            if_index = socket.if_nametoindex(interface)
        except OSError as exc:
            logger.warning(
                "UDP: cannot get if_index for %r: %s — multicast may not work",
                interface, exc,
            )

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass

    try:
        mreq = socket.inet_pton(socket.AF_INET6, DOIP_MCAST_ADDR) + struct.pack("I", if_index)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    except OSError as exc:
        logger.warning("UDP: multicast join failed: %s", exc)

    if if_index:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                            struct.pack("I", if_index))
        except OSError:
            pass

    try:
        sock.bind(("::", port, 0, 0))
    except OSError as exc:
        sock.close()
        logger.warning("UDP: cannot bind [::]:%d: %s — announcements disabled", port, exc)
        return

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _UDPProtocol(config, if_index),
        sock=sock,
    )

    logger.info("UDP: listening on [::]:%d  interface=%s", port, interface or "any")

    count = config.udp.announce_count
    interval = config.udp.announce_interval_ms / 1000.0
    for index in range(count):
        protocol.send_announcement()
        logger.info("UDP: sent Vehicle Announcement %d/%d", index + 1, count)
        if index < count - 1:
            await asyncio.sleep(interval)

    logger.info("UDP: announcements done; listening for Vehicle Identification Requests")
