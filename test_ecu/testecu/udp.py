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
Vehicle Announcement / Vehicle Identification / Entity Status over UDP (ISO 13400-2).

Port of ``echo_ecu.py`` lines 111-246, retyped against ``EcuConfig``. Entity
Status Request/Response support was added later: ``session.py``'s TCP-side
handler already covered it, but the UDP listener silently dropped anything
that was not a Vehicle Identification Request.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Any, Optional

from testecu.config import EcuConfig
from testecu.doip import (
    DOIP_MCAST_ADDR,
    PT_ENTITY_STATUS_REQUEST,
    PT_ENTITY_STATUS_RESPONSE,
    PT_POWER_MODE_REQUEST,
    PT_POWER_MODE_RESPONSE,
    PT_VEHICLE_ID_REQUEST,
    PT_VEHICLE_ID_REQUEST_WITH_EID,
    PT_VEHICLE_ID_REQUEST_WITH_VIN,
    PT_VEHICLE_ID_RESPONSE,
    build_frame,
)

logger = logging.getLogger("testecu.udp")


def _stagger_delay_ms(key: tuple, max_ms: int) -> int:
    """
    Deterministic A_DoIP_Announce_Wait in ``0..max_ms``, derived from ``key``.

    ISO 13400-2's A_DoIP_Announce_Wait is a *random* 0..500 ms delay used in
    two places: before answering a Vehicle Identification Request (keyed by
    the requester's address, so simultaneous responders don't burst), and
    before this entity's own first Vehicle Announcement after start-up (keyed
    by this entity's own identity, so simultaneous entities powering up
    together don't all announce at once). TestEcu deliberately substitutes a
    stable hash of ``key`` for the random draw in both cases: different keys
    get different delays (the same anti-burst effect), but the same key
    always gets the same delay, so a test can still assert on the behaviour.
    ``max_ms <= 0`` means "act immediately, no delay".
    """
    if max_ms <= 0:
        return 0
    seed = 0
    for part in key:
        if isinstance(part, str):
            for byte in part.encode("utf-8", "ignore"):
                seed = (seed * 31 + byte) & 0xFFFFFFFF
        elif isinstance(part, int):
            seed = (seed * 31 + part) & 0xFFFFFFFF
    return seed % (max_ms + 1)


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
    """Answers Vehicle Identification and Entity Status Requests, sends announcements."""

    def __init__(self, config: EcuConfig, if_index: int,
                 registry: Optional[Any] = None, max_sockets: int = 1) -> None:
        self._payload = build_announcement_payload(config)
        self._if_index = if_index
        self._port = config.listen.port
        self._node_type = config.doip.node_type
        self._power_mode = config.doip.power_mode
        self._max_data = config.doip.max_payload_bytes
        #: Only object queried for "currently open sockets" below — see
        #: ``_entity_status_payload`` for what it can and can't tell us.
        self._registry = registry
        self._max_sockets = max_sockets
        self._transport: Optional[asyncio.DatagramTransport] = None
        #: Entity identification used to match 0x0002 (VIR with EID) requests.
        self._eid = bytes.fromhex(config.doip.eid)
        #: VIN (17 bytes, zero-padded) used to match 0x0003 (VIR with VIN).
        self._vin = config.doip.vin.encode("ascii")[:17].ljust(17, b"\x00")
        self._announce_wait_ms = config.udp.announce_wait_ms
        #: Held refs to in-flight delayed responses so the event loop reaches them.
        self._tasks: set = set()

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if len(data) < 8:
            return
        pt = struct.unpack("!H", data[2:4])[0]
        if pt == PT_ENTITY_STATUS_REQUEST:
            logger.debug("UDP: Entity Status Request from %s", addr)
            if self._transport:
                self._transport.sendto(build_frame(PT_ENTITY_STATUS_RESPONSE,
                                                    self._entity_status_payload()), addr)
                logger.debug("UDP: sent Entity Status Response to %s", addr)
            return
        if pt == PT_POWER_MODE_REQUEST:
            # ISO 13400-2 Table 12 / DoIP-116..118: the Diagnostic Power Mode
            # info request (0x4003) arrives on UDP_DISCOVERY and the response
            # (0x4004) goes back over UDP to the requester's port.
            logger.debug("UDP: Power Mode Info Request from %s", addr)
            if self._transport:
                self._transport.sendto(build_frame(PT_POWER_MODE_RESPONSE,
                                                   bytes([self._power_mode])), addr)
                logger.debug("UDP: sent Power Mode Info Response to %s", addr)
            return
        if pt in (PT_VEHICLE_ID_REQUEST,
                  PT_VEHICLE_ID_REQUEST_WITH_EID,
                  PT_VEHICLE_ID_REQUEST_WITH_VIN):
            # ISO 13400-2 Figure 8: a VIN/EID-parameterised request is only
            # answered if the requested VIN/EID matches this entity.
            req = data[8:]
            if not self._matches(req, pt):
                logger.debug("UDP: Vehicle Identification Request (pt=0x%04X) "
                             "does not match from %s", pt, addr)
                return
            logger.debug("UDP: Vehicle Identification Request (pt=0x%04X) from %s",
                         pt, addr)
            self._schedule_identification_response(addr)
            return

    def _matches(self, req: bytes, pt: int) -> bool:
        """DoIP-051/-052/-053: does this identification request target this entity?"""
        if pt == PT_VEHICLE_ID_REQUEST:
            return True
        if pt == PT_VEHICLE_ID_REQUEST_WITH_EID:
            return len(req) >= 6 and req[:6] == self._eid
        if pt == PT_VEHICLE_ID_REQUEST_WITH_VIN:
            return len(req) >= 17 and req[:17] == self._vin
        return False

    def _schedule_identification_response(self, addr: tuple) -> None:
        """Send the identification response after a deferred A_DoIP_Announce_Wait."""
        if self._transport is None:
            return
        delay = _stagger_delay_ms(addr, self._announce_wait_ms) / 1000.0
        loop = asyncio.get_running_loop()
        task = loop.create_task(self._send_identification_after(delay, addr))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _send_identification_after(self, delay: float, addr: tuple) -> None:
        # ISO 13400-2 DoIP-051: the delay avoids UDP packet bursts when many
        # DoIP entities share the network and all answer one broadcast request.
        # TestEcu derives the delay deterministically from the requester (see
        # _stagger_delay_ms) rather than at random, so behaviour stays
        # assertable — a documented deviation from the ISO's random 0..500 ms.
        if delay:
            await asyncio.sleep(delay)
        if self._transport:
            self._transport.sendto(build_frame(PT_VEHICLE_ID_RESPONSE, self._payload), addr)
            logger.debug("UDP: sent Vehicle Identification Response to %s", addr)

    def _entity_status_payload(self) -> bytes:
        """Entity Status Response (0x4002), 7 bytes: node type, max/open sockets, max data.

        This is the only place Entity Status is answered — ISO 13400-2 makes
        it a UDP_DISCOVERY-only message type, so ``session.py``'s TCP_DATA
        loop rejects it instead of answering it (see that module's docstring).

        ``max_sockets`` is the caller's TCP listen backlog (best available
        proxy — this ECU does not otherwise cap concurrent sessions).
        ``open_sockets`` is ``len(registry)``: sessions that have completed
        Routing Activation. That is an approximation, not an exact count of
        open TCP sockets — a connected-but-not-yet-activated socket holds a
        real socket but has no registry entry — but it is closer to reality
        than the previous hardcoded 0, which told a tester this entity always
        had room for one more connection even when it did not.
        """
        open_sockets = min(len(self._registry), 0xFF) if self._registry is not None else 0
        max_sockets = min(max(self._max_sockets, 0), 0xFF)
        return (bytes([self._node_type, max_sockets, open_sockets])
                + struct.pack("!I", self._max_data))

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


async def run_announcer(config: EcuConfig, registry: Optional[Any] = None,
                        max_sockets: int = 1) -> None:
    """
    Bind UDP/IPv6, join the DoIP multicast group, wait out
    A_DoIP_Announce_Wait, send the configured number of announcements, then
    run until cancelled, answering Vehicle Identification Requests, and close
    the transport on the way out.

    Every step that depends on the interface is best-effort: on a developer
    machine there is no ``eth0`` and no multicast on loopback, and that must not
    stop the TCP side from coming up.

    ``registry``/``max_sockets`` are only used to answer Entity Status
    Requests (see ``_UDPProtocol._entity_status_payload``); both default so
    this stays usable standalone, same as before this parameter existed.
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
        lambda: _UDPProtocol(config, if_index, registry=registry, max_sockets=max_sockets),
        sock=sock,
    )

    logger.info("UDP: listening on [::]:%d  interface=%s", port, interface or "any")

    # Everything below runs inside the try so that closing the transport
    # (in the finally) covers every exit path — including cancellation
    # arriving mid-wait or mid-announcement, not just the "done, now idle"
    # case at the bottom. Without this, TestEcuServer.stop() cancels a task
    # that leaves the bound UDP socket open behind it (nothing else in the
    # process holds a reference that would close it), which leaks one socket
    # per start/stop cycle in tests and in any embedding that restarts the
    # server.
    try:
        # ISO 13400-2 A_DoIP_Announce_Wait: wait 0..announce_wait_ms before
        # the *first* Vehicle Announcement after start-up, so multiple DoIP
        # entities powering up together don't all announce in the same
        # instant. Keyed by this entity's own address/VIN (there is no
        # requester to key on here, unlike the Vehicle Identification
        # Request case above) — deterministic for the same testability
        # reason documented on ``_stagger_delay_ms``.
        initial_wait_ms = _stagger_delay_ms(
            (config.doip.ecu_logical_addr, config.doip.vin), config.udp.announce_wait_ms,
        )
        if initial_wait_ms:
            logger.debug(
                "UDP: waiting %d ms (A_DoIP_Announce_Wait) before the first "
                "Vehicle Announcement", initial_wait_ms,
            )
            await asyncio.sleep(initial_wait_ms / 1000.0)

        count = config.udp.announce_count
        interval = config.udp.announce_interval_ms / 1000.0
        for index in range(count):
            protocol.send_announcement()
            logger.info("UDP: sent Vehicle Announcement %d/%d", index + 1, count)
            if index < count - 1:
                await asyncio.sleep(interval)

        logger.info(
            "UDP: announcements done; listening for Vehicle Identification Requests")

        # Nothing else keeps this coroutine (or the transport it owns) alive:
        # TestEcuServer.stop() cancels this task to shut down, which raises
        # CancelledError out of this wait and into the finally below.
        await asyncio.Event().wait()
    finally:
        transport.close()
