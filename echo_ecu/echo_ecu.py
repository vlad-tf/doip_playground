"""
DoIP Echo ECU — minimal simulated ECU for testing the DoIP EdgeNode.

Runs on Linux.  Listens for TCP connections from the EdgeNode on IPv6.
No Scapy required — pure Python stdlib only.

Behaviour:
  - Routing Activation Request  → responds 0x10 (success)
  - Diagnostic Message          → sends Positive ACK, then echoes UDS payload
                                   back as a Diagnostic Message (src/tgt swapped)
  - Alive Check Request         → responds with Alive Check Response
  - Entity Status Request       → responds with static values from config
  - Power Mode Info Request     → responds with configured power mode
  - Unknown payload type        → responds with Header NACK 0x01

UDP (ISO 13400-2):
  - Sends Vehicle Announcement (0x0004) on startup:
      announce_count times at announce_interval_ms intervals.
      Sent to the DoIP IPv6 multicast address ff02::1 on the configured interface.
  - Responds to Vehicle Identification Requests (0x0001) with a
      Vehicle Identification Response (0x0004) sent unicast to the requester.

Binding notes:
  - TCP binds to "::" (all IPv6 interfaces) by default, accepting both
    link-local (fe80::) and global IPv6 connections.
  - If you need to bind to a specific link-local address you must also
    supply the interface scope ID; set listen.host to the link-local
    address and listen.interface to the interface name (e.g. "eth0").
  - UDP always binds to "::" on port 13400; the interface field controls
    which interface multicast announcements are sent out on.

Usage:
    python3 echo_ecu.py [--config config.yaml] [--log-level INFO]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import socket
import struct
import sys

import yaml

logger = logging.getLogger("echo_ecu")

# ---------------------------------------------------------------------------
# DoIP constants
# ---------------------------------------------------------------------------

_VER    = 0x02
_INV    = 0xFF ^ _VER

PT_HEADER_NACK              = 0x0000
PT_VEHICLE_ID_REQUEST       = 0x0001
PT_VEHICLE_ID_RESPONSE      = 0x0004
PT_ROUTING_ACT_REQUEST      = 0x0005
PT_ROUTING_ACT_RESPONSE     = 0x0006
PT_ALIVE_CHECK_REQUEST      = 0x0007
PT_ALIVE_CHECK_RESPONSE     = 0x0008
PT_ENTITY_STATUS_REQUEST    = 0x4001
PT_ENTITY_STATUS_RESPONSE   = 0x4002
PT_POWER_MODE_REQUEST       = 0x4003
PT_POWER_MODE_RESPONSE      = 0x4004
PT_DIAGNOSTIC_MESSAGE       = 0x8001
PT_DIAGNOSTIC_POSITIVE_ACK  = 0x8002

PTYPE_NAMES = {
    PT_HEADER_NACK:             "Header NACK",
    PT_ROUTING_ACT_REQUEST:     "Routing Activation Request",
    PT_ROUTING_ACT_RESPONSE:    "Routing Activation Response",
    PT_ALIVE_CHECK_REQUEST:     "Alive Check Request",
    PT_ALIVE_CHECK_RESPONSE:    "Alive Check Response",
    PT_ENTITY_STATUS_REQUEST:   "Entity Status Request",
    PT_ENTITY_STATUS_RESPONSE:  "Entity Status Response",
    PT_POWER_MODE_REQUEST:      "Power Mode Info Request",
    PT_POWER_MODE_RESPONSE:     "Power Mode Info Response",
    PT_DIAGNOSTIC_MESSAGE:      "Diagnostic Message",
    PT_DIAGNOSTIC_POSITIVE_ACK: "Diagnostic Message Positive ACK",
}


# IPv6 DoIP multicast group (all-nodes link-local) used for announcements
_DOIP_MCAST_ADDR = "ff02::1"

# Timeout for the Alive Check probe used during SA-conflict resolution.
# Defined here (module scope) so it is available when ECUSession is defined —
# it is referenced as a default argument in ECUSession.probe_alive().
_ALIVE_PROBE_TIMEOUT_S = 0.5

# ---------------------------------------------------------------------------
# UDP announcement payload
# ---------------------------------------------------------------------------

def _build_announcement_payload(config: dict) -> bytes:
    """
    Build the Vehicle Identification Response / Announcement payload.

    Structure (ISO 13400-2, 33 bytes):
      bytes  0-16 : VIN          (17 ASCII bytes)
      bytes 17-18 : logical addr (2 bytes, ECU logical address)
      bytes 19-24 : EID          (6 bytes, entity ID)
      bytes 25-30 : GID          (6 bytes, group ID)
      byte  31    : further action required (0x00 = none)
      byte  32    : VIN/GID sync status     (0x00 = synchronized)
    """
    doip = config.get("doip", {})
    vin  = str(doip.get("vin",  "00000000000000000")).encode("ascii")[:17].ljust(17, b"\x00")
    eid  = bytes.fromhex(str(doip.get("eid", "000000000000")))
    gid  = bytes.fromhex(str(doip.get("gid", "000000000000")))
    ecu_addr = int(str(doip.get("ecu_logical_addr", "0x0001")), 0)
    return (
        vin
        + struct.pack("!H", ecu_addr)
        + eid
        + gid
        + b"\x00"   # further action
        + b"\x00"   # sync status
    )


# ---------------------------------------------------------------------------
# UDP announcer
# ---------------------------------------------------------------------------

class _UDPProtocol(asyncio.DatagramProtocol):
    """
    asyncio.DatagramProtocol that:
      - receives Vehicle Identification Requests (0x0001) and responds unicast
      - is driven externally for initial announcements via send_announcement()
    """

    def __init__(self, config: dict, if_index: int) -> None:
        self._payload  = _build_announcement_payload(config)
        self._if_index = if_index
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if len(data) < 8:
            return
        pt = struct.unpack("!H", data[2:4])[0]
        if pt != PT_VEHICLE_ID_REQUEST:
            return
        logger.debug("UDP: Vehicle Identification Request from %s", addr)
        frame = _build(PT_VEHICLE_ID_RESPONSE, self._payload)
        if self._transport:
            self._transport.sendto(frame, addr)
            logger.debug("UDP: sent Vehicle Identification Response to %s", addr)

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDP: error: %s", exc)

    def send_announcement(self) -> None:
        """Send one Vehicle Announcement to the DoIP multicast group."""
        if not self._transport:
            return
        frame = _build(PT_VEHICLE_ID_RESPONSE, self._payload)
        dest  = (_DOIP_MCAST_ADDR, 13400, 0, self._if_index)
        try:
            self._transport.sendto(frame, dest)
        except Exception as exc:
            logger.warning("UDP: announcement send failed: %s", exc)


async def _run_udp_announcer(config: dict, interface: str) -> None:
    """
    Bind a UDP/IPv6 socket, join the DoIP multicast group, send the
    configured number of announcements, then keep listening.
    """
    udp_cfg = config.get("udp", {})
    count       = int(udp_cfg.get("announce_count",       3))
    interval_ms = int(udp_cfg.get("announce_interval_ms", 500))
    port        = int(config.get("listen", {}).get("port", 13400))

    # Resolve interface index (needed for multicast and scope_id)
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
    except AttributeError:
        pass

    # Join the all-nodes multicast group on the chosen interface so we
    # receive multicast Vehicle Identification Requests
    try:
        mreq = socket.inet_pton(socket.AF_INET6, _DOIP_MCAST_ADDR) + struct.pack("I", if_index)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    except OSError as exc:
        logger.warning("UDP: multicast join failed: %s", exc)

    # Set outgoing multicast interface and disable loopback to self
    if if_index:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                            struct.pack("I", if_index))
        except OSError:
            pass

    sock.bind(("::", port, 0, 0))

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _UDPProtocol(config, if_index),
        sock=sock,
    )
    protocol: _UDPProtocol  # type: ignore[assignment]

    logger.info("UDP: listening on [::]:%d  interface=%s", port, interface or "any")

    # Send initial announcements
    for i in range(count):
        protocol.send_announcement()
        logger.info("UDP: sent Vehicle Announcement %d/%d", i + 1, count)
        if i < count - 1:
            await asyncio.sleep(interval_ms / 1000.0)

    logger.info("UDP: announcements done; listening for Vehicle Identification Requests")


# ---------------------------------------------------------------------------
# Frame helpers
# ---------------------------------------------------------------------------

def _build(payload_type: int, payload: bytes, version: int = _VER) -> bytes:
    inv = 0xFF ^ version
    return struct.pack("!BBHI", version, inv, payload_type, len(payload)) + payload


async def _read_frame(reader: asyncio.StreamReader) -> bytes:
    hdr = await reader.readexactly(8)
    plen = struct.unpack("!I", hdr[4:8])[0]
    if plen == 0:
        return hdr
    payload = await reader.readexactly(plen)
    return hdr + payload


def _ptype(raw: bytes) -> int:
    return struct.unpack("!H", raw[2:4])[0]


def _payload(raw: bytes) -> bytes:
    return raw[8:]


def _fmt_hex(data: bytes, max_bytes: int = 32) -> str:
    if not data:
        return "(empty)"
    h = data[:max_bytes].hex(" ").upper()
    return h + (" …" if len(data) > max_bytes else "")


# ---------------------------------------------------------------------------
# ECU session handler
# ---------------------------------------------------------------------------

class ECUSession:
    """
    Handles one TCP connection from the EdgeNode.

    State:
        activated     — True once a successful Routing Activation has occurred.
                        Before this, Diagnostic Messages are rejected.
        tester_addr   — Source logical address presented by the EdgeNode/tester.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        config: dict,
        registry: ECUSessionRegistry | None = None,
    ) -> None:
        self._reader   = reader
        self._writer   = writer
        self._config   = config
        self._registry = registry
        self._peer     = writer.get_extra_info("peername")
        self.activated = False
        self.tester_addr: int | None = None

        self._ecu_addr   = int(str(config["doip"].get("ecu_logical_addr",  "0x0001")), 0)
        self._node_type  = int(str(config["doip"].get("node_type",          "0x01")),  0)
        self._power_mode = int(str(config["doip"].get("power_mode",         "0x01")),  0)
        self._max_data   = int(config["doip"].get("max_payload_bytes", 4096))

        # Alive Check probe support (used when a competing session checks us)
        self._alive_probe_pending: bool = False
        self._alive_probe_event: asyncio.Event | None = None

    async def run(self) -> None:
        logger.info("New connection from %s", self._peer)
        try:
            await self._loop()
        except asyncio.IncompleteReadError:
            logger.info("Connection closed by %s", self._peer)
        except ConnectionResetError:
            logger.info("Connection reset by %s", self._peer)
        except Exception:
            logger.exception("Unhandled error for %s", self._peer)
        finally:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            if self._registry and self.tester_addr is not None:
                self._registry.unregister(self.tester_addr)
            logger.info("Session closed for %s", self._peer)

    async def _loop(self) -> None:
        while True:
            raw   = await _read_frame(self._reader)
            pt    = _ptype(raw)
            pload = _payload(raw)

            name = PTYPE_NAMES.get(pt, f"0x{pt:04X}")
            logger.debug(
                "RX %-40s  %3d bytes  from %s",
                name,
                len(pload),
                self._peer,
            )

            # -- Validate header -------------------------------------------------
            ver = raw[0]
            inv = raw[1]
            if ver not in (0x02, 0x03) or inv != (0xFF ^ ver):
                logger.warning(
                    "Invalid header ver=0x%02X inv=0x%02X — sending NACK", ver, inv
                )
                await self._send(_build(PT_HEADER_NACK, bytes([0x00])))
                return

            # -- Dispatch --------------------------------------------------------
            if pt == PT_ROUTING_ACT_REQUEST:
                await self._handle_routing_activation(pload)

            elif pt == PT_DIAGNOSTIC_MESSAGE:
                await self._handle_diagnostic(pload)

            elif pt == PT_ALIVE_CHECK_REQUEST:
                await self._handle_alive_check()

            elif pt == PT_ALIVE_CHECK_RESPONSE:
                # Reply to our own probe — signal waiting probe_alive()
                logger.debug("Alive Check Response from %s", self._peer)
                if self._alive_probe_pending and self._alive_probe_event is not None:
                    self._alive_probe_event.set()

            elif pt == PT_ENTITY_STATUS_REQUEST:
                await self._handle_entity_status()

            elif pt == PT_POWER_MODE_REQUEST:
                await self._handle_power_mode()

            else:
                logger.warning("Unknown payload type 0x%04X — sending Header NACK", pt)
                await self._send(_build(PT_HEADER_NACK, bytes([0x01])))

    async def _send(self, raw: bytes) -> None:
        self._writer.write(raw)
        await self._writer.drain()

    # -----------------------------------------------------------------------
    # Handlers
    # -----------------------------------------------------------------------

    def evict(self) -> None:
        """
        Non-blocking eviction — cancel timers, close writer, unregister.
        The session's run() finally block handles the rest in its own context.
        See DoIPSession.evict() in session.py for the full explanation of why
        this must be synchronous (CancelledError propagation bug).
        """
        try:
            self._writer.close()
        except Exception:
            pass
        if self._registry is not None and self.tester_addr is not None:
            self._registry.unregister(self.tester_addr)
        logger.info("ECUSession: evicted session for %s", self._peer)

    async def probe_alive(self, timeout: float = _ALIVE_PROBE_TIMEOUT_S) -> bool:
        """
        Send an Alive Check Request to the connected EdgeNode and wait for
        its response.  Called by a competing session to check whether this
        connection is still live before evicting it.

        Returns True  — EdgeNode responded; this session is active.
        Returns False — no response within timeout; consider dead.
        """
        self._alive_probe_event = asyncio.Event()
        self._alive_probe_pending = True
        try:
            await self._send(_build(PT_ALIVE_CHECK_REQUEST, b""))
            logger.debug("Alive Check probe → %s", self._peer)
            try:
                await asyncio.wait_for(
                    self._alive_probe_event.wait(), timeout=timeout
                )
                return True
            except asyncio.TimeoutError:
                logger.debug("Alive Check probe timed out for %s", self._peer)
                return False
        except Exception as exc:
            logger.debug("Alive Check probe error for %s: %s", self._peer, exc)
            return False
        finally:
            self._alive_probe_pending = False
            self._alive_probe_event = None

    async def _handle_routing_activation(self, payload: bytes) -> None:
        """
        Routing Activation Request (0x0005).
        Payload: tester_logical_addr (2) + activation_type (1) + reserved (4)
        Response (0x0006), 13 bytes:
          bytes 0-1: tester logical address
          bytes 2-3: ECU logical address
          byte  4:   response code (0x10 = success)
          bytes 5-8: reserved
          bytes 9-12: OEM-specific

        ISO 13400-2 §9.3 conflict resolution:
          If src_addr is already registered on another socket, send an Alive
          Check Request to the existing connection first:
            - responds  → deny new with 0x03
            - times out → evict old, accept new with 0x10
        """
        if len(payload) < 3:
            logger.warning("Routing Activation Request too short")
            await self._send(_build(PT_HEADER_NACK, bytes([0x04])))
            return

        src_addr = struct.unpack("!H", payload[0:2])[0]
        activation_type = payload[2]

        logger.info(
            "Routing Activation  src=0x%04X  type=0x%02X  from %s",
            src_addr, activation_type, self._peer,
        )

        # --- SA conflict check -----------------------------------------------
        if self._registry is not None:
            existing = self._registry.lookup(src_addr)
            if existing is not None and existing is not self:
                logger.info(
                    "SA 0x%04X already registered on %s — probing with Alive Check",
                    src_addr, existing._peer,
                )
                alive = await existing.probe_alive(_ALIVE_PROBE_TIMEOUT_S)
                if alive:
                    logger.info(
                        "Existing session %s is alive — denying %s (0x03)",
                        existing._peer, self._peer,
                    )
                    resp = (
                        struct.pack("!HH", src_addr, self._ecu_addr)
                        + bytes([0x03])
                        + b"\x00\x00\x00\x00"
                        + b"\x00\x00\x00\x00"
                    )
                    await self._send(_build(PT_ROUTING_ACT_RESPONSE, resp))
                    return
                else:
                    logger.info(
                        "Existing session %s did not respond — evicting it",
                        existing._peer,
                    )
                    existing.evict()  # synchronous — no CancelledError propagation
        # ---------------------------------------------------------------------

        self.tester_addr = src_addr
        self.activated   = True

        if self._registry is not None:
            self._registry.register(src_addr, self)

        resp_payload = (
            struct.pack("!HH", src_addr, self._ecu_addr)
            + bytes([0x10])          # success
            + b"\x00\x00\x00\x00"   # reserved
            + b"\x00\x00\x00\x00"   # OEM-specific
        )
        await self._send(_build(PT_ROUTING_ACT_RESPONSE, resp_payload))
        logger.debug("Sent Routing Activation Response (success) to %s", self._peer)

    def _build_uds_response(self, uds: bytes) -> bytes:
        """
        Build a UDS response payload.

        Handled requests:
          0x22 F1 90  ReadDataByIdentifier — VIN
                      → 0x62 F1 90 + 17-byte VIN from config

        All other requests:
          → positive response SID (SID | 0x40) + echo sub-bytes + 4 random bytes
        """
        import os

        if len(uds) >= 3 and uds[0] == 0x22 and uds[1] == 0xF1 and uds[2] == 0x90:
            # ReadDataByIdentifier — VIN (ISO 14229-1 §B.4)
            vin_str = str(self._config.get("doip", {}).get("vin", "00000000000000000"))
            vin_bytes = vin_str.encode("ascii")[:17].ljust(17, b"\x00")
            return b"\x62\xF1\x90" + vin_bytes

        # Generic: echo with reply bit + random trailer
        if uds:
            return bytes([uds[0] | 0x40]) + uds[1:] + os.urandom(4)
        return os.urandom(4)

    async def _handle_diagnostic(self, payload: bytes) -> None:
        """
        Diagnostic Message (0x8001).
        Payload: src_addr (2) + tgt_addr (2) + UDS bytes.

        Responds with:
          1. Positive ACK (0x8002)  — acknowledges receipt
          2. Diagnostic Message (0x8001) with src/tgt swapped and a
             UDS response from _build_uds_response():
               22 F1 90  → 62 F1 90 + VIN (17 bytes from config)
               any other → SID|0x40 + echo sub-bytes + 4 random bytes
        """
        if not self.activated:
            logger.warning("Diagnostic Message before activation — ignoring")
            return

        if len(payload) < 4:
            logger.warning("Diagnostic Message payload too short")
            return

        src = struct.unpack("!H", payload[0:2])[0]
        tgt = struct.unpack("!H", payload[2:4])[0]
        uds = payload[4:]

        logger.info(
            "Diagnostic Message  src=0x%04X  tgt=0x%04X  UDS: %s  from %s",
            src, tgt, _fmt_hex(uds), self._peer,
        )

        # 1. Positive ACK
        ack_payload = struct.pack("!HHB", src, tgt, 0x00)  # ack_code 0x00 = OK
        await self._send(_build(PT_DIAGNOSTIC_POSITIVE_ACK, ack_payload))
        logger.debug("Sent Positive ACK to %s", self._peer)

        # 2. UDS response: swap src/tgt, build proper response via _build_uds_response
        response_uds = self._build_uds_response(uds)
        echo_payload = struct.pack("!HH", tgt, src) + response_uds
        await self._send(_build(PT_DIAGNOSTIC_MESSAGE, echo_payload))
        logger.debug(
            "Sent Diagnostic response  UDS: %s  to %s",
            _fmt_hex(response_uds), self._peer,
        )

    async def _handle_alive_check(self) -> None:
        # ISO 13400-2 Table 22: Alive Check Response payload = Source Address (2 bytes)
        # — the logical address of the entity sending the response.
        payload = struct.pack("!H", self._ecu_addr)
        await self._send(_build(PT_ALIVE_CHECK_RESPONSE, payload))
        logger.debug(
            "Sent Alive Check Response (src=0x%04X) to %s", self._ecu_addr, self._peer
        )

    async def _handle_entity_status(self) -> None:
        """
        Entity Status Response (0x4002), 7 bytes:
          byte 0: node type
          byte 1: max open sockets
          byte 2: currently open sockets
          bytes 3-6: max data size
        """
        payload = (
            bytes([self._node_type, 1, 1])
            + struct.pack("!I", self._max_data)
        )
        await self._send(_build(PT_ENTITY_STATUS_RESPONSE, payload))
        logger.debug("Sent Entity Status Response to %s", self._peer)

    async def _handle_power_mode(self) -> None:
        """Power Mode Info Response (0x4004), 1 byte: power_mode."""
        await self._send(_build(PT_POWER_MODE_RESPONSE, bytes([self._power_mode])))
        logger.debug("Sent Power Mode Response to %s", self._peer)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class ECUSessionRegistry:
    """
    Tracks active ECUSessions by tester logical address.

    ISO 13400-2 §9.3: when a new Routing Activation arrives for an SA already
    registered on another socket, the ECU probes the existing connection with
    an Alive Check Request before deciding whether to accept or deny.
    """

    def __init__(self) -> None:
        self._sessions: dict[int, "ECUSession"] = {}

    def register(self, logical_addr: int, session: "ECUSession") -> None:
        self._sessions[logical_addr] = session
        logger.debug("ECURegistry: registered SA=0x%04X", logical_addr)

    def unregister(self, logical_addr: int) -> None:
        if self._sessions.pop(logical_addr, None) is not None:
            logger.debug("ECURegistry: unregistered SA=0x%04X", logical_addr)

    def lookup(self, logical_addr: int) -> "ECUSession | None":
        return self._sessions.get(logical_addr)


class EchoECUServer:
    def __init__(self, config: dict) -> None:
        self._config = config
        self._registry = ECUSessionRegistry()

    async def start(self) -> None:
        listen = self._config.get("listen", {})
        host      = listen.get("host",      "::")
        port      = int(listen.get("port",  13400))
        interface = listen.get("interface", "")

        # Build the IPv6 listening socket manually so we can set
        # IPV6_V6ONLY and, if needed, bind to a link-local address with scope.
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET,   socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except AttributeError:
            pass  # not available on all systems

        scope_id = 0
        if interface:
            try:
                scope_id = socket.if_nametoindex(interface)
            except OSError as exc:
                logger.warning(
                    "Cannot get scope_id for interface %r: %s  (using 0)", interface, exc
                )

        sock.bind((host, port, 0, scope_id))
        sock.listen(1)

        server = await asyncio.start_server(
            self._handle_connection,
            sock=sock,
        )

        bound = sock.getsockname()
        logger.info(
            "Echo ECU listening on [%s]:%d  (interface=%s)",
            bound[0], bound[1], interface or "any",
        )
        print(f"Echo ECU ready — listening on [{bound[0]}]:{bound[1]}")
        print("Press Ctrl+C to stop.\n")

        # Start UDP announcer (non-blocking; runs alongside TCP server)
        asyncio.create_task(
            _run_udp_announcer(self._config, interface),
            name="udp-announcer",
        )

        async with server:
            await server.serve_forever()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        session = ECUSession(reader, writer, self._config, self._registry)
        await session.run()


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _load_config(path: str) -> dict:
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f)
        assert isinstance(cfg, dict)
        return cfg
    except FileNotFoundError:
        logger.warning("Config file %r not found — using defaults.", path)
        return {"listen": {}, "doip": {}}
    except Exception as exc:
        logger.error("Config error: %s — using defaults.", exc)
        return {"listen": {}, "doip": {}}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="DoIP Echo ECU")
    parser.add_argument("--config",    default="config.yaml")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    config = _load_config(args.config)
    server = EchoECUServer(config)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\nShutting down.")
        sys.exit(0)


if __name__ == "__main__":
    main()
