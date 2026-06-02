"""
DoIP EdgeNode — Per-connection session state machine.

One DoIPSession is created per accepted TCP connection.  It manages:
- T_TCP_Initial_Inactivity timer (fires if no Routing Activation arrives)
- T_TCP_General_Inactivity timer (fires on prolonged silence)
- Routing Activation handshake and session gate
- DoIP frame reading, dissection, middleware chain dispatch
- Forwarding to ECU and relaying responses back to tester

# Scapy DoIP field names (verified on Raspberry Pi 4, Scapy installed via pip):
#
# version byte  : 'protocol_version'   (XByteEnumField)
# inverse byte  : 'inverse_version'    (XByteEnumField)
# payload type  : 'payload_type'       (XShortEnumField)
# payload length: 'payload_length'     (IntField)
#
# All DoIP sub-fields (source_address, target_address, activation_type, etc.)
# are ConditionalField entries directly on the DoIP packet — NOT on a sub-layer.
# Access them with pkt.source_address, pkt.activation_type, etc.
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from config import AppConfig
from routing import RoutingTable
from middleware import MiddlewareChain, DoIPFaultInjectionError
from session_registry import SessionRegistry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scapy DoIP field name constants
# (assumed for Scapy 2.5.x — verify on Raspberry Pi)
# ---------------------------------------------------------------------------
_VER_FIELD = "protocol_version"
_INV_VER_FIELD = "inverse_version"
_TYPE_FIELD = "payload_type"
_LEN_FIELD = "payload_length"

DOIP_HEADER_LEN = 8

# Expected version bytes
_VALID_VERSIONS = {0x02, 0x03}  # ISO 13400-2:2012 and 2019

# Payload type codes
PT_HEADER_NACK = 0x0000
PT_ROUTING_ACTIVATION_REQUEST = 0x0005
PT_ROUTING_ACTIVATION_RESPONSE = 0x0006
PT_ALIVE_CHECK_REQUEST = 0x0007
PT_ALIVE_CHECK_RESPONSE = 0x0008
PT_ENTITY_STATUS_REQUEST = 0x4001
PT_ENTITY_STATUS_RESPONSE = 0x4002
PT_POWER_MODE_REQUEST = 0x4003
PT_POWER_MODE_RESPONSE = 0x4004
PT_DIAGNOSTIC_MESSAGE = 0x8001
PT_DIAGNOSTIC_POSITIVE_ACK = 0x8002
PT_DIAGNOSTIC_NEGATIVE_ACK = 0x8003

# Alive Check probe timeout (seconds) — how long to wait for the existing
# tester to respond before considering it dead and evicting its session.
_ALIVE_PROBE_TIMEOUT_S = 0.5


class DoIPProtocolError(Exception):
    """Raised internally when the session must be closed due to a protocol violation."""


class DoIPSession:
    """
    Per-connection DoIP session state machine.

    Lifecycle:
      1. TCP connect → start T_TCP_Initial_Inactivity
      2. (optional TLS handshake is done by the caller before constructing this)
      3. Receive Routing Activation Request → validate → activate
      4. Process Diagnostic Messages via middleware chain → forward to ECU
      5. Relay ECU responses back to tester
      6. Close on timer expiry, peer disconnect, or protocol error
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        config: AppConfig,
        routing_table: RoutingTable,
        middleware_chain: MiddlewareChain,
        loop: asyncio.AbstractEventLoop,
        executor: ThreadPoolExecutor,
        registry: SessionRegistry | None = None,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.config = config
        self.routing_table = routing_table
        self.middleware_chain = middleware_chain
        self.loop = loop
        self.executor = executor
        self._registry = registry

        self.activated: bool = False
        self.tester_logical_addr: int | None = None

        self._ecu_conn = None  # ECUConnection, set on first Diagnostic Message
        self._initial_timer_task: asyncio.Task | None = None
        self._inactivity_task: asyncio.Task | None = None
        self._session_start = time.monotonic()
        self._peer = writer.get_extra_info("peername")

        # Alive Check probe support (used when a competing session checks us)
        self._alive_probe_pending: bool = False
        self._alive_probe_event: asyncio.Event | None = None

    @property
    def peer(self):
        return self._peer

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Main session loop.  Returns when the session should be torn down.
        All exceptions are caught here; the caller (server) sees a clean return.
        """
        logger.info("DoIPSession: new connection from %s", self._peer)
        self._start_initial_timer()
        try:
            await self._session_loop()
        except asyncio.IncompleteReadError:
            logger.info("DoIPSession: peer %s disconnected", self._peer)
        except ConnectionResetError:
            logger.info("DoIPSession: peer %s reset connection", self._peer)
        except DoIPProtocolError as exc:
            logger.warning("DoIPSession: protocol error from %s: %s", self._peer, exc)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.critical(
                "DoIPSession: unhandled exception for %s",
                self._peer,
                exc_info=True,
            )
        finally:
            await self._cleanup()

    # ------------------------------------------------------------------
    # Session loop
    # ------------------------------------------------------------------

    async def _session_loop(self) -> None:
        while True:
            raw = await self._read_frame()
            # Only reset the general inactivity timer after activation.
            # Before activation the T_TCP_Initial_Inactivity timer is in charge;
            # resetting here would create a premature general timer and, after
            # successful activation, _handle_routing_activation would create a
            # second one — resulting in two concurrent timers.
            if self.activated:
                self._reset_inactivity_timer()
            pkt = self._dissect(raw)
            await self._dispatch(pkt)

    async def _read_frame(self) -> bytes:
        """
        Read one complete DoIP frame.  Validates version/inverse bytes
        and enforces max_payload_bytes.  Sends a Header NACK and raises
        on any validation failure.
        """
        try:
            header = await self.reader.readexactly(DOIP_HEADER_LEN)
        except asyncio.IncompleteReadError:
            raise

        # Validate version pattern
        ver = header[0]
        inv = header[1]
        if ver not in _VALID_VERSIONS or inv != (0xFF ^ ver):
            logger.warning(
                "DoIPSession: invalid header bytes ver=0x%02X inv=0x%02X from %s",
                ver,
                inv,
                self._peer,
            )
            await self._send_header_nack(0x00)  # incorrect pattern format
            raise DoIPProtocolError("invalid header pattern")

        payload_len = int.from_bytes(header[4:8], "big")

        if payload_len > self.config.doip.max_payload_bytes:
            logger.warning(
                "DoIPSession: payload too large (%d > %d) from %s",
                payload_len,
                self.config.doip.max_payload_bytes,
                self._peer,
            )
            await self._send_header_nack(0x02)  # message too large
            raise DoIPProtocolError("payload too large")

        if payload_len == 0:
            return header

        payload = await self.reader.readexactly(payload_len)
        return header + payload

    def _dissect(self, raw: bytes):
        """Dissect raw bytes into a Scapy DoIP packet."""
        from scapy.contrib.automotive.doip import DoIP  # type: ignore[import]
        pkt = DoIP(raw)
        return pkt

    async def _dispatch(self, pkt) -> None:
        """Route an incoming packet to the appropriate handler."""
        ptype = getattr(pkt, _TYPE_FIELD, None)
        if ptype is None:
            await self._send_header_nack(0x01)  # unknown payload type
            raise DoIPProtocolError("unknown payload type")

        logger.debug(
            "DoIPSession: RX type=0x%04X activated=%s from %s",
            ptype,
            self.activated,
            self._peer,
        )

        # Always handle alive check messages regardless of activation state
        if ptype == PT_ALIVE_CHECK_REQUEST:
            await self._handle_alive_check()
            return

        if ptype == PT_ALIVE_CHECK_RESPONSE:
            await self._handle_alive_check_response()
            return

        if ptype == PT_ROUTING_ACTIVATION_REQUEST:
            # Cancel the initial inactivity timer immediately upon receipt
            if self._initial_timer_task and not self._initial_timer_task.done():
                self._initial_timer_task.cancel()
                self._initial_timer_task = None
            await self._handle_routing_activation(pkt)
            return

        if ptype == PT_ENTITY_STATUS_REQUEST:
            await self._handle_entity_status()
            return

        if ptype == PT_POWER_MODE_REQUEST:
            await self._handle_power_mode()
            return

        # Gate: no middleware or ECU forwarding until activated
        if ptype == PT_DIAGNOSTIC_MESSAGE and not self.activated:
            logger.warning(
                "DoIPSession: Diagnostic Message before activation from %s", self._peer
            )
            await self._send_diag_nack(0x02)  # invalid source address
            raise DoIPProtocolError("diagnostic message before activation")

        if ptype == PT_DIAGNOSTIC_MESSAGE and self.activated:
            await self._handle_diagnostic(pkt)
            return

        # Unknown or unexpected payload type
        logger.warning(
            "DoIPSession: unhandled payload type 0x%04X from %s", ptype, self._peer
        )
        await self._send_header_nack(0x01)
        raise DoIPProtocolError(f"unknown payload type 0x{ptype:04X}")

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    async def _handle_routing_activation(self, pkt) -> None:
        """
        Process a Routing Activation Request.

        ISO 13400-2 §9.3 conflict resolution when SA already registered:
          1. Send Alive Check Request to the existing session's tester.
          2. If it responds within _ALIVE_PROBE_TIMEOUT_S → deny new (0x03).
          3. If it times out → evict old session, accept new (0x10).

        Scapy models all DoIP sub-fields as ConditionalFields directly on the
        DoIP packet.  For payload_type=0x0005 the relevant fields are:
        source_address (2 bytes) and activation_type (1 byte).
        """
        src_addr = getattr(pkt, "source_address", None)
        activation_type = getattr(pkt, "activation_type", None)

        if src_addr is None or activation_type is None:
            logger.warning("DoIPSession: malformed Routing Activation Request")
            await self._send_routing_activation_response(0x00, 0x0000)
            raise DoIPProtocolError("malformed Routing Activation Request")

        # Validate: source address must be in routing table
        entry = self.routing_table.lookup_by_tester_addr(src_addr)
        if entry is None:
            logger.warning(
                "DoIPSession: unknown tester logical addr 0x%04X from %s",
                src_addr,
                self._peer,
            )
            await self._send_routing_activation_response(0x00, src_addr)
            raise DoIPProtocolError("unknown source logical address")

        # Accept activation types 0x00 (default) and 0x01 (OEM pass-through)
        if activation_type not in (0x00, 0x01):
            logger.warning(
                "DoIPSession: unsupported activation type 0x%02X", activation_type
            )
            await self._send_routing_activation_response(0x06, src_addr)
            raise DoIPProtocolError("unsupported routing activation type")

        # --- SA conflict check (ISO 13400-2 §9.3) ----------------------------
        if self._registry is not None:
            existing = self._registry.lookup(src_addr)
            if existing is not None and existing is not self:
                logger.info(
                    "DoIPSession: SA 0x%04X already registered on %s — "
                    "probing that session with Alive Check",
                    src_addr, existing.peer,
                )
                alive = await existing.probe_alive(_ALIVE_PROBE_TIMEOUT_S)
                if alive:
                    logger.info(
                        "DoIPSession: existing session %s responded — "
                        "denying new connection %s (code 0x03)",
                        existing.peer, self._peer,
                    )
                    await self._send_routing_activation_response(0x03, src_addr)
                    raise DoIPProtocolError(
                        "SA already registered on another active socket"
                    )
                else:
                    logger.info(
                        "DoIPSession: existing session %s did not respond — "
                        "evicting it and accepting new connection %s",
                        existing.peer, self._peer,
                    )
                    await existing._cleanup()
                    self._registry.unregister(src_addr)

        # ---------------------------------------------------------------------
        self.tester_logical_addr = src_addr
        self.activated = True

        if self._registry is not None:
            self._registry.register(src_addr, self)

        await self._send_routing_activation_response(0x10, src_addr)

        logger.info(
            "DoIPSession: activated tester 0x%04X type=0x%02X from %s",
            src_addr,
            activation_type,
            self._peer,
        )
        self._start_inactivity_timer()

    async def _handle_alive_check(self) -> None:
        """Respond to an Alive Check Request immediately.

        ISO 13400-2 Table 22: Alive Check Response payload = Source Address (2 bytes)
        — the logical address of the entity sending the response.
        The EdgeNode uses its own node_logical_addr as the source.
        """
        payload = self.config.doip.node_logical_addr.to_bytes(2, "big")
        await self._send_raw(self._build_frame(PT_ALIVE_CHECK_RESPONSE, payload))
        logger.debug(
            "DoIPSession: sent Alive Check Response (src=0x%04X) to %s",
            self.config.doip.node_logical_addr,
            self._peer,
        )

    async def _handle_alive_check_response(self) -> None:
        """
        Received an Alive Check Response (0x0008) from our tester.

        This arrives when a competing session called probe_alive() on us and
        our tester replied.  Signal the waiting probe.
        """
        logger.debug(
            "DoIPSession: received Alive Check Response from %s", self._peer
        )
        if self._alive_probe_pending and self._alive_probe_event is not None:
            self._alive_probe_event.set()

    async def probe_alive(self, timeout: float = _ALIVE_PROBE_TIMEOUT_S) -> bool:
        """
        Send an Alive Check Request to our tester and wait for its response.

        Called by a competing session's _handle_routing_activation() to check
        whether this session is still alive before deciding to evict it.

        Returns True  — tester responded; this session is active.
        Returns False — tester did not respond within timeout; consider dead.
        """
        self._alive_probe_event = asyncio.Event()
        self._alive_probe_pending = True
        try:
            await self._send_raw(self._build_frame(PT_ALIVE_CHECK_REQUEST, b""))
            logger.debug(
                "DoIPSession: sent Alive Check Request (probe) to %s", self._peer
            )
            try:
                await asyncio.wait_for(
                    self._alive_probe_event.wait(), timeout=timeout
                )
                return True
            except asyncio.TimeoutError:
                logger.debug(
                    "DoIPSession: Alive Check probe timed out for %s", self._peer
                )
                return False
        except Exception as exc:
            logger.debug(
                "DoIPSession: Alive Check probe failed for %s: %s", self._peer, exc
            )
            return False
        finally:
            self._alive_probe_pending = False
            self._alive_probe_event = None

    async def _handle_entity_status(self) -> None:
        """
        Respond to Entity Status Request (0x4001).

        Response payload (ISO 13400-2):
          byte 0: node type
          byte 1: max open sockets (PoC: 1)
          byte 2: currently open sockets (PoC: 1)
          bytes 3-6: max data size (big-endian uint32)
        """
        payload = bytes([
            self.config.doip.node_type,
            0x01,  # max sockets (PoC)
            0x01,  # open sockets
        ]) + self.config.doip.max_payload_bytes.to_bytes(4, "big")
        await self._send_raw(self._build_frame(PT_ENTITY_STATUS_RESPONSE, payload))
        logger.debug("DoIPSession: sent Entity Status Response to %s", self._peer)

    async def _handle_power_mode(self) -> None:
        """Respond to Power Mode Info Request (0x4003)."""
        payload = bytes([self.config.doip.power_mode])
        await self._send_raw(self._build_frame(PT_POWER_MODE_RESPONSE, payload))
        logger.debug("DoIPSession: sent Power Mode Response to %s", self._peer)

    async def _handle_diagnostic(self, pkt) -> None:
        """
        Process a Diagnostic Message:
        1. Run through middleware chain (tester_to_ecu direction)
        2. If not dropped: ensure ECU connection, forward
        3. Read ECU response, run through middleware chain (ecu_to_tester)
        4. Relay response back to tester
        """
        try:
            processed = await self.middleware_chain.run(pkt, "tester_to_ecu", self)
        except DoIPFaultInjectionError as exc:
            await self._send_diag_nack(exc.nack_code)
            return

        if processed is None:
            logger.debug("DoIPSession: diagnostic packet dropped by middleware")
            return

        # Ensure ECU connection exists
        if self._ecu_conn is None:
            await self._connect_to_ecu()

        if self._ecu_conn is None:
            # ECU unreachable
            await self._send_diag_nack(0x03)  # target unreachable
            return

        # Forward to ECU
        try:
            await self._ecu_conn.send(bytes(processed))
        except Exception as exc:
            logger.error("DoIPSession: ECU send error: %s", exc)
            await self._send_diag_nack(0x03)
            return

        # Receive ECU response
        try:
            ecu_raw = await self._ecu_conn.recv()
        except Exception as exc:
            logger.error("DoIPSession: ECU recv error: %s", exc)
            return

        ecu_pkt = self._dissect(ecu_raw)

        # Run response through middleware (ecu_to_tester)
        try:
            resp = await self.middleware_chain.run(ecu_pkt, "ecu_to_tester", self)
        except DoIPFaultInjectionError:
            resp = ecu_pkt  # fault injection on ecu→tester path: send anyway

        if resp is not None:
            await self._send_raw(bytes(resp))

    # ------------------------------------------------------------------
    # ECU connection management
    # ------------------------------------------------------------------

    async def _connect_to_ecu(self) -> None:
        """Open a connection to the ECU for the activated tester address."""
        from ecu_client import ECUConnection
        from tls_bridge import TLSFaultPolicy

        if self.tester_logical_addr is None:
            return

        entry = self.routing_table.lookup_by_tester_addr(self.tester_logical_addr)
        if entry is None:
            logger.error(
                "DoIPSession: no routing entry for tester 0x%04X",
                self.tester_logical_addr,
            )
            return

        conn = ECUConnection(
            entry=entry,
            tls_config=self.config.tls,
            loop=self.loop,
            executor=self.executor,
            use_tls=False,  # use plain port for PoC; TLS path uses port 3496
            fault_policy=TLSFaultPolicy(),
        )
        try:
            await conn.connect(tester_logical_addr=self.tester_logical_addr or 0x0E00)
            self._ecu_conn = conn
        except Exception as exc:
            logger.error(
                "DoIPSession: failed to connect to ECU for tester 0x%04X: %s",
                self.tester_logical_addr,
                exc,
            )
            self._ecu_conn = None

    # ------------------------------------------------------------------
    # Public helper for ReplayMiddleware
    # ------------------------------------------------------------------

    async def send_to_ecu(self, pkt) -> None:
        """
        Inject a packet directly to the ECU (used by ReplayMiddleware).
        """
        if self._ecu_conn is None:
            logger.warning("DoIPSession.send_to_ecu: no ECU connection")
            return
        await self._ecu_conn.send(bytes(pkt))

    # ------------------------------------------------------------------
    # Frame builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_frame(payload_type: int, payload: bytes, version: int = 0x02) -> bytes:
        """
        Build a raw DoIP frame (8-byte header + payload).

        The inverse byte is computed as 0xFF XOR version.
        """
        inv = 0xFF ^ version
        pt_bytes = payload_type.to_bytes(2, "big")
        len_bytes = len(payload).to_bytes(4, "big")
        return bytes([version, inv]) + pt_bytes + len_bytes + payload

    async def _send_raw(self, data: bytes) -> None:
        """Write raw bytes to the tester socket."""
        self.writer.write(data)
        await self.writer.drain()

    async def _send_header_nack(self, nack_code: int) -> None:
        """Send a DoIP Header NACK (0x0000)."""
        payload = bytes([nack_code])
        await self._send_raw(self._build_frame(PT_HEADER_NACK, payload))
        logger.warning(
            "DoIPSession: sent Header NACK code=0x%02X to %s", nack_code, self._peer
        )

    async def _send_routing_activation_response(
        self, response_code: int, tester_addr: int
    ) -> None:
        """
        Send a Routing Activation Response (0x0006).

        Payload (ISO 13400-2, 13 bytes):
          bytes 0-1: tester logical address
          bytes 2-3: EdgeNode logical address (0x0000 for gateway PoC)
          byte  4:   response code
          bytes 5-8: reserved (0x00000000)
          bytes 9-12: OEM-specific (0x00000000)
        """
        payload = (
            tester_addr.to_bytes(2, "big")
            + b"\x00\x00"         # EdgeNode logical address
            + bytes([response_code])
            + b"\x00\x00\x00\x00"  # reserved
            + b"\x00\x00\x00\x00"  # OEM-specific
        )
        await self._send_raw(self._build_frame(PT_ROUTING_ACTIVATION_RESPONSE, payload))

    async def _send_diag_nack(self, nack_code: int) -> None:
        """Send a Diagnostic Message Negative ACK (0x8003)."""
        # Payload: source addr (2) + target addr (2) + nack code (1)
        src = (self.tester_logical_addr or 0x0000).to_bytes(2, "big")
        payload = src + b"\x00\x00" + bytes([nack_code])
        await self._send_raw(self._build_frame(PT_DIAGNOSTIC_NEGATIVE_ACK, payload))
        logger.warning(
            "DoIPSession: sent Diag NACK code=0x%02X to %s", nack_code, self._peer
        )

    # ------------------------------------------------------------------
    # Timer management
    # ------------------------------------------------------------------

    def _start_initial_timer(self) -> None:
        self._initial_timer_task = asyncio.create_task(
            self._initial_inactivity_timeout()
        )

    async def _initial_inactivity_timeout(self) -> None:
        try:
            await asyncio.sleep(self.config.timers.t_tcp_initial_inactivity_s)
            logger.info(
                "DoIPSession: T_TCP_Initial_Inactivity expired for %s (no RA received)",
                self._peer,
            )
            await self._cleanup()
        except asyncio.CancelledError:
            pass  # normal: RA arrived before timeout

    def _start_inactivity_timer(self) -> None:
        self._inactivity_task = asyncio.create_task(
            self._general_inactivity_timeout()
        )

    def _reset_inactivity_timer(self) -> None:
        if self._inactivity_task and not self._inactivity_task.done():
            self._inactivity_task.cancel()
        self._inactivity_task = asyncio.create_task(
            self._general_inactivity_timeout()
        )

    async def _general_inactivity_timeout(self) -> None:
        try:
            await asyncio.sleep(self.config.timers.t_tcp_general_inactivity_s)
            logger.info(
                "DoIPSession: T_TCP_General_Inactivity expired for %s", self._peer
            )
            await self._cleanup()
        except asyncio.CancelledError:
            pass  # timer was reset; normal

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def _cleanup(self) -> None:
        """Tear down the session: cancel timers, close ECU conn, close tester socket."""
        if self._initial_timer_task and not self._initial_timer_task.done():
            self._initial_timer_task.cancel()
        if self._inactivity_task and not self._inactivity_task.done():
            self._inactivity_task.cancel()
        if self._ecu_conn:
            try:
                await self._ecu_conn.close()
            except Exception:
                pass
            self._ecu_conn = None
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

        # Unregister from the session registry
        if self._registry is not None and self.tester_logical_addr is not None:
            self._registry.unregister(self.tester_logical_addr)

        logger.info(
            "DoIPSession: closed session for %s (activated=%s)", self._peer, self.activated
        )
