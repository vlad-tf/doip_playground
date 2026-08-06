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
The DoIP connection state machine.

Ported from ``echo_ecu.ECUSession``: routing activation (including the ISO
13400-2 §9.3 source-address conflict resolution and alive probe), alive check,
entity status, and power mode are unchanged.  The one difference is
``_handle_diagnostic``, which now hands the UDS bytes to the dispatcher instead
of building a canned echo.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Any, Awaitable, Callable, Dict, Optional

from testecu.doip import (
    ACCEPTED_VERSIONS,
    ALIVE_PROBE_TIMEOUT_S,
    NACK_MESSAGE_TOO_LARGE,
    NACK_UNKNOWN_TARGET_ADDRESS,
    PT_ALIVE_CHECK_REQUEST,
    PT_ALIVE_CHECK_RESPONSE,
    PT_DIAGNOSTIC_MESSAGE,
    PT_DIAGNOSTIC_NEGATIVE_ACK,
    PT_DIAGNOSTIC_POSITIVE_ACK,
    PT_ENTITY_STATUS_REQUEST,
    PT_ENTITY_STATUS_RESPONSE,
    PT_HEADER_NACK,
    PT_POWER_MODE_REQUEST,
    PT_POWER_MODE_RESPONSE,
    PT_ROUTING_ACT_REQUEST,
    PT_ROUTING_ACT_RESPONSE,
    PTYPE_NAMES,
    build_frame,
    fmt_hex,
    payload as frame_payload,
    ptype as frame_ptype,
    read_frame,
)
from testecu.uds import (
    FUNCTIONAL_SUPPRESSED_NRCS,
    NO_RESPONSE,
    NRC_RESPONSE_PENDING,
    NegativeResponse,
    SuppressResponse,
    UdsRequest,
    nrc_name,
)

logger = logging.getLogger("testecu.session")


class SessionRegistry:
    """
    Tracks active sessions by tester logical address.

    ISO 13400-2 §9.3: when a Routing Activation arrives for a source address
    already registered on another socket, probe the existing connection with an
    Alive Check before deciding whether to accept or deny the new one.
    """

    def __init__(self) -> None:
        self._sessions: Dict[int, "EcuSession"] = {}

    def register(self, logical_addr: int, session: "EcuSession") -> None:
        self._sessions[logical_addr] = session
        logger.debug("registry: registered SA=0x%04X", logical_addr)

    def unregister(self, logical_addr: int) -> None:
        if self._sessions.pop(logical_addr, None) is not None:
            logger.debug("registry: unregistered SA=0x%04X", logical_addr)

    def lookup(self, logical_addr: int) -> Optional["EcuSession"]:
        return self._sessions.get(logical_addr)

    def __len__(self) -> int:
        return len(self._sessions)


class EcuSession:
    """One TCP connection from a tester or EdgeNode."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 ecu: Any, registry: Optional[SessionRegistry] = None) -> None:
        self._reader = reader
        self._writer = writer
        self._ecu = ecu
        self._registry = registry
        self._peer = writer.get_extra_info("peername")

        config = ecu.config
        self._ecu_addr = config.doip.ecu_logical_addr
        self._node_type = config.doip.node_type
        self._power_mode = config.doip.power_mode
        self._max_data = config.doip.max_payload_bytes

        #: UDS state for this connection (session, security level, S3 timer)
        self.state = ecu.new_session(str(self._peer))

        self.activated = False
        self.tester_addr: Optional[int] = None

        # Alive Check probe support (used when a competing session checks us)
        self._alive_probe_pending: bool = False
        self._alive_probe_event: Optional[asyncio.Event] = None

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

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
            self.state.close()
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            if self._registry is not None and self.tester_addr is not None:
                self._registry.unregister(self.tester_addr)
            logger.info("Session closed for %s", self._peer)

    def evict(self) -> None:
        """
        Non-blocking eviction — close the writer and unregister.

        Must stay synchronous: awaiting here from a *competing* session's task
        propagates CancelledError into the wrong context.  ``run()``'s finally
        block cleans up the rest in its own task.
        """
        self.state.close()
        try:
            self._writer.close()
        except Exception:
            pass
        if self._registry is not None and self.tester_addr is not None:
            self._registry.unregister(self.tester_addr)
        logger.info("Evicted session for %s", self._peer)

    async def _send(self, raw: bytes) -> None:
        self._writer.write(raw)
        await self._writer.drain()

    # -----------------------------------------------------------------------
    # Frame loop
    # -----------------------------------------------------------------------

    async def _loop(self) -> None:
        while True:
            raw = await read_frame(self._reader)
            pt = frame_ptype(raw)
            pload = frame_payload(raw)

            logger.debug(
                "RX %-40s  %3d bytes  from %s",
                PTYPE_NAMES.get(pt, "0x%04X" % pt), len(pload), self._peer,
            )

            ver = raw[0]
            inv = raw[1]
            if ver not in ACCEPTED_VERSIONS or inv != (0xFF ^ ver):
                logger.warning(
                    "Invalid header ver=0x%02X inv=0x%02X — sending NACK", ver, inv
                )
                await self._send(build_frame(PT_HEADER_NACK, bytes([0x00])))
                return

            if pt == PT_ROUTING_ACT_REQUEST:
                await self._handle_routing_activation(pload)

            elif pt == PT_DIAGNOSTIC_MESSAGE:
                await self._handle_diagnostic(pload)

            elif pt == PT_ALIVE_CHECK_REQUEST:
                await self._handle_alive_check()

            elif pt == PT_ALIVE_CHECK_RESPONSE:
                logger.debug("Alive Check Response from %s", self._peer)
                if self._alive_probe_pending and self._alive_probe_event is not None:
                    self._alive_probe_event.set()

            elif pt == PT_ENTITY_STATUS_REQUEST:
                await self._handle_entity_status()

            elif pt == PT_POWER_MODE_REQUEST:
                await self._handle_power_mode()

            else:
                logger.warning("Unknown payload type 0x%04X — sending Header NACK", pt)
                await self._send(build_frame(PT_HEADER_NACK, bytes([0x01])))

    # -----------------------------------------------------------------------
    # Routing activation and alive check
    # -----------------------------------------------------------------------

    async def probe_alive(self, timeout: float = ALIVE_PROBE_TIMEOUT_S) -> bool:
        """
        Send an Alive Check Request and wait for the response.

        Called by a *competing* session to decide whether this connection is
        still live before evicting it.  True = responded, False = considered dead.
        """
        self._alive_probe_event = asyncio.Event()
        self._alive_probe_pending = True
        try:
            await self._send(build_frame(PT_ALIVE_CHECK_REQUEST, b""))
            logger.debug("Alive Check probe → %s", self._peer)
            try:
                await asyncio.wait_for(self._alive_probe_event.wait(), timeout=timeout)
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

        ISO 13400-2 §9.3 conflict resolution: if the source address is already
        registered on another socket, alive-probe that socket first —
        responds → deny the new one with 0x03; times out → evict it and accept.
        """
        if len(payload) < 3:
            logger.warning("Routing Activation Request too short")
            await self._send(build_frame(PT_HEADER_NACK, bytes([0x04])))
            return

        src_addr = struct.unpack("!H", payload[0:2])[0]
        activation_type = payload[2]

        logger.info(
            "Routing Activation  src=0x%04X  type=0x%02X  from %s",
            src_addr, activation_type, self._peer,
        )

        if self._registry is not None:
            existing = self._registry.lookup(src_addr)
            if existing is not None and existing is not self:
                logger.info(
                    "SA 0x%04X already registered on %s — probing with Alive Check",
                    src_addr, existing._peer,
                )
                if await existing.probe_alive(ALIVE_PROBE_TIMEOUT_S):
                    logger.info(
                        "Existing session %s is alive — denying %s (0x03)",
                        existing._peer, self._peer,
                    )
                    await self._send(build_frame(
                        PT_ROUTING_ACT_RESPONSE,
                        self._activation_response(src_addr, 0x03),
                    ))
                    return
                logger.info("Existing session %s did not respond — evicting it",
                            existing._peer)
                existing.evict()

        self.tester_addr = src_addr
        self.activated = True
        self.state.tester_addr = src_addr
        self.state.activated = True

        if self._registry is not None:
            self._registry.register(src_addr, self)

        await self._send(build_frame(
            PT_ROUTING_ACT_RESPONSE, self._activation_response(src_addr, 0x10),
        ))
        logger.debug("Sent Routing Activation Response (success) to %s", self._peer)

    def _activation_response(self, src_addr: int, code: int) -> bytes:
        """13-byte Routing Activation Response payload."""
        return (
            struct.pack("!HH", src_addr, self._ecu_addr)
            + bytes([code])
            + b"\x00\x00\x00\x00"   # reserved
            + b"\x00\x00\x00\x00"   # OEM-specific
        )

    async def _handle_alive_check(self) -> None:
        # ISO 13400-2 Table 22: payload is the responder's logical address.
        await self._send(build_frame(PT_ALIVE_CHECK_RESPONSE,
                                     struct.pack("!H", self._ecu_addr)))
        logger.debug("Sent Alive Check Response (src=0x%04X) to %s",
                     self._ecu_addr, self._peer)

    async def _handle_entity_status(self) -> None:
        """Entity Status Response (0x4002): node type, max/open sockets, max data."""
        open_sockets = len(self._registry) if self._registry is not None else 1
        payload = (
            bytes([self._node_type, 1, max(1, open_sockets)])
            + struct.pack("!I", self._max_data)
        )
        await self._send(build_frame(PT_ENTITY_STATUS_RESPONSE, payload))
        logger.debug("Sent Entity Status Response to %s", self._peer)

    async def _handle_power_mode(self) -> None:
        """Power Mode Info Response (0x4004), 1 byte."""
        await self._send(build_frame(PT_POWER_MODE_RESPONSE, bytes([self._power_mode])))
        logger.debug("Sent Power Mode Response to %s", self._peer)

    # -----------------------------------------------------------------------
    # Diagnostic messages — the UDS entry point
    # -----------------------------------------------------------------------

    async def _handle_diagnostic(self, payload: bytes) -> None:
        """
        Diagnostic Message (0x8001): src (2) + tgt (2) + UDS bytes.

        Sends the Positive ACK (0x8002), then whatever the dispatcher produces.
        A handler may emit extra frames of its own before the final one via
        ``ctx.send()`` / ``ctx.response_pending()``.
        """
        if not self.activated:
            logger.warning("Diagnostic Message before activation — ignoring")
            return

        if len(payload) < 5:
            logger.warning("Diagnostic Message payload too short (%d bytes)", len(payload))
            return

        src, tgt = struct.unpack("!HH", payload[0:4])
        uds = bytes(payload[4:])
        functional = (tgt == self._ecu.uds.functional_addr)

        logger.info(
            "Diagnostic Message  src=0x%04X  tgt=0x%04X  UDS: %s  from %s",
            src, tgt, fmt_hex(uds), self._peer,
        )

        if tgt != self._ecu_addr and not functional:
            logger.warning("Diagnostic Message for unknown target 0x%04X — NACK", tgt)
            await self._send(build_frame(
                PT_DIAGNOSTIC_NEGATIVE_ACK,
                struct.pack("!HHB", tgt, src, NACK_UNKNOWN_TARGET_ADDRESS),
            ))
            return

        if len(uds) > self._max_data:
            await self._send(build_frame(
                PT_DIAGNOSTIC_NEGATIVE_ACK,
                struct.pack("!HHB", tgt, src, NACK_MESSAGE_TOO_LARGE),
            ))
            return

        # 1. Positive ACK
        await self._send(build_frame(PT_DIAGNOSTIC_POSITIVE_ACK,
                                     struct.pack("!HHB", src, tgt, 0x00)))
        logger.debug("Sent Positive ACK to %s", self._peer)

        # 2. UDS response, with src/tgt swapped
        request = UdsRequest(raw=uds, source_addr=src, target_addr=tgt,
                             functional=functional)

        async def responder(response: bytes) -> None:
            await self._send(build_frame(
                PT_DIAGNOSTIC_MESSAGE, struct.pack("!HH", self._ecu_addr, src) + response
            ))

        result = await resolve_uds(self._ecu, self.state, request, responder)
        if result is None:
            return

        await responder(result)
        logger.debug("Sent Diagnostic response  UDS: %s  to %s",
                     fmt_hex(result), self._peer)


# ---------------------------------------------------------------------------
# UDS resolution — module level so tests can drive it without a socket
# ---------------------------------------------------------------------------

async def resolve_uds(ecu: Any, state: Any, request: UdsRequest,
                      responder: Callable[[bytes], Awaitable[None]]) -> Optional[bytes]:
    """
    Run the dispatcher for one request and apply the suppression rules.

    Returns the bytes to send, or None when nothing should go on the wire.
    ``responder`` is used for any *extra* frames a handler emits (0x78 pending,
    ``ctx.send()``); the final response is returned rather than sent, so the
    caller controls the last frame.
    """
    # ISO 14229-1 §9.3: *any* received request restarts the S3 timer, not just
    # TesterPresent.  Re-arming in the default session is a no-op.
    state.refresh_s3()

    try:
        result = await _dispatch_with_p2(ecu, state, request, responder)
    except SuppressResponse:
        logger.debug("Response suppressed for %s", request.describe())
        return None
    except NegativeResponse as exc:
        if exc.sid is None:
            exc.sid = request.sid
        if request.functional and exc.nrc in FUNCTIONAL_SUPPRESSED_NRCS:
            logger.debug("Functional request: suppressing %s for %s",
                         nrc_name(exc.nrc), request.describe())
            return None
        logger.info("%s -> %s%s", request.describe(), nrc_name(exc.nrc),
                    (": " + exc.reason) if exc.reason else "")
        return exc.to_bytes()

    if result is NO_RESPONSE or result is None:
        logger.debug("No UDS response for %s (suppressed)", request.describe())
        return None

    if not isinstance(result, (bytes, bytearray)):
        logger.error("Handler for %s returned %s — expected bytes; sending nothing",
                     request.describe(), type(result).__name__)
        return None

    result = bytes(result)
    if (request.suppress_pos_rsp
            and ecu.uds.suppress_pos_rsp_bit
            and result[:1] != b"\x7F"):
        logger.debug("suppressPosRspMsgIndicationBit set for %s — not responding",
                     request.describe())
        return None
    return result


async def _dispatch_with_p2(ecu: Any, state: Any, request: UdsRequest,
                            responder: Callable[[bytes], Awaitable[None]]) -> Any:
    """
    Run the dispatcher, emitting ``7F <sid> 78`` while it is still working.

    Without this a slow plugin handler blows the tester's P2 timeout.
    ``shield`` inside ``wait_for`` is the point: the timeout must observe the
    handler, never cancel it.
    """
    uds_cfg = ecu.uds
    task = asyncio.ensure_future(ecu.dispatcher.dispatch(request, state, responder))
    if not uds_cfg.auto_response_pending:
        return await task

    window = uds_cfg.p2_server_ms / 1000.0
    while True:
        try:
            return await asyncio.wait_for(asyncio.shield(task), timeout=window)
        except asyncio.TimeoutError:
            logger.debug("P2 elapsed for %s — sending ResponsePending",
                         request.describe())
            await responder(bytes([0x7F, request.sid & 0xFF, NRC_RESPONSE_PENDING]))
            window = (uds_cfg.p2_star_server_ms / 1000.0) * 0.9
