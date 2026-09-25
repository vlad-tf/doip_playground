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
13400-2 §9.3 source-address conflict resolution and alive probe) and alive
check are unchanged. Three differences from the port: ``_handle_diagnostic``
hands the UDS bytes to the dispatcher instead of building a canned echo;
this class also runs the ISO 13400-2 §7.2.2/§7.2.3 initial/general
inactivity timers (see ``_supervise``), which ``echo_ecu`` does not
implement; and Entity Status Request (0x4001) and Power Mode Info Request
(0x4003) are *not* answered here — ISO 13400-2 classes both as UDP_DISCOVERY
messages, so a TCP_DATA socket receiving either now gets the same Header
NACK 0x01 as any other payload type this socket doesn't accept (``udp.py``
answers the UDP side). ``echo_ecu`` still answers them over TCP; that's a
deliberate divergence, not a bug to sync back.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Any, Awaitable, Callable, Dict, Optional

from testecu.doip import (
    ACCEPTED_VERSIONS,
    ALIVE_PROBE_TIMEOUT_S,
    NACK_INVALID_SOURCE_ADDRESS,
    NACK_MESSAGE_TOO_LARGE,
    NACK_UNKNOWN_TARGET_ADDRESS,
    ROUTING_ACT_REQUEST_MIN_LEN,
    PT_ALIVE_CHECK_REQUEST,
    PT_ALIVE_CHECK_RESPONSE,
    PT_DIAGNOSTIC_MESSAGE,
    PT_DIAGNOSTIC_NEGATIVE_ACK,
    PT_DIAGNOSTIC_POSITIVE_ACK,
    PT_HEADER_NACK,
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
    NRC_GENERAL_REJECT,
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

    def unregister(self, logical_addr: int, session: "EcuSession") -> None:
        """
        Remove ``logical_addr`` only if it still points at ``session``.

        Identity-checked on purpose: eviction (``evict()``) unregisters the
        old session immediately, a new session then registers under the same
        SA, and only *afterwards* does the evicted session's own ``run()``
        ``finally`` run and call this again — a plain pop-by-key there would
        remove the *new* session's entry instead of noticing it's already
        gone. That silently defeated ISO 13400-2 §9.3 conflict resolution:
        the registry would end up empty, and a third connection with the
        same SA would be accepted with no alive probe at all.
        """
        if self._sessions.get(logical_addr) is session:
            del self._sessions[logical_addr]
            logger.debug("registry: unregistered SA=0x%04X", logical_addr)

    def lookup(self, logical_addr: int) -> Optional["EcuSession"]:
        return self._sessions.get(logical_addr)

    def __len__(self) -> int:
        return len(self._sessions)


class _CloseConnection(Exception):
    """Internal control flow: send the pending NACK/denial, then tear the
    socket down.

    Raised by handlers that must both emit a frame and close the TCP_DATA
    connection: a Diagnostic Message with an invalid source address (ISO
    13400-2 Table 31 / DoIP-070, NACK code 0x02) and any Routing Activation
    Response that denies rather than accepts (ISO 13400-2 Table 25 — every
    code other than 0x10/0x11 leaves the requester expected to reconnect, not
    keep talking on the same socket). ``_loop`` catches it, logs, and lets
    ``run()``'s ``finally`` close the writer and unregister the session.
    """


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
        self._max_data = config.doip.max_payload_bytes
        self._tester_addr_range = config.doip.tester_addr_range

        #: UDS state for this connection (session, security level, S3 timer)
        self.state = ecu.new_session(str(self._peer))

        self.activated = False
        self.tester_addr: Optional[int] = None

        # Alive Check probe support (used when a competing session checks us)
        self._alive_probe_pending: bool = False
        self._alive_probe_event: Optional[asyncio.Event] = None

        # -------- Inactivity timers (ISO 13400-2 §7.2.2 / §7.2.3) --------
        # The initial inactivity timer runs from connection to Routing
        # Activation; the general inactivity timer runs from Routing Activation
        # to shutdown and is reset by every byte sent or received.  A monotonic
        # deadline per timer, watched by one supervisor task, is enough — no
        # need to constantly reset OS timers on each packet.
        self._loop_ref = asyncio.get_running_loop()
        self._initial_timeout = config.doip.initial_inactivity_ms / 1000.0
        self._general_timeout = config.doip.general_inactivity_ms / 1000.0
        self._initial_deadline: Optional[float] = None
        self._general_deadline: Optional[float] = None
        self._kick_event = asyncio.Event()
        self._supervisor: Optional[asyncio.Task] = None
        self._finalized: bool = False
        self._finalize_reason: Optional[str] = None

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def run(self) -> None:
        logger.info("New connection from %s", self._peer)
        # DoIP-083/-084: start the initial inactivity timer once the TCP
        # connection is established.
        # A timeout of 0 means "disabled" (config.yaml's documented escape
        # hatch) — leave the deadline unset rather than firing immediately.
        if self._initial_timeout > 0:
            self._initial_deadline = self._loop_ref.time() + self._initial_timeout
        self._supervisor = asyncio.ensure_future(self._supervise())
        try:
            await self._loop()
        except asyncio.IncompleteReadError:
            logger.info("Connection closed by %s", self._peer)
        except ConnectionResetError:
            logger.info("Connection reset by %s", self._peer)
        except Exception:
            logger.exception("Unhandled error for %s", self._peer)
        finally:
            self._finalized = True
            if self._supervisor is not None and not self._supervisor.done():
                self._supervisor.cancel()
                try:
                    await self._supervisor
                except (asyncio.CancelledError, Exception):
                    pass
                self._supervisor = None
            self.state.close()
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            if self._registry is not None and self.tester_addr is not None:
                self._registry.unregister(self.tester_addr, self)
            logger.info("Session closed for %s", self._peer)

    def evict(self) -> None:
        """
        Non-blocking eviction — close the writer and unregister.

        Must stay synchronous: awaiting here from a *competing* session's task
        propagates CancelledError into the wrong context.  ``run()``'s finally
        block cleans up the rest in its own task.
        """
        self._finalized = True
        if self._supervisor is not None and not self._supervisor.done():
            self._supervisor.cancel()
            self._supervisor = None
        self.state.close()
        try:
            self._writer.close()
        except Exception:
            pass
        if self._registry is not None and self.tester_addr is not None:
            self._registry.unregister(self.tester_addr, self)
        logger.info("Evicted session for %s", self._peer)

    async def _send(self, raw: bytes) -> None:
        # DoIP-080: any traffic on a registered socket resets the general timer.
        self._bump_general()
        self._writer.write(raw)
        await self._writer.drain()

    # -----------------------------------------------------------------------
    # Inactivity supervision (§7.2.2, §7.2.3)
    # -----------------------------------------------------------------------

    def _bump_general(self) -> None:
        """Reset the general inactivity timer (any data sent or received)."""
        if self.activated and not self._finalized and self._general_timeout > 0:
            self._general_deadline = self._loop_ref.time() + self._general_timeout

    def _kick(self) -> None:
        """Wake the supervisor so it recomputes against a changed deadline."""
        if not self._finalized:
            self._kick_event.set()

    def _arm_general(self) -> None:
        """Calls after successful Routing Activation (DoIP-128): initial timer
        stops, general timer starts from now.

        A general timeout of 0 means "disabled" — leave the deadline unset
        rather than arming one that elapses immediately.
        """
        self._initial_deadline = None
        if self._general_timeout > 0:
            self._general_deadline = self._loop_ref.time() + self._general_timeout
        self._kick()

    def _finalize(self, reason: str, abortive: bool = False) -> None:
        """DoIP-132/-133: timer elapsed → tear this connection down.  Closing the
        writer unblocks ``_loop()``'s read, so ``run()``'s ``finally`` does the
        rest of the cleanup.

        ``abortive=True`` forces a TCP RST instead of the normal orderly FIN
        close — used for T_TCP_Initial_Inactivity (§7.2.2): the peer never
        completed Routing Activation, so this socket was never a trusted
        session, and the teardown should say so accordingly. Traffic-bearing
        closes (general inactivity, normal disconnect) keep the graceful FIN.
        """
        if self._finalized:
            return
        self._finalized = True
        self._finalize_reason = reason
        logger.info("Finalizing %s: %s", self._peer, reason)
        if abortive:
            self._abort_connection()
        else:
            try:
                self._writer.close()
            except Exception:
                pass

    def _abort_connection(self) -> None:
        """Force a TCP RST rather than an orderly FIN close.

        ``asyncio``'s normal ``close()`` performs a graceful shutdown; getting
        an RST out of it needs ``SO_LINGER`` set to "on, 0 seconds" on the raw
        socket *before* the transport is torn down, followed by an abortive
        close (``transport.abort()``, which skips flushing) rather than
        ``writer.close()``.
        """
        sock = self._writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack("ii", 1, 0))
            except OSError:
                logger.debug("Could not set SO_LINGER for abortive close of %s",
                             self._peer)
        transport = self._writer.transport
        try:
            if transport is not None:
                transport.abort()
            else:
                self._writer.close()
        except Exception:
            pass

    async def _supervise(self) -> None:
        """Watch the initial and general inactivity deadlines until one elapses."""
        while not self._finalized:
            now = self._loop_ref.time()
            deadlines = [d for d in (self._initial_deadline, self._general_deadline)
                         if d is not None]
            if not deadlines:
                # Nothing armed (not yet started); wait for a kick.
                self._kick_event.clear()
                await self._kick_event.wait()
                continue
            delay = max(0.0, min(deadlines) - now)
            self._kick_event.clear()
            try:
                await asyncio.wait_for(self._kick_event.wait(), timeout=delay)
                continue  # kicked — a deadline changed, recompute
            except asyncio.TimeoutError:
                pass
            if self._finalized:
                return
            if self._initial_deadline is not None \
                    and self._loop_ref.time() >= self._initial_deadline:
                self._finalize("initial inactivity timeout (T_TCP_Initial_Inactivity)",
                                abortive=True)
                return
            if self._general_deadline is not None \
                    and self._loop_ref.time() >= self._general_deadline:
                self._finalize("general inactivity timeout (T_TCP_General_Inactivity)")
                return

    # -----------------------------------------------------------------------
    # Frame loop
    # -----------------------------------------------------------------------

    async def _loop(self) -> None:
        while True:
            raw = await read_frame(self._reader)
            pt = frame_ptype(raw)
            pload = frame_payload(raw)

            # DoIP-080: any received data on a registered socket resets the
            # general inactivity timer.
            self._bump_general()

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
                try:
                    await self._handle_routing_activation(pload)
                except _CloseConnection:
                    logger.info(
                        "Closing socket after Routing Activation denial for %s",
                        self._peer,
                    )
                    return

            elif pt == PT_DIAGNOSTIC_MESSAGE:
                try:
                    await self._handle_diagnostic(pload)
                except _CloseConnection:
                    logger.info(
                        "Closing socket after Diagnostic NACK for %s", self._peer,
                    )
                    return

            elif pt == PT_ALIVE_CHECK_REQUEST:
                await self._handle_alive_check()

            elif pt == PT_ALIVE_CHECK_RESPONSE:
                logger.debug("Alive Check Response from %s", self._peer)
                if self._alive_probe_pending and self._alive_probe_event is not None:
                    self._alive_probe_event.set()

            else:
                # Covers truly unknown payload types and the two ISO 13400-2
                # UDP_DISCOVERY-only types (Entity Status Request 0x4001,
                # Power Mode Info Request 0x4003) if sent here by mistake —
                # this TCP_DATA socket doesn't accept either; ``udp.py``
                # answers them on the UDP side.
                logger.warning("Unknown/unsupported payload type 0x%04X on TCP_DATA "
                               "— sending Header NACK", pt)
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

        ISO 13400-2 Table 15: the fixed payload is source address (2) +
        activation type (1) + reserved (4) = 7 bytes; anything shorter is a
        malformed frame and must be rejected with Generic NACK 0x04 (payload
        length not valid for this message), not parsed.

        ISO 13400-2 Table 25: every response code other than success (0x10)
        denies the request, and every denial here closes the TCP_DATA socket
        (raises ``_CloseConnection``, caught by ``_loop``) rather than leaving
        it open for a retry on the same connection.
        """
        if len(payload) < ROUTING_ACT_REQUEST_MIN_LEN:
            logger.warning(
                "Routing Activation Request too short (%d < %d bytes) — Generic NACK",
                len(payload), ROUTING_ACT_REQUEST_MIN_LEN,
            )
            await self._send(build_frame(PT_HEADER_NACK, bytes([0x04])))
            return

        src_addr = struct.unpack("!H", payload[0:2])[0]
        activation_type = payload[2]

        logger.info(
            "Routing Activation  src=0x%04X  type=0x%02X  from %s",
            src_addr, activation_type, self._peer,
        )

        # ISO 13400-2 Table 13 / Table 48 code 0x00: a source address outside
        # the tester (client) logical address range is not a valid tester and
        # must be denied, regardless of any conflict-resolution logic below.
        low, high = self._tester_addr_range
        if not (low <= src_addr <= high):
            logger.warning(
                "Routing Activation from unknown/out-of-range SA=0x%04X "
                "(expected 0x%04X-0x%04X) — denying (0x00)",
                src_addr, low, high,
            )
            await self._send(build_frame(
                PT_ROUTING_ACT_RESPONSE,
                self._activation_response(src_addr, 0x00),
            ))
            raise _CloseConnection()

        # ISO 13400-2 Table 48 code 0x06: only the default (0x00) and the
        # OEM-specific/WWH-OBD pass-through (0x01) activation types are
        # supported — anything else is denied, not silently accepted.
        if activation_type not in (0x00, 0x01):
            logger.warning(
                "Routing Activation with unsupported type=0x%02X from %s — "
                "denying (0x06)", activation_type, self._peer,
            )
            await self._send(build_frame(
                PT_ROUTING_ACT_RESPONSE,
                self._activation_response(src_addr, 0x06),
            ))
            raise _CloseConnection()

        # ISO 13400-2 Table 48 code 0x02: this socket is already activated for
        # a different SA, so a Routing Activation Request for a new SA on the
        # same socket (a "re-bind") is denied rather than silently re-registered.
        if self.activated and src_addr != self.tester_addr:
            logger.warning(
                "Routing Activation re-bind attempt: socket already activated "
                "for SA=0x%04X, new request is SA=0x%04X — denying (0x02)",
                self.tester_addr, src_addr,
            )
            await self._send(build_frame(
                PT_ROUTING_ACT_RESPONSE,
                self._activation_response(src_addr, 0x02),
            ))
            raise _CloseConnection()

        # A repeat Routing Activation Request for the already-bound SA is
        # idempotent — re-confirm success rather than falling through.
        if self.activated and src_addr == self.tester_addr:
            logger.debug("Repeat Routing Activation for already-active SA=0x%04X "
                         "— re-confirming success", src_addr)
            await self._send(build_frame(
                PT_ROUTING_ACT_RESPONSE, self._activation_response(src_addr, 0x10),
            ))
            return

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
                    raise _CloseConnection()
                logger.info("Existing session %s did not respond — evicting it",
                            existing._peer)
                existing.evict()

        self.tester_addr = src_addr
        self.activated = True
        self.state.tester_addr = src_addr
        self.state.activated = True

        if self._registry is not None:
            self._registry.register(src_addr, self)

        # DoIP-128: routing activation accepted — stop the initial inactivity
        # timer and start the general inactivity timer for this connection.
        self._arm_general()

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

        # ISO 13400-2 DoIP-070 / Table 31 code 0x02: the diagnostic message's
        # source address must be the one that activated routing on THIS socket.
        # A never-activated socket has no registered SA (self.tester_addr is
        # None, which no real SA can equal) and a spoofed SA on an activated
        # socket both fail this same check — both are the same protocol
        # violation and get the same treatment: NACK 0x02 and close the
        # TCP_DATA socket (a real gateway would, and it stops a
        # merely-connected-but-never-activated peer from injecting requests).
        if not self.activated or src != self.tester_addr:
            logger.warning(
                "Diagnostic Message src=0x%04X on socket registered to %s — "
                "NACK 0x02 + close",
                src,
                "0x%04X" % self.tester_addr if self.activated else "<not activated>",
            )
            await self._send(build_frame(
                PT_DIAGNOSTIC_NEGATIVE_ACK,
                struct.pack("!HHB", self._ecu_addr, src, NACK_INVALID_SOURCE_ADDRESS),
            ))
            raise _CloseConnection()

        if tgt != self._ecu_addr and not functional:
            logger.warning("Diagnostic Message for unknown target 0x%04X — NACK", tgt)
            await self._send(build_frame(
                PT_DIAGNOSTIC_NEGATIVE_ACK,
                struct.pack("!HHB", self._ecu_addr, src, NACK_UNKNOWN_TARGET_ADDRESS),
            ))
            return

        if len(uds) > self._max_data:
            await self._send(build_frame(
                PT_DIAGNOSTIC_NEGATIVE_ACK,
                struct.pack("!HHB", self._ecu_addr, src, NACK_MESSAGE_TOO_LARGE),
            ))
            return

        # 1. Positive ACK.  ISO 13400-2 Table 28 / DoIP-066: the ack's SA is
        # always this entity's own logical address — never the request's
        # ``tgt`` field, which is only *this* ECU's address in the plain
        # physical-addressing case. A functional request's ``tgt`` is the
        # functional address, and an unknown-target NACK's ``tgt`` is
        # whatever invalid address the requester sent; using either as our
        # own SA would tell the tester this ECU is answering from an address
        # it doesn't own.
        await self._send(build_frame(PT_DIAGNOSTIC_POSITIVE_ACK,
                                     struct.pack("!HHB", self._ecu_addr, src, 0x00)))
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

    ``uds.max_response_pending`` caps how many 0x78 frames one request may
    generate. A handler that never returns would otherwise make this emit
    0x78 forever — and since every sent frame resets the general inactivity
    timer (DoIP-080), the connection could never time out either, turning one
    hung handler into a permanent frame flood on an immortal connection. Once
    the cap is hit, this gives up: cancels ``task``, sends a final NRC 0x10
    (generalReject), and stops waiting. Cancelling (not detaching) matters —
    ``shield`` only protects the handler from the P2 timeout, never from
    teardown, and plugin code is already expected to be cancellable
    (``dispatcher.py`` re-raises ``CancelledError`` rather than isolating
    it) — otherwise the abandoned task outlives the connection for good and
    can still call ``responder()`` whenever it eventually wakes up.
    """
    uds_cfg = ecu.uds
    task = asyncio.ensure_future(ecu.dispatcher.dispatch(request, state, responder))
    if not uds_cfg.auto_response_pending:
        return await task

    window = uds_cfg.p2_server_ms / 1000.0
    pending_sent = 0
    while True:
        try:
            return await asyncio.wait_for(asyncio.shield(task), timeout=window)
        except asyncio.TimeoutError:
            if uds_cfg.max_response_pending and pending_sent >= uds_cfg.max_response_pending:
                logger.warning(
                    "%s: handler still running after %d ResponsePending frames "
                    "— giving up with NRC 0x10 (uds.max_response_pending)",
                    request.describe(), pending_sent,
                )
                # Cancel rather than detach: shield only protects the handler
                # from the P2 timeout, not from teardown — plugin code is
                # already expected to be cancellable (dispatcher.py re-raises
                # CancelledError instead of isolating it), cancelling runs its
                # finally blocks, and a merely-slow handler that outlives the
                # cap must not wake up later and ctx.send() a stray frame onto
                # a connection the tester has moved on from.
                task.cancel()
                task.add_done_callback(_log_abandoned_dispatch)
                await responder(bytes([0x7F, request.sid & 0xFF, NRC_GENERAL_REJECT]))
                return NO_RESPONSE
            logger.debug("P2 elapsed for %s — sending ResponsePending",
                         request.describe())
            await responder(bytes([0x7F, request.sid & 0xFF, NRC_RESPONSE_PENDING]))
            pending_sent += 1
            window = (uds_cfg.p2_star_server_ms / 1000.0) * 0.9


def _log_abandoned_dispatch(task: "asyncio.Task") -> None:
    """Done callback for a dispatch task abandoned by the max_response_pending cap.

    Only purpose: consume the eventual result/exception so asyncio doesn't
    log "Task exception was never retrieved" for a task nothing awaits anymore.
    """
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.debug("Abandoned dispatch task raised after giving up: %r", exc)
