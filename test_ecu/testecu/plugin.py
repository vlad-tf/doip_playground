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
The TestEcu plugin API — this is the module plugin authors work against.

A plugin module is any ``.py`` file that defines one or more ``Plugin``
subclasses.  The loader instantiates each subclass with the YAML ``params:``
mapping as keyword arguments, then the dispatcher collects the decorated
methods into its hook tables.

    from testecu import Plugin, read_did, write_did, routine, on_service

    class MyEcu(Plugin):
        priority = 50

        @read_did(0xF190)
        def vin(self, req, ctx):
            return b"WVWZZZ1JZXW000001"

Handler contract — every handler may be ``def`` or ``async def``:

    @on_service(sid) / @on_service()   (self, req, ctx)          -> bytes | NO_RESPONSE | None
    @on_request()                      (self, req, ctx)          -> ignored
    @read_did(did)                     (self, req, ctx)          -> bytes | None
    @write_did(did)                    (self, value, req, ctx)   -> True | None
    @routine(rid[, control])           (self, control, data, req, ctx) -> bytes | None

``None`` always means "I did not handle this — fall through to the next
candidate".  Raise ``NegativeResponse`` (easiest: ``raise ctx.nrc(NRC_...)``)
to emit ``7F <sid> <nrc>``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from testecu.uds import NegativeResponse, UdsRequest

#: Sentinel service id meaning "every service" — ``@on_service()``.
ANY_SERVICE = -1

#: Attribute the decorators attach to a function.  Public only so that the
#: dispatcher and the tests can read it; plugin authors never touch it.
HOOK_ATTR = "_testecu_hooks"

# UDS-layer hook kinds
KIND_OBSERVER  = "observer"
KIND_SERVICE   = "service"
KIND_READ_DID  = "read_did"
KIND_WRITE_DID = "write_did"
KIND_ROUTINE   = "routine"

# DoIP-layer hook kinds (architecture roadmap P2). Same registration
# machinery as the UDS kinds above (``Plugin.__init_subclass__`` collects
# every kind generically), but resolved by ``DoipDispatcher``
# (``testecu/doip_dispatcher.py``), not ``Dispatcher`` — the two hook
# universes are kept in separate dispatchers because they act on different
# things (a connection/frame vs. a UDS request) and have no shared state.
KIND_ROUTING_ACTIVATION     = "routing_activation"
KIND_DIAGNOSTIC_ACK         = "diagnostic_ack"
KIND_FRAME_RX               = "frame_rx"
KIND_FRAME_TX               = "frame_tx"
KIND_IDENTIFICATION_REQUEST = "identification_request"


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def _mark(fn: Callable, kind: str, key: Any, extra: dict) -> Callable:
    hooks: List[Tuple[str, Any, dict]] = list(getattr(fn, HOOK_ATTR, []))
    hooks.append((kind, key, extra))
    setattr(fn, HOOK_ATTR, hooks)
    return fn


def on_service(sid: int = ANY_SERVICE, *, priority: Optional[int] = None):
    """
    Intercept a raw UDS service.

    ``@on_service(0x19)`` claims ReadDTCInformation; ``@on_service()`` is a
    catch-all that sees every request.  Return the *complete* UDS response
    (including the response SID), ``NO_RESPONSE``, or ``None`` to fall through.

    A per-SID hook shadows the ``@read_did`` / ``@write_did`` / ``@routine``
    sugar for that SID: if you take over 0x22 wholesale you own DID routing.
    Return ``None`` to hand it back.
    """
    def deco(fn: Callable) -> Callable:
        return _mark(fn, KIND_SERVICE, int(sid), {"priority": priority})
    return deco


def on_request(*, priority: Optional[int] = None):
    """
    Observer: runs for *every* request before any handler.

    The return value is ignored and exceptions are logged and swallowed, so an
    observer can never change or break the response.  Use it for logging,
    counters, and fault-injection bookkeeping.
    """
    def deco(fn: Callable) -> Callable:
        return _mark(fn, KIND_OBSERVER, None, {"priority": priority})
    return deco


def read_did(did: int, *, priority: Optional[int] = None):
    """
    ReadDataByIdentifier (0x22) handler for one DID.

    Return the DID **value bytes only** — the dispatcher prepends ``62 <did>``
    and handles multi-DID requests.  Return ``None`` to fall through to the
    YAML ``data_identifiers:`` table.
    """
    def deco(fn: Callable) -> Callable:
        return _mark(fn, KIND_READ_DID, int(did), {"priority": priority})
    return deco


def write_did(did: int, *, priority: Optional[int] = None):
    """
    WriteDataByIdentifier (0x2E) handler for one DID.

    Receives the value bytes.  Return ``True`` to accept (the dispatcher sends
    ``6E <did>``), ``None`` to fall through to the YAML table, or raise for an
    NRC.
    """
    def deco(fn: Callable) -> Callable:
        return _mark(fn, KIND_WRITE_DID, int(did), {"priority": priority})
    return deco


def routine(rid: int, control: Optional[int] = None, *, priority: Optional[int] = None):
    """
    RoutineControl (0x31) handler for one routine identifier.

    ``control`` is 0x01 startRoutine / 0x02 stopRoutine / 0x03
    requestRoutineResults; pass ``None`` (the default) to handle all three in
    one method.  Return the routineStatusRecord bytes — the dispatcher prepends
    ``71 <control> <rid>`` — or ``None`` to fall through to the YAML
    ``routines:`` table.
    """
    def deco(fn: Callable) -> Callable:
        key = (int(rid), None if control is None else int(control))
        return _mark(fn, KIND_ROUTINE, key, {"priority": priority})
    return deco


# ---------------------------------------------------------------------------
# DoIP-layer decorators (architecture roadmap P2)
#
# Same ``None``-means-fall-through contract as the UDS decorators above, and
# the same handler-isolation guarantee (a raised exception is logged and
# swallowed, never crashes the connection or the process) — see
# ``testecu/doip_dispatcher.py: DoipDispatcher._call``.
# ---------------------------------------------------------------------------

def on_routing_activation(*, priority: Optional[int] = None):
    """
    Intercept a Routing Activation Request before the default accept/deny
    logic (SA range, re-bind, §9.3 conflict resolution) runs.

    ``(self, request: RoutingActivationRequest, ctx: DoipContext) -> int | None``.
    Return a Routing Activation Response code (ISO 13400-2 Table 48 — e.g.
    ``0x01`` busy, ``0x04``/``0x05`` auth/confirmation, ``0x11``
    confirmation required) to short-circuit with that response instead of
    the default logic; ``None`` falls through. ``await asyncio.sleep(...)``
    here to delay the response past ``T_TCP_Initial_Inactivity``.
    """
    def deco(fn: Callable) -> Callable:
        return _mark(fn, KIND_ROUTING_ACTIVATION, None, {"priority": priority})
    return deco


def on_diagnostic_ack(*, priority: Optional[int] = None):
    """
    Intercept the Diagnostic Message Positive ACK before it is sent.

    ``(self, request: UdsRequest, ctx: DoipContext) -> int | object | None``.
    Return a Diagnostic NACK code (ISO 13400-2 Table 26, e.g. ``0x05`` out of
    memory, ``0x06`` target unreachable) to send that NACK instead of the
    normal ACK; return ``WITHHOLD_ACK`` to send nothing at all (the tester's
    own timeout is the only signal); ``None`` sends the normal, correct ACK.
    """
    def deco(fn: Callable) -> Callable:
        return _mark(fn, KIND_DIAGNOSTIC_ACK, None, {"priority": priority})
    return deco


def on_frame_rx(*, priority: Optional[int] = None):
    """
    Observer: runs after every DoIP frame is read (TCP or UDP), before it is
    handled. ``(self, payload_type: int, payload: bytes, ctx: DoipContext)``.
    Return value ignored, exceptions logged and swallowed — same contract as
    ``@on_request``, one layer down.
    """
    def deco(fn: Callable) -> Callable:
        return _mark(fn, KIND_FRAME_RX, None, {"priority": priority})
    return deco


def on_frame_tx(*, priority: Optional[int] = None):
    """
    Observer: runs after every DoIP frame this entity sends (TCP or UDP).
    ``(self, payload_type: int, payload: bytes, ctx: DoipContext)``. Return
    value ignored, exceptions logged and swallowed.
    """
    def deco(fn: Callable) -> Callable:
        return _mark(fn, KIND_FRAME_TX, None, {"priority": priority})
    return deco


def on_identification_request(*, priority: Optional[int] = None):
    """
    Intercept a Vehicle Identification Request over UDP.

    ``(self, request: IdentificationRequest, ctx: DoipContext) -> bytes | None``.
    Return the complete Vehicle Identification Response payload (33 bytes,
    see ``udp.py: build_announcement_payload``) to override the default
    answer; ``None`` sends the default. To withhold the response entirely,
    return empty bytes (``b""``) — the caller sends nothing in that case.
    For anything that isn't a single substituted response — a duplicate
    answer, an unsolicited Vehicle Announcement, a delayed answer — use
    ``ctx.send_raw(...)`` from inside the hook (``await asyncio.sleep(...)``
    first for the delayed case) and still return ``None`` or ``b""``.
    """
    def deco(fn: Callable) -> Callable:
        return _mark(fn, KIND_IDENTIFICATION_REQUEST, None, {"priority": priority})
    return deco


#: Sentinel returned by an ``@on_diagnostic_ack`` hook to withhold the
#: Positive ACK entirely (as opposed to returning ``None``, which sends the
#: normal one, or an ``int``, which sends that NACK code instead).
WITHHOLD_ACK = object()


@dataclass(frozen=True)
class RoutingActivationRequest:
    """What an ``@on_routing_activation`` hook sees — the parsed request,
    not the raw payload (ISO 13400-2 Table 15: source address, activation
    type, then a reserved field this simulator does not otherwise expose)."""

    source_addr: int
    activation_type: int
    raw: bytes


@dataclass(frozen=True)
class IdentificationRequest:
    """What an ``@on_identification_request`` hook sees."""

    #: One of ``PT_VEHICLE_ID_REQUEST`` / ``..._WITH_EID`` / ``..._WITH_VIN``.
    payload_type: int
    #: The requester's UDP address, as handed to ``DatagramProtocol``.
    requester: tuple
    #: Raw request payload past the generic header (empty, an EID, or a VIN).
    raw: bytes


class DoipContext:
    """
    Everything a DoIP-layer handler gets besides the request itself.

    Deliberately decoupled from any one transport: ``session.py`` (TCP) and
    ``udp.py`` (UDP) each supply their own ``send_frame``/``close``
    callables, so the same hook types and the same plugin code work on
    either side without knowing which one it's running against.
    """

    __slots__ = ("ecu", "log", "peer", "_send_frame", "_close")

    def __init__(self, ecu: Any, log: logging.Logger, peer: Any,
                 send_frame: Callable[[int, bytes], Awaitable[None]],
                 close: Optional[Callable[[], None]] = None) -> None:
        self.ecu = ecu
        self.log = log
        self.peer = peer
        self._send_frame = send_frame
        self._close = close

    async def send_raw(self, payload_type: int, payload: bytes) -> None:
        """
        Send an arbitrary extra DoIP frame right now.

        For fault injection that isn't "answer this one request instead" —
        an unsolicited Alive Check, a stray Vehicle Announcement, a
        duplicate Vehicle Identification Response.
        """
        await self._send_frame(payload_type, payload)

    def close(self) -> None:
        """
        Close the underlying connection immediately.

        TCP only — a no-op on the UDP side, which has no persistent
        per-request socket to close.
        """
        if self._close is not None:
            self._close()


# ---------------------------------------------------------------------------
# Plugin base class
# ---------------------------------------------------------------------------

class Plugin:
    """
    Base class for TestEcu plugins.

    Class attributes:
        name      — label used in logs; defaults to the class name
        priority  — lower runs first (default 100); YAML ``priority:`` overrides
        enabled   — set False to keep the class but never register its hooks
    """

    name: str = ""
    priority: int = 100
    enabled: bool = True

    #: Set by the loader — position in the resolved load order, used to break
    #: priority ties deterministically.
    load_index: int = 0

    #: kind -> key -> [(method_name, extra), ...].  Built by __init_subclass__.
    hooks: Dict[str, Dict[Any, List[Tuple[str, dict]]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        collected: Dict[str, Dict[Any, List[Tuple[str, dict]]]] = {}
        # Walk the MRO base-first so a subclass overriding a decorated method
        # contributes its own name once, not twice.
        for klass in reversed(cls.__mro__):
            for attr_name, attr in vars(klass).items():
                for kind, key, extra in getattr(attr, HOOK_ATTR, ()):
                    bucket = collected.setdefault(kind, {}).setdefault(key, [])
                    entry = (attr_name, extra)
                    if entry not in bucket:
                        bucket.append(entry)
        cls.hooks = collected

    def __init__(self, **params: Any) -> None:
        self.params = dict(params)
        for key, value in params.items():
            setattr(self, key, value)
        if not self.name:
            self.name = type(self).__name__

    async def setup(self, ecu: Any) -> None:
        """Called once after all plugins load, before the server binds."""

    async def teardown(self, ecu: Any) -> None:
        """Called once on shutdown."""

    def __repr__(self) -> str:
        return "<%s priority=%d>" % (self.name or type(self).__name__, self.priority)


# ---------------------------------------------------------------------------
# Handler context
# ---------------------------------------------------------------------------

class Context:
    """
    Everything a handler gets besides the request itself.

    Lifetime is one UDS request.  ``ecu`` and ``data`` are process-wide;
    ``session`` is per TCP connection.
    """

    __slots__ = ("ecu", "session", "request", "log", "_responder")

    def __init__(self, ecu: Any, session: Any, request: UdsRequest,
                 responder: Callable, log: logging.Logger) -> None:
        self.ecu = ecu              # EcuCore — process-wide state
        self.session = session      # SessionState — per TCP connection
        self.request = request
        self.log = log
        self._responder = responder

    # -- shared state ------------------------------------------------------

    @property
    def data(self) -> dict:
        """Free-form, mutable, process-wide scratch dict."""
        return self.ecu.data

    @property
    def store(self) -> Any:
        """The DidStore: YAML defaults plus anything written at runtime."""
        return self.ecu.store

    @property
    def config(self) -> dict:
        """The raw parsed YAML, for anything the typed config does not expose."""
        return self.ecu.raw_config

    # -- session state -----------------------------------------------------

    @property
    def session_type(self) -> int:
        return self.session.session_type

    @property
    def security_level(self) -> int:
        return self.session.security_level

    @property
    def source_addr(self) -> int:
        return self.request.source_addr

    @property
    def target_addr(self) -> int:
        return self.request.target_addr

    @property
    def functional(self) -> bool:
        return self.request.functional

    # -- emitting extra responses -----------------------------------------

    async def send(self, uds: bytes) -> None:
        """Send an additional UDS response frame right now."""
        await self._responder(uds)

    async def response_pending(self) -> None:
        """Send ``7F <sid> 78`` (requestCorrectlyReceived-ResponsePending)."""
        await self._responder(
            bytes([0x7F, self.request.sid & 0xFF, 0x78])
        )

    # -- negative responses ------------------------------------------------

    def nrc(self, code: int, message: str = "") -> NegativeResponse:
        """Build a ``NegativeResponse`` for this request — ``raise ctx.nrc(...)``."""
        return NegativeResponse(code, self.request.sid, message)
