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
from typing import Any, Callable, Dict, List, Optional, Tuple

from testecu.uds import NegativeResponse, UdsRequest

#: Sentinel service id meaning "every service" — ``@on_service()``.
ANY_SERVICE = -1

#: Attribute the decorators attach to a function.  Public only so that the
#: dispatcher and the tests can read it; plugin authors never touch it.
HOOK_ATTR = "_testecu_hooks"

# Hook kinds
KIND_OBSERVER  = "observer"
KIND_SERVICE   = "service"
KIND_READ_DID  = "read_did"
KIND_WRITE_DID = "write_did"
KIND_ROUTINE   = "routine"


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
