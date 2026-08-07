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
The UDS dispatcher: hook tables, the precedence ladder, and handler isolation.

Precedence — the first candidate that returns something other than ``None``
wins:

    0. @on_request observers      always run; return ignored, errors swallowed
    1. @on_service(<sid>) hooks   ordered by (priority, load_index, name)
    2. @on_service() catch-alls   same ordering
    3. the built-in core service for <sid>
         0x22 -> @read_did  -> YAML data_identifiers -> uds.unknown_did
         0x2E -> @write_did -> YAML writable entry   -> uds.unknown_did
         0x31 -> @routine   -> YAML routines         -> NRC 0x31
    4. uds.unknown_service policy (nrc 0x11 | echo | silent)

A per-SID hook therefore shadows the per-DID sugar for that SID.  That is
deliberate: without it, a catch-all 0x22 interceptor would be impossible.  A
hook that returns ``None`` un-claims the request and the ladder continues.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from testecu.plugin import (
    ANY_SERVICE,
    KIND_OBSERVER,
    KIND_READ_DID,
    KIND_ROUTINE,
    KIND_SERVICE,
    KIND_WRITE_DID,
    Context,
    Plugin,
)
from testecu.uds import (
    NO_RESPONSE,
    NRC_CONDITIONS_NOT_CORRECT,
    NRC_SERVICE_NOT_SUPPORTED,
    NegativeResponse,
    SuppressResponse,
    UdsRequest,
)

logger = logging.getLogger("testecu.dispatcher")


@dataclass(frozen=True)
class Hook:
    """One registered handler, resolved to a bound method."""

    priority: int
    load_index: int
    plugin_name: str
    method_name: str
    method: Callable
    extra: dict

    @property
    def label(self) -> str:
        return "%s.%s" % (plugin_or_unknown(self.plugin_name), self.method_name)


def plugin_or_unknown(name: str) -> str:
    return name or "<plugin>"


def _sort_key(hook: Hook) -> Tuple[int, int, str]:
    return (hook.priority, hook.load_index, hook.plugin_name)


class Dispatcher:
    """Routes one UDS request through plugins, then the core, then the fallback."""

    def __init__(self, ecu: Any, plugins: Iterable[Plugin],
                 log: Optional[logging.Logger] = None) -> None:
        self._ecu = ecu
        self._log = log or logger

        self._observers: List[Hook] = []
        self._service: Dict[int, List[Hook]] = {}
        self._any: List[Hook] = []
        self._read_did: Dict[int, List[Hook]] = {}
        self._write_did: Dict[int, List[Hook]] = {}
        self._routines: Dict[Tuple[int, Optional[int]], List[Hook]] = {}

        self.plugins: List[Plugin] = [p for p in plugins if p.enabled]
        self._register(self.plugins)

        # Imported here rather than at module scope: services/ reaches back into
        # the dispatcher for the per-DID and per-routine hooks.
        from testecu.services import CoreServices
        self._core = CoreServices(ecu, self)

    # -----------------------------------------------------------------------
    # Registration
    # -----------------------------------------------------------------------

    def _bucket(self, kind: str, key: Any) -> List[Hook]:
        if kind == KIND_OBSERVER:
            return self._observers
        if kind == KIND_SERVICE:
            if key == ANY_SERVICE:
                return self._any
            return self._service.setdefault(int(key), [])
        if kind == KIND_READ_DID:
            return self._read_did.setdefault(int(key), [])
        if kind == KIND_WRITE_DID:
            return self._write_did.setdefault(int(key), [])
        if kind == KIND_ROUTINE:
            return self._routines.setdefault(key, [])
        raise ValueError("unknown hook kind %r" % kind)

    def _all_buckets(self) -> List[List[Hook]]:
        buckets: List[List[Hook]] = [self._observers, self._any]
        for table in (self._service, self._read_did, self._write_did, self._routines):
            buckets.extend(table.values())
        return buckets

    def _register(self, plugins: Iterable[Plugin]) -> None:
        for plugin in plugins:
            for kind, table in plugin.hooks.items():
                for key, entries in table.items():
                    for method_name, extra in entries:
                        priority = extra.get("priority")
                        self._bucket(kind, key).append(Hook(
                            priority=plugin.priority if priority is None else priority,
                            load_index=plugin.load_index,
                            plugin_name=plugin.name,
                            method_name=method_name,
                            method=getattr(plugin, method_name),
                            extra=extra,
                        ))
        for bucket in self._all_buckets():
            bucket.sort(key=_sort_key)
        self._warn_on_duplicate_claims()

    def _warn_on_duplicate_claims(self) -> None:
        checks = (
            ("service 0x%02X", self._service),
            ("read_did 0x%04X", self._read_did),
            ("write_did 0x%04X", self._write_did),
        )
        for template, table in checks:
            for key, hooks in sorted(table.items()):
                names = {hook.plugin_name for hook in hooks}
                if len(names) > 1:
                    self._log.warning(
                        "dispatcher: %s is claimed by %d plugins (%s) — they run in "
                        "that order and a plugin returning None hands over to the next",
                        template % key, len(hooks),
                        ", ".join(hook.label for hook in hooks),
                    )

    # -----------------------------------------------------------------------
    # Introspection (used by --check and the tests)
    # -----------------------------------------------------------------------

    def describe(self) -> List[str]:
        """Human-readable dump of the resolved hook table, in dispatch order."""
        lines: List[str] = []

        def add(title: str, hooks: List[Hook]) -> None:
            for hook in hooks:
                lines.append("  %-24s %-28s priority=%d" % (title, hook.label, hook.priority))

        add("observer", self._observers)
        for sid in sorted(self._service):
            add("service 0x%02X" % sid, self._service[sid])
        add("service <any>", self._any)
        for did in sorted(self._read_did):
            add("read_did 0x%04X" % did, self._read_did[did])
        for did in sorted(self._write_did):
            add("write_did 0x%04X" % did, self._write_did[did])
        for key in sorted(self._routines, key=lambda k: (k[0], -1 if k[1] is None else k[1])):
            rid, control = key
            title = "routine 0x%04X %s" % (rid, "*" if control is None else "0x%02X" % control)
            add(title, self._routines[key])
        return lines

    # -----------------------------------------------------------------------
    # Dispatch
    # -----------------------------------------------------------------------

    async def dispatch(self, request: UdsRequest, session: Any,
                       responder: Callable) -> Any:
        """
        Run one request through the ladder.

        Returns the UDS response bytes, ``NO_RESPONSE``, or raises
        ``NegativeResponse``.  Never returns None — the fallback policy always
        produces an outcome.
        """
        ctx = Context(self._ecu, session, request, responder, self._log)

        for hook in self._observers:
            await self._call(hook, ctx, (request, ctx), observer=True)

        for hook in self._service.get(request.sid, ()):
            result = await self._call(hook, ctx, (request, ctx))
            if result is not None:
                return result

        for hook in self._any:
            result = await self._call(hook, ctx, (request, ctx))
            if result is not None:
                return result

        result = await self._core.handle(ctx)
        if result is not None:
            return result

        return self._fallback(request)

    def _fallback(self, request: UdsRequest) -> Any:
        policy = self._ecu.uds.unknown_service
        if policy == "silent":
            self._log.debug("no handler for %s — staying silent", request.describe())
            return NO_RESPONSE
        if policy == "echo":
            # Deterministic echo: SID | 0x40 plus the request body, and nothing
            # else.  (echo_ecu appends 4 random bytes here; TestEcu never does.)
            self._log.debug("no handler for %s — echoing", request.describe())
            return request.positive(request.data)
        raise NegativeResponse(NRC_SERVICE_NOT_SUPPORTED, request.sid,
                               "no handler for %s" % request.describe())

    # -----------------------------------------------------------------------
    # Per-DID / per-routine resolution (called by the core services)
    # -----------------------------------------------------------------------

    async def resolve_did_read(self, did: int, ctx: Context) -> Optional[bytes]:
        """First ``@read_did`` hook that returns bytes, else None."""
        for hook in self._read_did.get(did, ()):
            result = await self._call(hook, ctx, (ctx.request, ctx))
            if result is None:
                continue
            if result is NO_RESPONSE:
                raise SuppressResponse()
            if not isinstance(result, (bytes, bytearray)):
                self._log.error(
                    "%s returned %s for DID 0x%04X — expected bytes; ignoring",
                    hook.label, type(result).__name__, did,
                )
                continue
            return bytes(result)
        return None

    async def resolve_did_write(self, did: int, value: bytes,
                                ctx: Context) -> Optional[bool]:
        """True if a ``@write_did`` hook accepted the write, else None."""
        for hook in self._write_did.get(did, ()):
            result = await self._call(hook, ctx, (value, ctx.request, ctx))
            if result is None:
                continue
            if result is NO_RESPONSE:
                raise SuppressResponse()
            return bool(result)
        return None

    async def resolve_routine(self, rid: int, control: int, data: bytes,
                              ctx: Context) -> Optional[bytes]:
        """
        First ``@routine`` hook that returns bytes, else None.

        An exact ``(rid, control)`` registration is tried before a catch-all
        ``(rid, None)`` one.
        """
        for key in ((rid, control), (rid, None)):
            for hook in self._routines.get(key, ()):
                result = await self._call(hook, ctx, (control, data, ctx.request, ctx))
                if result is None:
                    continue
                if result is NO_RESPONSE:
                    raise SuppressResponse()
                if not isinstance(result, (bytes, bytearray)):
                    self._log.error(
                        "%s returned %s for routine 0x%04X — expected bytes; ignoring",
                        hook.label, type(result).__name__, rid,
                    )
                    continue
                return bytes(result)
        return None

    def has_routine(self, rid: int) -> bool:
        return any(key[0] == rid for key in self._routines)

    # -----------------------------------------------------------------------
    # Handler isolation
    # -----------------------------------------------------------------------

    async def _call(self, hook: Hook, ctx: Context, args: tuple,
                    observer: bool = False) -> Any:
        """
        Invoke one handler, awaiting it if it returned an awaitable.

        A raised ``NegativeResponse`` propagates (that is the handler telling us
        what to send).  Anything else is logged with a traceback and converted
        per ``uds.on_handler_error`` — one bad plugin must never kill the
        connection or the process.
        """
        try:
            result = hook.method(*args)
            if inspect.isawaitable(result):
                result = await result
            return result
        except NegativeResponse as exc:
            if exc.sid is None:
                exc.sid = ctx.request.sid
            raise
        except (SuppressResponse, asyncio.CancelledError):
            raise
        except Exception:
            self._log.exception(
                "plugin %s raised on %s — isolating",
                hook.label, ctx.request.describe(),
            )
            if observer:
                return None
            policy = self._ecu.uds.on_handler_error
            if policy == "fallthrough":
                return None
            if policy == "silent":
                raise SuppressResponse()
            raise NegativeResponse(NRC_CONDITIONS_NOT_CORRECT, ctx.request.sid,
                                   "handler %s raised" % hook.label)
