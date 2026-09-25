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
The DoIP-layer plugin dispatcher (architecture roadmap P2).

Deliberately a separate class from ``dispatcher.Dispatcher``, not a shared
one: the two hook universes act on different things (a connection/frame vs.
a UDS request) and carry no shared state, but the shape — collect hooks by
kind, sort by ``(priority, load_index, plugin_name)``, first non-``None``
wins, isolate handler exceptions so one bad plugin can never crash the
connection or the process — is copied on purpose from ``Dispatcher``. Keep
the two in sync stylistically if one changes; do not merge them into one
class just to remove the duplication, since the DoIP dispatcher's `resolve_*`
methods are not interchangeable with the UDS dispatcher's `resolve_did_*` -
one call per DoIP-layer decision point (this module's job), not one call per
service (that module's).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional

from testecu.plugin import (
    KIND_DIAGNOSTIC_ACK,
    KIND_FRAME_RX,
    KIND_FRAME_TX,
    KIND_IDENTIFICATION_REQUEST,
    KIND_ROUTING_ACTIVATION,
    Plugin,
)

logger = logging.getLogger("testecu.doip_dispatcher")

_DOIP_KINDS = (
    KIND_ROUTING_ACTIVATION,
    KIND_DIAGNOSTIC_ACK,
    KIND_FRAME_RX,
    KIND_FRAME_TX,
    KIND_IDENTIFICATION_REQUEST,
)


@dataclass(frozen=True)
class DoipHook:
    """One registered DoIP-layer handler, resolved to a bound method."""

    priority: int
    load_index: int
    plugin_name: str
    method_name: str
    method: Callable

    @property
    def label(self) -> str:
        return "%s.%s" % (self.plugin_name or "<plugin>", self.method_name)


def _sort_key(hook: DoipHook):
    return (hook.priority, hook.load_index, hook.plugin_name)


class DoipDispatcher:
    """Routes DoIP-layer decision points through plugins, same precedence
    ladder and isolation as the UDS ``Dispatcher``, none of its UDS-specific
    machinery (sessions, DIDs, routines, suppression)."""

    def __init__(self, ecu: Any, plugins: Iterable[Plugin],
                log: Optional[logging.Logger] = None) -> None:
        self._ecu = ecu
        self._log = log or logger
        self._buckets: Dict[str, List[DoipHook]] = {kind: [] for kind in _DOIP_KINDS}
        self._register(plugins)

    # -----------------------------------------------------------------------
    # Registration
    # -----------------------------------------------------------------------

    def _register(self, plugins: Iterable[Plugin]) -> None:
        for plugin in plugins:
            for kind, table in plugin.hooks.items():
                if kind not in _DOIP_KINDS:
                    continue    # a UDS-layer kind -- Dispatcher's job
                for _key, entries in table.items():   # key is always None here
                    for method_name, extra in entries:
                        priority = extra.get("priority")
                        self._buckets[kind].append(DoipHook(
                            priority=plugin.priority if priority is None else priority,
                            load_index=plugin.load_index,
                            plugin_name=plugin.name,
                            method_name=method_name,
                            method=getattr(plugin, method_name),
                        ))
        for bucket in self._buckets.values():
            bucket.sort(key=_sort_key)

    # -----------------------------------------------------------------------
    # Resolution
    # -----------------------------------------------------------------------

    async def resolve_routing_activation(self, request: Any, ctx: Any) -> Optional[int]:
        """First ``@on_routing_activation`` hook to return non-``None``, else ``None``."""
        for hook in self._buckets[KIND_ROUTING_ACTIVATION]:
            result = await self._call(hook, request, ctx)
            if result is not None:
                return int(result)
        return None

    async def resolve_diagnostic_ack(self, request: Any, ctx: Any) -> Any:
        """First ``@on_diagnostic_ack`` hook to return non-``None``, else ``None``."""
        for hook in self._buckets[KIND_DIAGNOSTIC_ACK]:
            result = await self._call(hook, request, ctx)
            if result is not None:
                return result
        return None

    async def resolve_identification_request(self, request: Any, ctx: Any) -> Optional[bytes]:
        """First ``@on_identification_request`` hook to return non-``None``, else ``None``."""
        for hook in self._buckets[KIND_IDENTIFICATION_REQUEST]:
            result = await self._call(hook, request, ctx)
            if result is not None:
                return bytes(result)
        return None

    async def notify_frame_rx(self, payload_type: int, payload: bytes, ctx: Any) -> None:
        """Run every ``@on_frame_rx`` observer. Return values ignored."""
        for hook in self._buckets[KIND_FRAME_RX]:
            await self._call(hook, payload_type, payload, ctx, observer=True)

    async def notify_frame_tx(self, payload_type: int, payload: bytes, ctx: Any) -> None:
        """Run every ``@on_frame_tx`` observer. Return values ignored."""
        for hook in self._buckets[KIND_FRAME_TX]:
            await self._call(hook, payload_type, payload, ctx, observer=True)

    # -----------------------------------------------------------------------
    # Handler isolation
    # -----------------------------------------------------------------------

    async def _call(self, hook: DoipHook, *args: Any, observer: bool = False) -> Any:
        """
        Invoke one handler, awaiting it if it returned an awaitable.

        Mirrors ``Dispatcher._call``: a raised exception is logged with a
        traceback and swallowed (returns ``None``, i.e. "fall through" for a
        decision hook, "nothing happened" for an observer) — one bad DoIP
        fault-injection plugin must never crash the connection or the
        process. ``CancelledError`` always propagates; a handler is expected
        to be cancellable like any other.
        """
        try:
            result = hook.method(*args)
            if inspect.isawaitable(result):
                result = await result
            return result
        except asyncio.CancelledError:
            raise
        except Exception:
            self._log.exception("DoIP plugin %s raised — isolating", hook.label)
            return None

    # -----------------------------------------------------------------------
    # Introspection (used by --check)
    # -----------------------------------------------------------------------

    def describe(self) -> List[str]:
        """Human-readable dump of the resolved DoIP-layer hook table."""
        lines: List[str] = []
        for kind in _DOIP_KINDS:
            for hook in self._buckets[kind]:
                lines.append("  %-24s %-28s priority=%d" % (kind, hook.label, hook.priority))
        return lines
