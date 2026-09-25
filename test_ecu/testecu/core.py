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
Process-wide ECU state (``EcuCore``) and per-connection state (``SessionState``).

The split matters for plugin authors: ``ctx.ecu`` / ``ctx.store`` / ``ctx.data``
are shared by every tester connection, while ``ctx.session_type`` and
``ctx.security_level`` belong to the one TCP connection the request arrived on.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from testecu.config import EcuConfig, UdsConfig
from testecu.dispatcher import Dispatcher
from testecu.doip_dispatcher import DoipDispatcher
from testecu.loader import load_plugins
from testecu.plugin import Plugin
from testecu.store import DidStore

logger = logging.getLogger("testecu.core")


class SessionState:
    """Diagnostic state of one tester connection."""

    def __init__(self, ecu: "EcuCore", label: str = "") -> None:
        self._ecu = ecu
        self._label = label
        self.session_type: int = ecu.uds.default_session
        self.security_level: int = 0
        self.seed_pending: Optional[int] = None
        self.security_attempts: int = 0
        self.tester_addr: Optional[int] = None
        self.activated: bool = False
        self._s3_task: Optional[asyncio.Task] = None

    # -- transitions -------------------------------------------------------

    def enter_session(self, session_type: int) -> None:
        """DiagnosticSessionControl: switch session and relock security."""
        self.session_type = session_type
        self.security_level = 0
        self.seed_pending = None
        self.security_attempts = 0
        self.refresh_s3()

    def reset(self) -> None:
        """ECUReset / S3 expiry: back to the default session, fully locked."""
        self.session_type = self._ecu.uds.default_session
        self.security_level = 0
        self.seed_pending = None
        self.security_attempts = 0
        self._cancel_s3()

    # -- S3 server timer ---------------------------------------------------

    def refresh_s3(self) -> None:
        """
        (Re)arm the S3 timer.

        Only non-default sessions time out; the default session is the resting
        state, so there is nothing to fall back to.
        """
        self._cancel_s3()
        if self.session_type == self._ecu.uds.default_session:
            return
        timeout = self._ecu.uds.s3_server_ms / 1000.0
        if timeout <= 0:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:              # no running loop (sync test) — nothing to arm
            return
        self._s3_task = loop.create_task(self._s3_expiry(timeout))

    async def _s3_expiry(self, timeout: float) -> None:
        try:
            await asyncio.sleep(timeout)
        except asyncio.CancelledError:
            return
        logger.info(
            "S3 timeout after %.1fs — session 0x%02X -> default%s",
            timeout, self.session_type, (" for " + self._label) if self._label else "",
        )
        self.reset()
        # Architecture roadmap P9: this timer can legitimately fire with no
        # live socket watching it (the tester disconnected mid-non-default
        # session and hasn't reconnected yet -- the whole point of keying
        # state by tester rather than by socket). Reverting to default here
        # is exactly the "nothing left to remember" tidy-up condition, so
        # drop this entry from the shared table now rather than leaving it
        # to a reconnect that may never come.
        self._ecu.maybe_drop_session_state(self.tester_addr, self)

    def _cancel_s3(self) -> None:
        if self._s3_task is not None and not self._s3_task.done():
            try:
                self._s3_task.cancel()
            except RuntimeError:
                pass          # its loop is already closed — nothing left to cancel
        self._s3_task = None

    def close(self) -> None:
        self._cancel_s3()

    def __repr__(self) -> str:
        return "<SessionState session=0x%02X security=%d>" % (
            self.session_type, self.security_level,
        )


class EcuCore:
    """Everything shared across tester connections for one simulated ECU."""

    def __init__(self, config: EcuConfig, plugins: Optional[List[Plugin]] = None,
                 log: Optional[logging.Logger] = None) -> None:
        self.config = config
        self.raw_config = config.raw
        self.uds: UdsConfig = config.uds
        self.log = log or logging.getLogger("testecu")
        self.store = DidStore(config.dids)
        #: Free-form process-wide scratch space for plugins (``ctx.data``).
        self.data: dict = {}

        if plugins is None:
            plugins = load_plugins(config.plugins.specs, strict=config.plugins.strict)
        self.plugins: List[Plugin] = plugins
        self.dispatcher = Dispatcher(self, plugins, self.log)
        #: DoIP-layer hooks (architecture roadmap P2) — routing activation,
        #: diagnostic ACK, frame rx/tx, identification request. Separate
        #: from ``dispatcher`` on purpose; see ``doip_dispatcher.py``.
        self.doip_hooks = DoipDispatcher(self, plugins, self.log)
        #: UDS session state keyed by tester logical address, not by socket
        #: (architecture roadmap P9) -- a tester that drops TCP and
        #: reconnects within S3 finds the same session/security state, the
        #: same way a real ECU's diagnostic session belongs to the tester,
        #: not the transport. ``SessionRegistry`` (``session.py``) answers a
        #: different question -- which *socket* currently owns an SA -- and
        #: is intentionally not merged with this. Bounded by construction:
        #: at most one entry per SA in ``doip.tester_addr_range``, and
        #: ``maybe_drop_session_state`` keeps only non-default ones around
        #: past their socket closing.
        self._session_states: Dict[int, "SessionState"] = {}

    # -- lifecycle ---------------------------------------------------------

    async def startup(self) -> None:
        for plugin in self.plugins:
            try:
                await plugin.setup(self)
            except Exception:
                self.log.exception("plugin %s: setup() failed — continuing without it",
                                   plugin.name)
                if self.config.plugins.strict:
                    raise

    async def shutdown(self) -> None:
        for plugin in self.plugins:
            try:
                await plugin.teardown(self)
            except Exception:
                self.log.exception("plugin %s: teardown() failed", plugin.name)

    # -- state -------------------------------------------------------------

    def new_session(self, label: str = "") -> SessionState:
        """A throwaway ``SessionState``, not tracked in ``_session_states``.

        Kept for callers that drive UDS resolution without a real socket
        (``tests/conftest.py``'s ``Probe``) -- they want a fresh state each
        time, not one keyed by and shared across some tester address.
        """
        return SessionState(self, label)

    def session_for(self, tester_addr: int, label: str = "") -> SessionState:
        """
        The ``SessionState`` for ``tester_addr`` (architecture roadmap P9).

        Returns the existing entry when this tester still has one (a
        reconnect within S3, or a still-live one from another socket that
        just got evicted via §9.3 conflict resolution) or creates and
        registers a fresh default/locked one otherwise. Called from
        ``session.py`` only on a *successful* Routing Activation -- there is
        no state to look up or create before a tester has a registered SA.
        """
        state = self._session_states.get(tester_addr)
        if state is not None:
            state._label = label
            return state
        state = SessionState(self, label)
        state.tester_addr = tester_addr
        self._session_states[tester_addr] = state
        return state

    def maybe_drop_session_state(self, tester_addr: Optional[int],
                                 state: "Optional[SessionState]" = None) -> None:
        """
        Drop ``tester_addr``'s state if there is nothing left to remember.

        "Nothing to remember" = default session, security locked, no
        pending seed -- the same state a fresh ``SessionState`` would start
        in, so keeping it around buys a reconnecting tester nothing. Called
        when a socket closes/is evicted (``session.py``) and when the S3
        timer itself returns a state to default with no socket watching
        (``SessionState._s3_expiry``). A non-default state is deliberately
        left in place either way, for a reconnect within S3 to find.

        ``state``, when given, is identity-checked against the table entry
        before anything is dropped -- the same reason
        ``SessionRegistry.unregister`` identity-checks (see that docstring):
        an evicted socket's own ``run()`` can notice its writer closed and
        run its cleanup well after a *new* socket has already looked up or
        created a fresh entry for the same SA, and a plain
        "drop by SA" here would delete that new session's state instead of
        the caller's own, stale one.
        """
        if tester_addr is None:
            return
        current = self._session_states.get(tester_addr)
        if current is None:
            return
        if state is not None and current is not state:
            return    # this entry now belongs to a different, newer session
        if (current.session_type == self.uds.default_session
                and current.security_level == 0
                and current.seed_pending is None):
            current.close()
            del self._session_states[tester_addr]

    def drop_session_state(self, tester_addr: Optional[int]) -> None:
        """
        Unconditionally forget ``tester_addr``'s state.

        Used only by ECUReset when ``uds.reset_drops_connection`` is set: a
        real reset forgets everything immediately, not just when the state
        happens to already be tidy.
        """
        if tester_addr is None:
            return
        state = self._session_states.pop(tester_addr, None)
        if state is not None:
            state.close()

    def reset(self, clear_writes: bool = True) -> None:
        """ECUReset: drop runtime DID writes and the routine bookkeeping."""
        if clear_writes:
            self.store.reset()
        self.data.pop("routines", None)

    # -- introspection -----------------------------------------------------

    def describe(self) -> List[str]:
        """Lines for ``--check`` and the startup log."""
        lines = [
            "ECU logical address : 0x%04X" % self.config.doip.ecu_logical_addr,
            "Functional address  : 0x%04X" % self.uds.functional_addr,
            "Default session     : 0x%02X" % self.uds.default_session,
            "Unknown service     : %s" % self.uds.unknown_service,
            "Unknown DID         : %s" % self.uds.unknown_did,
            "Handler error       : %s" % self.uds.on_handler_error,
            "Static DIDs         : %d" % len(self.store),
            "Static routines     : %d" % len(self.config.routines),
            "Plugins             : %d" % len(self.plugins),
        ]
        hooks = self.dispatcher.describe()
        lines.append("Hooks               : %d" % len(hooks))
        lines.extend(hooks)
        doip_hooks = self.doip_hooks.describe()
        lines.append("DoIP-layer hooks    : %d" % len(doip_hooks))
        lines.extend(doip_hooks)
        return lines
