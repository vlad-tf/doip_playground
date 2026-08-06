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
from typing import Any, List, Optional

from testecu.config import EcuConfig, UdsConfig
from testecu.dispatcher import Dispatcher
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
        return SessionState(self, label)

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
        return lines
