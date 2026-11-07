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
DoIP EdgeNode — Session Registry.

Tracks active DoIPSessions by tester logical address.

Used to enforce the ISO 13400-2 §9.3 Routing Activation conflict-resolution
rule: when a new Routing Activation Request arrives with a source address
(SA) that is already registered on a different socket, this server probes
the existing connection with an Alive Check Request before deciding whether
to accept or deny the new one.

  - Old connection responds   → deny new with response code 0x03 (SA already
                                registered on a different socket)
  - Old connection times out  → evict old, accept new with response code 0x10

All access is from the asyncio event loop. Per-address asyncio locks serialize
activation decisions across alive-probe awaits; no thread locks are needed.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from session import DoIPSession

logger = logging.getLogger(__name__)


class SessionRegistry:
    """
    Maps tester_logical_addr → active DoIPSession.

    Lifecycle:
      - Registered in DoIPSession._handle_routing_activation() on success.
      - Unregistered in DoIPSession._cleanup().
    """

    def __init__(self, max_connections: int = 8) -> None:
        if type(max_connections) is not int or not 1 <= max_connections <= 254:
            raise ValueError("max_connections must be an integer in [1, 254]")
        self.max_connections = max_connections
        self._open_sockets: dict[object, "DoIPSession | None"] = {}
        self._capacity_lock: asyncio.Lock | None = None
        self._sessions: dict[int, "DoIPSession"] = {}
        self._activation_locks: dict[int, tuple[asyncio.Lock, int]] = {}

    def reserve(self, writer) -> bool:
        """Atomically admit up to n+1 initialized/registered inbound sockets."""
        if writer in self._open_sockets:
            return True
        if len(self._open_sockets) >= self.max_connections + 1:
            return False
        self._open_sockets[writer] = None
        return True

    @property
    def capacity_lock(self) -> asyncio.Lock:
        """Create the decision lock only inside the running server event loop."""
        if self._capacity_lock is None:
            asyncio.get_running_loop()
            self._capacity_lock = asyncio.Lock()
        return self._capacity_lock

    def attach(self, writer, session: "DoIPSession") -> None:
        """Associate a socket, enforcing admission for directly constructed sessions."""
        if not self.reserve(writer):
            raise RuntimeError("inbound socket capacity exhausted")
        self._open_sockets[writer] = session

    def release(self, writer) -> None:
        """Idempotent release when local transport closure begins."""
        self._open_sockets.pop(writer, None)

    def open_count(self) -> int:
        return len(self._open_sockets)

    def registered_sessions(self):
        return tuple(self._sessions.items())

    def status_payload(self, config) -> bytes:
        """Live counts include initialized/reserve sockets; capacity excludes reserve."""
        return bytes((config.doip.node_type, self.max_connections, self.open_count()))

    @asynccontextmanager
    async def activation_lock(self, logical_addr: int):
        """Serialize contenders for one SA without blocking unrelated addresses."""
        lock, users = self._activation_locks.get(logical_addr, (asyncio.Lock(), 0))
        self._activation_locks[logical_addr] = (lock, users + 1)
        try:
            async with lock:
                yield
        finally:
            # Count holders and waiters so cancellation cannot split a live lock.
            _, users = self._activation_locks[logical_addr]
            if users == 1:
                del self._activation_locks[logical_addr]
            else:
                self._activation_locks[logical_addr] = (lock, users - 1)

    def register(self, logical_addr: int, session: "DoIPSession") -> None:
        self._sessions[logical_addr] = session
        logger.debug(
            "SessionRegistry: registered SA=0x%04X → %s",
            logical_addr,
            session.peer,
        )

    def unregister(self, logical_addr: int, session: "DoIPSession") -> None:
        """Remove an address only while it is still owned by this session."""
        # An evicted session can finish cleanup after a replacement registers.
        # Identity checking and removal are synchronous on the event loop.
        if self._sessions.get(logical_addr) is session:
            del self._sessions[logical_addr]
            logger.debug("SessionRegistry: unregistered SA=0x%04X", logical_addr)

    def lookup(self, logical_addr: int) -> "DoIPSession | None":
        return self._sessions.get(logical_addr)

    def count(self) -> int:
        return len(self._sessions)
