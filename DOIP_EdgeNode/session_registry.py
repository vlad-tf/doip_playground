"""
DoIP EdgeNode — Session Registry.

Tracks active DoIPSessions by tester logical address.

Used to enforce ISO 13400-2 §9.3 (Routing Activation):
  When a new Routing Activation Request arrives with a source address (SA)
  that is already registered on a different socket, the DoIP server MUST
  send an Alive Check Request to the existing connection before deciding
  whether to accept or deny the new one.

  - Old connection responds   → deny new with response code 0x03
                                ("SA already registered on different socket")
  - Old connection times out  → evict old, accept new with response code 0x10

All access is from the asyncio event loop; no locking is needed.
"""

from __future__ import annotations

import logging
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

    def __init__(self) -> None:
        self._sessions: dict[int, "DoIPSession"] = {}

    def register(self, logical_addr: int, session: "DoIPSession") -> None:
        self._sessions[logical_addr] = session
        logger.debug(
            "SessionRegistry: registered SA=0x%04X → %s",
            logical_addr,
            session.peer,
        )

    def unregister(self, logical_addr: int) -> None:
        removed = self._sessions.pop(logical_addr, None)
        if removed is not None:
            logger.debug("SessionRegistry: unregistered SA=0x%04X", logical_addr)

    def lookup(self, logical_addr: int) -> "DoIPSession | None":
        return self._sessions.get(logical_addr)

    def count(self) -> int:
        return len(self._sessions)
