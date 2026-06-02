"""
DoIP EdgeNode — Replay middleware.

Records packets in the tester→ECU direction and, once replay_count
packets have been captured, re-injects them back into the ECU path.

This simulates duplicate/replayed messages to test ECU resilience.

Config params:
    record       (bool): Enable recording mode.
    replay_count (int):  Number of packets to record before auto-replaying.

The session must expose a send_to_ecu(pkt) coroutine for injection.

# TODO: replay trigger — currently auto-triggers after replay_count packets
#       are recorded (simple eager strategy).  A more sophisticated trigger
#       (e.g. on an external signal) would require a separate control channel.
"""

from __future__ import annotations

import copy
import logging
from typing import Literal, TYPE_CHECKING

from middleware import Middleware

if TYPE_CHECKING:
    from session import DoIPSession

logger = logging.getLogger(__name__)


class ReplayMiddleware(Middleware):
    def __init__(self, record: bool = False, replay_count: int = 1, **_) -> None:
        self.record = bool(record)
        self.replay_count = int(replay_count)
        self._recorded: list = []
        self._replayed = False

    async def process(
        self,
        pkt,
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ):
        if not self.record:
            return pkt

        if direction == "tester_to_ecu" and not self._replayed:
            # Deep-copy the Scapy object so later modifications don't affect it
            try:
                self._recorded.append(copy.deepcopy(pkt))
            except Exception:
                self._recorded.append(pkt)

            logger.debug(
                "ReplayMiddleware: recorded packet %d/%d",
                len(self._recorded),
                self.replay_count,
            )

            if len(self._recorded) >= self.replay_count:
                self._replayed = True
                logger.debug(
                    "ReplayMiddleware: triggering replay of %d packet(s)",
                    len(self._recorded),
                )
                await self._replay(session)

        return pkt

    async def _replay(self, session: "DoIPSession") -> None:
        """Inject the recorded packets directly to the ECU."""
        for pkt in self._recorded:
            try:
                await session.send_to_ecu(pkt)
                logger.debug("ReplayMiddleware: injected replayed packet")
            except Exception as exc:
                logger.warning("ReplayMiddleware: injection failed: %s", exc)
