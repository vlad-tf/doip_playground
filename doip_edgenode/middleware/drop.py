"""
DoIP EdgeNode — Drop middleware.

Randomly drops packets matching a configurable predicate.  Returns None
to signal the chain that the packet should not be forwarded.

Config params:
    drop_rate (float):  Probability [0.0–1.0] that a matching packet is dropped.
    match (dict):       Optional filter; both conditions must match (AND):
        direction (str):      "tester_to_ecu" | "ecu_to_tester"
        payload_type (int):   Drop only this payload type.
"""

from __future__ import annotations

import logging
import random
from typing import Literal, TYPE_CHECKING

from middleware import Middleware

if TYPE_CHECKING:
    from session import DoIPSession

logger = logging.getLogger(__name__)

# Verified on Raspberry Pi 4
_DOIP_TYPE_FIELD = "payload_type"


class DropMiddleware(Middleware):
    def __init__(
        self,
        drop_rate: float = 0.0,
        match: dict | None = None,
        **_,
    ) -> None:
        self.drop_rate = float(drop_rate)
        self._match_direction: str | None = None
        self._match_payload_type: int | None = None
        if match:
            self._match_direction = match.get("direction")
            pt = match.get("payload_type")
            self._match_payload_type = int(pt) if pt is not None else None

    def _matches(self, pkt, direction: str) -> bool:
        """Return True if this packet/direction satisfies the match filter."""
        if self._match_direction is not None and direction != self._match_direction:
            return False
        if self._match_payload_type is not None:
            ptype = getattr(pkt, _DOIP_TYPE_FIELD, None)
            if ptype != self._match_payload_type:
                return False
        return True

    async def process(
        self,
        pkt,
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ):
        if self._matches(pkt, direction) and random.random() < self.drop_rate:
            ptype = getattr(pkt, _DOIP_TYPE_FIELD, None)
            logger.debug(
                "DropMiddleware: dropped packet dir=%s type=0x%04X rate=%.2f",
                direction,
                ptype if ptype is not None else 0,
                self.drop_rate,
            )
            return None  # drop
        return pkt
