"""
DoIP EdgeNode — Delay middleware.

Introduces a fixed delay plus optional random jitter before forwarding.
The packet is not dropped; it is only held for the specified duration.

Config params:
    delay_ms  (int): Base delay in milliseconds.
    jitter_ms (int): Maximum additional random jitter in milliseconds.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Literal, TYPE_CHECKING

from middleware import Middleware

if TYPE_CHECKING:
    from session import DoIPSession

logger = logging.getLogger(__name__)


class DelayMiddleware(Middleware):
    def __init__(self, delay_ms: int = 0, jitter_ms: int = 0, **_) -> None:
        self.delay_ms = int(delay_ms)
        self.jitter_ms = int(jitter_ms)

    async def process(
        self,
        pkt,
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ):
        total_ms = self.delay_ms + random.randint(0, max(0, self.jitter_ms))
        if total_ms > 0:
            logger.debug(
                "DelayMiddleware: sleeping %d ms dir=%s", total_ms, direction
            )
            await asyncio.sleep(total_ms / 1000.0)
        return pkt
