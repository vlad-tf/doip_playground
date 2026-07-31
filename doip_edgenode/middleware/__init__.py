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
DoIP EdgeNode — Middleware base classes.

The middleware chain runs on fully decrypted DoIP frames, after TLS
termination and before re-encryption toward the ECU.  Each middleware
receives a Scapy DoIP packet object, may modify or drop it, and returns
the (possibly modified) packet or None to drop it.

Raising DoIPFaultInjectionError inside process() causes the session to
send a synthetic error response instead of forwarding the packet.
"""

from __future__ import annotations

import asyncio
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from session import DoIPSession


class DoIPFaultInjectionError(Exception):
    """
    Raised by middleware to inject a synthetic error response instead of
    forwarding the current packet.

    :param nack_code: The NACK code to send back to the tester.
    """

    def __init__(self, nack_code: int, message: str = "") -> None:
        self.nack_code = nack_code
        super().__init__(message)


class Middleware:
    """Base middleware.  Override process() in subclasses."""

    enabled: bool = True

    async def process(
        self,
        pkt,
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ):
        """
        Process a DoIP packet.

        :param pkt:       Scapy DoIP packet.
        :param direction: Which direction the packet is travelling.
        :param session:   The active DoIPSession (for sending replies, etc.).
        :returns:         Modified packet, or None to drop.
        :raises DoIPFaultInjectionError: To inject a synthetic protocol error.
        """
        return pkt  # default: pass through unchanged


class MiddlewareChain:
    """Ordered chain of enabled middleware instances."""

    def __init__(self, middlewares: list[Middleware]) -> None:
        self._chain = [m for m in middlewares if getattr(m, "enabled", True)]

    async def run(
        self,
        pkt,
        direction: str,
        session: "DoIPSession",
    ):
        """
        Run the packet through every enabled middleware in order.

        Returns None if any middleware drops the packet.
        """
        for mw in self._chain:
            if pkt is None:
                return None
            pkt = await mw.process(pkt, direction, session)
        return pkt
