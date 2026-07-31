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
DoIP EdgeNode — Corrupt middleware.

Flips bits in the DoIP payload (the bytes after the 8-byte header).
The header itself is left intact so the packet still gets parsed by the
peer before the corruption is noticed.

Config params:
    byte_offset (int | None): Byte index within the payload to corrupt.
                              None → pick a random byte.
    flip_mask   (int):        XOR mask to apply (e.g. 0x01 flips the LSB).
"""

from __future__ import annotations

import logging
import random
from typing import Literal, TYPE_CHECKING

from middleware import Middleware

if TYPE_CHECKING:
    from session import DoIPSession

logger = logging.getLogger(__name__)

_DOIP_HEADER_LEN = 8


class CorruptMiddleware(Middleware):
    def __init__(
        self,
        byte_offset: int | None = None,
        flip_mask: int = 0x01,
        **_,
    ) -> None:
        self.byte_offset = byte_offset
        self.flip_mask = int(flip_mask)

    async def process(
        self,
        pkt,
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ):
        try:
            raw = bytearray(bytes(pkt))
        except Exception as exc:
            logger.warning("CorruptMiddleware: failed to serialise packet: %s", exc)
            return pkt

        payload = raw[_DOIP_HEADER_LEN:]
        if not payload:
            logger.warning("CorruptMiddleware: payload is empty, skipping corruption")
            return pkt

        if self.byte_offset is None:
            offset = random.randint(0, len(payload) - 1)
        else:
            offset = int(self.byte_offset)
            if offset >= len(payload):
                logger.warning(
                    "CorruptMiddleware: byte_offset=%d out of range (payload len=%d), "
                    "skipping",
                    offset,
                    len(payload),
                )
                return pkt

        original_byte = payload[offset]
        payload[offset] ^= self.flip_mask
        raw[_DOIP_HEADER_LEN:] = payload

        logger.debug(
            "CorruptMiddleware: dir=%s offset=%d 0x%02X -> 0x%02X",
            direction,
            offset,
            original_byte,
            payload[offset],
        )

        # Rebuild Scapy packet from modified bytes
        from scapy.contrib.automotive.doip import DoIP  # type: ignore[import]
        return DoIP(bytes(raw))
