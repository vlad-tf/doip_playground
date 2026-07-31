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
DoIP EdgeNode — Address middleware.

Overwrites the source and/or target logical address fields in DoIP
Diagnostic Messages.  Useful for simulating wrong SA/TA scenarios.

Config params:
    src_override (int | None): New value for the source logical address field.
                               None → leave unchanged.
    tgt_override (int | None): New value for the target logical address field.
                               None → leave unchanged.

# TODO: verify Scapy field names for source/target logical address on
#       Raspberry Pi.  Assumed names for Scapy 2.5.x inside a Diagnostic
#       Message sub-layer:
#         source address: 'source_address'
#         target address: 'target_address'
#       These are on the inner DiagnosticMessage layer, not the DoIP header.
#       If Scapy doesn't model a separate sub-layer, they live directly on
#       the DoIP packet as 'sa' and 'ta' or similar.
"""

from __future__ import annotations

import logging
from typing import Literal, TYPE_CHECKING

from middleware import Middleware

if TYPE_CHECKING:
    from session import DoIPSession

logger = logging.getLogger(__name__)

# Verified on Raspberry Pi 4 — these are ConditionalFields directly on DoIP,
# not on a sub-layer.  For payload_type=0x8001 (Diagnostic Message) these
# fields are active.
_SRC_FIELD = "source_address"
_TGT_FIELD = "target_address"


class AddressMiddleware(Middleware):
    def __init__(
        self,
        src_override: int | None = None,
        tgt_override: int | None = None,
        **_,
    ) -> None:
        self.src_override = int(src_override) if src_override is not None else None
        self.tgt_override = int(tgt_override) if tgt_override is not None else None

    async def process(
        self,
        pkt,
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ):
        if self.src_override is not None:
            try:
                old = getattr(pkt, _SRC_FIELD, None)
                setattr(pkt, _SRC_FIELD, self.src_override)
                logger.debug(
                    "AddressMiddleware: src 0x%04X -> 0x%04X dir=%s",
                    old or 0,
                    self.src_override,
                    direction,
                )
            except Exception as exc:
                logger.warning(
                    "AddressMiddleware: failed to override src: %s", exc
                )

        if self.tgt_override is not None:
            try:
                old = getattr(pkt, _TGT_FIELD, None)
                setattr(pkt, _TGT_FIELD, self.tgt_override)
                logger.debug(
                    "AddressMiddleware: tgt 0x%04X -> 0x%04X dir=%s",
                    old or 0,
                    self.tgt_override,
                    direction,
                )
            except Exception as exc:
                logger.warning(
                    "AddressMiddleware: failed to override tgt: %s", exc
                )

        return pkt
