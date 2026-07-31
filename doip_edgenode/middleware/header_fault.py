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
DoIP EdgeNode — Header fault injection middleware.

Corrupts specific DoIP header fields to test how the peer handles
protocol errors.  Uses Scapy field assignment (not raw byte manipulation)
so the corruption is explicit and survives Scapy API changes.

Fault modes:
    wrong_version  — set version byte to 0xFF
    bad_inverse    — set inverse byte to 0x00 (always wrong)
    bad_length     — set payload length to 0xFFFFFFFF
    unknown_type   — set payload type to 0xDEAD

Config params:
    fault        (str): One of the four modes above.
    direction    (str): "tester_to_ecu" | "ecu_to_tester" | "both"
    inject_on_nth (int): Inject only on every Nth call (1 = every message).

# Scapy DoIP field names (verified on Raspberry Pi 4):
# version byte  : 'protocol_version'
# inverse byte  : 'inverse_version'
# payload type  : 'payload_type'
# payload length: 'payload_length'
"""

from __future__ import annotations

import copy
import logging
from typing import Literal, TYPE_CHECKING

from middleware import Middleware

if TYPE_CHECKING:
    from session import DoIPSession

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scapy DoIP field name constants
# (assumed for Scapy 2.5.x — verify on target Raspberry Pi)
# ---------------------------------------------------------------------------
_VER_FIELD = "protocol_version"
_INV_VER_FIELD = "inverse_version"
_TYPE_FIELD = "payload_type"
_LEN_FIELD = "payload_length"

FAULT_MODES = {"wrong_version", "bad_inverse", "bad_length", "unknown_type"}


class HeaderFaultMiddleware(Middleware):
    """Injects DoIP header faults on a configurable cadence."""

    def __init__(
        self,
        fault: str = "wrong_version",
        direction: str = "tester_to_ecu",
        inject_on_nth: int = 1,
        **_,
    ) -> None:
        if fault not in FAULT_MODES:
            raise ValueError(
                f"HeaderFaultMiddleware: unknown fault mode {fault!r}. "
                f"Valid modes: {sorted(FAULT_MODES)}"
            )
        self.fault = fault
        self.direction = direction  # "tester_to_ecu" | "ecu_to_tester" | "both"
        self.inject_on_nth = int(inject_on_nth)
        self._counter = 0

    def _should_inject(self, direction: str) -> bool:
        """Return True if fault should be injected this call."""
        if self.direction != "both" and direction != self.direction:
            return False
        self._counter += 1
        if self._counter >= self.inject_on_nth:
            self._counter = 0
            return True
        return False

    def _apply_fault(self, pkt):
        """Return a copy of pkt with the header field corrupted."""
        from scapy.contrib.automotive.doip import DoIP  # type: ignore[import]

        # Work on a copy so we don't mutate the original
        corrupted = DoIP(bytes(pkt))

        if self.fault == "wrong_version":
            setattr(corrupted, _VER_FIELD, 0xFF)
        elif self.fault == "bad_inverse":
            setattr(corrupted, _INV_VER_FIELD, 0x00)
        elif self.fault == "bad_length":
            setattr(corrupted, _LEN_FIELD, 0xFFFFFFFF)
        elif self.fault == "unknown_type":
            setattr(corrupted, _TYPE_FIELD, 0xDEAD)

        return corrupted

    async def process(
        self,
        pkt,
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ):
        if not self._should_inject(direction):
            return pkt

        faulted = self._apply_fault(pkt)
        logger.warning(
            "HeaderFaultMiddleware: injecting fault=%s dir=%s",
            self.fault,
            direction,
        )
        return faulted
