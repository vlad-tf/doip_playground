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

"""ECUReset (0x11)."""

from __future__ import annotations

from typing import Any

from testecu.plugin import Context
from testecu.uds import (
    NRC_INCORRECT_MESSAGE_LENGTH,
    NRC_SUB_FUNCTION_NOT_SUPPORTED,
)

RESET_HARD        = 0x01
RESET_KEY_OFF_ON  = 0x02
RESET_SOFT        = 0x03

_SUPPORTED = (RESET_HARD, RESET_KEY_OFF_ON, RESET_SOFT)

_NAMES = {
    RESET_HARD:       "hardReset",
    RESET_KEY_OFF_ON: "keyOffOnReset",
    RESET_SOFT:       "softReset",
}


async def ecu_reset(core: Any, ctx: Context) -> bytes:
    """
    0x11 — reset the simulated ECU.

    Returns to the default session, relocks security, and (when
    ``uds.reset_clears_writes`` is set) restores every DID to its YAML default.

    Deliberate deviation from a real ECU: **the TCP connection is not dropped**.
    A real ECU would disappear off the bus here, but tearing down the socket
    would force every test client to reconnect and re-activate routing after a
    reset, which makes the simulator far less useful than it should be.
    """
    request = ctx.request
    if len(request.raw) != 2:
        raise ctx.nrc(NRC_INCORRECT_MESSAGE_LENGTH,
                      "ECUReset takes exactly one sub-function byte")

    sub = request.sub_function
    if sub not in _SUPPORTED:
        raise ctx.nrc(NRC_SUB_FUNCTION_NOT_SUPPORTED,
                      "ECUReset sub-function 0x%02X is not supported" % sub)

    core.ecu.reset(clear_writes=core.ecu.uds.reset_clears_writes)
    ctx.session.reset()

    ctx.log.info(
        "ECUReset %s from tester 0x%04X — session and security cleared%s",
        _NAMES[sub], request.source_addr,
        ", DID defaults restored" if core.ecu.uds.reset_clears_writes else "",
    )
    return request.positive(bytes([sub]))
