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

"""DiagnosticSessionControl (0x10) and TesterPresent (0x3E)."""

from __future__ import annotations

import struct
from typing import Any

from testecu.plugin import Context
from testecu.uds import (
    NRC_INCORRECT_MESSAGE_LENGTH,
    NRC_SUB_FUNCTION_NOT_SUPPORTED,
    SESSION_NAMES,
)


async def diagnostic_session_control(core: Any, ctx: Context) -> bytes:
    """
    0x10 — switch the diagnostic session.

    Response: ``50 <sub> P2hi P2lo P2*hi P2*lo``, where P2 is in milliseconds
    and P2* is in units of 10 ms (ISO 14229-1 §9.2.2.2).

    Switching session always relocks security and re-arms the S3 timer.
    """
    request = ctx.request
    if len(request.raw) != 2:
        raise ctx.nrc(NRC_INCORRECT_MESSAGE_LENGTH,
                      "DiagnosticSessionControl takes exactly one sub-function byte")

    sub = request.sub_function
    if sub not in core.ecu.uds.sessions:
        raise ctx.nrc(NRC_SUB_FUNCTION_NOT_SUPPORTED,
                      "session 0x%02X is not configured" % sub)

    previous = ctx.session.session_type
    ctx.session.enter_session(sub)

    ctx.log.info(
        "session 0x%02X (%s) -> 0x%02X (%s) for tester 0x%04X",
        previous, SESSION_NAMES.get(previous, "custom"),
        sub, SESSION_NAMES.get(sub, "custom"), request.source_addr,
    )

    p2 = core.ecu.uds.p2_server_ms & 0xFFFF
    p2_star = (core.ecu.uds.p2_star_server_ms // 10) & 0xFFFF
    return request.positive(bytes([sub]) + struct.pack("!HH", p2, p2_star))


async def tester_present(core: Any, ctx: Context) -> bytes:
    """
    0x3E — keep the non-default session alive.

    Only sub-function 0x00 (zeroSubFunction) exists.  ``3E 80`` sets the
    suppressPosRspMsgIndicationBit, so the positive response built here is
    dropped by the session layer before it reaches the wire.
    """
    request = ctx.request
    if len(request.raw) != 2:
        raise ctx.nrc(NRC_INCORRECT_MESSAGE_LENGTH,
                      "TesterPresent takes exactly one sub-function byte")
    if request.sub_function != 0x00:
        raise ctx.nrc(NRC_SUB_FUNCTION_NOT_SUPPORTED,
                      "TesterPresent only defines sub-function 0x00")

    ctx.session.refresh_s3()
    return request.positive(bytes([0x00]))
