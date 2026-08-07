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

"""RoutineControl (0x31)."""

from __future__ import annotations

import struct
from typing import Any

from testecu.plugin import Context
from testecu.uds import (
    NRC_CONDITIONS_NOT_CORRECT,
    NRC_INCORRECT_MESSAGE_LENGTH,
    NRC_REQUEST_OUT_OF_RANGE,
    NRC_REQUEST_SEQUENCE_ERROR,
    NRC_SECURITY_ACCESS_DENIED,
    NRC_SUB_FUNCTION_NOT_SUPPORTED,
)

START_ROUTINE           = 0x01
STOP_ROUTINE            = 0x02
REQUEST_ROUTINE_RESULTS = 0x03

_SUPPORTED = (START_ROUTINE, STOP_ROUTINE, REQUEST_ROUTINE_RESULTS)


async def routine_control(core: Any, ctx: Context) -> bytes:
    """
    0x31 — start / stop / query a routine.

    Response: ``71 <control> <rid>`` followed by the routineStatusRecord.
    A ``@routine(rid)`` plugin handler is consulted first; otherwise the YAML
    ``routines:`` table supplies a canned record.
    """
    request = ctx.request
    if len(request.raw) < 4:
        raise ctx.nrc(NRC_INCORRECT_MESSAGE_LENGTH,
                      "RoutineControl needs a sub-function and a 2-byte identifier")

    control = request.sub_function
    if control not in _SUPPORTED:
        raise ctx.nrc(NRC_SUB_FUNCTION_NOT_SUPPORTED,
                      "RoutineControl sub-function 0x%02X is not defined" % control)

    rid = int.from_bytes(request.raw[2:4], "big")
    data = bytes(request.raw[4:])
    header = bytes([control]) + struct.pack("!H", rid)

    # 1. Python handler
    record = await core.dispatcher.resolve_routine(rid, control, data, ctx)
    if record is not None:
        _track(core, rid, control)
        return request.positive(header + record)

    # 2. YAML table
    spec = core.ecu.config.routines.get(rid)
    if spec is None:
        raise ctx.nrc(NRC_REQUEST_OUT_OF_RANGE, "routine 0x%04X is not defined" % rid)

    if spec.sessions is not None and ctx.session_type not in spec.sessions:
        raise ctx.nrc(NRC_REQUEST_OUT_OF_RANGE,
                      "%s is not available in session 0x%02X"
                      % (spec.label(), ctx.session_type))
    if spec.security > ctx.security_level:
        raise ctx.nrc(NRC_SECURITY_ACCESS_DENIED,
                      "%s needs security level %d, tester has %d"
                      % (spec.label(), spec.security, ctx.security_level))

    started = _state(core).get(rid, False)
    if control == STOP_ROUTINE and not started:
        raise ctx.nrc(NRC_REQUEST_SEQUENCE_ERROR,
                      "%s was never started" % spec.label())
    if control == REQUEST_ROUTINE_RESULTS and not started:
        raise ctx.nrc(NRC_CONDITIONS_NOT_CORRECT,
                      "%s has no results yet" % spec.label())

    _track(core, rid, control)
    record = {
        START_ROUTINE:           spec.start,
        STOP_ROUTINE:            spec.stop,
        REQUEST_ROUTINE_RESULTS: spec.results,
    }[control]
    return request.positive(header + record)


def _state(core: Any) -> dict:
    return core.ecu.data.setdefault("routines", {})


def _track(core: Any, rid: int, control: int) -> None:
    """Remember whether a routine has been started, for the sequence checks."""
    state = _state(core)
    if control == START_ROUTINE:
        state[rid] = True
    elif control == STOP_ROUTINE:
        state[rid] = False
