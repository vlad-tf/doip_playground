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
Example plugin: a small stateful engine model.

Shows the five things a real plugin needs to do:

  1. keep state across requests               -> self.rpm
  2. compute a DID value on the fly           -> @read_did(0xF40C)
  3. refuse a read under some condition       -> @read_did(0xF40D)
  4. validate and gate a write                -> @write_did(0x2A00)
  5. run something slow without a P2 timeout  -> @routine(0x0203)

Try it:

    python3 tools/uds_probe.py --host ::1 --uds "22 F4 0C"
    python3 tools/uds_probe.py --host ::1 --uds "10 03" --uds "27 01" \\
        --uds "27 02 B4 87 96 E1" --uds "2E 2A 00 17 70"
    python3 tools/uds_probe.py --host ::1 --uds "31 01 02 03" --uds "31 03 02 03"
"""

from __future__ import annotations

import asyncio
from typing import Optional

from testecu import (
    NRC_CONDITIONS_NOT_CORRECT,
    NRC_REQUEST_OUT_OF_RANGE,
    NRC_SECURITY_ACCESS_DENIED,
    Context,
    Plugin,
    UdsRequest,
    on_request,
    read_did,
    routine,
    write_did,
)

DID_ENGINE_SPEED  = 0xF40C     # ISO 14229-1 Annex C: EngineSpeed
DID_VEHICLE_SPEED = 0xF40D     # ISO 14229-1 Annex C: VehicleSpeed
DID_REV_LIMIT     = 0x2A00     # OEM-specific, writable
RID_SELF_TEST     = 0x0203


class EngineEcu(Plugin):
    """Stateful engine model: computed DIDs, a gated write, and a slow routine."""

    name = "EngineEcu"
    priority = 50

    def __init__(self, idle_rpm: int = 800, redline: int = 6500, **params) -> None:
        super().__init__(idle_rpm=idle_rpm, redline=redline, **params)
        self.rpm = int(idle_rpm)
        self.self_test_result: Optional[bytes] = None

    async def setup(self, ecu) -> None:
        ecu.log.info("EngineEcu ready: idle=%d rpm, redline=%d rpm",
                     self.idle_rpm, self.redline)

    # -- observer: sees everything, can change nothing ---------------------

    @on_request()
    def trace(self, req: UdsRequest, ctx: Context) -> None:
        ctx.log.debug("EngineEcu saw %s from 0x%04X (session 0x%02X, security %d)",
                      req.describe(), req.source_addr,
                      ctx.session_type, ctx.security_level)

    # -- computed DID: a different value on every read ---------------------

    @read_did(DID_ENGINE_SPEED)
    def read_engine_speed(self, req: UdsRequest, ctx: Context) -> bytes:
        # Deterministic ramp rather than a random number: a simulator you
        # cannot write an assertion against is not much use.
        self.rpm = self.idle_rpm + ((self.rpm - self.idle_rpm) + 250) % 4000
        return self.rpm.to_bytes(2, "big")

    # -- conditional negative response -------------------------------------

    @read_did(DID_VEHICLE_SPEED)
    def read_vehicle_speed(self, req: UdsRequest, ctx: Context) -> bytes:
        if self.rpm < self.idle_rpm + 100:
            raise ctx.nrc(NRC_CONDITIONS_NOT_CORRECT, "engine is not running")
        return bytes([min(255, self.rpm // 40)])

    # -- validated, security-gated write -----------------------------------

    @write_did(DID_REV_LIMIT)
    def write_rev_limit(self, value: bytes, req: UdsRequest, ctx: Context) -> bool:
        if ctx.security_level < 1:
            raise ctx.nrc(NRC_SECURITY_ACCESS_DENIED, "rev limit needs level 1")
        if len(value) != 2:
            raise ctx.nrc(NRC_REQUEST_OUT_OF_RANGE, "rev limit is 2 bytes")
        limit = int.from_bytes(value, "big")
        if not self.idle_rpm <= limit <= self.redline:
            raise ctx.nrc(NRC_REQUEST_OUT_OF_RANGE,
                          "%d is outside [%d, %d]" % (limit, self.idle_rpm, self.redline))
        ctx.data.setdefault("engine", {})["rev_limit"] = limit
        ctx.log.info("EngineEcu: rev limit set to %d rpm", limit)
        return True

    @read_did(DID_REV_LIMIT)
    def read_rev_limit(self, req: UdsRequest, ctx: Context) -> bytes:
        limit = ctx.data.get("engine", {}).get("rev_limit", self.redline)
        return limit.to_bytes(2, "big")

    # -- slow routine: the dispatcher emits 0x78 while this runs -----------

    @routine(RID_SELF_TEST)
    async def self_test(self, control: int, data: bytes,
                        req: UdsRequest, ctx: Context) -> Optional[bytes]:
        if control == 0x01:                      # startRoutine
            self.self_test_result = None
            await asyncio.sleep(2.0)             # > p2_server_ms, so 7F 31 78 goes out
            self.self_test_result = b"\x00" + self.rpm.to_bytes(2, "big")
            return b"\x00"                       # routineStatusRecord: completed OK
        if control == 0x03:                      # requestRoutineResults
            if self.self_test_result is None:
                raise ctx.nrc(NRC_CONDITIONS_NOT_CORRECT, "self test has not run")
            return self.self_test_result
        return None                              # stopRoutine: fall through to YAML
