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
Example plugin: raw-service interception and fault injection.

This is the catch-all side of the API — no DIDs, no routines, just
``@on_service()`` seeing every request before anything else does.  Use this
shape when you want to implement a service TestEcu has no core support for
(0x19 ReadDTCInformation is the classic one) or to misbehave on purpose while
testing a tester.

Everything is driven from YAML ``params:``, so one file covers many scenarios::

    - file: "plugins/example_faults.py"
      priority: 10
      params:
        drop_sids:  [0x11]     # ECUReset vanishes; the tester must time out
        stall_sids: [0x22]     # first 2 reads get a 0x78 before the real answer
        stall_count: 2
"""

from __future__ import annotations

import asyncio
from typing import Optional

from testecu import NO_RESPONSE, Context, Plugin, UdsRequest, on_service

SID_READ_DTC_INFORMATION = 0x19
REPORT_DTC_BY_STATUS_MASK = 0x02


class RawFaults(Plugin):
    """Catch-all interception: drop, stall, or answer a service outright."""

    name = "RawFaults"
    priority = 10                       # low number -> runs before other plugins

    def __init__(self, drop_sids=(), stall_sids=(), stall_count: int = 2,
                 **params) -> None:
        super().__init__(**params)
        self.drop_sids = {int(sid) for sid in drop_sids}
        self.stall_sids = {int(sid) for sid in stall_sids}
        self.stall_count = int(stall_count)
        self._seen: dict = {}

    @on_service()                       # ANY_SERVICE
    async def intercept(self, req: UdsRequest, ctx: Context):
        if req.sid in self.drop_sids:
            ctx.log.info("RawFaults: swallowing %s", req.describe())
            return NO_RESPONSE          # handled, but nothing goes on the wire

        if req.sid in self.stall_sids:
            count = self._seen.get(req.sid, 0) + 1
            self._seen[req.sid] = count
            if count <= self.stall_count:
                ctx.log.info("RawFaults: stalling %s (%d/%d)",
                             req.describe(), count, self.stall_count)
                await ctx.response_pending()     # manual 7F <sid> 78
                await asyncio.sleep(0.2)

        return None                     # not handled -> continue down the ladder


class SimpleDtcs(Plugin):
    """
    A service the core does not implement: 0x19 ReadDTCInformation.

    Only ``reportDTCByStatusMask`` (0x02) is answered, which is enough for most
    tester smoke tests.  Everything else falls through and ends up as
    subFunctionNotSupported from the ``unknown_service`` policy.
    """

    name = "SimpleDtcs"
    priority = 100

    #: (DTC 3 bytes, status byte) — confirmed + testFailed
    DTCS = (
        (0xC10A00, 0x2F),
        (0xD24B14, 0x08),
    )

    @on_service(SID_READ_DTC_INFORMATION)
    def read_dtc(self, req: UdsRequest, ctx: Context) -> Optional[bytes]:
        if req.sub_function != REPORT_DTC_BY_STATUS_MASK or len(req.raw) != 3:
            return None                 # not ours — hand it back

        mask = req.raw[2]
        record = bytearray([0xFF])      # DTCStatusAvailabilityMask
        for dtc, status in self.DTCS:
            if status & mask:
                record += dtc.to_bytes(3, "big") + bytes([status])
        return req.positive(bytes([REPORT_DTC_BY_STATUS_MASK]) + bytes(record))
