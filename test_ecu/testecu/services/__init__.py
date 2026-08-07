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
The built-in UDS core.

These seven services exist so that a plugin author only has to write the parts
that are specific to their ECU.  Every one of them can be overridden or removed
by a plugin: an ``@on_service(sid)`` hook runs first, and returning anything but
``None`` means the core never sees the request.

Deliberately *not* implemented here — these are OEM-shaped and are exactly what
the plugin system is for: 0x14 ClearDiagnosticInformation, 0x19
ReadDTCInformation, 0x23/0x3D read/write memory, 0x28 CommunicationControl,
0x2C DynamicallyDefineDataIdentifier, 0x2F InputOutputControlByIdentifier,
0x34-0x37 the transfer services, 0x85 ControlDTCSetting.
"""

from __future__ import annotations

from typing import Any, Optional

from testecu.plugin import Context
from testecu.services import data_identifier, reset, routine, security, session_control
from testecu.uds import (
    SID_DIAGNOSTIC_SESSION_CONTROL,
    SID_ECU_RESET,
    SID_READ_DATA_BY_IDENTIFIER,
    SID_ROUTINE_CONTROL,
    SID_SECURITY_ACCESS,
    SID_TESTER_PRESENT,
    SID_WRITE_DATA_BY_IDENTIFIER,
)


class CoreServices:
    """Dispatch table for the services TestEcu implements out of the box."""

    def __init__(self, ecu: Any, dispatcher: Any) -> None:
        self.ecu = ecu
        self.dispatcher = dispatcher
        self._table = {
            SID_DIAGNOSTIC_SESSION_CONTROL: session_control.diagnostic_session_control,
            SID_TESTER_PRESENT:             session_control.tester_present,
            SID_ECU_RESET:                  reset.ecu_reset,
            SID_SECURITY_ACCESS:            security.security_access,
            SID_READ_DATA_BY_IDENTIFIER:    data_identifier.read_data_by_identifier,
            SID_WRITE_DATA_BY_IDENTIFIER:   data_identifier.write_data_by_identifier,
            SID_ROUTINE_CONTROL:            routine.routine_control,
        }

    def supports(self, sid: int) -> bool:
        return sid in self._table

    async def handle(self, ctx: Context) -> Optional[Any]:
        """
        Serve one request, or return ``None`` if this is not a core service
        (in which case the dispatcher applies the ``unknown_service`` policy).
        """
        handler = self._table.get(ctx.request.sid)
        if handler is None:
            return None
        return await handler(self, ctx)
