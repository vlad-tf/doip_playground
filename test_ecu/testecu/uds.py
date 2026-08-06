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
UDS (ISO 14229-1) vocabulary: service identifiers, negative response codes,
the parsed request object, and the two control-flow types plugins use.

This module has no dependencies inside TestEcu — it is the bottom of the stack.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

# ---------------------------------------------------------------------------
# Service identifiers
# ---------------------------------------------------------------------------

SID_DIAGNOSTIC_SESSION_CONTROL = 0x10
SID_ECU_RESET                  = 0x11
SID_READ_DATA_BY_IDENTIFIER    = 0x22
SID_SECURITY_ACCESS            = 0x27
SID_WRITE_DATA_BY_IDENTIFIER   = 0x2E
SID_ROUTINE_CONTROL            = 0x31
SID_TESTER_PRESENT             = 0x3E
SID_NEGATIVE_RESPONSE          = 0x7F

SID_NAMES = {
    SID_DIAGNOSTIC_SESSION_CONTROL: "DiagnosticSessionControl",
    SID_ECU_RESET:                  "ECUReset",
    SID_READ_DATA_BY_IDENTIFIER:    "ReadDataByIdentifier",
    SID_SECURITY_ACCESS:            "SecurityAccess",
    SID_WRITE_DATA_BY_IDENTIFIER:   "WriteDataByIdentifier",
    SID_ROUTINE_CONTROL:            "RoutineControl",
    SID_TESTER_PRESENT:             "TesterPresent",
}

# ---------------------------------------------------------------------------
# Negative response codes (ISO 14229-1 Table A.1)
# ---------------------------------------------------------------------------

NRC_GENERAL_REJECT                   = 0x10
NRC_SERVICE_NOT_SUPPORTED            = 0x11
NRC_SUB_FUNCTION_NOT_SUPPORTED       = 0x12
NRC_INCORRECT_MESSAGE_LENGTH         = 0x13
NRC_RESPONSE_TOO_LONG                = 0x14
NRC_BUSY_REPEAT_REQUEST              = 0x21
NRC_CONDITIONS_NOT_CORRECT           = 0x22
NRC_REQUEST_SEQUENCE_ERROR           = 0x24
NRC_REQUEST_OUT_OF_RANGE             = 0x31
NRC_SECURITY_ACCESS_DENIED           = 0x33
NRC_INVALID_KEY                      = 0x35
NRC_EXCEEDED_NUMBER_OF_ATTEMPTS      = 0x36
NRC_RESPONSE_PENDING                 = 0x78
NRC_SERVICE_NOT_SUPPORTED_IN_SESSION = 0x7F

NRC_NAMES = {
    NRC_GENERAL_REJECT:                   "generalReject",
    NRC_SERVICE_NOT_SUPPORTED:            "serviceNotSupported",
    NRC_SUB_FUNCTION_NOT_SUPPORTED:       "subFunctionNotSupported",
    NRC_INCORRECT_MESSAGE_LENGTH:         "incorrectMessageLengthOrInvalidFormat",
    NRC_RESPONSE_TOO_LONG:                "responseTooLong",
    NRC_BUSY_REPEAT_REQUEST:              "busyRepeatRequest",
    NRC_CONDITIONS_NOT_CORRECT:           "conditionsNotCorrect",
    NRC_REQUEST_SEQUENCE_ERROR:           "requestSequenceError",
    NRC_REQUEST_OUT_OF_RANGE:             "requestOutOfRange",
    NRC_SECURITY_ACCESS_DENIED:           "securityAccessDenied",
    NRC_INVALID_KEY:                      "invalidKey",
    NRC_EXCEEDED_NUMBER_OF_ATTEMPTS:      "exceededNumberOfAttempts",
    NRC_RESPONSE_PENDING:                 "requestCorrectlyReceived-ResponsePending",
    NRC_SERVICE_NOT_SUPPORTED_IN_SESSION: "serviceNotSupportedInActiveSession",
}

#: Services whose byte 1 is a sub-function parameter, and therefore the only
#: ones where bit 7 is the suppressPosRspMsgIndicationBit (ISO 14229-1 §8.2.2).
#:
#: This set is load-bearing: for ReadDataByIdentifier byte 1 is the high byte of
#: the DID, so ``22 F1 90`` would otherwise look like a suppressed request and
#: the VIN would never be sent.  A plugin implementing a sub-function service
#: that is not listed here should read ``req.raw[1]`` directly.
SUB_FUNCTION_SERVICES = frozenset((
    0x10,   # DiagnosticSessionControl
    0x11,   # ECUReset
    0x19,   # ReadDTCInformation
    0x27,   # SecurityAccess
    0x28,   # CommunicationControl
    0x2C,   # DynamicallyDefineDataIdentifier
    0x31,   # RoutineControl
    0x3E,   # TesterPresent
    0x83,   # AccessTimingParameter
    0x85,   # ControlDTCSetting
    0x86,   # ResponseOnEvent
    0x87,   # LinkControl
))

#: NRCs that must NOT be sent in reply to a functionally addressed request
#: (ISO 14229-1 §7.5 — otherwise every ECU on the bus would answer).
FUNCTIONAL_SUPPRESSED_NRCS = frozenset((
    NRC_SERVICE_NOT_SUPPORTED,
    NRC_SUB_FUNCTION_NOT_SUPPORTED,
    NRC_REQUEST_OUT_OF_RANGE,
    NRC_SERVICE_NOT_SUPPORTED_IN_SESSION,
))

# ---------------------------------------------------------------------------
# Diagnostic sessions
# ---------------------------------------------------------------------------

SESSION_DEFAULT     = 0x01
SESSION_PROGRAMMING = 0x02
SESSION_EXTENDED    = 0x03
SESSION_SAFETY      = 0x04

SESSION_NAMES = {
    SESSION_DEFAULT:     "default",
    SESSION_PROGRAMMING: "programming",
    SESSION_EXTENDED:    "extendedDiagnostic",
    SESSION_SAFETY:      "safetySystemDiagnostic",
}

#: DID served by the core: the currently active diagnostic session
DID_ACTIVE_DIAGNOSTIC_SESSION = 0xF186


def nrc_name(nrc: int) -> str:
    return NRC_NAMES.get(nrc, "0x%02X" % nrc)


def sid_name(sid: int) -> str:
    return SID_NAMES.get(sid, "0x%02X" % sid)


# ---------------------------------------------------------------------------
# Control-flow types
# ---------------------------------------------------------------------------

class NegativeResponse(Exception):
    """
    Raise from any handler to emit ``7F <sid> <nrc>``.

    ``sid`` may be left None — the dispatcher fills in the SID of the request
    being processed.  Prefer ``raise ctx.nrc(NRC_..., "why")``, which fills it
    in for you and keeps the reason in the log.
    """

    def __init__(self, nrc: int, sid: Optional[int] = None, message: str = "") -> None:
        self.nrc = nrc
        self.sid = sid
        self.reason = message
        super().__init__(message or nrc_name(nrc))

    def to_bytes(self) -> bytes:
        return bytes([SID_NEGATIVE_RESPONSE, (self.sid or 0x00) & 0xFF, self.nrc])


class SuppressResponse(Exception):
    """
    Internal control flow: send nothing at all for this request.

    Raised when a handler nested inside a service (a ``@read_did`` hook, say)
    returns ``NO_RESPONSE``, or when ``uds.on_handler_error`` is ``silent`` and
    a handler blew up.  It has to be an exception rather than a return value so
    that it escapes the surrounding core service instead of looking like "this
    DID could not be read, try the next candidate".
    """


class _NoResponse:
    """Sentinel: the request was handled, but nothing is to be sent back."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "NO_RESPONSE"

    def __bool__(self) -> bool:
        # Truthy so that `if result is not None` style fall-through still works
        # and so a handler returning it never looks like "not handled".
        return True


#: Returned by a handler that wants the request swallowed silently.
NO_RESPONSE = _NoResponse()


# ---------------------------------------------------------------------------
# Parsed request
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UdsRequest:
    """One inbound UDS request, already stripped of its DoIP framing."""

    raw: bytes                #: full request including the SID
    source_addr: int          #: tester logical address
    target_addr: int          #: the logical address the tester addressed
    functional: bool = False  #: True when target_addr is the functional address

    @property
    def sid(self) -> int:
        return self.raw[0] if self.raw else -1

    @property
    def data(self) -> bytes:
        """Everything after the SID."""
        return self.raw[1:]

    @property
    def has_sub_function(self) -> bool:
        return self.sid in SUB_FUNCTION_SERVICES

    @property
    def sub_function(self) -> Optional[int]:
        """
        Byte 1 with the suppressPosRspMsgIndicationBit masked off.

        None for services that have no sub-function — for those, byte 1 is data
        (a DID high byte, a memory address, ...) and must not be reinterpreted.
        """
        if not self.has_sub_function or len(self.raw) < 2:
            return None
        return self.raw[1] & 0x7F

    @property
    def suppress_pos_rsp(self) -> bool:
        """suppressPosRspMsgIndicationBit — sub-function bit 7 (§8.2.2)."""
        return bool(self.has_sub_function and len(self.raw) > 1 and self.raw[1] & 0x80)

    @property
    def did(self) -> Optional[int]:
        """First DID of a 0x22 / 0x2E request, if present."""
        if self.sid in (SID_READ_DATA_BY_IDENTIFIER, SID_WRITE_DATA_BY_IDENTIFIER) \
                and len(self.raw) >= 3:
            return int.from_bytes(self.raw[1:3], "big")
        return None

    def dids(self) -> List[int]:
        """Every DID in a (possibly multi-DID) 0x22 request."""
        body = self.raw[1:]
        return [
            int.from_bytes(body[i:i + 2], "big")
            for i in range(0, len(body) - 1, 2)
        ]

    def positive(self, payload: bytes = b"") -> bytes:
        """``SID | 0x40`` followed by ``payload``."""
        return bytes([(self.sid | 0x40) & 0xFF]) + payload

    def negative(self, nrc: int) -> bytes:
        """``7F <sid> <nrc>``."""
        return bytes([SID_NEGATIVE_RESPONSE, self.sid & 0xFF, nrc])

    def describe(self) -> str:
        return "%s (0x%02X)" % (sid_name(self.sid), self.sid & 0xFF)
