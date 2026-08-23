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
DoIP (ISO 13400-2) constants and frame helpers.

This module is a port of the framing layer from ``echo_ecu/echo_ecu.py``
(constants at lines 67-105, frame helpers at 253-279).  The byte semantics are
identical — ``tests/test_doip_parity.py`` asserts that against the original.

The only addition is ``PT_DIAGNOSTIC_NEGATIVE_ACK`` (0x8003), which TestEcu
sends when a Diagnostic Message is addressed to a logical address this ECU
does not own.
"""

from __future__ import annotations

import asyncio
import struct

# ---------------------------------------------------------------------------
# Protocol version
# ---------------------------------------------------------------------------

VER = 0x02
INV = 0xFF ^ VER

#: Versions accepted on inbound frames (0x02 = ISO 13400-2:2012, 0x03 = :2019)
ACCEPTED_VERSIONS = (0x02, 0x03)

# ---------------------------------------------------------------------------
# Payload types
# ---------------------------------------------------------------------------

PT_HEADER_NACK              = 0x0000
PT_VEHICLE_ID_REQUEST       = 0x0001
PT_VEHICLE_ID_RESPONSE      = 0x0004
PT_ROUTING_ACT_REQUEST      = 0x0005
PT_ROUTING_ACT_RESPONSE     = 0x0006
PT_ALIVE_CHECK_REQUEST      = 0x0007
PT_ALIVE_CHECK_RESPONSE     = 0x0008
PT_ENTITY_STATUS_REQUEST    = 0x4001
PT_ENTITY_STATUS_RESPONSE   = 0x4002
PT_POWER_MODE_REQUEST       = 0x4003
PT_POWER_MODE_RESPONSE      = 0x4004
PT_DIAGNOSTIC_MESSAGE       = 0x8001
PT_DIAGNOSTIC_POSITIVE_ACK  = 0x8002
PT_DIAGNOSTIC_NEGATIVE_ACK  = 0x8003

PTYPE_NAMES = {
    PT_HEADER_NACK:             "Header NACK",
    PT_VEHICLE_ID_REQUEST:      "Vehicle Identification Request",
    PT_VEHICLE_ID_RESPONSE:     "Vehicle Identification Response",
    PT_ROUTING_ACT_REQUEST:     "Routing Activation Request",
    PT_ROUTING_ACT_RESPONSE:    "Routing Activation Response",
    PT_ALIVE_CHECK_REQUEST:     "Alive Check Request",
    PT_ALIVE_CHECK_RESPONSE:    "Alive Check Response",
    PT_ENTITY_STATUS_REQUEST:   "Entity Status Request",
    PT_ENTITY_STATUS_RESPONSE:  "Entity Status Response",
    PT_POWER_MODE_REQUEST:      "Power Mode Info Request",
    PT_POWER_MODE_RESPONSE:     "Power Mode Info Response",
    PT_DIAGNOSTIC_MESSAGE:      "Diagnostic Message",
    PT_DIAGNOSTIC_POSITIVE_ACK: "Diagnostic Message Positive ACK",
    PT_DIAGNOSTIC_NEGATIVE_ACK: "Diagnostic Message Negative ACK",
}

# Diagnostic Message negative acknowledge codes (ISO 13400-2 Table 26).
# 0x00 and 0x01 are reserved by ISO 13400 — valid codes start at 0x02.
NACK_INVALID_SOURCE_ADDRESS   = 0x02
NACK_UNKNOWN_TARGET_ADDRESS   = 0x03
NACK_MESSAGE_TOO_LARGE        = 0x04
NACK_OUT_OF_MEMORY            = 0x05
NACK_TARGET_UNREACHABLE       = 0x06
NACK_UNKNOWN_NETWORK          = 0x07
NACK_TRANSPORT_PROTOCOL_ERROR = 0x08

# Tester (client) logical address range accepted by Routing Activation
# (ISO 13400-2 Table 13). A source address outside this range is denied with
# Routing Activation Response code 0x00 ("denied — unknown source address").
TESTER_ADDR_RANGE = (0x0E00, 0x0FFF)

# Minimum Routing Activation Request payload length (ISO 13400-2 Table 15):
# source address (2) + activation type (1) + reserved (4) = 7 bytes.
ROUTING_ACT_REQUEST_MIN_LEN = 7

# IPv6 DoIP multicast group (all-nodes link-local) used for announcements
DOIP_MCAST_ADDR = "ff02::1"

# Timeout for the Alive Check probe used during SA-conflict resolution
ALIVE_PROBE_TIMEOUT_S = 0.5


# ---------------------------------------------------------------------------
# Frame helpers
# ---------------------------------------------------------------------------

def build_frame(payload_type: int, payload: bytes, version: int = VER) -> bytes:
    """Wrap ``payload`` in an 8-byte DoIP generic header."""
    inv = 0xFF ^ version
    return struct.pack("!BBHI", version, inv, payload_type, len(payload)) + payload


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    """Read exactly one DoIP frame (header + payload) from ``reader``."""
    hdr = await reader.readexactly(8)
    plen = struct.unpack("!I", hdr[4:8])[0]
    if plen == 0:
        return hdr
    payload = await reader.readexactly(plen)
    return hdr + payload


def ptype(raw: bytes) -> int:
    """Payload type of a complete frame."""
    return struct.unpack("!H", raw[2:4])[0]


def payload(raw: bytes) -> bytes:
    """Payload bytes of a complete frame."""
    return raw[8:]


def fmt_hex(data: bytes, max_bytes: int = 32) -> str:
    """Human-readable hex dump for logging."""
    if not data:
        return "(empty)"
    h = data[:max_bytes].hex(" ").upper()
    return h + (" …" if len(data) > max_bytes else "")
