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
from typing import Iterable, Optional

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

PT_HEADER_NACK                   = 0x0000
PT_VEHICLE_ID_REQUEST            = 0x0001
PT_VEHICLE_ID_REQUEST_WITH_EID   = 0x0002
PT_VEHICLE_ID_REQUEST_WITH_VIN   = 0x0003
PT_VEHICLE_ID_RESPONSE           = 0x0004
PT_ROUTING_ACT_REQUEST           = 0x0005
PT_ROUTING_ACT_RESPONSE          = 0x0006
PT_ALIVE_CHECK_REQUEST           = 0x0007
PT_ALIVE_CHECK_RESPONSE          = 0x0008
PT_ENTITY_STATUS_REQUEST         = 0x4001
PT_ENTITY_STATUS_RESPONSE        = 0x4002
PT_POWER_MODE_REQUEST            = 0x4003
PT_POWER_MODE_RESPONSE           = 0x4004
PT_DIAGNOSTIC_MESSAGE            = 0x8001
PT_DIAGNOSTIC_POSITIVE_ACK       = 0x8002
PT_DIAGNOSTIC_NEGATIVE_ACK       = 0x8003

PTYPE_NAMES = {
    PT_HEADER_NACK:                 "Header NACK",
    PT_VEHICLE_ID_REQUEST:          "Vehicle Identification Request",
    PT_VEHICLE_ID_REQUEST_WITH_EID: "Vehicle Identification Request with EID",
    PT_VEHICLE_ID_REQUEST_WITH_VIN: "Vehicle Identification Request with VIN",
    PT_VEHICLE_ID_RESPONSE:         "Vehicle Identification Response",
    PT_ROUTING_ACT_REQUEST:         "Routing Activation Request",
    PT_ROUTING_ACT_RESPONSE:        "Routing Activation Response",
    PT_ALIVE_CHECK_REQUEST:         "Alive Check Request",
    PT_ALIVE_CHECK_RESPONSE:        "Alive Check Response",
    PT_ENTITY_STATUS_REQUEST:       "Entity Status Request",
    PT_ENTITY_STATUS_RESPONSE:      "Entity Status Response",
    PT_POWER_MODE_REQUEST:          "Power Mode Info Request",
    PT_POWER_MODE_RESPONSE:         "Power Mode Info Response",
    PT_DIAGNOSTIC_MESSAGE:          "Diagnostic Message",
    PT_DIAGNOSTIC_POSITIVE_ACK:     "Diagnostic Message Positive ACK",
    PT_DIAGNOSTIC_NEGATIVE_ACK:     "Diagnostic Message Negative ACK",
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

# Generic Header (PT_HEADER_NACK) negative acknowledge codes (ISO 13400-2
# Table 14 / DoIP-045) — architecture roadmap P6. A *different* code space
# from the ``NACK_*`` family above (Table 26, the Diagnostic Message NACK):
# the two tables happen to share some of the same small integers (0x00..0x04
# on both), which is exactly why they are named distinctly here rather than
# under one shared prefix — conflating them would make a call site's
# ``0x02`` ambiguous between "message too large" on two unrelated tables.
NACK_GENERIC_INCORRECT_PATTERN      = 0x00
NACK_GENERIC_UNKNOWN_PAYLOAD_TYPE   = 0x01
NACK_GENERIC_MESSAGE_TOO_LARGE      = 0x02
NACK_GENERIC_INVALID_PAYLOAD_LENGTH = 0x04

# Tester (client) logical address range accepted by Routing Activation
# (ISO 13400-2 Table 13). A source address outside this range is denied with
# Routing Activation Response code 0x00 (an unrecognised/unknown source
# address).
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


class FrameTooLarge(Exception):
    """
    Raised by ``read_frame`` when the declared payload length exceeds
    ``max_len`` — before any of that payload has been read.

    The generic header's length field is 32 bits (ISO 13400-2 Table 2), so a
    peer that sends a genuine 8-byte header but lies in that field — up to
    ~4 GiB — makes a trusting ``readexactly(plen)`` wait for the rest of
    those bytes forever. That ties up the connection (and its task)
    indefinitely: the general inactivity timer (DoIP-080) only resets once a
    full frame has actually been read, so a stalled read like this never
    times out on its own. Raising here instead of reading lets the caller
    send a Generic NACK and close the connection, rather than hang.
    """

    def __init__(self, declared_len: int, max_len: int) -> None:
        self.declared_len = declared_len
        self.max_len = max_len
        super().__init__(
            f"declared payload length {declared_len} exceeds max_len {max_len}"
        )


async def read_frame(reader: asyncio.StreamReader,
                      max_len: Optional[int] = None) -> bytes:
    """
    Read exactly one DoIP frame (header + payload) from ``reader``.

    ``max_len``, when given, bounds the declared payload length: anything
    over it raises ``FrameTooLarge`` immediately, without attempting
    ``readexactly`` on that many bytes (see that exception's docstring for
    why this matters). Callers that omit it get the original, unbounded
    behaviour — this is opt-in so it stays a byte-identical port for anyone
    diffing against ``echo_ecu``'s framing.
    """
    hdr = await reader.readexactly(8)
    plen = struct.unpack("!I", hdr[4:8])[0]
    if max_len is not None and plen > max_len:
        raise FrameTooLarge(plen, max_len)
    if plen == 0:
        return hdr
    payload = await reader.readexactly(plen)
    return hdr + payload


def validate_header(raw: bytes, known_types: Optional[Iterable[int]] = None, *,
                    version_wildcard_types: Iterable[int] = ()) -> Optional[int]:
    """
    ISO 13400-2 Table 2 Generic Header check: protocol version vs. its
    bitwise-inverse companion, plus (when the caller cares) whether the
    payload type is one it accepts at all.

    Shared between ``session.py`` (TCP_DATA) and ``udp.py`` (UDP_DISCOVERY)
    — architecture roadmap P4. The two sides used to check this
    independently; TCP validated version/inverse inline and UDP didn't check
    it at all, so any junk header slipped straight through
    ``datagram_received``'s payload-type dispatch.

    Returns a Generic Header NACK code (Table 14 / DoIP-045) or ``None`` if
    the header is acceptable:

      - ``0x00`` ("incorrect pattern format") if ``inv`` isn't ``raw[0]``'s
        bitwise complement, or the version isn't one of
        ``ACCEPTED_VERSIONS`` and isn't the ``0xFF`` "version not yet known"
        wildcard for a payload type listed in ``version_wildcard_types``.
        ISO 13400-2 Figure 8 permits ``0xFF`` specifically on a Vehicle
        Identification Request, because a tester that has not yet completed
        the vehicle discovery exchange cannot know which protocol version
        this entity speaks — TCP_DATA has no such request, so it passes an
        empty tuple and never allows the wildcard.
      - ``0x01`` ("unknown payload type") if ``known_types`` is given and
        the payload type isn't in it. ``None`` (the default) skips this
        check entirely — a caller that already has its own payload-type
        dispatch/fallback (``session.py``'s, unchanged by this function) can
        keep doing that instead of duplicating it here.

    ``raw`` must be at least the 4 leading header bytes (version, inverse,
    2-byte payload type); every caller reaches this only after a complete
    8-byte-header read (``read_frame`` on TCP, the ``len(data) < 8`` guard on
    UDP), so that is never actually the tight edge in practice.
    """
    ver = raw[0]
    inv = raw[1]
    pt = struct.unpack("!H", raw[2:4])[0]
    if inv != (0xFF ^ ver):
        return NACK_GENERIC_INCORRECT_PATTERN
    if ver not in ACCEPTED_VERSIONS and not (ver == 0xFF and pt in version_wildcard_types):
        return NACK_GENERIC_INCORRECT_PATTERN
    if known_types is not None and pt not in known_types:
        return NACK_GENERIC_UNKNOWN_PAYLOAD_TYPE
    return None


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
