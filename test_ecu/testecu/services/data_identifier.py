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
ReadDataByIdentifier (0x22) and WriteDataByIdentifier (0x2E).

Resolution order for one DID:

    1. a Python ``@read_did`` / ``@write_did`` handler
    2. the YAML ``data_identifiers:`` entry
    3. the ``uds.unknown_did`` policy

The session/security gates declared in YAML apply to step 2 only.  A Python
handler is trusted to enforce its own policy — it has ``ctx.session_type`` and
``ctx.security_level`` right there.
"""

from __future__ import annotations

import struct
from typing import Any, Optional

from testecu.config import DidSpec
from testecu.plugin import Context
from testecu.uds import (
    DID_ACTIVE_DIAGNOSTIC_SESSION,
    NO_RESPONSE,
    NRC_INCORRECT_MESSAGE_LENGTH,
    NRC_REQUEST_OUT_OF_RANGE,
    NRC_RESPONSE_TOO_LONG,
    NRC_SECURITY_ACCESS_DENIED,
)


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

async def read_data_by_identifier(core: Any, ctx: Context) -> Any:
    """0x22 — read one or more DIDs; response is ``62`` + ``<did><value>``*."""
    request = ctx.request
    body = request.data
    if not body or len(body) % 2 != 0:
        raise ctx.nrc(NRC_INCORRECT_MESSAGE_LENGTH,
                      "ReadDataByIdentifier takes whole 2-byte identifiers")

    record = bytearray()
    served = 0
    for did in request.dids():
        value = await _read_one(core, ctx, did)
        if value is None:
            continue                      # skipped by the 'silent' policy
        record += struct.pack("!H", did) + value
        served += 1

    if served == 0:
        ctx.log.debug("0x22: no DID could be served — staying silent")
        return NO_RESPONSE

    response = request.positive(bytes(record))
    if len(response) > core.ecu.config.doip.max_payload_bytes:
        raise ctx.nrc(NRC_RESPONSE_TOO_LONG,
                      "%d bytes exceeds doip.max_payload_bytes" % len(response))
    return response


async def _read_one(core: Any, ctx: Context, did: int) -> Optional[bytes]:
    # 1. Python handler
    value = await core.dispatcher.resolve_did_read(did, ctx)
    if value is not None:
        return value

    # 2. YAML table
    spec = core.ecu.store.spec(did)
    if spec is None or not spec.read:
        return _unknown_did(core, ctx, did, "read")

    if spec.read_nrc is not None:
        raise ctx.nrc(spec.read_nrc, "%s: read_nrc from config" % spec.label())
    _check_gates(ctx, spec, spec.read_sessions, spec.read_security, "read")

    if spec.dynamic:
        dynamic = _dynamic_value(ctx, did)
        if dynamic is not None:
            return dynamic
        raise ctx.nrc(NRC_REQUEST_OUT_OF_RANGE,
                      "%s is declared dynamic but nothing provides it" % spec.label())

    stored = core.ecu.store.read(did)
    if stored is None:                    # pragma: no cover — config guarantees a value
        raise ctx.nrc(NRC_REQUEST_OUT_OF_RANGE, "%s has no value" % spec.label())
    return stored


def _dynamic_value(ctx: Context, did: int) -> Optional[bytes]:
    """DIDs the core can answer without any configuration."""
    if did == DID_ACTIVE_DIAGNOSTIC_SESSION:
        return bytes([ctx.session.session_type])
    return None


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

async def write_data_by_identifier(core: Any, ctx: Context) -> Any:
    """0x2E — write one DID; response is ``6E <did>``."""
    request = ctx.request
    body = request.data
    if len(body) < 3:
        raise ctx.nrc(NRC_INCORRECT_MESSAGE_LENGTH,
                      "WriteDataByIdentifier takes a 2-byte identifier and a value")

    did = int.from_bytes(body[0:2], "big")
    value = bytes(body[2:])

    # 1. Python handler
    accepted = await core.dispatcher.resolve_did_write(did, value, ctx)
    if accepted:
        return request.positive(struct.pack("!H", did))
    if accepted is False:
        raise ctx.nrc(NRC_REQUEST_OUT_OF_RANGE,
                      "a handler rejected the write to DID 0x%04X" % did)

    # 2. YAML table
    spec = core.ecu.store.spec(did)
    if spec is None:
        _unknown_did(core, ctx, did, "write")
        return NO_RESPONSE                # only reachable under the 'silent' policy
    if not spec.write:
        raise ctx.nrc(NRC_REQUEST_OUT_OF_RANGE, "%s is read-only" % spec.label())

    if spec.write_nrc is not None:
        raise ctx.nrc(spec.write_nrc, "%s: write_nrc from config" % spec.label())
    _check_gates(ctx, spec, spec.write_sessions, spec.write_security, "write")

    if spec.length is not None and len(value) != spec.length:
        raise ctx.nrc(NRC_INCORRECT_MESSAGE_LENGTH,
                      "%s takes %d byte(s), got %d"
                      % (spec.label(), spec.length, len(value)))

    core.ecu.store.write(did, value)
    ctx.log.info("wrote %s = %s", spec.label(), value.hex(" ").upper())
    return request.positive(struct.pack("!H", did))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _check_gates(ctx: Context, spec: DidSpec, sessions, security: int,
                 action: str) -> None:
    """Enforce the YAML session and security gates for one DID."""
    if sessions is not None and ctx.session_type not in sessions:
        raise ctx.nrc(
            NRC_REQUEST_OUT_OF_RANGE,
            "%s is not %sable in session 0x%02X" % (spec.label(), action,
                                                    ctx.session_type),
        )
    if security > ctx.security_level:
        raise ctx.nrc(
            NRC_SECURITY_ACCESS_DENIED,
            "%s needs security level %d, tester has %d"
            % (spec.label(), security, ctx.security_level),
        )


def _unknown_did(core: Any, ctx: Context, did: int, action: str) -> Optional[bytes]:
    """
    Apply ``uds.unknown_did``.

    nrc     — requestOutOfRange for the whole request (the default)
    echo    — answer the DID with its own identifier bytes as the value; an
              obviously-synthetic but well-formed record, so a tester's parser
              keeps working while it is clear the data is not real
    silent  — skip this DID; if no DID in the request could be served, the
              request produces no response at all
    """
    policy = core.ecu.uds.unknown_did
    if policy == "silent":
        ctx.log.debug("0x%02X: DID 0x%04X unknown — skipping", ctx.request.sid, did)
        return None
    if policy == "echo":
        ctx.log.debug("0x%02X: DID 0x%04X unknown — echoing the identifier",
                      ctx.request.sid, did)
        return struct.pack("!H", did)
    raise ctx.nrc(NRC_REQUEST_OUT_OF_RANGE,
                  "DID 0x%04X is not %sable here" % (did, action))
