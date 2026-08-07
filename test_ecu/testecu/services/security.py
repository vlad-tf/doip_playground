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
SecurityAccess (0x27).

This is deliberately the simplest thing that can unlock a DID: a fixed seed
from the config and a key derived from it by XOR, addition, or identity.  It is
in the core because without *some* 0x27 the ``write_security:`` gate on a DID
would be untestable — not because it is a realistic security model.

Real seed/key algorithms belong in a plugin::

    @on_service(0x27)
    def security(self, req, ctx):
        ...   # your OEM algorithm here

The seed is **deterministic**, taken straight from the config.  A simulator
whose responses change from run to run cannot be asserted against, so no part
of TestEcu draws from a randomness source — ``tests/test_dispatcher.py``
enforces that at the source level.
"""

from __future__ import annotations

from typing import Any, Optional

from testecu.plugin import Context
from testecu.uds import (
    NRC_EXCEEDED_NUMBER_OF_ATTEMPTS,
    NRC_INCORRECT_MESSAGE_LENGTH,
    NRC_INVALID_KEY,
    NRC_REQUEST_SEQUENCE_ERROR,
    NRC_SUB_FUNCTION_NOT_SUPPORTED,
)


async def security_access(core: Any, ctx: Context) -> Optional[bytes]:
    """
    0x27 — requestSeed on odd sub-functions, sendKey on even ones.

    Returns ``None`` when security is disabled in the config, which lets the
    dispatcher fall through to ``uds.unknown_service`` (serviceNotSupported by
    default).
    """
    config = core.ecu.uds.security
    if not config.enabled:
        return None

    request = ctx.request
    if len(request.raw) < 2:
        raise ctx.nrc(NRC_INCORRECT_MESSAGE_LENGTH,
                      "SecurityAccess needs a sub-function byte")

    sub = request.sub_function
    if sub == 0x00:
        raise ctx.nrc(NRC_SUB_FUNCTION_NOT_SUPPORTED,
                      "SecurityAccess sub-function 0x00 is reserved")

    if sub % 2 == 1:
        return _request_seed(core, ctx, sub)
    return _send_key(core, ctx, sub)


def level_of(sub: int) -> int:
    """Security level granted by sub-function ``sub`` (0x01/0x02 -> 1, ...)."""
    return (sub + 1) // 2


def expected_key(seed: bytes, config: Any) -> bytes:
    """Derive the key the tester is expected to send back for ``seed``."""
    if config.algorithm == "none":
        return seed
    if config.algorithm == "add":
        return bytes((s + k) & 0xFF for s, k in zip(seed, config.key))
    return bytes(s ^ k for s, k in zip(seed, config.key))


def _request_seed(core: Any, ctx: Context, sub: int) -> bytes:
    config = core.ecu.uds.security
    level = level_of(sub)

    if len(ctx.request.raw) != 2:
        raise ctx.nrc(NRC_INCORRECT_MESSAGE_LENGTH,
                      "requestSeed takes no data")

    if ctx.session.security_level >= level:
        # ISO 14229-1 §9.4.5.2: already unlocked -> reply with an all-zero seed
        # and do not arm a new sendKey exchange.
        ctx.log.debug("0x27: level %d already unlocked — sending a zero seed", level)
        return ctx.request.positive(bytes([sub]) + bytes(len(config.seed)))

    ctx.session.seed_pending = sub
    ctx.log.debug("0x27: issued seed for level %d to tester 0x%04X",
                  level, ctx.request.source_addr)
    return ctx.request.positive(bytes([sub]) + config.seed)


def _send_key(core: Any, ctx: Context, sub: int) -> bytes:
    config = core.ecu.uds.security
    session = ctx.session
    level = level_of(sub)

    if session.seed_pending != sub - 1:
        raise ctx.nrc(NRC_REQUEST_SEQUENCE_ERROR,
                      "sendKey 0x%02X without a matching requestSeed" % sub)

    key = ctx.request.raw[2:]
    if len(key) != len(config.seed):
        raise ctx.nrc(NRC_INCORRECT_MESSAGE_LENGTH,
                      "key must be %d byte(s), got %d" % (len(config.seed), len(key)))

    if key != expected_key(config.seed, config):
        session.security_attempts += 1
        session.seed_pending = None
        if session.security_attempts >= config.max_attempts:
            ctx.log.warning(
                "0x27: tester 0x%04X exhausted %d attempts for level %d",
                ctx.request.source_addr, session.security_attempts, level,
            )
            raise ctx.nrc(NRC_EXCEEDED_NUMBER_OF_ATTEMPTS,
                          "too many invalid keys")
        raise ctx.nrc(NRC_INVALID_KEY,
                      "attempt %d of %d" % (session.security_attempts,
                                            config.max_attempts))

    session.security_level = level
    session.security_attempts = 0
    session.seed_pending = None
    ctx.log.info("0x27: tester 0x%04X unlocked security level %d",
                 ctx.request.source_addr, level)
    return ctx.request.positive(bytes([sub]))
