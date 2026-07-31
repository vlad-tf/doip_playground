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
DoIP EdgeNode — Logger middleware.

Logs every DoIP frame to both stdout and a rotating log file.
Each entry includes: ISO 8601 timestamp, direction, payload type (hex +
human-readable name), payload length, and an optional full hex dump.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from datetime import datetime, timezone
from typing import Literal, TYPE_CHECKING

from middleware import Middleware

if TYPE_CHECKING:
    from session import DoIPSession

# ---------------------------------------------------------------------------
# Payload type → human-readable name
# (covers all types defined in the requirements)
# ---------------------------------------------------------------------------
_PAYLOAD_TYPE_NAMES: dict[int, str] = {
    0x0000: "DoIP Header NACK",
    0x0001: "Vehicle Identification Request",
    0x0002: "Vehicle Identification Request (EID)",
    0x0003: "Vehicle Identification Request (VIN)",
    0x0004: "Vehicle Identification Response / Vehicle Announcement",
    0x0005: "Routing Activation Request",
    0x0006: "Routing Activation Response",
    0x0007: "Alive Check Request",
    0x0008: "Alive Check Response",
    0x4001: "Entity Status Request",
    0x4002: "Entity Status Response",
    0x4003: "Power Mode Info Request",
    0x4004: "Power Mode Info Response",
    0x8001: "Diagnostic Message",
    0x8002: "Diagnostic Message Positive ACK",
    0x8003: "Diagnostic Message Negative ACK",
}

# ---------------------------------------------------------------------------
# Scapy DoIP field names (verified on Raspberry Pi 4)
_DOIP_TYPE_FIELD = "payload_type"
_DOIP_LEN_FIELD = "payload_length"


def _get_ptype(pkt) -> int | None:
    """Extract payload type from a DoIP packet; return None on failure."""
    try:
        return getattr(pkt, _DOIP_TYPE_FIELD, None)
    except Exception:
        return None


def _get_plen(pkt) -> int | None:
    """Extract payload length from a DoIP packet; return None on failure."""
    try:
        return getattr(pkt, _DOIP_LEN_FIELD, None)
    except Exception:
        return None


def _make_logger(log_path: str) -> logging.Logger:
    """Create (or retrieve) a logger that writes to file + stdout."""
    log_name = f"doip.{log_path}"
    lgr = logging.getLogger(log_name)
    if lgr.handlers:
        return lgr  # already configured

    lgr.setLevel(logging.DEBUG)

    # Ensure the log directory exists
    log_dir = os.path.dirname(log_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    fmt = logging.Formatter("%(message)s")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    lgr.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    lgr.addHandler(stream_handler)

    # Prevent propagation to root logger to avoid duplicate output
    lgr.propagate = False
    return lgr


class LoggerMiddleware(Middleware):
    """
    Logs every DoIP frame that passes through the chain.

    Config params:
        log_path (str):  Path for the log file.  Directory is created on startup.
        hex_dump (bool): If True, include a full hex dump of the raw packet bytes.
    """

    def __init__(self, log_path: str = "logs/doip.log", hex_dump: bool = True, **_):
        self.log_path = log_path
        self.hex_dump = hex_dump
        self._logger = _make_logger(log_path)

    async def process(
        self,
        pkt,
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ):
        try:
            ptype = _get_ptype(pkt)
            plen = _get_plen(pkt)

            type_hex = f"0x{ptype:04X}" if ptype is not None else "?"
            type_name = _PAYLOAD_TYPE_NAMES.get(ptype, "unknown") if ptype is not None else "?"
            len_str = str(plen) if plen is not None else "?"

            ts = datetime.now(tz=timezone.utc).isoformat()
            line = (
                f"{ts}  dir={direction}  "
                f"type={type_hex}({type_name})  len={len_str}"
            )

            if self.hex_dump:
                try:
                    raw = bytes(pkt)
                    hex_str = raw.hex(" ")
                    line += f"\n  hex: {hex_str}"
                except Exception:
                    pass

            self._logger.debug(line)
        except Exception:
            # LoggerMiddleware must never throw for a valid packet
            pass

        return pkt
