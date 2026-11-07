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

from middleware import Middleware, _strict_bool

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


# Product logging policy, not an ISO protocol limit.
_MAX_BYTES = 5 * 1024 * 1024
_BACKUP_COUNT = 3
_MAX_HEX_BYTES = 4096
_MAX_RECORD_BYTES = 16 * 1024
# Only live sinks are retained here; do not grow logging's global name registry.
_sinks: dict[str, tuple[logging.Logger, int]] = {}


def _sink_path(log_path: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(log_path)))


def _make_logger(log_path: str) -> logging.Logger:
    """Acquire one lease on a canonical path's rotating file + stream sink."""
    path = _sink_path(log_path)
    if path in _sinks:
        lgr, references = _sinks[path]
        _sinks[path] = (lgr, references + 1)
        return lgr
    lgr = logging.Logger(f"doip.{path}", logging.DEBUG)
    lgr.propagate = False
    log_dir = os.path.dirname(path)
    os.makedirs(log_dir, exist_ok=True)
    handlers: list[logging.Handler] = []
    try:
        handlers.append(logging.handlers.RotatingFileHandler(
            path, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8"
        ))
        handlers.append(logging.StreamHandler())
        fmt = logging.Formatter("%(message)s")
        for handler in handlers:
            handler.setFormatter(fmt)
            lgr.addHandler(handler)
    except BaseException:
        for handler in handlers:
            lgr.removeHandler(handler)
            handler.close()
        raise
    _sinks[path] = (lgr, 1)
    return lgr


def _release_logger(path: str, lgr: logging.Logger) -> None:
    current = _sinks.get(path)
    if current is None or current[0] is not lgr:
        return
    if current[1] > 1:
        _sinks[path] = (lgr, current[1] - 1)
        return
    del _sinks[path]
    for handler in list(lgr.handlers):
        lgr.removeHandler(handler)
        handler.close()


class LogSinkOwner:
    """One server's leases; session middleware borrows without acquiring refs.

    Construction and shutdown run synchronously on the server's event-loop
    thread. This registry is not a cross-thread or multiprocess logging service.
    """

    def __init__(self) -> None:
        self._loggers: dict[str, logging.Logger] = {}
        self._closed = False

    def acquire(self, log_path: str) -> logging.Logger:
        if self._closed:
            raise RuntimeError("log sink owner is closed")
        path = _sink_path(log_path)
        if path not in self._loggers:
            self._loggers[path] = _make_logger(path)
        return self._loggers[path]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        loggers, self._loggers = self._loggers, {}
        for path, lgr in loggers.items():
            _release_logger(path, lgr)


class LoggerMiddleware(Middleware):
    """
    Logs every DoIP frame that passes through the chain.

    Config params:
        log_path (str):  Path for the log file.  Directory is created on startup.
        hex_dump (bool): If True, include up to 4096 raw bytes, marking truncation.

    Standalone users must call close(); server-created instances borrow sinks
    released by server shutdown. Rotation retains three 5 MiB backups; records
    are capped at 16 KiB. Serialization still builds bytes(pkt), so this is not
    a total CPU/allocation/output-rate bound.
    """

    def __init__(self, log_path: str = "logs/doip.log", hex_dump: bool = True,
                 *, _sink_owner: LogSinkOwner | None = None,
                 _open_sink: bool = True, **_):
        if not isinstance(log_path, str) or not log_path.strip():
            raise ValueError("log_path must be a non-empty string")
        self.log_path = log_path
        self.hex_dump = _strict_bool(hex_dump, "hex_dump")
        self._closed = False
        self._owns_sink = _open_sink and _sink_owner is None
        self._sink_path = _sink_path(log_path)
        self._logger = None
        if _open_sink:
            self._logger = (_make_logger(log_path) if _sink_owner is None
                            else _sink_owner.acquire(log_path))

    def close(self) -> None:
        """Release standalone ownership only; a session cannot close its server sink."""
        if self._closed:
            return
        self._closed = True
        if self._owns_sink and self._logger is not None:
            _release_logger(self._sink_path, self._logger)

    async def process(
        self,
        pkt,
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ):
        if self._closed or self._logger is None or not self._logger.handlers:
            return pkt
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
                    hex_str = raw[:_MAX_HEX_BYTES].hex(" ")
                    line += f"\n  hex: {hex_str}"
                    if len(raw) > _MAX_HEX_BYTES:
                        line += f" ... [truncated; {len(raw)} total bytes]"
                except Exception:
                    pass

            # Bound UTF-8 records as well as hex output (including unusual fields).
            encoded = line.encode("utf-8")
            if len(encoded) > _MAX_RECORD_BYTES:
                line = encoded[:_MAX_RECORD_BYTES - 32].decode("utf-8", errors="ignore")
                line += " ... [record truncated]"
            self._logger.debug(line)
        except Exception:
            # LoggerMiddleware must never throw for a valid packet
            pass

        return pkt
