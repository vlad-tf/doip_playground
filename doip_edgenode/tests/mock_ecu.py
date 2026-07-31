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
DoIP EdgeNode — Minimal DoIP ECU stub for unit tests.

Runs on loopback (127.0.0.1:0 — ephemeral port so tests can run in
parallel without port conflicts).

Handles:
  - Routing Activation Request  → responds 0x10 (success)
  - Diagnostic Message           → echoes back with Positive ACK
  - Alive Check Request          → responds with Alive Check Response

Does not require Scapy; uses raw bytes so tests run without root or
special capabilities.

Usage:
    ecu = MockECU()
    server = await ecu.start()        # returns asyncio.Server
    port = ecu.port                   # actual bound port
    ...
    await ecu.stop()
"""

from __future__ import annotations

import asyncio
import struct
from typing import Optional

# ---------------------------------------------------------------------------
# DoIP frame helpers (pure bytes — no Scapy dependency)
# ---------------------------------------------------------------------------

DOIP_HDR_LEN = 8
_VER = 0x02
_INV_VER = 0xFF ^ _VER

# Payload types
PT_HEADER_NACK             = 0x0000
PT_ROUTING_ACT_REQUEST     = 0x0005
PT_ROUTING_ACT_RESPONSE    = 0x0006
PT_ALIVE_CHECK_REQUEST     = 0x0007
PT_ALIVE_CHECK_RESPONSE    = 0x0008
PT_DIAGNOSTIC_MESSAGE      = 0x8001
PT_DIAGNOSTIC_POSITIVE_ACK = 0x8002
PT_DIAGNOSTIC_NEGATIVE_ACK = 0x8003


def _build(payload_type: int, payload: bytes) -> bytes:
    hdr = struct.pack(
        "!BBHI",
        _VER, _INV_VER,
        payload_type,
        len(payload),
    )
    return hdr + payload


async def _read_frame(reader: asyncio.StreamReader) -> bytes:
    """Read one complete DoIP frame from a StreamReader."""
    hdr = await reader.readexactly(DOIP_HDR_LEN)
    payload_len = struct.unpack("!I", hdr[4:8])[0]
    if payload_len == 0:
        return hdr
    payload = await reader.readexactly(payload_len)
    return hdr + payload


def _ptype(raw: bytes) -> int:
    return struct.unpack("!H", raw[2:4])[0]


# ---------------------------------------------------------------------------
# MockECU
# ---------------------------------------------------------------------------


class MockECU:
    """Minimal DoIP ECU stub.  Runs on loopback; no Scapy required."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._host = host
        self._port = port          # 0 = let the OS pick an ephemeral port
        self._server: asyncio.Server | None = None
        self.received_packets: list[bytes] = []
        self.sent_packets: list[bytes] = []

    @property
    def port(self) -> int:
        """Actual bound port (valid after start() returns)."""
        if self._server is None:
            raise RuntimeError("MockECU not started")
        return self._server.sockets[0].getsockname()[1]

    async def start(self) -> asyncio.Server:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._host,
            port=self._port,
        )
        return self._server

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            while True:
                raw = await _read_frame(reader)
                self.received_packets.append(raw)

                pt = _ptype(raw)

                if pt == PT_ROUTING_ACT_REQUEST:
                    # Parse source address (bytes 8-9 of the full frame)
                    src_addr = struct.unpack("!H", raw[8:10])[0]
                    # Routing Activation Response: success (0x10)
                    resp_payload = (
                        struct.pack("!H", src_addr)   # tester logical addr
                        + b"\x00\x00"                  # EdgeNode logical addr
                        + bytes([0x10])                # response code: success
                        + b"\x00" * 4                  # reserved
                        + b"\x00" * 4                  # OEM-specific
                    )
                    resp = _build(PT_ROUTING_ACT_RESPONSE, resp_payload)
                    self.sent_packets.append(resp)
                    writer.write(resp)
                    await writer.drain()

                elif pt == PT_DIAGNOSTIC_MESSAGE:
                    # Positive ACK: mirror source/target addresses
                    if len(raw) >= 12:
                        src = raw[8:10]
                        tgt = raw[10:12]
                    else:
                        src = b"\x00\x00"
                        tgt = b"\x00\x00"
                    ack_payload = src + tgt + bytes([0x00])  # NACK code 0 = success
                    resp = _build(PT_DIAGNOSTIC_POSITIVE_ACK, ack_payload)
                    self.sent_packets.append(resp)
                    writer.write(resp)
                    await writer.drain()

                elif pt == PT_ALIVE_CHECK_REQUEST:
                    resp = _build(PT_ALIVE_CHECK_RESPONSE, b"")
                    self.sent_packets.append(resp)
                    writer.write(resp)
                    await writer.drain()

                # All other types: ignore silently
        except asyncio.IncompleteReadError:
            pass
        except ConnectionResetError:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
