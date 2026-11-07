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

"""Raw-frame tests for the EdgeNode UDP discovery protocol (F13)."""

from __future__ import annotations

import asyncio
import os
import struct
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from udp_announcer import _UDPProtocol  # noqa: E402
from tests.test_session import _make_app_config  # noqa: E402

DISCOVERY = 0x0001
DISCOVERY_EID = 0x0002
DISCOVERY_VIN = 0x0003
VEHICLE_ID = 0x0004
HEADER_NACK = 0x0000
ENTITY_STATUS_REQ = 0x4001
ENTITY_STATUS_RES = 0x4002
POWER_MODE_REQ = 0x4003
POWER_MODE_RES = 0x4004
NACK_INVALID_HEADER = 0x00
NACK_UNKNOWN_PAYLOAD = 0x01
NACK_TOO_LARGE = 0x02
NACK_INVALID_PAYLOAD = 0x04
ADDR = ("192.0.2.44", 49152)


def frame(pt: int, payload: bytes = b"", version: int = 2,
          inverse: int | None = None, declared: int | None = None) -> bytes:
    inverse = (0xFF ^ version) if inverse is None else inverse
    size = len(payload) if declared is None else declared
    return bytes((version, inverse)) + struct.pack("!HI", pt, size) + payload


def _make_immediate(proto: _UDPProtocol) -> _UDPProtocol:
    """Keep legacy raw-frame assertions synchronous; policy tests cover timers."""
    proto._schedule_discovery = lambda addr: proto._send(
        VEHICLE_ID, proto._payload, addr)
    return proto


def protocol(power_mode: int = 1) -> tuple[_UDPProtocol, MagicMock]:
    config = _make_app_config()
    config.doip.power_mode = power_mode
    transport = MagicMock()
    proto = _make_immediate(_UDPProtocol(config))
    proto.connection_made(transport)
    return proto, transport


def sent(transport: MagicMock) -> bytes:
    assert transport.sendto.call_count == 1
    return transport.sendto.call_args.args[0]


def sent_type_payload(transport: MagicMock) -> tuple[int, bytes]:
    data = sent(transport)
    assert data[:2] == b"\x02\xfd"
    assert data[4:8] == len(data[8:]).to_bytes(4, "big")
    return int.from_bytes(data[2:4], "big"), data[8:]


def assert_nack(transport: MagicMock, code: int) -> None:
    assert sent_type_payload(transport) == (HEADER_NACK, bytes((code,)))


def test_discovery_requests_versions_and_response_header() -> None:
    config = _make_app_config()
    requests = ((DISCOVERY, b""), (DISCOVERY_EID, bytes.fromhex(config.doip.eid)),
                (DISCOVERY_VIN, config.doip.vin.encode("ascii")))
    for version in (2, 3, 0xFF):
        for payload_type, payload in requests:
            proto, transport = protocol()
            proto.datagram_received(frame(payload_type, payload, version), ADDR)
            assert sent_type_payload(transport) == (VEHICLE_ID, proto._payload)
            assert transport.sendto.call_args.args[1] == ADDR


def test_discovery_mismatches_are_silent() -> None:
    config = _make_app_config()
    cases = ((DISCOVERY_EID, b"X" * 6), (DISCOVERY_VIN, b"X" * 17))
    for payload_type, payload in cases:
        proto, transport = protocol()
        proto.datagram_received(frame(payload_type, payload), ADDR)
        transport.sendto.assert_not_called()


def test_discovery_response_is_exact_33_bytes_with_configured_fields() -> None:
    config = _make_app_config()
    config.doip.gid = "112233445566"
    proto = _make_immediate(_UDPProtocol(config))
    transport = MagicMock()
    proto.connection_made(transport)
    proto.datagram_received(frame(DISCOVERY), ADDR)
    payload_type, payload = sent_type_payload(transport)
    assert payload_type == VEHICLE_ID
    assert len(payload) == 33
    assert payload[:17] == config.doip.vin.encode("ascii")
    assert payload[17:19] == config.doip.node_logical_addr.to_bytes(2, "big")
    assert payload[19:25] == bytes.fromhex(config.doip.eid)
    assert payload[25:31] == bytes.fromhex(config.doip.gid)
    assert payload[31:33] == b"\x00\x00"


def test_discovery_request_lengths_are_strict() -> None:
    config = _make_app_config()
    cases = ((DISCOVERY, b"X"),
             (DISCOVERY_EID, bytes.fromhex(config.doip.eid) + b"X"),
             (DISCOVERY_VIN, config.doip.vin.encode() + b"X"))
    for payload_type, payload in cases:
        proto, transport = protocol()
        proto.datagram_received(frame(payload_type, payload), ADDR)
        assert_nack(transport, NACK_INVALID_PAYLOAD)


def test_default_ff_version_is_only_for_discovery_requests() -> None:
    for payload_type, payload in ((POWER_MODE_REQ, b""), (VEHICLE_ID, b"A" * 33)):
        proto, transport = protocol()
        proto.datagram_received(frame(payload_type, payload, version=0xFF), ADDR)
        assert_nack(transport, NACK_INVALID_HEADER)


def test_power_mode_response_is_one_configured_byte() -> None:
    for mode in (0, 1, 2):
        proto, transport = protocol(mode)
        proto.datagram_received(frame(POWER_MODE_REQ), ADDR)
        assert sent_type_payload(transport) == (POWER_MODE_RES, bytes((mode,)))


def test_power_mode_nonempty_payload_is_invalid() -> None:
    proto, transport = protocol()
    proto.datagram_received(frame(POWER_MODE_REQ, b"X"), ADDR)
    assert_nack(transport, NACK_INVALID_PAYLOAD)


def test_response_and_other_non_discovery_types_are_unsupported() -> None:
    for payload_type in (ENTITY_STATUS_RES, POWER_MODE_RES,
                         0x0005, 0x0006, 0x0007, 0x0008, 0x8001, 0x8002, 0x8003,
                         0x1234):
        proto, transport = protocol()
        proto.datagram_received(frame(payload_type, b"", declared=999999), ADDR)
        assert_nack(transport, NACK_UNKNOWN_PAYLOAD)


def test_valid_received_responses_and_generic_nack_are_ignored() -> None:
    for payload in (b"A" * 32, b"A" * 33):
        proto, transport = protocol()
        proto.datagram_received(frame(VEHICLE_ID, payload), ADDR)
        transport.sendto.assert_not_called()
    proto, transport = protocol()
    proto.datagram_received(frame(HEADER_NACK, b"\x01"), ADDR)
    transport.sendto.assert_not_called()


def test_mismatched_vehicle_id_response_is_invalid_payload() -> None:
    proto, transport = protocol()
    proto.datagram_received(frame(VEHICLE_ID, b"X" * 34), ADDR)
    assert_nack(transport, NACK_INVALID_PAYLOAD)


def test_malformed_known_frames_are_checked_before_ignore() -> None:
    for payload_type, payload in ((VEHICLE_ID, b"A" * 31),
                                  (HEADER_NACK, b""), (HEADER_NACK, b"\x00\x01")):
        proto, transport = protocol()
        proto.datagram_received(frame(payload_type, payload), ADDR)
        assert_nack(transport, NACK_INVALID_PAYLOAD)


def test_header_errors_and_precedence() -> None:
    cases = ((frame(DISCOVERY, b"", version=1), NACK_INVALID_HEADER),
             (frame(DISCOVERY, b"", inverse=0), NACK_INVALID_HEADER),
             (frame(0x9999, b"", version=0xFF), NACK_INVALID_HEADER),
             (frame(0x9999, b"", declared=999999), NACK_UNKNOWN_PAYLOAD),
             (frame(DISCOVERY, b"", declared=4097), NACK_TOO_LARGE),
             (frame(DISCOVERY, b"", declared=1), NACK_INVALID_PAYLOAD))
    for data, code in cases:
        proto, transport = protocol()
        proto.datagram_received(data, ADDR)
        assert_nack(transport, code)


def test_datagram_boundaries_and_short_datagrams() -> None:
    config = _make_app_config()
    valid_eid = frame(DISCOVERY_EID, bytes.fromhex(config.doip.eid))
    for data in (b"", b"1234567", valid_eid[:-1], frame(DISCOVERY) + b"extra",
                 frame(DISCOVERY) + frame(DISCOVERY)):
        proto, transport = protocol()
        proto.datagram_received(data, ADDR)
        if len(data) < 8:
            transport.sendto.assert_not_called()
        else:
            assert_nack(transport, NACK_INVALID_PAYLOAD)


def test_configured_payload_cap_precedes_body_and_fixed_shape_validation() -> None:
    config = _make_app_config()
    config.doip.max_payload_bytes = 6
    proto = _make_immediate(_UDPProtocol(config))
    transport = MagicMock()
    proto.connection_made(transport)
    proto.datagram_received(frame(DISCOVERY_EID, bytes.fromhex(config.doip.eid)), ADDR)
    assert sent_type_payload(transport) == (VEHICLE_ID, proto._payload)

    proto, transport = protocol()
    proto._config.doip.max_payload_bytes = 6
    proto.datagram_received(frame(DISCOVERY_VIN, b"", declared=17), ADDR)
    assert_nack(transport, NACK_TOO_LARGE)
    proto, transport = protocol()
    proto._config.doip.max_payload_bytes = 6
    proto.datagram_received(frame(DISCOVERY_EID, b"X" * 5, declared=5), ADDR)
    assert_nack(transport, NACK_INVALID_PAYLOAD)


def test_bad_then_good_request_keeps_shared_transport_open() -> None:
    proto, transport = protocol()
    proto.datagram_received(frame(POWER_MODE_REQ, b"bad"), ADDR)
    assert_nack(transport, NACK_INVALID_PAYLOAD)
    proto.datagram_received(frame(DISCOVERY), ADDR)
    assert transport.sendto.call_count == 2
    transport.close.assert_not_called()


def test_transport_lifecycle_and_send_errors_are_contained(caplog: pytest.LogCaptureFixture) -> None:
    proto = _make_immediate(_UDPProtocol(_make_app_config()))
    transport = MagicMock()
    proto.connection_made(transport)
    transport.sendto.side_effect = OSError("closed")
    proto.datagram_received(frame(DISCOVERY), ADDR)
    assert "closed" in caplog.text
    proto.error_received(OSError("socket error"))
    assert "socket error" in caplog.text
    proto.connection_lost(None)
    proto.datagram_received(frame(DISCOVERY), ADDR)
    transport.sendto.assert_called_once()


def test_real_asyncio_loopback_handles_bad_then_healthy_request() -> None:
    async def exercise() -> None:
        loop = asyncio.get_running_loop()
        config = _make_app_config()
        queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue()

        class Client(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                queue.put_nowait((data, addr))

        server_transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(config), local_addr=("127.0.0.1", 0))
        client_transport = None
        try:
            try:
                client_transport, _ = await loop.create_datagram_endpoint(
                    Client, local_addr=("127.0.0.1", 0))
            except Exception:
                server_transport.close()
                await asyncio.sleep(0)
                raise
            server_addr = server_transport.get_extra_info("sockname")
            client_transport.sendto(frame(POWER_MODE_REQ, b"x"), server_addr)
            bad, _ = await asyncio.wait_for(queue.get(), timeout=1.0)
            assert bad == frame(HEADER_NACK, bytes((NACK_INVALID_PAYLOAD,)))
            client_transport.sendto(frame(POWER_MODE_REQ), server_addr)
            good, _ = await asyncio.wait_for(queue.get(), timeout=1.0)
            assert good == frame(POWER_MODE_RES, b"\x01")
            client_transport.sendto(frame(DISCOVERY), server_addr)
            discovery, _ = await asyncio.wait_for(queue.get(), timeout=1.0)
            assert int.from_bytes(discovery[2:4], "big") == VEHICLE_ID
            assert discovery[8:] == _UDPProtocol(config)._payload
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(queue.get(), timeout=0.05)
        finally:
            if client_transport is not None:
                client_transport.close()
            server_transport.close()
            await asyncio.sleep(0)

    asyncio.run(exercise())
