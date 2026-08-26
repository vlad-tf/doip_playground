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
``_UDPProtocol.datagram_received`` against a fake transport.

No real socket needed: ``datagram_received`` is plain synchronous code, so a
stand-in transport that just records ``sendto()`` calls is enough — same
spirit as ``conftest.Probe`` avoiding real sockets for dispatcher tests.
"""

from __future__ import annotations

import struct

from conftest import BASE_CONFIG, merge
from testecu.config import parse_config
from testecu.doip import (
    PT_ENTITY_STATUS_REQUEST,
    PT_ENTITY_STATUS_RESPONSE,
    PT_VEHICLE_ID_REQUEST,
    PT_VEHICLE_ID_RESPONSE,
    build_frame,
    payload as frame_payload,
    ptype as frame_ptype,
)
from testecu.udp import _UDPProtocol


class _FakeTransport:
    def __init__(self) -> None:
        self.sent: list = []

    def sendto(self, data: bytes, addr) -> None:
        self.sent.append((data, addr))


def _protocol() -> tuple:
    config = parse_config(merge(BASE_CONFIG, {}))
    protocol = _UDPProtocol(config, if_index=0)
    transport = _FakeTransport()
    protocol.connection_made(transport)
    return protocol, transport


ADDR = ("::1", 54321, 0, 0)


def test_entity_status_request_gets_a_response():
    protocol, transport = _protocol()
    protocol.datagram_received(build_frame(PT_ENTITY_STATUS_REQUEST, b""), ADDR)

    assert len(transport.sent) == 1
    raw, addr = transport.sent[0]
    assert addr == ADDR
    assert frame_ptype(raw) == PT_ENTITY_STATUS_RESPONSE
    payload = frame_payload(raw)
    assert len(payload) == 7
    assert payload[0] == 0x01                        # node type (default config)
    assert struct.unpack("!I", payload[3:7])[0] == 4096


def test_vehicle_id_request_still_works():
    protocol, transport = _protocol()
    protocol.datagram_received(build_frame(PT_VEHICLE_ID_REQUEST, b""), ADDR)

    assert len(transport.sent) == 1
    raw, addr = transport.sent[0]
    assert addr == ADDR
    assert frame_ptype(raw) == PT_VEHICLE_ID_RESPONSE


def test_unknown_payload_type_is_ignored():
    protocol, transport = _protocol()
    protocol.datagram_received(build_frame(0x00FF, b""), ADDR)

    assert transport.sent == []


def test_short_datagram_is_ignored():
    protocol, transport = _protocol()
    protocol.datagram_received(b"\x02\xfd\x40", ADDR)

    assert transport.sent == []
