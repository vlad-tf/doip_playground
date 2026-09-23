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

No real socket needed: ``datagram_received`` dispatches to a stand-in transport
that just records ``sendto()`` calls — same spirit as ``conftest.Probe``
avoiding real sockets for dispatcher tests.  Vehicle Identification responses
are scheduled (A_DoIP_Announce_Wait, ISO 13400-2 DoIP-051), so those tests are
driven through ``run()``.
"""

from __future__ import annotations

import asyncio
import struct

from conftest import BASE_CONFIG, merge, run
from testecu.config import parse_config
from testecu.doip import (
    PT_ENTITY_STATUS_REQUEST,
    PT_ENTITY_STATUS_RESPONSE,
    PT_POWER_MODE_REQUEST,
    PT_POWER_MODE_RESPONSE,
    PT_VEHICLE_ID_REQUEST,
    PT_VEHICLE_ID_REQUEST_WITH_EID,
    PT_VEHICLE_ID_REQUEST_WITH_VIN,
    PT_VEHICLE_ID_RESPONSE,
    build_frame,
    payload as frame_payload,
    ptype as frame_ptype,
)
from testecu.udp import _UDPProtocol, _stagger_delay_ms, run_announcer


class _FakeTransport:
    def __init__(self) -> None:
        self.sent: list = []

    def sendto(self, data: bytes, addr) -> None:
        self.sent.append((data, addr))


def _protocol(extra=None) -> tuple:
    config = parse_config(merge(BASE_CONFIG, extra or {}))
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


def test_power_mode_info_request_gets_a_response():
    # ISO 13400-2 Table 12 / DoIP-116..118: the Diagnostic Power Mode info
    # request (0x4003) is sent over UDP (UDP_DISCOVERY) and must be answered
    # over UDP with 0x4004 carrying the configured power mode byte — it used
    # to be dropped by the UDP responder.
    protocol, transport = _protocol()
    protocol.datagram_received(build_frame(PT_POWER_MODE_REQUEST, b""), ADDR)

    assert len(transport.sent) == 1
    raw, addr = transport.sent[0]
    assert addr == ADDR
    assert frame_ptype(raw) == PT_POWER_MODE_RESPONSE
    assert frame_payload(raw) == b"\x01"            # power_mode (default config)


def test_vehicle_id_request_still_works():
    protocol, transport = _protocol({"udp": {"announce_wait_ms": 0}})

    async def scenario():
        protocol.datagram_received(build_frame(PT_VEHICLE_ID_REQUEST, b""), ADDR)
        await asyncio.sleep(0)
        assert len(transport.sent) == 1
        raw, addr = transport.sent[0]
        assert addr == ADDR
        assert frame_ptype(raw) == PT_VEHICLE_ID_RESPONSE

    run(scenario())


def test_identification_response_is_delayed_by_announce_wait():
    # ISO 13400-2 DoIP-051: the response is withheld for an A_DoIP_Announce_Wait
    # (0..announce_wait_ms) to avoid UDP bursts.  TestEcu derives that delay
    # deterministically from the requester, so the test can assert on the exact
    # value rather than just "some delay happened".
    wait_ms = 100
    delay_ms = _stagger_delay_ms(ADDR, wait_ms)
    assert 0 < delay_ms < wait_ms
    protocol, transport = _protocol({"udp": {"announce_wait_ms": wait_ms}})

    async def scenario():
        protocol.datagram_received(build_frame(PT_VEHICLE_ID_REQUEST, b""), ADDR)
        await asyncio.sleep(0)
        assert transport.sent == []                 # still inside the delay window
        await asyncio.sleep((delay_ms + 5) / 1000.0)
        assert len(transport.sent) == 1
        assert frame_ptype(transport.sent[0][0]) == PT_VEHICLE_ID_RESPONSE

    run(scenario())


def test_run_announcer_waits_before_first_announcement():
    # Regression test: the first startup Vehicle Announcement was going out
    # immediately, with no A_DoIP_Announce_Wait at all. ``run_announcer``
    # needs a real bound socket (unlike the ``_UDPProtocol``-only tests
    # above), so this one does bind one — on loopback/ephemeral port, best
    # effort like the function itself.
    wait_ms = 150
    seed_key = (BASE_CONFIG["doip"]["ecu_logical_addr"], BASE_CONFIG["doip"]["vin"])
    delay_ms = _stagger_delay_ms(seed_key, wait_ms)
    assert 0 < delay_ms < wait_ms

    config = parse_config(merge(BASE_CONFIG, {
        "udp": {"enabled": True, "announce_count": 1, "announce_wait_ms": wait_ms},
    }))

    async def scenario():
        task = asyncio.ensure_future(run_announcer(config))
        await asyncio.sleep((delay_ms - 30) / 1000.0)
        assert not task.done()                       # still inside the wait window
        await task                                    # completes once it sends
        assert task.done()

    run(scenario())


def test_eid_request_matching_responds():
    # DoIP-053: answer a Vehicle Identification Request with EID only when
    # the requested EID matches.
    protocol, transport = _protocol({"udp": {"announce_wait_ms": 0}})

    async def scenario():
        protocol.datagram_received(
            build_frame(PT_VEHICLE_ID_REQUEST_WITH_EID,
                        bytes.fromhex("AABBCCDDEEFF")), ADDR)
        await asyncio.sleep(0)
        assert len(transport.sent) == 1
        assert frame_ptype(transport.sent[0][0]) == PT_VEHICLE_ID_RESPONSE

    run(scenario())


def test_eid_request_not_matching_is_ignored():
    protocol, transport = _protocol({"udp": {"announce_wait_ms": 0}})

    async def scenario():
        protocol.datagram_received(
            build_frame(PT_VEHICLE_ID_REQUEST_WITH_EID,
                        bytes.fromhex("000000000000")), ADDR)
        await asyncio.sleep(0)
        assert transport.sent == []

    run(scenario())


def test_vin_request_matching_responds():
    # DoIP-052: answer a Vehicle Identification Request with VIN only when
    # the requested VIN matches.
    protocol, transport = _protocol({"udp": {"announce_wait_ms": 0}})

    async def scenario():
        protocol.datagram_received(
            build_frame(PT_VEHICLE_ID_REQUEST_WITH_VIN, b"1HGBH41JXMN109186"), ADDR)
        await asyncio.sleep(0)
        assert len(transport.sent) == 1
        assert frame_ptype(transport.sent[0][0]) == PT_VEHICLE_ID_RESPONSE

    run(scenario())


def test_vin_request_not_matching_is_ignored():
    protocol, transport = _protocol({"udp": {"announce_wait_ms": 0}})

    async def scenario():
        protocol.datagram_received(
            build_frame(PT_VEHICLE_ID_REQUEST_WITH_VIN, b"0" * 17), ADDR)
        await asyncio.sleep(0)
        assert transport.sent == []

    run(scenario())


def test_unknown_payload_type_is_ignored():
    protocol, transport = _protocol()
    protocol.datagram_received(build_frame(0x00FF, b""), ADDR)

    assert transport.sent == []


def test_short_datagram_is_ignored():
    protocol, transport = _protocol()
    protocol.datagram_received(b"\x02\xfd\x40", ADDR)

    assert transport.sent == []
