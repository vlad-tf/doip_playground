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

import pytest

from conftest import BASE_CONFIG, merge, run
from testecu.config import parse_config
from testecu.doip import (
    PT_ENTITY_STATUS_REQUEST,
    PT_ENTITY_STATUS_RESPONSE,
    PT_HEADER_NACK,
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
import testecu.udp as udp_module
from testecu.udp import _UDPProtocol, _stagger_delay_ms, run_announcer


class _FakeTransport:
    def __init__(self) -> None:
        self.sent: list = []

    def sendto(self, data: bytes, addr) -> None:
        self.sent.append((data, addr))


def _protocol(extra=None, registry=None, max_sockets=1) -> tuple:
    config = parse_config(merge(BASE_CONFIG, extra or {}))
    protocol = _UDPProtocol(config, if_index=0, registry=registry, max_sockets=max_sockets)
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


def test_entity_status_reports_zero_open_sockets_with_no_registry():
    # Default (no registry passed) — the previous, still-supported behaviour
    # for a standalone _UDPProtocol.
    protocol, transport = _protocol(registry=None, max_sockets=5)
    protocol.datagram_received(build_frame(PT_ENTITY_STATUS_REQUEST, b""), ADDR)
    payload = frame_payload(transport.sent[0][0])
    assert payload[1] == 5      # max sockets: the configured backlog
    assert payload[2] == 0      # open sockets: no registry to count against


def test_entity_status_reports_the_live_registry_size():
    # SessionRegistry compares by identity only (see test_session_registry.py),
    # so plain object() sentinels work as stand-in sessions -- no real socket
    # or Routing Activation needed to populate it.
    from testecu.session import SessionRegistry

    registry = SessionRegistry()
    registry.register(0x0E00, object())
    registry.register(0x0E01, object())

    protocol, transport = _protocol(registry=registry, max_sockets=8)
    protocol.datagram_received(build_frame(PT_ENTITY_STATUS_REQUEST, b""), ADDR)
    payload = frame_payload(transport.sent[0][0])
    assert payload[1] == 8      # max sockets: the configured backlog
    assert payload[2] == 2      # open sockets: len(registry)


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
    #
    # ``run_announcer`` runs until cancelled (see
    # ``test_run_announcer_closes_the_transport_on_cancellation`` below) —
    # it no longer returns on its own once the startup announcements are
    # sent, so this test cancels it once it has confirmed the wait/send
    # behaviour rather than awaiting completion.
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
        await asyncio.sleep((delay_ms + 30) / 1000.0)
        assert not task.done()                        # sent, now waiting to be cancelled
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(scenario())


def test_run_announcer_closes_the_transport_on_cancellation():
    """
    Regression test: ``run_announcer`` used to return right after sending the
    startup announcements. The UDP socket kept working only because the
    event loop held a reference to the transport through its reader
    callback -- nothing in the code closed it. ``TestEcuServer.stop()``
    cancels this task to shut down; before this fix that cancelled a task
    that had already finished, so the socket was never closed (one leaked
    bound socket per start/stop cycle).

    ``_UDPProtocol`` is swapped for a capturing subclass for the duration of
    this test so the transport it receives in ``connection_made`` can be
    inspected -- ``run_announcer`` does not otherwise hand it back to the
    caller.
    """
    created = []

    class _CapturingProtocol(udp_module._UDPProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)

    config = parse_config(merge(BASE_CONFIG, {
        "udp": {"enabled": True, "announce_count": 1, "announce_wait_ms": 0},
    }))

    original = udp_module._UDPProtocol
    udp_module._UDPProtocol = _CapturingProtocol
    try:
        async def scenario():
            task = asyncio.ensure_future(udp_module.run_announcer(config))
            # Give it time to bind, announce, and reach the "run until
            # cancelled" wait -- at that point it must still be open.
            await asyncio.sleep(0.05)
            assert len(created) == 1
            transport = created[0]._transport
            assert transport is not None
            assert not transport.is_closing()

            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert transport.is_closing()

        run(scenario())
    finally:
        udp_module._UDPProtocol = original


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


def test_unknown_payload_type_gets_a_header_nack():
    # Architecture roadmap P4: previously silently ignored; now shares
    # session.py's Header NACK behaviour via ``validate_header``.
    protocol, transport = _protocol()
    protocol.datagram_received(build_frame(0x00FF, b""), ADDR)

    assert len(transport.sent) == 1
    data, addr = transport.sent[0]
    assert struct.unpack("!H", data[2:4])[0] == PT_HEADER_NACK
    assert data[8:] == b"\x01"
    assert addr == ADDR


def test_bad_version_inverse_gets_a_header_nack_0x00():
    protocol, transport = _protocol()
    # A real version paired with the wrong inverse -- Table 2's basic check.
    bad = struct.pack("!BBHI", 0x02, 0x02, PT_ENTITY_STATUS_REQUEST, 0)
    protocol.datagram_received(bad, ADDR)

    assert len(transport.sent) == 1
    data, addr = transport.sent[0]
    assert struct.unpack("!H", data[2:4])[0] == PT_HEADER_NACK
    assert data[8:] == b"\x00"


def test_unsupported_version_gets_a_header_nack_0x00():
    protocol, transport = _protocol()
    # 0x01 is a well-formed version/inverse pair, just not one this entity
    # accepts (ACCEPTED_VERSIONS is (0x02, 0x03)), and Entity Status is not
    # one of the payload types the 0xFF wildcard carve-out applies to anyway.
    bad = struct.pack("!BBHI", 0x01, 0xFE, PT_ENTITY_STATUS_REQUEST, 0)
    protocol.datagram_received(bad, ADDR)

    assert len(transport.sent) == 1
    data, addr = transport.sent[0]
    assert struct.unpack("!H", data[2:4])[0] == PT_HEADER_NACK
    assert data[8:] == b"\x00"


def test_version_0xff_wildcard_is_accepted_for_vehicle_id_request():
    # ISO 13400-2 Figure 8: a Vehicle Identification Request may use protocol
    # version 0xFF ("not yet known") -- must NOT be Header-NACKed. The
    # matching identification response is scheduled (A_DoIP_Announce_Wait),
    # so this needs a running loop like the other VIR-matching tests.
    protocol, transport = _protocol({"udp": {"announce_wait_ms": 0}})
    frame = struct.pack("!BBHI", 0xFF, 0x00, PT_VEHICLE_ID_REQUEST, 0)

    async def scenario():
        protocol.datagram_received(frame, ADDR)
        await asyncio.sleep(0)
        assert len(transport.sent) == 1
        data, addr = transport.sent[0]
        # Answered as a normal Vehicle Identification Response, not a NACK.
        assert struct.unpack("!H", data[2:4])[0] == PT_VEHICLE_ID_RESPONSE

    run(scenario())


def test_version_0xff_wildcard_is_rejected_for_entity_status():
    # The wildcard is VIR-specific -- Entity Status must still be denied.
    protocol, transport = _protocol()
    frame = struct.pack("!BBHI", 0xFF, 0x00, PT_ENTITY_STATUS_REQUEST, 0)
    protocol.datagram_received(frame, ADDR)

    assert len(transport.sent) == 1
    data, addr = transport.sent[0]
    assert struct.unpack("!H", data[2:4])[0] == PT_HEADER_NACK
    assert data[8:] == b"\x00"


def test_short_datagram_is_ignored():
    protocol, transport = _protocol()
    protocol.datagram_received(b"\x02\xfd\x40", ADDR)

    assert transport.sent == []
