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

"""F04: validate original diagnostic SA before local/routed processing."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from middleware import MiddlewareChain
from middleware.address import AddressMiddleware
from session import DoIPProtocolError
from tests.test_routing_activation import activate, make_session
from tests.test_session import _diagnostic_message, _routing_activation_request


@pytest.mark.parametrize("target", [0x1234, 0x0001, 0x9999])
@pytest.mark.parametrize("spoofed_source", [0x0E01, 0x0000])
def test_spoofed_diagnostic_is_rejected_before_any_processing(target, spoofed_source):
    async def scenario():
        session, writer, registry = make_session(True)
        try:
            await activate(session, 0x0E00)
            session.middleware_chain.run = AsyncMock(side_effect=AssertionError("middleware reached"))
            session._handle_self_diagnostic = AsyncMock(side_effect=AssertionError("local handler reached"))
            session._connect_to_ecu = AsyncMock(side_effect=AssertionError("ECU connect reached"))
            ecu = AsyncMock()
            session._ecu_conns[0x0001] = ecu
            packet = session._dissect(_diagnostic_message(spoofed_source, target))
            with pytest.raises(DoIPProtocolError):
                await session._dispatch(packet)
            raw = writer.frames[-1]
            assert raw[:4] == b"\x02\xfd\x80\x03"
            assert int.from_bytes(raw[4:8], "big") == len(raw) - 8
            assert raw[12] == 0x02
            assert len(writer.frames) == 2  # RA + NACK, no ACK/UDS response
            session.middleware_chain.run.assert_not_awaited()
            session._handle_self_diagnostic.assert_not_awaited()
            session._connect_to_ecu.assert_not_awaited()
            ecu.send.assert_not_awaited()
            assert session.tester_logical_addr == 0x0E00
            assert registry.lookup(0x0E00) is session
        finally:
            await session._cleanup()
        assert registry.count() == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("target", [0x1234, 0x0001])
def test_session_run_closes_and_unregisters_after_spoofed_diagnostic(target):
    async def scenario():
        session, writer, registry = make_session(True)
        session.middleware_chain.run = AsyncMock(side_effect=AssertionError("middleware reached"))
        session._connect_to_ecu = AsyncMock(side_effect=AssertionError("ECU connect reached"))
        session.reader.feed_data(_routing_activation_request(0x0E00))
        session.reader.feed_data(_diagnostic_message(0x0E01, target))
        session.reader.feed_eof()
        await asyncio.wait_for(session.run(), 1)
        assert writer.closed
        assert registry.count() == 0
        assert len(writer.frames) == 2
        assert writer.frames[-1][2:4] == b"\x80\x03"
        assert writer.frames[-1][12] == 0x02
        session.middleware_chain.run.assert_not_awaited()
        session._connect_to_ecu.assert_not_awaited()

    asyncio.run(scenario())


def test_matching_source_self_diagnostic_still_returns_ack_and_vin():
    async def scenario():
        session, writer, _ = make_session(False)
        try:
            await activate(session, 0x0E00)
            request = _diagnostic_message(0x0E00, 0x1234, b"\x22\xf1\x90")
            await session._dispatch(session._dissect(request))
            assert writer.frames[1][2:4] == b"\x80\x02"
            assert writer.frames[1][8:13] == b"\x12\x34\x0e\x00\x00"
            assert writer.frames[2][2:4] == b"\x80\x01"
            assert writer.frames[2][8:12] == b"\x12\x34\x0e\x00"
            assert writer.frames[2][12:] == b"\x62\xf1\x90" + session.config.doip.vin.encode("ascii")
        finally:
            await session._cleanup()

    asyncio.run(scenario())


@pytest.mark.parametrize("override", [False, True])
def test_valid_wire_source_can_be_rewritten_by_address_fault_injection(override):
    async def scenario():
        session, writer, _ = make_session(False)
        ecu = AsyncMock()
        try:
            await activate(session, 0x0E00)
            session.middleware_chain = MiddlewareChain(
                [AddressMiddleware(src_override=0x0E55, tgt_override=0x0002)] if override else [])
            route_target = 0x0002 if override else 0x0001
            session._connect_to_ecu = AsyncMock(return_value=ecu)
            ecu.recv.return_value = session._build_frame(0x8003, b"\x00\x01\x0e\x00\x03")
            raw = _diagnostic_message(0x0E00, 0x0001)
            await asyncio.wait_for(session._dispatch(session._dissect(raw)), 1)
            session._connect_to_ecu.assert_awaited_once_with(route_target, raw)
            sent = ecu.send.await_args.args[0]
            assert int.from_bytes(sent[8:10], "big") == (0x0E55 if override else 0x0E00)
            assert int.from_bytes(sent[10:12], "big") == route_target
            assert session.tester_logical_addr == 0x0E00
            assert len(writer.frames) == 2  # RA and relayed ECU NACK
        finally:
            await session._cleanup()

    asyncio.run(scenario())
