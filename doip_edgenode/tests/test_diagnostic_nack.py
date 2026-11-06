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

"""F05: local Diagnostic NACKs identify the sender and request originator."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from middleware import MiddlewareChain, DoIPFaultInjectionError
from middleware.address import AddressMiddleware
from session import DoIPProtocolError
from tests.test_routing_activation import activate, make_session
from tests.test_session import _diagnostic_message


def assert_nack(raw, node, tester, code):
    assert raw[:4] == b"\x02\xfd\x80\x03"
    assert int.from_bytes(raw[4:8], "big") == 5
    assert raw[8:10] == node.to_bytes(2, "big")
    assert raw[10:12] == tester.to_bytes(2, "big")
    assert raw[12:] == bytes([code])  # no optional previous-message data


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("source", [0x0E55, 0x0000])
def test_invalid_source_nack_addresses_the_actual_request_source(activated, source):
    async def scenario():
        session, writer, _ = make_session(False)
        session.config.doip.node_logical_addr = 0x4321
        try:
            if activated:
                await activate(session, 0x0E00)
            raw = _diagnostic_message(source, 0x9999)
            with pytest.raises(DoIPProtocolError):
                await session._dispatch(session._dissect(raw))
            assert_nack(writer.frames[-1], 0x4321, source, 0x02)
        finally:
            await session._cleanup()

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["unknown", "connect", "send", "middleware", "short"])
def test_local_failures_use_original_context_after_address_injection(failure):
    async def scenario():
        session, writer, _ = make_session(False)
        session.config.doip.node_logical_addr = 0x4321
        try:
            await activate(session, 0x0E00)
            session.middleware_chain = MiddlewareChain(
                [AddressMiddleware(src_override=0x0E55, tgt_override=0x9999)])
            raw = _diagnostic_message(0x0E00, 0x0001)
            if failure == "middleware":
                session.middleware_chain.run = AsyncMock(side_effect=DoIPFaultInjectionError(0x04))
            elif failure == "short":
                session.middleware_chain.run = AsyncMock(return_value=raw[:10])
            elif failure == "send":
                ecu = AsyncMock()
                ecu.send.side_effect = ConnectionResetError()
                session._ecu_conns[0x9999] = ecu
            elif failure == "connect":
                # Keep the configured route while still injecting a source.
                session.middleware_chain = MiddlewareChain([AddressMiddleware(src_override=0x0E55)])
            with patch("ecu_client.ECUConnection.connect", new_callable=AsyncMock,
                       side_effect=ConnectionRefusedError()) as connect:
                await asyncio.wait_for(session._dispatch(session._dissect(raw)), 1)
                assert connect.await_count == (1 if failure == "connect" else 0)
            code = {"unknown": 0x03, "connect": 0x06, "send": 0x06,
                    "middleware": 0x04, "short": 0x03}[failure]
            assert_nack(writer.frames[-1], 0x4321, 0x0E00, code)
        finally:
            await session._cleanup()

    asyncio.run(scenario())


def test_replay_connection_failure_has_injected_request_context():
    async def scenario():
        session, writer, _ = make_session(False)
        try:
            await activate(session, 0x0E00)
            raw = _diagnostic_message(0x0E55, 0x9999)
            await session.send_to_ecu(session._dissect(raw))
            assert_nack(writer.frames[-1], 0x1234, 0x0E55, 0x03)
        finally:
            await session._cleanup()

    asyncio.run(scenario())


def test_nack_without_complete_request_source_uses_header_error():
    async def scenario():
        session, writer, _ = make_session(False)
        try:
            with pytest.raises(DoIPProtocolError):
                await session._send_diag_nack(0x02, b"\x02\xfd\x80\x01\x00\x00\x00\x01\x0e")
            assert writer.frames[-1] == b"\x02\xfd\x00\x00\x00\x00\x00\x01\x04"
        finally:
            await session._cleanup()

    asyncio.run(scenario())
