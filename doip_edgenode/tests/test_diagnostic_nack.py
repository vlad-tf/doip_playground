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

"""F05: local Diagnostic NACKs swap the original request's addresses."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from middleware import MiddlewareChain, DoIPFaultInjectionError
from middleware.address import AddressMiddleware
from session import DoIPProtocolError
from tests.test_routing_activation import activate, make_session
from tests.test_session import _diagnostic_message


def assert_nack(raw, target, tester, code):
    assert raw[:4] == b"\x02\xfd\x80\x03"
    assert int.from_bytes(raw[4:8], "big") == 5
    assert raw[8:10] == target.to_bytes(2, "big")
    assert raw[10:12] == tester.to_bytes(2, "big")
    assert raw[12:] == bytes([code])  # no optional previous-message data


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("source", [0x0E55, 0x0000])
@pytest.mark.parametrize("target", [0x4321, 0x0001, 0x9999])
def test_invalid_source_nack_swaps_actual_request_addresses(activated, source, target):
    async def scenario():
        session, writer, _ = make_session(False)
        session.config.doip.node_logical_addr = 0x4321
        try:
            if activated:
                await activate(session, 0x0E00)
            raw = _diagnostic_message(source, target)
            with pytest.raises(DoIPProtocolError):
                await session._dispatch(session._dissect(raw))
            assert_nack(writer.frames[-1], target, source, 0x02)
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
            assert_nack(writer.frames[-1], 0x0001, 0x0E00, code)
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
            assert_nack(writer.frames[-1], 0x9999, 0x0E55, 0x03)
        finally:
            await session._cleanup()

    asyncio.run(scenario())


@pytest.mark.parametrize("address_bytes", [b"", b"\x0e", b"\x0e\x00", b"\x0e\x00\x99"])
def test_nack_without_complete_request_addresses_uses_header_error(address_bytes):
    async def scenario():
        session, writer, _ = make_session(False)
        try:
            raw = session._build_frame(0x8001, address_bytes)
            with pytest.raises(DoIPProtocolError):
                await session._send_diag_nack(0x02, raw)
            assert writer.frames == [b"\x02\xfd\x00\x00\x00\x00\x00\x01\x04"]
        finally:
            await session._cleanup()

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["recv", "timeout"])
def test_exchange_failure_nack_uses_original_addresses(failure):
    async def scenario():
        session, writer, _ = make_session(False)
        ecu = AsyncMock()
        try:
            await activate(session, 0x0E00)
            session.config.timers.ecu_response_timeout_s = 0.01
            session.middleware_chain = MiddlewareChain(
                [AddressMiddleware(src_override=0x0E55, tgt_override=0x9999)])
            session._ecu_conns[0x9999] = ecu
            if failure == "recv":
                ecu.recv.side_effect = ConnectionResetError()
            else:
                async def no_response():
                    await asyncio.Event().wait()
                ecu.recv.side_effect = no_response
            raw = _diagnostic_message(0x0E00, 0x0001)
            await asyncio.wait_for(session._dispatch(session._dissect(raw)), 1)
            assert_nack(writer.frames[-1], 0x0001, 0x0E00, 0x06)
            assert len(writer.frames) == 2
            assert 0x9999 not in session._ecu_conns
            ecu.close.assert_awaited_once()
        finally:
            await session._cleanup()

    asyncio.run(scenario())


def test_unknown_target_nack_preserves_unknown_address():
    async def scenario():
        session, writer, _ = make_session(False)
        try:
            await activate(session, 0x0E00)
            raw = _diagnostic_message(0x0E00, 0x9999)
            await session._dispatch(session._dissect(raw))
            assert_nack(writer.frames[-1], 0x9999, 0x0E00, 0x03)
            assert len(writer.frames) == 2
        finally:
            await session._cleanup()

    asyncio.run(scenario())


def test_ecu_generated_nack_is_relayed_without_rewriting():
    async def scenario():
        session, writer, _ = make_session(False)
        ecu = AsyncMock()
        try:
            await activate(session, 0x0E00)
            session._ecu_conns[0x0001] = ecu
            downstream = session._build_frame(0x8003, b"\x00\x01\x0e\x00\x06\x22\xf1\x90")
            ecu.recv.return_value = downstream
            await session._dispatch(session._dissect(_diagnostic_message(0x0E00, 0x0001)))
            assert writer.frames[-1] == downstream
            assert len(writer.frames) == 2
        finally:
            await session._cleanup()

    asyncio.run(scenario())
