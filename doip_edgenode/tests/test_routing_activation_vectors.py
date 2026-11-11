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

"""Byte-exact routing activation vectors.

Requests are fed to the session as hand-written wire bytes and responses are
compared with hand-written wire bytes; neither side is produced by the session
codec. The test configuration uses entity address 0x1234 and the default tester
range 0x0E00-0x0FFF.
"""

import asyncio

import pytest

from middleware import MiddlewareChain
from routing import RoutingTable
from session import DoIPProtocolError, DoIPSession
from session_registry import SessionRegistry
from tests.test_routing_activation import RecordingWriter
from tests.test_session import _make_app_config


def make_session(with_registry):
    config = _make_app_config()
    assert config.doip.node_logical_addr == 0x1234
    assert config.doip.tester_addr_range == (0x0E00, 0x0FFF)
    writer = RecordingWriter()
    registry = SessionRegistry() if with_registry else None
    session = DoIPSession(
        reader=asyncio.StreamReader(), writer=writer, config=config,
        routing_table=RoutingTable(config.routing_table),
        middleware_chain=MiddlewareChain([]),
        loop=asyncio.get_running_loop(), executor=None, registry=registry,
    )
    return session, writer, registry


async def feed_and_dispatch(session, request):
    """Run one request through frame validation, dissection and dispatch."""
    session.reader.feed_data(request)
    raw = await session._read_frame()
    assert raw == request
    await session._dispatch(session._dissect(raw))


def _wire(text):
    return bytes.fromhex(text)


# Response for tester 0x0E00, entity 0x1234, success: 13-byte payload.
SUCCESS_RESPONSE = _wire(
    "02FD0006 0000000D 0E00 1234 10 00000000 00000000"
)

# 7-byte request, and 11-byte requests with non-zero reserved/tail bytes.
REQUEST_7 = _wire("02FD0005 00000007 0E00 00 00000000")
REQUEST_7_RESERVED = _wire("02FD0005 00000007 0E00 00 01020304")
REQUEST_11 = _wire("02FD0005 0000000B 0E00 00 00000000 00000000")
REQUEST_11_TAIL = _wire("02FD0005 0000000B 0E00 00 01020304 A55A3CC3")
REQUEST_TYPE_01 = _wire("02FD0005 00000007 0E00 01 00000000")


@pytest.mark.parametrize("with_registry", [False, True])
@pytest.mark.parametrize("request_bytes", [
    REQUEST_7, REQUEST_7_RESERVED, REQUEST_11, REQUEST_11_TAIL,
], ids=["7-byte", "7-byte-reserved-set", "11-byte", "11-byte-nonzero-tail"])
def test_request_shapes_activate_with_identical_response(
        with_registry, request_bytes):
    async def scenario():
        session, writer, registry = make_session(with_registry)
        try:
            await feed_and_dispatch(session, request_bytes)
            assert writer.frames == [SUCCESS_RESPONSE]
            assert len(writer.frames[0]) == 21
            assert session.activated
            assert session.tester_logical_addr == 0x0E00
            assert not writer.closed
            if registry is not None:
                assert registry.count() == 1
                assert registry.lookup(0x0E00) is session
        finally:
            await session._cleanup()

    asyncio.run(scenario())


@pytest.mark.parametrize("with_registry", [False, True])
def test_activation_type_01_is_accepted(with_registry):
    async def scenario():
        session, writer, registry = make_session(with_registry)
        try:
            await feed_and_dispatch(session, REQUEST_TYPE_01)
            assert writer.frames == [SUCCESS_RESPONSE]
            assert session.activated
            assert not writer.closed
            if registry is not None:
                assert registry.lookup(0x0E00) is session
        finally:
            await session._cleanup()

    asyncio.run(scenario())


# (request, expected response) pairs for denied activations.
DENIED = [
    pytest.param(
        _wire("02FD0005 00000007 0DFF 00 00000000"),
        _wire("02FD0006 0000000D 0DFF 1234 00 00000000 00000000"),
        0x0DFF, id="sa-below-range-code-00"),
    pytest.param(
        _wire("02FD0005 00000007 1000 00 00000000"),
        _wire("02FD0006 0000000D 1000 1234 00 00000000 00000000"),
        0x1000, id="sa-above-range-code-00"),
    pytest.param(
        _wire("02FD0005 00000007 0E00 02 00000000"),
        _wire("02FD0006 0000000D 0E00 1234 06 00000000 00000000"),
        0x0E00, id="type-02-code-06"),
    pytest.param(
        _wire("02FD0005 00000007 0E00 7F 00000000"),
        _wire("02FD0006 0000000D 0E00 1234 06 00000000 00000000"),
        0x0E00, id="type-7f-code-06"),
    pytest.param(
        _wire("02FD0005 00000007 0E00 E0 00000000"),
        _wire("02FD0006 0000000D 0E00 1234 06 00000000 00000000"),
        0x0E00, id="type-e0-code-06"),
    pytest.param(
        _wire("02FD0005 00000007 0E00 FF 00000000"),
        _wire("02FD0006 0000000D 0E00 1234 06 00000000 00000000"),
        0x0E00, id="type-ff-code-06"),
    pytest.param(
        _wire("02FD0005 0000000B 0E00 E0 00000000 00000000"),
        _wire("02FD0006 0000000D 0E00 1234 06 00000000 00000000"),
        0x0E00, id="type-e0-11-byte-code-06"),
]


@pytest.mark.parametrize("with_registry", [False, True])
@pytest.mark.parametrize("request_bytes,expected,address", DENIED)
def test_denied_activation_leaves_session_unactivated(
        with_registry, request_bytes, expected, address):
    async def scenario():
        session, writer, registry = make_session(with_registry)
        try:
            with pytest.raises(DoIPProtocolError):
                await feed_and_dispatch(session, request_bytes)
            assert writer.frames[0] == expected
            assert not session.activated
            assert session.tester_logical_addr is None
            if registry is not None:
                assert registry.count() == 0
                assert registry.lookup(address) is None
        finally:
            await session._cleanup()
        if registry is not None:
            assert registry.count() == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("with_registry", [False, True])
@pytest.mark.parametrize("request_bytes,expected,address", DENIED)
def test_denied_activation_closes_connection(
        with_registry, request_bytes, expected, address):
    async def scenario():
        session, writer, registry = make_session(with_registry)
        # The reader never reaches end-of-stream: only the denial can end run().
        # Observe completion explicitly; a timed-out wait would cancel run(),
        # which swallows cancellation and would look like a clean return.
        session.reader.feed_data(request_bytes)
        task = asyncio.ensure_future(session.run())
        done, _ = await asyncio.wait({task}, timeout=1)
        try:
            assert task in done, "session kept the connection open after denial"
            assert task.result() is None
            assert writer.frames == [expected]
            assert writer.closed
            assert not session.activated
            if registry is not None:
                assert registry.count() == 0
                assert registry.lookup(address) is None
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await session._cleanup()

    asyncio.run(scenario())
