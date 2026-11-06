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

"""F01 regressions: one tester source address per activated TCP socket."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from middleware import MiddlewareChain
from routing import RoutingTable
from session import DoIPProtocolError, DoIPSession
from session_registry import SessionRegistry
from tests.test_session import _make_app_config, _routing_activation_request


class RecordingWriter:
    def __init__(self):
        self.frames = []
        self.closed = False

    def get_extra_info(self, name):
        return ("127.0.0.1", 12345)

    def write(self, data):
        self.frames.append(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def make_session(with_registry):
    config = _make_app_config()
    writer = RecordingWriter()
    registry = SessionRegistry() if with_registry else None
    session = DoIPSession(
        reader=asyncio.StreamReader(), writer=writer, config=config,
        routing_table=RoutingTable(config.routing_table),
        middleware_chain=MiddlewareChain([]),
        loop=asyncio.get_running_loop(), executor=None, registry=registry,
    )
    return session, writer, registry


async def activate(session, address):
    # Exercise the installed Scapy dissector and the real dispatch/RA handler.
    pkt = session._dissect(_routing_activation_request(address))
    await session._dispatch(pkt)


def assert_response(raw, address, code):
    assert raw[:4] == b"\x02\xfd\x00\x06"
    assert int.from_bytes(raw[4:8], "big") == len(raw) - 8
    assert int.from_bytes(raw[8:10], "big") == address
    assert int.from_bytes(raw[10:12], "big") == 0x1234
    assert raw[12] == code


@pytest.mark.parametrize("with_registry", [False, True])
@pytest.mark.parametrize("new_address", [0x0E01, 0x0001])
def test_changed_sa_is_denied_without_rebinding(with_registry, new_address):
    async def scenario():
        session, writer, registry = make_session(with_registry)
        try:
            await activate(session, 0x0E00)
            timer = session._inactivity_task
            with pytest.raises(DoIPProtocolError):
                await activate(session, new_address)
            assert_response(writer.frames[-1], new_address, 0x02)
            assert session.activated
            assert session.tester_logical_addr == 0x0E00
            assert session._inactivity_task is timer
            if registry is not None:
                assert registry.count() == 1
                assert registry.lookup(0x0E00) is session
                assert registry.lookup(new_address) is None
        finally:
            await session._cleanup()
        if registry is not None:
            assert registry.count() == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("with_registry", [False, True])
def test_same_sa_reactivation_keeps_one_timer(with_registry):
    async def scenario():
        session, writer, registry = make_session(with_registry)
        try:
            await activate(session, 0x0E00)
            old_timer = session._inactivity_task
            # Let the old timer begin sleeping before reactivation cancels it.
            await asyncio.sleep(0)
            await activate(session, 0x0E00)
            new_timer = session._inactivity_task
            await asyncio.sleep(0)
            assert_response(writer.frames[0], 0x0E00, 0x10)
            assert_response(writer.frames[1], 0x0E00, 0x10)
            assert session.tester_logical_addr == 0x0E00
            assert old_timer is not new_timer
            assert old_timer.done()
            assert not new_timer.done()
            timers = [t for t in asyncio.all_tasks()
                      if t.get_coro().__qualname__ ==
                      "DoIPSession._general_inactivity_timeout"]
            assert timers == [new_timer]
            if registry is not None:
                assert registry.count() == 1
                assert registry.lookup(0x0E00) is session
        finally:
            await session._cleanup()

    asyncio.run(scenario())


@pytest.mark.parametrize("with_registry", [False, True])
def test_session_run_closes_after_changed_sa_denial(with_registry):
    async def scenario():
        session, writer, registry = make_session(with_registry)
        session.reader.feed_data(_routing_activation_request(0x0E00))
        session.reader.feed_data(_routing_activation_request(0x0E01))
        session.reader.feed_eof()
        await asyncio.wait_for(session.run(), timeout=1)
        assert len(writer.frames) == 2
        assert_response(writer.frames[0], 0x0E00, 0x10)
        assert_response(writer.frames[1], 0x0E01, 0x02)
        assert writer.closed
        assert session.tester_logical_addr == 0x0E00
        if registry is not None:
            assert registry.count() == 0

    asyncio.run(scenario())


def test_changed_sa_does_not_probe_or_evict_existing_owner():
    async def scenario():
        session, writer, registry = make_session(True)
        owner, owner_writer, _ = make_session(False)
        owner._registry = registry
        try:
            await activate(session, 0x0E00)
            await activate(owner, 0x0E01)
            timer = owner._inactivity_task
            # A false probe result would evict the owner if conflict handling
            # were reached. Neither operation belongs in a same-socket rebind.
            owner.probe_alive = AsyncMock(return_value=False)
            owner.evict = Mock(wraps=owner.evict)
            with pytest.raises(DoIPProtocolError):
                await activate(session, 0x0E01)
            assert_response(writer.frames[-1], 0x0E01, 0x02)
            owner.probe_alive.assert_not_awaited()
            owner.evict.assert_not_called()
            assert registry.count() == 2
            assert registry.lookup(0x0E00) is session
            assert registry.lookup(0x0E01) is owner
            assert owner.activated
            assert not owner_writer.closed
            assert len(owner_writer.frames) == 1
            assert owner._inactivity_task is timer
            await session._cleanup()
            assert registry.count() == 1
            assert registry.lookup(0x0E01) is owner
        finally:
            await session._cleanup()
            await owner._cleanup()
        assert registry.count() == 0

    asyncio.run(scenario())
