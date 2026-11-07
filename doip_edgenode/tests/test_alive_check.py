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

"""F09: alive checks belong to registered clients and matching probes."""

import asyncio

import pytest

from session import DoIPProtocolError
from tests.test_routing_activation import activate, make_session
from tests.test_ecu_setup import connection, frame, ra_payload
from tests.test_routing_activation import RecordingWriter


@pytest.mark.parametrize("source", [0x0E00, 0x0E55])
def test_only_matching_wire_response_satisfies_probe(source):
    async def scenario():
        session, writer, _ = make_session(False)
        task = None
        try:
            await activate(session, 0x0E00)
            task = asyncio.create_task(session.probe_alive(0.05))
            async def sent():
                while len(writer.frames) < 2:
                    assert not task.done()
                    await asyncio.sleep(0)
            await asyncio.wait_for(sent(), 0.3)
            await session._dispatch(session._dissect(frame(8, source.to_bytes(2, "big"))))
            if source != 0x0E00:
                assert not session._alive_probe_event.is_set()
            assert await asyncio.wait_for(task, 0.3) is (source == 0x0E00)
            assert not session._alive_probe_pending
        finally:
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await session._cleanup()

    asyncio.run(scenario())


@pytest.mark.parametrize("ptype,payload", [(8, b""), (8, b"\x0e"), (8, b"\x0e\x00\x00"), (7, b"x")])
def test_malformed_alive_frame_cannot_complete_probe(ptype, payload):
    async def scenario():
        session, writer, _ = make_session(False)
        try:
            await activate(session, 0x0E00)
            event = asyncio.Event()
            session._alive_probe_pending = True
            session._alive_probe_event = event
            session.reader.feed_data(frame(ptype, payload))
            with pytest.raises(DoIPProtocolError):
                await session._read_frame()
            assert not event.is_set()
            assert writer.frames[-1] == frame(0, b"\x04")
        finally:
            await session._cleanup()

    asyncio.run(scenario())


@pytest.mark.parametrize("ptype,payload", [(7, b""), (8, b"\x0e\x00")])
def test_pre_activation_alive_traffic_is_ignored(ptype, payload):
    async def scenario():
        session, writer, _ = make_session(False)
        try:
            session._start_initial_timer()
            timer = session._initial_timer_task
            await session._dispatch(session._dissect(frame(ptype, payload)))
            assert writer.frames == []
            assert session._initial_timer_task is timer
            assert not timer.done()
            assert not await session.probe_alive(0.01)
            assert writer.frames == []
        finally:
            await session._cleanup()

    asyncio.run(scenario())


def test_unsolicited_reply_does_not_create_or_poison_probe_state():
    async def scenario():
        session, writer, _ = make_session(False)
        try:
            await activate(session, 0x0E00)
            await session._dispatch(session._dissect(frame(8, b"\x0e\x00")))
            assert session._alive_probe_event is None
            assert not session._alive_probe_pending
            assert not await session.probe_alive(0.01)
            assert writer.frames[-1] == frame(7)
        finally:
            await session._cleanup()

    asyncio.run(scenario())


def test_tester_alive_request_does_not_get_server_role_reply():
    async def scenario():
        session, writer, _ = make_session(False)
        try:
            await activate(session, 0x0E00)
            await session._dispatch(session._dissect(frame(7)))
            assert len(writer.frames) == 1  # RA only
        finally:
            await session._cleanup()

    asyncio.run(scenario())


@pytest.mark.parametrize("source", [0x0E00, 0x0E55])
def test_early_ecu_probe_uses_requested_client_identity(source):
    async def scenario():
        conn = connection()
        conn._reader = asyncio.StreamReader()
        conn._writer = RecordingWriter()
        conn._connected = True
        conn._tester_logical_addr = source
        conn._reader.feed_data(frame(7) + frame(6, ra_payload(tester=source)))
        try:
            await asyncio.wait_for(conn._do_routing_activation(source), 0.3)
            assert conn._writer.frames[1] == frame(8, source.to_bytes(2, "big"))
            conn._reader_task = asyncio.create_task(conn._background_reader())
            conn._reader.feed_data(frame(7) + frame(0x8001, b"abcde"))
            assert await asyncio.wait_for(conn.recv(), 0.3) == frame(0x8001, b"abcde")
            assert conn._writer.frames[2] == conn._writer.frames[1]
        finally:
            await conn.close()

    asyncio.run(scenario())


def test_malformed_ecu_probe_is_not_answered():
    async def scenario():
        conn = connection()
        conn._reader = asyncio.StreamReader()
        conn._writer = RecordingWriter()
        conn._connected = True
        conn._reader.feed_data(frame(7, b"x"))
        try:
            with pytest.raises(RuntimeError):
                await asyncio.wait_for(conn._do_routing_activation(0x0E00), 0.3)
            assert len(conn._writer.frames) == 1  # RA only
        finally:
            await conn.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("payload", [b"", b"\x0e", b"\x0e\x00\x00"])
def test_pre_activation_short_alive_response_does_not_reach_scapy(payload):
    async def scenario():
        session, writer, _ = make_session(False)
        session.reader.feed_data(frame(8, payload))
        session.reader.feed_eof()
        await asyncio.wait_for(session.run(), 0.3)
        assert writer.closed and writer.frames == [frame(0, b"\x04")]

    asyncio.run(scenario())


def test_unsolicited_client_keepalive_resets_timer_through_session_loop():
    async def scenario():
        session, writer, _ = make_session(False)
        try:
            await activate(session, 0x0E00)
            timer = session._inactivity_task
            session.reader.feed_data(frame(8, b"\x0e\x00"))
            session.reader.feed_eof()
            with pytest.raises(asyncio.IncompleteReadError):
                await asyncio.wait_for(session._session_loop(), 0.3)
            assert session._inactivity_task is not timer
            assert timer.done()  # timeout coroutine swallows normal cancellation
            assert len(writer.frames) == 1  # no reply to client keepalive
            assert session._alive_probe_event is None
            assert not session._alive_probe_pending
        finally:
            await session._cleanup()

    asyncio.run(scenario())
