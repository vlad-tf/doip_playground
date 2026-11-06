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

"""F07: terminal ECU reader state wakes receivers and prevents dead-leg reuse."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from ecu_client import ECUConnection
from tests.test_ecu_exchange import ACK, FINAL, PENDING, QueueECU, exchange, setup
from tests.test_response_pending import frame
from tests.test_routing_activation import RecordingWriter
from tests.test_session import _diagnostic_message, _make_app_config


def connection():
    cfg = _make_app_config()
    conn = ECUConnection(cfg.routing_table[0], cfg.tls,
                         asyncio.get_running_loop(), None)
    conn._reader = asyncio.StreamReader()
    conn._writer = RecordingWriter()
    conn._connected = True
    return conn


def start_reader(conn):
    conn._reader_task = asyncio.create_task(conn._background_reader())
    return conn._reader_task


async def terminal_error(awaitable):
    with pytest.raises(ConnectionError) as caught:
        await asyncio.wait_for(awaitable, 0.3)
    return caught.value


@pytest.mark.parametrize("partial", [b"", b"\x02\xfd", ACK[:10]])
def test_eof_clears_connected_closes_writer_and_wakes_all_waiters(partial):
    async def scenario():
        conn = connection()
        reader = start_reader(conn)
        waiters = [asyncio.create_task(conn.recv()) for _ in range(3)]
        try:
            await asyncio.sleep(0)
            conn._reader.feed_data(partial)
            conn._reader.feed_eof()
            await asyncio.wait_for(reader, 0.3)
            assert not conn._connected
            assert conn._writer.closed
            for waiter in waiters:
                exc = await terminal_error(waiter)
                assert isinstance(exc.__cause__, asyncio.IncompleteReadError)
            await terminal_error(conn.recv())
            await terminal_error(conn.send(b"ignored"))
            assert not conn._writer.frames
        finally:
            for task in waiters:
                task.cancel()
            await asyncio.gather(*waiters, return_exceptions=True)
            await conn.close()
    asyncio.run(scenario())


def test_reader_error_preserves_cause_and_wakes_receiver():
    async def scenario():
        conn = connection()
        reader = start_reader(conn)
        failure = OSError("ECU transport failed")
        try:
            conn._reader.set_exception(failure)
            await asyncio.wait_for(reader, 0.3)
            assert not conn._connected
            exc = await terminal_error(conn.recv())
            assert exc.__cause__ is failure
            assert conn._writer.closed
        finally:
            await conn.close()
    asyncio.run(scenario())


def test_complete_frames_are_drained_in_order_before_remote_eof():
    async def scenario():
        conn = connection()
        try:
            reader = start_reader(conn)
            conn._reader.feed_data(ACK + PENDING + FINAL)
            conn._reader.feed_eof()
            await asyncio.wait_for(reader, 0.3)
            assert not conn._connected
            assert [await conn.recv() for _ in range(3)] == [ACK, PENDING, FINAL]
            for _ in range(3):
                await terminal_error(conn.recv())
            assert conn._recv_queue.qsize() == 1  # one reusable terminal marker
        finally:
            await conn.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("with_reader", [False, True])
def test_explicit_close_wakes_waiters_and_discards_buffered_frames(with_reader):
    async def scenario():
        conn = connection()
        if with_reader:
            start_reader(conn)
        waiters = [asyncio.create_task(conn.recv()) for _ in range(2)]
        try:
            await asyncio.sleep(0)
            await asyncio.wait_for(conn.close(), 0.3)
            for waiter in waiters:
                await terminal_error(waiter)
            conn._recv_queue.put_nowait(FINAL)
            await conn.close()  # repeated close also discards stale data
            await terminal_error(conn.recv())
            assert conn._recv_queue.qsize() == 1
            assert conn._writer.closed
        finally:
            for task in waiters:
                task.cancel()
            await asyncio.gather(*waiters, return_exceptions=True)
            await conn.close()
    asyncio.run(scenario())


def test_cancelled_reader_marks_connection_terminal():
    async def scenario():
        conn = connection()
        reader = start_reader(conn)
        try:
            await asyncio.sleep(0)
            reader.cancel()
            await asyncio.wait_for(reader, 0.3)
            assert not conn._connected
            assert conn._writer.closed
            await terminal_error(conn.recv())
        finally:
            await conn.close()
    asyncio.run(scenario())


def test_live_reader_still_handles_alive_requests_and_delivers_diagnostics():
    async def scenario():
        conn = connection()
        start_reader(conn)
        try:
            conn._reader.feed_data(frame(7, b"") + FINAL)
            assert await asyncio.wait_for(conn.recv(), 0.3) == FINAL
            assert conn._writer.frames == [frame(8, b"\x0e\x00")]
            assert conn._connected
        finally:
            await conn.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("prefix", [[], [ACK], [ACK, PENDING]])
def test_disconnect_during_exchange_is_prompt_and_next_request_reconnects(prefix):
    async def scenario():
        old = connection()
        session, writer = await setup(old, per_frame=2, budget=5)
        task = asyncio.create_task(exchange(session))
        try:
            start_reader(old)
            old._reader.feed_data(b"".join(prefix))
            # Wait until the session has actually sent before simulating EOF.
            async def sent():
                while not old._writer.frames:
                    await asyncio.sleep(0)
            await asyncio.wait_for(sent(), 0.3)
            old._reader.feed_eof()
            await asyncio.wait_for(task, 0.3)
            if prefix:
                assert writer.frames == prefix
            else:
                assert writer.frames[-1][8:] == b"\x12\x34\x0e\x00\x06"
            assert 1 not in session._ecu_conns
            assert not session._ecu_read_tasks
            assert not old._connected
            assert old._writer.closed
            assert not writer.closed
            new = QueueECU([ACK, FINAL])
            async def reconnect(target, raw):
                session._ecu_conns[target] = new
                return new
            session._connect_to_ecu = AsyncMock(side_effect=reconnect)
            writer.frames.clear()
            await exchange(session)
            assert writer.frames == [ACK, FINAL]
            session._connect_to_ecu.assert_awaited_once()
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await session._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("replay", [False, True])
def test_idle_disconnected_cache_is_replaced_before_send(replay):
    async def scenario():
        old = connection()
        session, writer = await setup(old)
        new = QueueECU([ACK, FINAL])
        try:
            reader = start_reader(old)
            old._reader.feed_eof()
            await asyncio.wait_for(reader, 0.3)
            async def reconnect(target, raw):
                session._ecu_conns[target] = new
                return new
            session._connect_to_ecu = AsyncMock(side_effect=reconnect)
            raw = _diagnostic_message(0x0E00, 1, b"\x22\xf1\x90")
            if replay:
                await session.send_to_ecu(session._dissect(raw))
                assert new.sent == [raw]
            else:
                await exchange(session)
                assert writer.frames == [ACK, FINAL]
            session._connect_to_ecu.assert_awaited_once_with(1, raw)
            assert session._ecu_conns[1] is new
            assert old._writer.frames == []
            assert old._writer.closed
        finally:
            await session._cleanup()
    asyncio.run(scenario())


def test_cancelled_receiver_does_not_consume_terminal_notification():
    async def scenario():
        conn = connection()
        reader = start_reader(conn)
        cancelled = asyncio.create_task(conn.recv())
        other = asyncio.create_task(conn.recv())
        try:
            await asyncio.sleep(0)
            cancelled.cancel()
            conn._reader.feed_eof()
            await asyncio.wait_for(reader, 0.3)
            with pytest.raises(asyncio.CancelledError):
                await cancelled
            await terminal_error(other)
            await terminal_error(conn.recv())
            assert conn._recv_queue.qsize() == 1
        finally:
            cancelled.cancel()
            other.cancel()
            await asyncio.gather(cancelled, other, return_exceptions=True)
            await conn.close()
    asyncio.run(scenario())


def test_terminal_cause_is_sticky_and_instance_cannot_reconnect():
    async def scenario():
        conn = connection()
        reader = start_reader(conn)
        try:
            failure = OSError("original failure")
            conn._reader.set_exception(failure)
            await asyncio.wait_for(reader, 0.3)
            await conn.close()
            assert (await terminal_error(conn.recv())).__cause__ is failure
            assert (await terminal_error(conn.connect())).__cause__ is failure
            assert not conn.connected
        finally:
            await conn.close()
    asyncio.run(scenario())


def test_never_connected_instance_preserves_runtime_error_contract():
    async def scenario():
        conn = connection()
        conn._connected = False
        try:
            with pytest.raises(RuntimeError):
                await conn.send(b"unused")
            with pytest.raises(RuntimeError):
                await conn.recv()
        finally:
            await conn.close()
    asyncio.run(scenario())


def test_reconnect_failure_does_not_retain_dead_cache():
    async def scenario():
        from unittest.mock import patch
        old = connection()
        session, writer = await setup(old)
        try:
            reader = start_reader(old)
            old._reader.feed_eof()
            await asyncio.wait_for(reader, 0.3)
            with patch("ecu_client.ECUConnection.connect", new_callable=AsyncMock,
                       side_effect=ConnectionRefusedError("ECU unavailable")) as connect:
                await exchange(session)
                connect.assert_awaited_once()
            assert 1 not in session._ecu_conns
            assert writer.frames[-1][8:] == b"\x12\x34\x0e\x00\x06"
            assert not writer.closed
            assert old._writer.closed
        finally:
            await session._cleanup()
    asyncio.run(scenario())


def test_real_tcp_eof_preserves_complete_frame_and_reports_terminal_error():
    async def scenario():
        done = asyncio.Event()
        async def ecu_peer(reader, writer):
            try:
                writer.write(ACK + FINAL)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                done.set()
        server = await asyncio.start_server(ecu_peer, "127.0.0.1", 0)
        conn = connection()
        try:
            port = server.sockets[0].getsockname()[1]
            conn._reader, conn._writer = await asyncio.open_connection("127.0.0.1", port)
            reader = start_reader(conn)
            assert await asyncio.wait_for(conn.recv(), 0.5) == ACK
            assert await asyncio.wait_for(conn.recv(), 0.5) == FINAL
            exc = await terminal_error(conn.recv())
            assert isinstance(exc.__cause__, asyncio.IncompleteReadError)
            assert not conn.connected
            assert conn._writer.is_closing()
            await asyncio.wait_for(reader, 0.5)
            await asyncio.wait_for(done.wait(), 0.5)
        finally:
            await conn.close()
            server.close()
            await server.wait_closed()
    asyncio.run(scenario())
