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

"""F17 owned startup/shutdown regressions, driven by asyncio.run."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from server import DoIPServer
from tests.test_capacity import Writer
from tests.test_session import _make_app_config


class Listener:
    def __init__(self):
        self.closed = False
        self.serving = asyncio.Event()
        self.drained = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    async def serve_forever(self):
        self.serving.set()
        try:
            await asyncio.Future()
        finally:
            self.drained = True


def server():
    config = _make_app_config()
    config.middleware = []
    obj = DoIPServer(config)
    obj._executor.shutdown(wait=True)
    obj._executor = Mock()
    obj._udp_announcer = Mock(start=AsyncMock(), stop=AsyncMock())
    return obj


async def finish(obj, task=None):
    await obj.stop()
    if task is not None:
        await asyncio.gather(task, return_exceptions=True)
    assert not obj._connection_tasks
    assert not obj._sessions
    assert obj._registry.open_count() == 0
    obj._executor.shutdown.assert_called_once_with(wait=True)


@pytest.mark.parametrize("failure", ["first", "second", "udp"])
def test_partial_startup_failure_rolls_back_every_acquired_resource(failure):
    async def scenario():
        obj = server()
        listeners = [Listener(), Listener()]
        effects = [OSError("bind")] if failure == "first" else (
            [listeners[0], OSError("bind")] if failure == "second" else listeners)
        if failure == "udp":
            obj._udp_announcer.start.side_effect = OSError("udp")
        with patch("server.asyncio.start_server", side_effect=effects):
            with pytest.raises(OSError):
                await asyncio.wait_for(obj.start(), 1)
        assert all(x.closed for x in listeners[:0 if failure == "first" else
                                                  1 if failure == "second" else 2])
        obj._udp_announcer.stop.assert_awaited_once()
        await finish(obj)
    asyncio.run(scenario())


@pytest.mark.parametrize("stage", ["first", "second", "udp"])
def test_stop_during_startup_acquisition_drains_child_without_lifetime_cycle(stage):
    async def scenario():
        obj = server()
        entered = asyncio.Event()
        listeners = [Listener(), Listener()]
        calls = 0

        async def bind(*args, **kwargs):
            nonlocal calls
            index = calls
            calls += 1
            if (stage == "first" and index == 0) or (stage == "second" and index == 1):
                entered.set()
                await asyncio.Future()
            return listeners[index]

        async def udp():
            entered.set()
            await asyncio.Future()

        if stage == "udp":
            obj._udp_announcer.start.side_effect = udp
        with patch("server.asyncio.start_server", side_effect=bind):
            task = asyncio.create_task(obj.start())
            try:
                await asyncio.wait_for(entered.wait(), 1)
                await asyncio.wait_for(obj.stop(), 1)
                await finish(obj, task)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        acquired = 0 if stage == "first" else 1 if stage == "second" else 2
        assert all(x.closed for x in listeners[:acquired])
        assert obj._startup_task.done()
        with pytest.raises(RuntimeError):
            await obj.start()
    asyncio.run(scenario())


def test_lifetime_cancel_drains_both_serving_children():
    async def scenario():
        obj = server()
        listeners = [Listener(), Listener()]
        with patch("server.asyncio.start_server", side_effect=listeners):
            task = asyncio.create_task(obj.start())
            await asyncio.wait_for(asyncio.gather(*(x.serving.wait() for x in listeners)), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 1)
        assert all(x.closed and x.drained for x in listeners)
        await finish(obj)
    asyncio.run(scenario())


@pytest.mark.parametrize("tls", [False, True])
def test_shutdown_owns_pre_ra_or_handshake_handler_and_releases_capacity(tls):
    async def scenario():
        obj = server()
        entered = asyncio.Event()
        writer = Writer()

        async def blocked(*args):
            entered.set()
            await asyncio.Future()

        if tls:
            obj._do_tls_handshake = blocked
        else:
            obj._run_connection = blocked
        obj._accept_connection(asyncio.StreamReader(), writer, tls)
        assert len(obj._connection_tasks) == 1  # registered before handler runs
        await asyncio.wait_for(entered.wait(), 1)
        assert obj._registry.open_count() == 1
        await asyncio.wait_for(finish(obj), 1)
        assert writer.closed
    asyncio.run(scenario())


def test_late_accept_after_completed_stop_closes_synchronously_without_child():
    async def scenario():
        obj = server()
        await finish(obj)
        obj._run_connection = AsyncMock()
        writer = Writer()
        obj._accept_connection(None, writer, False)
        assert writer.closed and not obj._connection_tasks
        obj._run_connection.assert_not_awaited()
        with pytest.raises(RuntimeError):
            await obj.start()
    asyncio.run(scenario())


def test_repeated_stop_waiter_cancellation_does_not_abandon_owner():
    async def scenario():
        obj = server()
        entered, release = asyncio.Event(), asyncio.Event()

        async def slow_stop():
            entered.set()
            await release.wait()

        obj._udp_announcer.stop.side_effect = slow_stop
        first = asyncio.create_task(obj.stop())
        await asyncio.wait_for(entered.wait(), 1)
        second = asyncio.create_task(obj.stop())
        await asyncio.sleep(0)
        second.cancel()
        await asyncio.sleep(0)
        second.cancel()
        await asyncio.sleep(0)
        assert not second.done() and not obj._cleanup_task.done()
        release.set()
        await asyncio.wait_for(first, 1)
        with pytest.raises(asyncio.CancelledError):
            await second
        await finish(obj)
        obj._udp_announcer.stop.assert_awaited_once()
    asyncio.run(scenario())


def test_returning_session_run_still_joins_close_before_releasing_ownership():
    async def scenario():
        obj = server()
        obj._loop = asyncio.get_running_loop()
        writer = Writer()
        with patch("server.DoIPSession.run", new_callable=AsyncMock):
            obj._accept_connection(asyncio.StreamReader(), writer, False)
            task = next(iter(obj._connection_tasks))
            await asyncio.wait_for(task, 1)
        assert writer.closed and not obj._sessions
        await finish(obj)
    asyncio.run(scenario())


def test_real_ephemeral_listeners_and_pre_ra_session_shutdown():
    async def scenario():
        obj = server()
        obj._config.ports.doip_plain = obj._config.ports.doip_tls = 0
        task = asyncio.create_task(obj.start())
        writer = None
        try:
            async def ready():
                while len(obj._listeners) != 2 or not obj._serve_tasks:
                    assert not task.done()
                    await asyncio.sleep(0)
            await asyncio.wait_for(ready(), 1)
            listeners = tuple(obj._listeners)
            _, writer = await asyncio.open_connection(
                "127.0.0.1", listeners[0].sockets[0].getsockname()[1])
            async def admitted():
                while not obj._sessions:
                    await asyncio.sleep(0)
            await asyncio.wait_for(admitted(), 1)
            await asyncio.wait_for(finish(obj, task), 2)
            assert all(not x.is_serving() for x in listeners)
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
            await finish(obj, task)
    asyncio.run(scenario())


def test_stop_immediately_after_accept_closes_writer_before_handler_first_step():
    async def scenario():
        obj = server()
        writer = Writer()
        obj._run_connection = AsyncMock()
        obj._accept_connection(None, writer, False)
        await finish(obj)
        assert writer.closed and not obj._connection_writers
        obj._run_connection.assert_not_awaited()
    asyncio.run(scenario())


def test_serving_failure_drains_sibling_and_closes_both_listeners():
    async def scenario():
        obj = server()
        good, bad = Listener(), Listener()
        async def failed():
            await asyncio.wait_for(good.serving.wait(), 1)
            raise OSError("serve failed")
        bad.serve_forever = failed
        with patch("server.asyncio.start_server", side_effect=[good, bad]):
            with pytest.raises(OSError, match="serve failed"):
                await asyncio.wait_for(obj.start(), 1)
        assert good.drained and good.closed and bad.closed
        await finish(obj)
    asyncio.run(scenario())
