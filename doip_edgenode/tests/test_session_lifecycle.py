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

"""F17 session teardown races, using asyncio.run rather than pytest-asyncio."""

import asyncio
from unittest.mock import patch

import pytest

from tests.test_capacity import Writer, make
from tests.test_session import _make_app_config


class ECU:
    def __init__(self, *, connect_gate=None):
        self.closed = 0
        self.connected = True
        self.connect_gate = connect_gate
        self.connect_started = asyncio.Event()
        self.read_started = asyncio.Event()
        self.read_cancelled = asyncio.Event()

    async def connect(self, **_):
        self.connect_started.set()
        if self.connect_gate is not None:
            try:
                await self.connect_gate.wait()
            except asyncio.CancelledError:
                await self.connect_gate.wait()

    async def close(self):
        self.closed += 1
        self.connected = False

    async def send(self, _):
        pass

    async def recv(self):
        self.read_started.set()
        try:
            await asyncio.Future()
        finally:
            self.read_cancelled.set()


def run(coro):
    return asyncio.run(coro)


def fast_config(**values):
    config = _make_app_config(**values)
    config.timers.ecu_response_timeout_s = 0.05
    config.timers.ecu_pending_max_wait_s = 0.1
    return config


def test_initial_and_general_expiry_schedule_cleanup_and_close_ecu():
    async def scenario():
        config = fast_config(initial_s=0.01, general_s=0.01)
        session, writer = make(None, config=config)
        initial_ecu = ECU()
        session._ecu_conns[1] = initial_ecu
        session._start_initial_timer()
        async def expired():
            while session._cleanup_task is None:
                await asyncio.sleep(0)
        await asyncio.wait_for(expired(), 1)
        await asyncio.wait_for(session._cleanup_task, 1)
        assert writer.closed and initial_ecu.closed == 1
        assert session._initial_timer_task.done() and not session._timer_tasks

        session, writer = make(None, config=fast_config(initial_s=1, general_s=0.01))
        session.activated = True
        ecu = ECU()
        session._ecu_conns[1] = ecu
        session._reset_inactivity_timer()
        await asyncio.wait_for(expired(), 1)
        await asyncio.wait_for(session._cleanup_task, 1)
        assert writer.closed and ecu.closed == 1

    run(scenario())


def test_concurrent_cleanup_and_retirement_close_each_ecu_once():
    async def scenario():
        session, _ = make(None, config=fast_config())
        ecu = ECU()
        session._ecu_conns[1] = ecu
        await asyncio.gather(session._retire_ecu_connection(1, ecu), session.close())
        assert ecu.closed == 1
        assert not session._ecu_conns

    run(scenario())


def test_repeated_cancelled_cleanup_joiners_wait_for_actual_owner():
    async def scenario():
        session, writer = make(None, config=fast_config())
        entered = asyncio.Event()
        release = asyncio.Event()

        async def wait_closed():
            entered.set()
            await release.wait()

        writer.wait_closed = wait_closed
        owner = asyncio.create_task(session.close())
        await asyncio.wait_for(entered.wait(), 1)
        joiner = asyncio.create_task(session._cleanup())
        await asyncio.sleep(0)
        joiner.cancel()
        await asyncio.sleep(0)
        joiner.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await joiner
        await asyncio.wait_for(owner, 1)
        assert writer.closed

    run(scenario())


def test_replaced_timer_tasks_are_retained_until_done():
    async def scenario():
        session, _ = make(None, config=fast_config())
        session._reset_inactivity_timer()
        first = session._inactivity_task
        session._reset_inactivity_timer()
        second = session._inactivity_task
        assert first is not second
        assert first in session._timer_tasks
        first.cancel()
        await asyncio.sleep(0)
        assert first.done()
        await session.close()
        assert not session._timer_tasks

    run(scenario())


def test_cancelled_exchange_drains_pending_read_in_finally():
    async def scenario():
        session, _ = make(None, config=fast_config())
        ecu = ECU()
        session._ecu_conns[1] = ecu
        request = session._build_frame(0x8001, b"\x0e\x00\x00\x01\x22")
        task = asyncio.create_task(session._exchange_with_ecu(1, ecu, request, request))
        await asyncio.wait_for(ecu.read_started.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert ecu.read_cancelled.is_set() and ecu.closed == 1
        assert not session._ecu_read_tasks
        await session.close()

    run(scenario())


def test_pending_connect_finishes_after_session_cancel_without_nack_or_cache():
    async def scenario():
        gate = asyncio.Event()
        session, writer = make(None, config=fast_config())
        ecu = ECU(connect_gate=gate)
        request = session._build_frame(0x8001, b"\x0e\x00\x00\x01\x22")
        with patch("ecu_client.ECUConnection", return_value=ecu):
            task = asyncio.create_task(session._connect_to_ecu(1, request))
            await asyncio.wait_for(ecu.connect_started.wait(), 1)
            session.close_task = asyncio.create_task(session.close())
            await asyncio.sleep(0)
            gate.set()
            await asyncio.wait_for(session.close_task, 1)
            result = await asyncio.wait_for(task, 1)
        assert result is None
        assert ecu.closed == 1
        assert not session._ecu_conns
        assert writer.frames == []

    run(scenario())


def test_evict_is_synchronous_registry_release_then_cleanup_eventually_finishes():
    async def scenario():
        from session_registry import SessionRegistry

        registry = SessionRegistry(1)
        old, writer = make(registry, config=fast_config())
        old.tester_logical_addr = 0x0E00
        registry.register(0x0E00, old)
        entered = asyncio.Event()
        release = asyncio.Event()

        async def wait_closed():
            entered.set()
            await release.wait()

        writer.wait_closed = wait_closed
        old.evict()
        assert writer.closed and registry.lookup(0x0E00) is None
        await asyncio.wait_for(entered.wait(), 1)
        release.set()
        await asyncio.wait_for(old._cleanup_task, 1)

    run(scenario())


def test_blocked_ecu_and_tester_close_waits_use_real_deadlines():
    async def scenario():
        session, writer = make(None, config=fast_config())
        ecu = ECU()
        session._ecu_conns[1] = ecu
        ecu_cancelled, writer_cancelled = asyncio.Event(), asyncio.Event()
        async def blocked_close():
            try:
                await asyncio.Future()
            finally:
                ecu_cancelled.set()
        async def blocked_wait():
            try:
                await asyncio.Future()
            finally:
                writer_cancelled.set()
        ecu.close = blocked_close
        writer.wait_closed = blocked_wait
        started = asyncio.get_running_loop().time()
        await asyncio.wait_for(session.close(), 3)
        assert writer.closed and ecu_cancelled.is_set() and writer_cancelled.is_set()
        assert 1.9 <= asyncio.get_running_loop().time() - started < 3
    run(scenario())


def test_cleanup_drains_receive_finally_before_finishing():
    async def scenario():
        session, _ = make(None, config=fast_config())
        entered, cancelled, release, drained = (asyncio.Event() for _ in range(4))
        async def recv():
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()
                await release.wait()
                drained.set()
        ecu = ECU()
        ecu.recv = recv
        session._ecu_conns[1] = ecu
        reader = asyncio.create_task(recv())
        session._ecu_read_tasks[1] = reader
        session._ecu_read_owners[1] = ecu
        await asyncio.wait_for(entered.wait(), 1)
        closing = asyncio.create_task(session.close())
        try:
            await asyncio.wait_for(cancelled.wait(), 1)
            assert not closing.done() and not drained.is_set()
        finally:
            release.set()
            await asyncio.wait_for(closing, 1)
        assert reader.done() and drained.is_set() and ecu.closed == 1
        assert not session._ecu_read_tasks
    run(scenario())


def test_cancelling_setup_caller_retains_and_drains_connect_child():
    async def scenario():
        session, writer = make(None, config=fast_config())
        entered, cancelled, release = (asyncio.Event() for _ in range(3))
        ecu = ECU()
        async def connect(**kwargs):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()
                await release.wait()
                ecu.connected = False  # ECUConnection owns failed setup close
        ecu.connect = connect
        request = session._build_frame(0x8001, b"\x0e\x00\x00\x01\x22")
        with patch("ecu_client.ECUConnection", return_value=ecu):
            task = asyncio.create_task(session._connect_to_ecu(1, request))
            await asyncio.wait_for(entered.wait(), 1)
            child = next(iter(session._connect_tasks))
            task.cancel()
            await asyncio.wait_for(cancelled.wait(), 1)
            assert not task.done() and child in session._connect_tasks
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 1)
        assert child.done() and not session._ecu_conns and not writer.frames
        await session.close()
    run(scenario())


def test_closed_session_cannot_start_run_timer_replay_connect_or_receive():
    async def scenario():
        session, writer = make(None, config=fast_config())
        await session.close()
        session._start_initial_timer()
        session._reset_inactivity_timer()
        await session.run()
        request = session._build_frame(0x8001, b"\x0e\x00\x00\x01\x22")
        with patch("ecu_client.ECUConnection") as constructor:
            assert await session._connect_to_ecu(1, request) is None
            await session.send_to_ecu(request)
            constructor.assert_not_called()
        ecu = ECU()
        assert await session._recv_ecu_frame(1, ecu, 0.1) is None
        assert not session._timer_tasks and not session._ecu_read_tasks
        assert writer.frames == []
    run(scenario())
