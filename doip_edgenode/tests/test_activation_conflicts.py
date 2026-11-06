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

"""F03 regressions: serialized SA conflicts and independently owned probes."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from session import DoIPProtocolError
from tests.test_routing_activation import activate, assert_response, make_session


def shared_sessions(count):
    first = make_session(True)
    sessions = [first]
    for _ in range(count - 1):
        session, writer, _ = make_session(False)
        session._registry = first[2]
        sessions.append((session, writer, first[2]))
    return sessions


async def finish(tasks, sessions):
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    for session, _, _ in sessions:
        await session._cleanup()


@pytest.mark.parametrize("old_alive", [False, True])
def test_three_contenders_have_exactly_one_live_owner(old_alive):
    async def scenario():
        sessions = shared_sessions(4)
        old, _, registry = sessions[0]
        entered, release = asyncio.Event(), asyncio.Event()
        tasks = []

        async def probe(timeout):
            entered.set()
            await release.wait()
            return old_alive

        try:
            await activate(old, 0x0E00)
            old.probe_alive = AsyncMock(side_effect=probe)
            old.evict = Mock(wraps=old.evict)
            for contender, _, _ in sessions[1:]:
                contender.probe_alive = AsyncMock(return_value=True)
                tasks.append(asyncio.create_task(activate(contender, 0x0E00)))
            await asyncio.wait_for(entered.wait(), 1)
            await asyncio.sleep(0)
            release.set()
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), 1)
            assert sum(result is None for result in results) == (0 if old_alive else 1)
            for result, (_, writer, _) in zip(results, sessions[1:]):
                assert result is None or isinstance(result, DoIPProtocolError)
                assert_response(writer.frames[-1], 0x0E00,
                                0x10 if result is None else 0x03)
            owner = old if old_alive else sessions[1][0]
            assert registry.lookup(0x0E00) is owner
            assert registry.count() == 1
            assert not owner._closing
            assert old.evict.call_count == (0 if old_alive else 1)
        finally:
            await finish(tasks, sessions)
        assert not registry._activation_locks

    asyncio.run(scenario())


@pytest.mark.parametrize("probe_result", [False, True])
def test_owner_change_during_probe_is_rechecked(probe_result):
    async def scenario():
        sessions = shared_sessions(3)
        old, _, registry = sessions[0]
        contender, writer, _ = sessions[1]
        replacement, _, _ = sessions[2]
        old.evict = Mock(wraps=old.evict)
        replacement.probe_alive = AsyncMock(return_value=True)

        async def changed_owner(timeout):
            registry.register(0x0E00, replacement)
            return probe_result

        try:
            await activate(old, 0x0E00)
            old.probe_alive = AsyncMock(side_effect=changed_owner)
            with pytest.raises(DoIPProtocolError):
                await activate(contender, 0x0E00)
            replacement.probe_alive.assert_awaited_once()
            old.evict.assert_not_called()
            assert registry.lookup(0x0E00) is replacement
            assert_response(writer.frames[-1], 0x0E00, 0x03)
        finally:
            registry.unregister(0x0E00, replacement)
            await finish([], sessions)

    asyncio.run(scenario())


@pytest.mark.parametrize("cancel_first", [False, True])
def test_overlapping_probes_keep_their_own_event(cancel_first):
    async def scenario():
        sessions = shared_sessions(1)
        owner, writer, _ = sessions[0]
        sent = asyncio.Queue()
        tasks = []

        async def record_send(raw):
            writer.write(raw)
            sent.put_nowait(raw)

        owner._send_raw = record_send
        try:
            await activate(owner, 0x0E00)
            sent.get_nowait()  # Routing Activation Response
            tasks.append(asyncio.create_task(owner.probe_alive(1)))
            await asyncio.wait_for(sent.get(), 1)
            event = owner._alive_probe_event
            tasks.append(asyncio.create_task(owner.probe_alive(1)))
            await asyncio.sleep(0)
            assert owner._alive_probe_event is event
            assert sent.empty()
            if cancel_first:
                tasks[0].cancel()
                with pytest.raises(asyncio.CancelledError):
                    await tasks[0]
            else:
                await owner._handle_alive_check_response()
                assert await asyncio.wait_for(tasks[0], 1)
            await asyncio.wait_for(sent.get(), 1)
            assert owner._alive_probe_event is not event
            await owner._handle_alive_check_response()
            assert await asyncio.wait_for(tasks[1], 1)
            assert not owner._alive_probe_pending
            assert owner._alive_probe_event is None
        finally:
            await finish(tasks, sessions)

    asyncio.run(scenario())


@pytest.mark.parametrize("action", ["cancel_holder", "cancel_waiter", "close_waiter"])
def test_waiting_activation_releases_locks_and_does_not_resurrect(action):
    async def scenario():
        sessions = shared_sessions(3)
        old, _, registry = sessions[0]
        holder, _, _ = sessions[1]
        waiter, _, _ = sessions[2]
        entered, release = asyncio.Event(), asyncio.Event()
        tasks = []

        async def probe(timeout):
            entered.set()
            await release.wait()
            return True

        try:
            await activate(old, 0x0E00)
            old.probe_alive = AsyncMock(side_effect=probe)
            tasks.append(asyncio.create_task(activate(holder, 0x0E00)))
            await asyncio.wait_for(entered.wait(), 1)
            tasks.append(asyncio.create_task(activate(waiter, 0x0E00)))
            await asyncio.sleep(0)
            # A different SA must activate while this one is blocked.
            unrelated = make_session(False)
            unrelated[0]._registry = registry
            sessions.append(unrelated)
            await asyncio.wait_for(activate(unrelated[0], 0x0E01), 1)
            if action == "close_waiter":
                await waiter._cleanup()
            else:
                tasks[0 if action == "cancel_holder" else 1].cancel()
            release.set()
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), 1)
            assert all(isinstance(result, (DoIPProtocolError, asyncio.CancelledError))
                       for result in results)
            assert registry.lookup(0x0E00) is old
            assert not waiter.activated
            assert not registry._activation_locks
            # Use a fresh socket to retry acquisition of the contested SA.
            retry = make_session(False)
            retry[0]._registry = registry
            sessions.append(retry)
            with pytest.raises(DoIPProtocolError):
                await asyncio.wait_for(activate(retry[0], 0x0E00), 1)
            assert_response(retry[1].frames[-1], 0x0E00, 0x03)
            assert not registry._activation_locks
        finally:
            await finish(tasks, sessions)

    asyncio.run(scenario())


@pytest.mark.parametrize("close_method", ["cleanup", "evict"])
def test_cleanup_wakes_probe_without_reporting_alive(close_method):
    async def scenario():
        sessions = shared_sessions(1)
        owner, _, _ = sessions[0]
        sent = asyncio.Event()
        tasks = []

        async def send(raw):
            sent.set()

        try:
            await activate(owner, 0x0E00)
            owner._send_raw = send
            tasks.append(asyncio.create_task(owner.probe_alive(10)))
            await asyncio.wait_for(sent.wait(), 1)
            await owner._cleanup()
            assert await asyncio.wait_for(tasks[0], 1) is False
            assert not owner._alive_probe_pending
        finally:
            await finish(tasks, sessions)

    asyncio.run(scenario())


def test_probe_timeout_does_not_poison_the_next_probe():
    async def scenario():
        sessions = shared_sessions(1)
        owner, _, _ = sessions[0]
        sent = asyncio.Event()
        tasks = []

        async def send(raw):
            sent.set()

        try:
            await activate(owner, 0x0E00)
            owner._send_raw = send
            assert await owner.probe_alive(0.01) is False
            assert owner._alive_probe_event is None
            sent.clear()
            tasks.append(asyncio.create_task(owner.probe_alive(1)))
            await asyncio.wait_for(sent.wait(), 1)
            # Exercise response dissection and dispatch with a real wire frame.
            response = owner._build_frame(0x0008, b"\x0e\x00")
            await owner._dispatch(owner._dissect(response))
            assert await asyncio.wait_for(tasks[0], 1) is True
        finally:
            await finish(tasks, sessions)

    asyncio.run(scenario())


@pytest.mark.parametrize("close_contender", [False, True])
def test_cleanup_during_conflict_probe_does_not_use_stale_state(close_contender):
    async def scenario():
        sessions = shared_sessions(2)
        old, _, registry = sessions[0]
        contender, writer, _ = sessions[1]
        entered, release = asyncio.Event(), asyncio.Event()
        tasks = []

        async def probe(timeout):
            entered.set()
            await release.wait()
            return True

        try:
            await activate(old, 0x0E00)
            old.probe_alive = probe
            tasks.append(asyncio.create_task(activate(contender, 0x0E00)))
            await asyncio.wait_for(entered.wait(), 1)
            await (contender if close_contender else old)._cleanup()
            release.set()
            if close_contender:
                with pytest.raises(DoIPProtocolError):
                    await asyncio.wait_for(tasks[0], 1)
                assert registry.lookup(0x0E00) is old
                assert not contender.activated
                assert contender._inactivity_task is None
            else:
                await asyncio.wait_for(tasks[0], 1)
                assert registry.lookup(0x0E00) is contender
                assert_response(writer.frames[-1], 0x0E00, 0x10)
            assert not registry._activation_locks
        finally:
            await finish(tasks, sessions)

    asyncio.run(scenario())


def test_probe_send_failure_clears_state_for_retry():
    async def scenario():
        sessions = shared_sessions(1)
        owner, _, _ = sessions[0]
        sent = asyncio.Event()
        tasks = []

        async def send(raw):
            sent.set()

        try:
            await activate(owner, 0x0E00)
            owner._send_raw = AsyncMock(side_effect=ConnectionResetError())
            assert await owner.probe_alive(1) is False
            assert owner._alive_probe_event is None
            assert not owner._alive_probe_pending
            owner._send_raw = send
            tasks.append(asyncio.create_task(owner.probe_alive(1)))
            await asyncio.wait_for(sent.wait(), 1)
            await owner._handle_alive_check_response()
            assert await asyncio.wait_for(tasks[0], 1) is True
        finally:
            await finish(tasks, sessions)

    asyncio.run(scenario())
