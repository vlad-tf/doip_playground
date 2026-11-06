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

"""F06: exercise the production exchange, not a copied receive-loop harness."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from tests.test_response_pending import diag, frame
from tests.test_routing_activation import activate, make_session
from tests.test_session import _diagnostic_message


ACK = frame(0x8002, b"\x00\x01\x0e\x00\x00")
NACK = frame(0x8003, b"\x00\x01\x0e\x00\x03")
FINAL = diag(b"\x62\xf1\x90new")
PENDING = diag(b"\x7f\x22\x78")


class QueueECU:
    def __init__(self, frames=(), error_at=None, send_error=False):
        self.queue = asyncio.Queue()
        for raw in frames:
            self.queue.put_nowait(raw)
        self.sent = []
        self.reads = []
        self.active = 0
        self.max_active = 0
        self.closed = False
        self.error_at = error_at
        self.send_error = send_error
        self.receiving = asyncio.Event()

    @property
    def connected(self):
        return not self.closed

    async def send(self, raw):
        self.sent.append(raw)
        if self.send_error:
            raise ConnectionResetError("send failed")

    async def recv(self):
        self.reads.append(asyncio.current_task())
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.receiving.set()
        try:
            if len(self.reads) == self.error_at:
                raise ConnectionResetError("recv failed")
            return await self.queue.get()
        finally:
            self.active -= 1

    async def close(self):
        self.closed = True


async def setup(ecu, *, strict=True, per_frame=0.03, budget=0.25):
    session, writer, _ = make_session(False)
    await activate(session, 0x0E00)
    writer.frames.clear()
    session.config.timers.ecu_response_timeout_s = per_frame
    session.config.timers.ecu_pending_max_wait_s = budget
    session.config.timers.strict_response_matching = strict
    session._ecu_conns[1] = ecu
    return session, writer


async def exchange(session, uds=b"\x22\xf1\x90"):
    raw = _diagnostic_message(0x0E00, 1, uds)
    await asyncio.wait_for(session._dispatch(session._dissect(raw)), 0.8)


def assert_retired(session, ecu):
    assert ecu.closed
    assert 1 not in session._ecu_conns
    assert not session._ecu_read_tasks
    assert ecu.active == 0
    assert all(task.done() for task in ecu.reads)
    assert ecu.max_active <= 1


def test_missing_first_ack_is_bounded_and_reports_unreachable():
    async def scenario():
        ecu = QueueECU()
        session, writer = await setup(ecu)
        try:
            await exchange(session)
            assert writer.frames[-1][8:] == b"\x00\x01\x0e\x00\x06"
            assert_retired(session, ecu)
            assert not writer.closed
        finally:
            await session._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("frames", [[ACK], [ACK, PENDING], [PENDING]])
def test_abandoned_exchange_retires_stream_without_synthetic_uds_error(frames):
    async def scenario():
        ecu = QueueECU(frames)
        session, writer = await setup(ecu, budget=0.08)
        try:
            await exchange(session)
            assert writer.frames == frames
            assert_retired(session, ecu)
            assert not writer.closed
        finally:
            await session._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("phase", ["send", "first", "followup"])
def test_transport_errors_retire_stream_and_report_unreachable(phase):
    async def scenario():
        ecu = QueueECU([ACK] if phase == "followup" else [],
                       error_at={"first": 1, "followup": 2}.get(phase),
                       send_error=phase == "send")
        session, writer = await setup(ecu)
        try:
            await exchange(session)
            if phase != "followup":
                assert writer.frames[-1][8:] == b"\x00\x01\x0e\x00\x06"
            else:
                assert writer.frames == [ACK]
            assert_retired(session, ecu)
        finally:
            await session._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("prefix", [[], [ACK]])
@pytest.mark.parametrize("bad", [diag(b"\x7f\x31\x78"), diag(b"\x71old")])
def test_strict_mismatch_is_checked_before_any_diagnostic_relay(prefix, bad):
    async def scenario():
        ecu = QueueECU(prefix + [bad, FINAL])
        session, writer = await setup(ecu)
        try:
            await exchange(session)
            assert writer.frames == prefix
            assert_retired(session, ecu)
        finally:
            await session._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("prefix", [[], [ACK]])
def test_permissive_mismatched_pending_does_not_extend_exchange(prefix):
    async def scenario():
        bad = diag(b"\x7f\x31\x78")
        ecu = QueueECU(prefix + [bad, FINAL])
        session, writer = await setup(ecu, strict=False)
        try:
            await exchange(session)
            assert writer.frames == prefix + [bad]
            assert ecu.queue.qsize() == 1  # matching final remains untouched
            assert len(ecu.reads) == len(prefix) + 1
            assert_retired(session, ecu)
        finally:
            await session._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("prefix", [[], [ACK]])
def test_pending_gap_reuses_one_read_and_relays_final(prefix):
    async def scenario():
        ecu = QueueECU(prefix + [PENDING])
        session, writer = await setup(ecu, per_frame=0.02, budget=1.0)
        async def delayed_final():
            await asyncio.sleep(0.09)
            ecu.queue.put_nowait(FINAL)
        producer = asyncio.create_task(delayed_final())
        try:
            await exchange(session)
            await producer
            assert writer.frames == prefix + [PENDING, FINAL]
            assert len(ecu.reads) == len(prefix) + 2
            assert ecu.max_active == 1
            assert not session._ecu_read_tasks
            assert not ecu.closed
        finally:
            producer.cancel()
            await asyncio.gather(producer, return_exceptions=True)
            await session._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("first_frames", [[], [ACK], [ACK, PENDING]])
def test_late_same_sid_response_cannot_be_consumed_by_next_request(first_frames):
    async def scenario():
        old = QueueECU(first_frames)
        new = QueueECU([ACK, FINAL])
        session, writer = await setup(old, budget=0.07)
        try:
            await exchange(session)
            assert_retired(session, old)
            old.queue.put_nowait(diag(b"\x62\xf1\x90old"))
            writer.frames.clear()
            async def reconnect(target, raw):
                session._ecu_conns[target] = new
                return new
            session._connect_to_ecu = AsyncMock(side_effect=reconnect)
            await exchange(session)
            assert writer.frames == [ACK, FINAL]
            session._connect_to_ecu.assert_awaited_once()
            assert old.queue.qsize() == 1
            assert new.max_active == 1
        finally:
            await session._cleanup()
    asyncio.run(scenario())


def test_budget_includes_first_ack_wait():
    async def scenario():
        ecu = QueueECU()
        session, writer = await setup(ecu, per_frame=0.25, budget=0.04)
        async def delayed_ack():
            await asyncio.sleep(0.12)
            ecu.queue.put_nowait(ACK)
            ecu.queue.put_nowait(FINAL)
        producer = asyncio.create_task(delayed_ack())
        try:
            await exchange(session)
            assert len(writer.frames) == 1
            assert writer.frames[0][2:4] == b"\x80\x03"
            assert_retired(session, ecu)
        finally:
            producer.cancel()
            await asyncio.gather(producer, return_exceptions=True)
            await session._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("frames", [[FINAL], [NACK], [ACK, FINAL],
                                  [ACK, diag(b"\x7f\x22\x31")]])
def test_completed_exchange_preserves_frame_bytes_and_connection(frames):
    async def scenario():
        ecu = QueueECU(frames)
        session, writer = await setup(ecu)
        try:
            await exchange(session)
            assert writer.frames == frames
            assert not ecu.closed
            assert session._ecu_conns[1] is ecu
            assert not session._ecu_read_tasks
        finally:
            await session._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("frames", [[], [ACK, PENDING]])
def test_cancellation_drains_receive_and_retires_connection(frames):
    async def scenario():
        ecu = QueueECU(frames)
        session, writer = await setup(ecu)
        task = asyncio.create_task(session._dispatch(session._dissect(
            _diagnostic_message(0x0E00, 1, b"\x22\xf1\x90"))))
        try:
            async def ready():
                while len(ecu.reads) <= len(frames):
                    assert not task.done(), "exchange ended before receive readiness"
                    await asyncio.sleep(0)
            await asyncio.wait_for(ready(), 0.5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert_retired(session, ecu)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await session._cleanup()
    asyncio.run(scenario())


def test_retirement_does_not_remove_replacement_or_its_read():
    async def scenario():
        old, new = QueueECU(), QueueECU()
        session, _ = await setup(new)
        task = asyncio.create_task(new.recv())
        session._ecu_read_tasks[1] = task
        session._ecu_read_owners[1] = new
        try:
            await new.receiving.wait()
            await session._retire_ecu_connection(1, old)
            assert old.closed
            assert not new.closed
            assert session._ecu_conns[1] is new
            assert session._ecu_read_tasks[1] is task
            assert not task.done()
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await session._cleanup()
    asyncio.run(scenario())


def test_cancel_during_retirement_still_finishes_close():
    async def scenario():
        ecu = QueueECU()
        session, _ = await setup(ecu, per_frame=0.2)
        entered, release = asyncio.Event(), asyncio.Event()
        async def close():
            entered.set()
            await release.wait()
            ecu.closed = True
        ecu.close = close
        task = asyncio.create_task(session._dispatch(session._dissect(
            _diagnostic_message(0x0E00, 1, b"\x22\xf1\x90"))))
        try:
            await asyncio.wait_for(entered.wait(), 0.5)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert_retired(session, ecu)
        finally:
            release.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await session._cleanup()
    asyncio.run(scenario())


def test_blocked_send_is_bounded_by_exchange_budget():
    async def scenario():
        ecu = QueueECU()
        session, writer = await setup(ecu, budget=0.04)
        async def blocked_send(raw):
            await asyncio.Event().wait()
        ecu.send = AsyncMock(side_effect=blocked_send)
        try:
            await exchange(session)
            assert writer.frames[-1][8:] == b"\x00\x01\x0e\x00\x06"
            assert_retired(session, ecu)
        finally:
            await session._cleanup()
    asyncio.run(scenario())


def test_matching_uses_post_middleware_sid():
    async def scenario():
        pending = diag(b"\x7f\x31\x78")
        final = diag(b"\x71done")
        ecu = QueueECU([ACK, pending, final])
        session, writer = await setup(ecu)
        async def rewrite(pkt, direction, owner):
            raw = bytes(pkt)
            return raw[:12] + b"\x31" + raw[13:] if direction == "tester_to_ecu" else pkt
        session.middleware_chain.run = rewrite
        try:
            await exchange(session)
            assert ecu.sent[0][12] == 0x31
            assert writer.frames == [ACK, pending, final]
            assert not ecu.closed
        finally:
            await session._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("phase", ["send", "relay"])
def test_cancellation_during_send_or_relay_finishes_retirement(phase):
    async def scenario():
        ecu = QueueECU([ACK])
        session, _ = await setup(ecu)
        entered = asyncio.Event()
        async def block(*args):
            entered.set()
            await asyncio.Event().wait()
        if phase == "send":
            ecu.send = block
        else:
            session._relay_ecu_frame = block
        task = asyncio.create_task(session._dispatch(session._dissect(
            _diagnostic_message(0x0E00, 1, b"\x22\xf1\x90"))))
        try:
            await asyncio.wait_for(entered.wait(), 0.5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert_retired(session, ecu)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await session._cleanup()
    asyncio.run(scenario())


def test_old_receive_is_drained_even_after_cache_replacement():
    async def scenario():
        old, new = QueueECU(), QueueECU()
        session, _ = await setup(old)
        try:
            assert await session._recv_ecu_frame(1, old, 0.01) is None
            old_read = session._ecu_read_tasks[1]
            session._ecu_conns[1] = new
            await session._retire_ecu_connection(1, old)
            assert old.closed and old_read.done()
            assert old.active == 0
            assert session._ecu_conns[1] is new
            assert not session._ecu_read_tasks
            assert not session._ecu_read_owners
            assert not new.closed
        finally:
            await session._cleanup()
    asyncio.run(scenario())


def test_direct_pending_then_recv_error_does_not_invent_ack_or_nack():
    async def scenario():
        ecu = QueueECU([PENDING], error_at=2)
        session, writer = await setup(ecu)
        try:
            await exchange(session)
            assert writer.frames == [PENDING]
            assert_retired(session, ecu)
        finally:
            await session._cleanup()
    asyncio.run(scenario())
