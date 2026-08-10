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

"""
Regression tests for the multi-frame ECU exchange.

The EdgeNode used to read a fixed two frames per diagnostic request (ACK plus
one response).  An ECU that answers with one or more
``7F <sid> 78`` requestCorrectlyReceived-ResponsePending frames sends three or
more, so the real answer stayed in the socket buffer until the *next* request
pumped recv() — which then delivered it as the response to an unrelated
request, silently, for the rest of the session.

These tests do NOT require Scapy, root, or network access.

Run with:
    cd doip_edgenode && pytest tests/test_response_pending.py -v
"""

from __future__ import annotations

import asyncio
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from session import (                                    # noqa: E402
    PT_DIAGNOSTIC_MESSAGE,
    PT_DIAGNOSTIC_POSITIVE_ACK,
    _is_response_pending,
)

TESTER, ECU = 0x0E00, 0x0001


def run(coro):
    """
    Run a coroutine synchronously (helper for pytest without async plugin).

    Outstanding reads are cancelled and drained before the loop closes — every
    test here deliberately leaves a read in flight, and without this each one
    prints "Task was destroyed but it is pending" into the next test's output.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for t in pending:
            t.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


def frame(payload_type: int, payload: bytes) -> bytes:
    return struct.pack("!BBHI", 0x02, 0xFD, payload_type, len(payload)) + payload


def diag(uds: bytes, src: int = ECU, tgt: int = TESTER) -> bytes:
    return frame(PT_DIAGNOSTIC_MESSAGE, struct.pack("!HH", src, tgt) + uds)


def ack() -> bytes:
    return frame(PT_DIAGNOSTIC_POSITIVE_ACK,
                 struct.pack("!HHB", TESTER, ECU, 0x00))


# ---------------------------------------------------------------------------
# _is_response_pending
# ---------------------------------------------------------------------------

class TestIsResponsePending:
    def test_detects_7f_xx_78(self):
        assert _is_response_pending(diag(b"\x7F\x31\x78"))

    def test_rejects_a_final_positive_response(self):
        assert not _is_response_pending(diag(b"\x71\x01\x02\x03\x00"))

    def test_rejects_another_negative_response(self):
        # 7F 31 22 conditionsNotCorrect is final, not pending
        assert not _is_response_pending(diag(b"\x7F\x31\x22"))

    def test_rejects_a_positive_ack(self):
        assert not _is_response_pending(ack())

    def test_rejects_a_short_frame(self):
        assert not _is_response_pending(frame(PT_DIAGNOSTIC_MESSAGE, b"\x00\x01"))

    def test_rejects_a_payload_that_merely_contains_78(self):
        # 62 F1 78 is ReadDataByIdentifier data, not a pending frame
        assert not _is_response_pending(diag(b"\x62\xF1\x78"))


# ---------------------------------------------------------------------------
# The read loop
# ---------------------------------------------------------------------------

class FakeECUConnection:
    """
    Serves a scripted list of frames, then blocks like a quiet socket.

    Each entry is either ``frame`` or ``(frame, delay_before_it)`` so a test can
    make one specific frame slow.  The delay is awaited *before* the frame is
    taken off the list, mirroring the real queue-backed ECUConnection.recv():
    cancelling a read in flight never consumes anything.
    """

    def __init__(self, frames, delay: float = 0.0):
        self._frames = [f if isinstance(f, tuple) else (f, delay) for f in frames]
        self.sent: list = []

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def recv(self) -> bytes:
        if not self._frames:
            await asyncio.sleep(3600)          # quiet socket
        if self._frames[0][1]:
            await asyncio.sleep(self._frames[0][1])
        return self._frames.pop(0)[0]


class Harness:
    """
    The follow-up read loop, lifted verbatim in structure from
    DoIPSession._handle_diagnostic, with the relay captured instead of sent.
    """

    def __init__(self, conn, request_sid, *, per_frame=0.2, budget=2.0,
                 strict=True):
        self.conn = conn
        self.request_sid = request_sid
        self.per_frame = per_frame
        self.budget = budget
        self.strict = strict
        self.relayed: list = []
        self._read_task = None

    async def _relay(self, raw: bytes) -> None:
        self.relayed.append(raw[12:])

    async def _recv(self, timeout):
        """Mirrors DoIPSession._recv_ecu_frame: never cancels a read in flight."""
        if self._read_task is None:
            self._read_task = asyncio.ensure_future(self.conn.recv())
        try:
            return await asyncio.wait_for(
                asyncio.shield(self._read_task), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            if self._read_task is not None and self._read_task.done():
                self._read_task = None

    def _matches(self, raw: bytes) -> bool:
        if self.request_sid is None or len(raw) < 13:
            return True
        sid = raw[12]
        if sid == (self.request_sid | 0x40):
            return True
        if sid == 0x7F and len(raw) >= 14 and raw[13] == self.request_sid:
            return True
        return not self.strict

    async def run(self):
        first = await self.conn.recv()
        await self._relay(first)
        if int.from_bytes(first[2:4], "big") != PT_DIAGNOSTIC_POSITIVE_ACK:
            return
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.budget
        pending = 0
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            raw = await self._recv(min(self.per_frame, remaining))
            if raw is None:
                if pending:
                    continue
                return
            if _is_response_pending(raw):
                pending += 1
                await self._relay(raw)
                continue
            if not self._matches(raw):
                return
            await self._relay(raw)
            return


def hexes(frames):
    return [f.hex(" ").upper() for f in frames]


class TestFollowUpLoop:
    def test_two_frame_exchange_still_works(self):
        """The ordinary ACK + response case must be unchanged."""
        h = Harness(FakeECUConnection([ack(), diag(b"\x62\xF1\x90ABC")]), 0x22)
        run(h.run())
        assert hexes(h.relayed)[1].startswith("62 F1 90")

    def test_pending_then_final_is_fully_relayed(self):
        """The bug: the third frame used to be stranded."""
        h = Harness(FakeECUConnection(
            [ack(), diag(b"\x7F\x31\x78"), diag(b"\x71\x01\x02\x03\x00")]), 0x31)
        run(h.run())
        assert hexes(h.relayed)[1:] == ["7F 31 78", "71 01 02 03 00"]

    def test_many_pendings_are_all_relayed(self):
        h = Harness(FakeECUConnection(
            [ack()] + [diag(b"\x7F\x31\x78")] * 5 + [diag(b"\x71\x01\x02\x03\x00")]),
            0x31)
        run(h.run())
        assert hexes(h.relayed).count("7F 31 78") == 5
        assert hexes(h.relayed)[-1] == "71 01 02 03 00"

    def test_pending_survives_a_gap_longer_than_the_per_frame_timeout(self):
        """
        Once the ECU has said 0x78 it has promised an answer, so a gap longer
        than the per-frame timeout must NOT abandon the exchange — only the
        whole-exchange budget may.  This is the 2 s routine case.
        """
        conn = FakeECUConnection([
            ack(),
            diag(b"\x7F\x31\x78"),
            (diag(b"\x71\x01\x02\x03\x00"), 0.25),   # far longer than per_frame
        ])
        h = Harness(conn, 0x31, per_frame=0.02, budget=3.0)
        run(h.run())
        assert hexes(h.relayed)[-1] == "71 01 02 03 00"

    def test_slow_response_without_a_pending_still_times_out(self):
        """No 0x78 means no promise — the old per-frame timeout still applies."""
        conn = FakeECUConnection([ack(), (diag(b"\x62\xF1\x90A"), 0.5)])
        h = Harness(conn, 0x22, per_frame=0.05, budget=3.0)
        run(h.run())
        assert len(h.relayed) == 1                  # only the ACK

    def test_budget_caps_an_ecu_that_pends_forever(self):
        h = Harness(FakeECUConnection([ack()] + [diag(b"\x7F\x31\x78")] * 500),
                    0x31, per_frame=0.01, budget=0.2)
        run(h.run())
        assert hexes(h.relayed)[-1] == "7F 31 78"     # gave up, never hung

    def test_silent_ecu_after_ack_returns_promptly(self):
        h = Harness(FakeECUConnection([ack()]), 0x22, per_frame=0.05, budget=1.0)
        run(h.run())
        assert len(h.relayed) == 1

    def test_final_negative_response_ends_the_loop(self):
        h = Harness(FakeECUConnection(
            [ack(), diag(b"\x7F\x31\x78"), diag(b"\x7F\x31\x22")]), 0x31)
        run(h.run())
        assert hexes(h.relayed)[-1] == "7F 31 22"


class TestResponseMatching:
    def test_positive_response_to_our_request_is_accepted(self):
        h = Harness(FakeECUConnection([ack(), diag(b"\x62\xF1\x90A")]), 0x22)
        run(h.run())
        assert len(h.relayed) == 2

    def test_negative_response_to_our_request_is_accepted(self):
        h = Harness(FakeECUConnection([ack(), diag(b"\x7F\x22\x31")]), 0x22)
        run(h.run())
        assert hexes(h.relayed)[-1] == "7F 22 31"

    def test_a_stale_answer_to_another_request_is_dropped(self):
        """The desync symptom: 71 ... must not be delivered as an answer to 0x22."""
        h = Harness(FakeECUConnection([ack(), diag(b"\x71\x01\x02\x03\x00")]), 0x22)
        run(h.run())
        assert len(h.relayed) == 1                 # only the ACK

    def test_mismatch_is_forwarded_when_strict_matching_is_off(self):
        h = Harness(FakeECUConnection([ack(), diag(b"\x71\x01\x02\x03\x00")]),
                    0x22, strict=False)
        run(h.run())
        assert hexes(h.relayed)[-1] == "71 01 02 03 00"


class TestConfigDefaults:
    def test_timer_defaults_are_present(self):
        from config import TimerConfig
        t = TimerConfig(t_tcp_initial_inactivity_s=2,
                        t_tcp_general_inactivity_s=300,
                        alive_check_interval_ms=500)
        assert t.ecu_response_timeout_s == 2.0
        assert t.ecu_pending_max_wait_s == 30.0
        assert t.strict_response_matching is True

    def test_timers_are_read_from_yaml(self):
        import config as cfgmod
        t = cfgmod._load_timers({
            "t_tcp_initial_inactivity_s": 2,
            "t_tcp_general_inactivity_s": 300,
            "ecu_pending_max_wait_s": 90,
            "strict_response_matching": False,
        })
        assert t.ecu_pending_max_wait_s == 90.0
        assert t.strict_response_matching is False
        assert t.ecu_response_timeout_s == 2.0     # default still applied
