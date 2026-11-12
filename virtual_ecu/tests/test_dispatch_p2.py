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
``_dispatch_with_p2`` against a handler that finishes at the edge of a P2 window.

The function must decide from the handler task, never from the window timer:
a handler that completes in the same event-loop iteration in which the window
expires has to have its result returned, with no extra ``7F <sid> 78`` in
front of it and no give-up (``7F <sid> 10``) in place of it.

The scenarios drive the real function with a small fake ECU (the few
attributes it reads) and a fake dispatcher, so the oracle is only what the
responder saw and what the function returned. Expected frames are hand-written
byte literals. The "same iteration" cases stall the event loop with a
blocking ``time.sleep`` so that the handler's wake-up and the window timer are
both overdue when the loop next looks at its timers -- that makes the overlap
deterministic instead of depending on scheduling luck.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from conftest import run
from virtecu.session import _dispatch_with_p2
from virtecu.uds import NO_RESPONSE, UdsRequest

RESULT = b"\x62\xF1\x90\x01"
PENDING = b"\x7F\x22\x78"
REJECT = b"\x7F\x22\x10"


class Boom(Exception):
    """Raised by the fake handler to prove exceptions pass through untouched."""


class Rig:
    """A fake ECU + dispatcher + responder around one ``_dispatch_with_p2`` call."""

    def __init__(self, handler_s=None, *, p2_ms=20, p2_star_ms=500, cap=10,
                 auto=True, raises=False):
        self.uds = SimpleNamespace(auto_response_pending=auto, p2_server_ms=p2_ms,
                                   p2_star_server_ms=p2_star_ms,
                                   max_response_pending=cap)
        self.handler_s = handler_s          # None = never finishes
        self.raises = raises
        self.finished = False
        self.cancelled = False              # handler saw a cancellation ...
        self.cancelled_live = None          # ... as of just before run() cleanup
        self.finished_when_rejected = None
        self.frames = []
        self.stamps = []
        self.ecu = SimpleNamespace(
            uds=self.uds, dispatcher=SimpleNamespace(dispatch=self._dispatch))
        self.request = UdsRequest(raw=b"\x22\xF1\x90", source_addr=0x0E00,
                                  target_addr=0x0002)

    async def _dispatch(self, request, state, responder):
        try:
            if self.handler_s is None:
                await asyncio.Event().wait()
            await asyncio.sleep(self.handler_s)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        self.finished = True
        if self.raises:
            raise Boom("handler failed")
        return RESULT

    async def responder(self, payload):
        self.frames.append(bytes(payload))
        self.stamps.append(time.monotonic())
        if bytes(payload) == REJECT:
            self.finished_when_rejected = self.finished

    def call(self):
        return _dispatch_with_p2(self.ecu, object(), self.request, self.responder)


def stall(at_s, for_s):
    """Block the whole loop for ``for_s`` seconds, starting ``at_s`` from now."""
    asyncio.get_running_loop().call_later(at_s, time.sleep, for_s)


def drive(rig):
    async def scenario():
        result = await rig.call()
        await asyncio.sleep(0.02)           # let a cancelled handler observe it
        rig.cancelled_live = rig.cancelled  # run() cancels leftovers afterwards
        return result
    return run(scenario())


class TestSameIterationCompletion:
    def test_no_pending_frame_when_the_handler_finishes_with_the_first_window(self):
        rig = Rig(handler_s=0.030, p2_ms=40)

        async def scenario():
            stall(0.010, 0.080)             # both timers overdue together
            return await rig.call()

        assert run(scenario()) == RESULT
        assert rig.frames == []             # a spurious 7F 22 78 would be here

    def test_result_survives_with_the_pending_cap_already_reached(self):
        # cap 1: the first window yields the one allowed pending frame; the
        # handler (ready at 70 ms) and the second window (36 ms after the
        # first, so about 76 ms) both come due while the loop is stalled.
        rig = Rig(handler_s=0.070, p2_ms=40, p2_star_ms=40, cap=1)

        async def scenario():
            stall(0.055, 0.080)
            return await rig.call()

        assert run(scenario()) == RESULT
        assert rig.frames == [PENDING]      # no 7F 22 10, result not dropped
        assert rig.finished_when_rejected is None
        assert not rig.cancelled

    def test_handler_error_in_the_same_iteration_is_raised_without_a_pending_frame(self):
        rig = Rig(handler_s=0.030, p2_ms=40, raises=True)

        async def scenario():
            stall(0.010, 0.080)
            await rig.call()

        with pytest.raises(Boom):
            run(scenario())
        assert rig.frames == []


class TestControls:
    def test_a_fast_handler_gets_no_pending_frame(self):
        rig = Rig(handler_s=0.005, p2_ms=100)
        assert drive(rig) == RESULT
        assert rig.frames == []

    def test_a_handler_slower_than_one_window_gets_exactly_one_pending_frame(self):
        rig = Rig(handler_s=0.060, p2_ms=30, p2_star_ms=500)
        assert drive(rig) == RESULT
        assert rig.frames == [PENDING]
        assert rig.finished and rig.cancelled_live is False

    def test_a_handler_that_never_finishes_is_given_up_at_the_cap(self):
        rig = Rig(handler_s=None, p2_ms=20, p2_star_ms=20, cap=2)
        assert drive(rig) is NO_RESPONSE
        assert rig.frames == [PENDING, PENDING, REJECT]
        assert rig.cancelled_live is True

    def test_cap_of_one_allows_exactly_one_pending_frame(self):
        rig = Rig(handler_s=None, p2_ms=20, p2_star_ms=20, cap=1)
        assert drive(rig) is NO_RESPONSE
        assert rig.frames == [PENDING, REJECT]
        assert rig.cancelled_live is True

    def test_cap_zero_means_no_cap_pending_frames_keep_coming(self):
        # Pins today's behaviour: 0 disables the cap, so a slow handler is
        # answered with a pending frame per window until it finishes.
        rig = Rig(handler_s=0.120, p2_ms=20, p2_star_ms=20, cap=0)
        assert drive(rig) == RESULT
        assert len(rig.frames) >= 3
        assert set(rig.frames) == {PENDING}
        assert rig.finished and rig.cancelled_live is False

    def test_pending_frames_off_switch_waits_silently(self):
        rig = Rig(handler_s=0.080, p2_ms=20, auto=False)
        assert drive(rig) == RESULT
        assert rig.frames == []
        assert rig.finished

    def test_pending_frames_off_switch_propagates_handler_errors(self):
        rig = Rig(handler_s=0.010, auto=False, raises=True)
        with pytest.raises(Boom):
            drive(rig)
        assert rig.frames == []

    def test_a_handler_error_propagates_after_a_pending_frame(self):
        rig = Rig(handler_s=0.050, p2_ms=20, p2_star_ms=500, raises=True)
        with pytest.raises(Boom):
            drive(rig)
        assert rig.frames == [PENDING]

    def test_a_handler_error_inside_the_first_window_propagates(self):
        rig = Rig(handler_s=0.005, p2_ms=100, raises=True)
        with pytest.raises(Boom):
            drive(rig)
        assert rig.frames == []

    @pytest.mark.parametrize("cancel_after_s, frames", [(0.005, []), (0.045, [PENDING])])
    def test_cancelling_the_caller_cancels_the_handler(self, cancel_after_s, frames):
        rig = Rig(handler_s=None, p2_ms=20, p2_star_ms=500, cap=10)

        async def scenario():
            caller = asyncio.ensure_future(rig.call())
            await asyncio.sleep(cancel_after_s)
            caller.cancel()
            with pytest.raises(asyncio.CancelledError):
                await caller
            await asyncio.sleep(0.02)
            rig.cancelled_live = rig.cancelled      # before run() cleans up

        run(scenario())
        assert rig.cancelled_live is True
        assert rig.frames == frames

    def test_the_window_after_the_first_pending_frame_is_ninety_percent_of_p2_star(self):
        # Never-finishing handler, cap 1: the gap between the pending frame and
        # the give-up frame is the second window. 90% of 400 ms is 360 ms; a
        # timer can only be late, never early, so the lower bound is firm and
        # the upper bound (a full 400 ms window would exceed it) has 35 ms of
        # scheduling slack.
        rig = Rig(handler_s=None, p2_ms=20, p2_star_ms=400, cap=1)
        assert drive(rig) is NO_RESPONSE
        assert rig.frames == [PENDING, REJECT]
        gap = rig.stamps[1] - rig.stamps[0]
        assert 0.355 <= gap < 0.395

    def test_the_second_window_is_far_longer_than_p2(self):
        rig = Rig(handler_s=0.150, p2_ms=20, p2_star_ms=500, cap=1)
        assert drive(rig) == RESULT
        assert rig.frames == [PENDING]


class TestNaturalSweep:
    def test_a_handler_finishing_around_the_second_window_is_never_given_up_on(self):
        # No artificial stall: the handler's ready time walks across the end of
        # the second window (about 38 ms: 20 ms, then 90% of 20 ms). A give-up
        # is wrong exactly when the handler had already finished at the moment
        # the reject frame went out.
        spurious = []

        async def sweep():
            for step in range(37):
                ready = 0.036 + step * 0.00025
                rig = Rig(handler_s=ready, p2_ms=20, p2_star_ms=20, cap=1)
                result = await rig.call()
                await asyncio.sleep(0.005)
                if rig.frames == [PENDING, REJECT]:
                    assert result is NO_RESPONSE
                    if rig.finished_when_rejected:
                        spurious.append(round(ready * 1000, 2))
                else:
                    assert rig.frames == [PENDING]
                    assert result == RESULT

        run(sweep())
        assert spurious == []
