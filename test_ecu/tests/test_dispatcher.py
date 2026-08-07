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

"""The precedence ladder, handler isolation, and the automatic 0x78 path."""

from __future__ import annotations

import asyncio
import os
import re

from conftest import probe_for
from testecu import (
    NO_RESPONSE,
    NRC_CONDITIONS_NOT_CORRECT,
    Plugin,
    on_request,
    on_service,
    read_did,
    routine,
    write_did,
)

DIDS = {
    0xF190: {"type": "ascii", "length": 17, "value": "1HGBH41JXMN109186"},
    0x0100: {"type": "hex", "length": 4, "value": "DEADBEEF", "write": True},
}
CONFIG = {"data_identifiers": DIDS}


def hx(data):
    return None if data is None else data.hex(" ").upper()


# ---------------------------------------------------------------------------
# Precedence
# ---------------------------------------------------------------------------

class DidPlugin(Plugin):
    name = "DidPlugin"
    priority = 50

    @read_did(0xF190)
    def vin(self, req, ctx):
        return b"PLUGINVIN00000000"


class ServicePlugin(Plugin):
    name = "ServicePlugin"
    priority = 50

    @on_service(0x22)
    def read(self, req, ctx):
        return req.positive(b"\xAA\xAA")


class CatchAllPlugin(Plugin):
    name = "CatchAllPlugin"
    priority = 90

    @on_service()
    def anything(self, req, ctx):
        return req.positive(b"\xCC")


class TestPrecedence:
    def test_did_handler_beats_the_yaml_table(self):
        assert hx(probe_for(CONFIG, [DidPlugin()]).send("22 F1 90")) == \
            "62 F1 90 " + b"PLUGINVIN00000000".hex(" ").upper()

    def test_service_handler_beats_the_did_handler(self):
        p = probe_for(CONFIG, [DidPlugin(), ServicePlugin()])
        assert hx(p.send("22 F1 90")) == "62 AA AA"

    def test_specific_service_runs_before_the_catch_all(self):
        p = probe_for(CONFIG, [CatchAllPlugin(), ServicePlugin()])
        assert hx(p.send("22 F1 90")) == "62 AA AA"

    def test_catch_all_beats_the_core(self):
        assert hx(probe_for(CONFIG, [CatchAllPlugin()]).send("3E 00")) == "7E CC"

    def test_yaml_is_used_when_no_handler_claims_the_did(self):
        assert hx(probe_for(CONFIG, [DidPlugin()]).send("22 01 00")) == \
            "62 01 00 DE AD BE EF"

    def test_lower_priority_number_runs_first(self):
        class First(Plugin):
            name = "First"
            priority = 10

            @on_service(0x22)
            def read(self, req, ctx):
                return req.positive(b"\x01")

        class Second(Plugin):
            name = "Second"
            priority = 20

            @on_service(0x22)
            def read(self, req, ctx):
                return req.positive(b"\x02")

        assert hx(probe_for(CONFIG, [Second(), First()]).send("22 F1 90")) == "62 01"


class TestFallThrough:
    def test_returning_none_hands_over_to_the_next_candidate(self):
        class Passive(Plugin):
            name = "Passive"

            @read_did(0xF190)
            def vin(self, req, ctx):
                return None

            @on_service(0x22)
            def read(self, req, ctx):
                return None

        assert hx(probe_for(CONFIG, [Passive()]).send("22 01 00")) == \
            "62 01 00 DE AD BE EF"

    def test_no_response_stops_the_ladder_and_sends_nothing(self):
        class Silent(Plugin):
            name = "Silent"

            @on_service()
            def swallow(self, req, ctx):
                return NO_RESPONSE

        assert probe_for(CONFIG, [Silent()]).send("22 F1 90") is None

    def test_negative_response_from_a_handler(self):
        class Grumpy(Plugin):
            name = "Grumpy"

            @read_did(0xF190)
            def vin(self, req, ctx):
                raise ctx.nrc(NRC_CONDITIONS_NOT_CORRECT, "nope")

        assert hx(probe_for(CONFIG, [Grumpy()]).send("22 F1 90")) == "7F 22 22"


class TestHandlerKinds:
    def test_async_and_sync_handlers_both_work(self):
        class Mixed(Plugin):
            name = "Mixed"

            @read_did(0x0300)
            async def slow(self, req, ctx):
                await asyncio.sleep(0)
                return b"\xA5"

            @read_did(0x0301)
            def fast(self, req, ctx):
                return b"\x5A"

        p = probe_for(CONFIG, [Mixed()])
        assert hx(p.send("22 03 00")) == "62 03 00 A5"
        assert hx(p.send("22 03 01")) == "62 03 01 5A"

    def test_write_handler_receives_the_value(self):
        seen = {}

        class Writer(Plugin):
            name = "Writer"

            @write_did(0x0400)
            def write(self, value, req, ctx):
                seen["value"] = value
                return True

        assert hx(probe_for(CONFIG, [Writer()]).send("2E 04 00 DE AD")) == "6E 04 00"
        assert seen["value"] == b"\xDE\xAD"

    def test_routine_handler_receives_control_and_data(self):
        seen = {}

        class Runner(Plugin):
            name = "Runner"

            @routine(0x0500)
            def run_it(self, control, data, req, ctx):
                seen["control"] = control
                seen["data"] = data
                return b"\x00\x11"

        assert hx(probe_for(CONFIG, [Runner()]).send("31 01 05 00 AB")) == \
            "71 01 05 00 00 11"
        assert seen == {"control": 0x01, "data": b"\xAB"}

    def test_routine_can_be_bound_to_one_sub_function(self):
        class OnlyStart(Plugin):
            name = "OnlyStart"

            @routine(0x0500, control=0x01)
            def start(self, control, data, req, ctx):
                return b"\x01"

        p = probe_for(CONFIG, [OnlyStart()])
        assert hx(p.send("31 01 05 00")) == "71 01 05 00 01"
        assert hx(p.send("31 03 05 00")) == "7F 31 31"     # no handler, no YAML entry

    def test_observers_run_and_cannot_change_the_response(self):
        calls = []

        class Watcher(Plugin):
            name = "Watcher"

            @on_request()
            def watch(self, req, ctx):
                calls.append(req.sid)
                return b"\xFF\xFF"        # ignored on purpose

        assert hx(probe_for(CONFIG, [Watcher()]).send("3E 00")) == "7E 00"
        assert calls == [0x3E]

    def test_ctx_send_emits_an_extra_frame_before_the_final_one(self):
        class Chatty(Plugin):
            name = "Chatty"

            @on_service(0x22)
            async def read(self, req, ctx):
                await ctx.send(b"\x62\x00\x01\xAA")
                return req.positive(b"\x00\x02\xBB")

        p = probe_for(CONFIG, [Chatty()])
        assert hx(p.send("22 F1 90")) == "62 00 02 BB"
        assert [hx(frame) for frame in p.extra] == ["62 00 01 AA"]


class TestErrorIsolation:
    def _exploding(self):
        class Boom(Plugin):
            name = "Boom"

            @read_did(0xF190)
            def vin(self, req, ctx):
                raise ValueError("kaboom")

        return Boom()

    def test_default_policy_turns_an_exception_into_conditions_not_correct(self):
        assert hx(probe_for(CONFIG, [self._exploding()]).send("22 F1 90")) == "7F 22 22"

    def test_the_session_survives_a_raising_handler(self):
        p = probe_for(CONFIG, [self._exploding()])
        responses = p.exchange("22 F1 90", "22 01 00", "3E 00")
        assert hx(responses[0]) == "7F 22 22"
        assert hx(responses[1]) == "62 01 00 DE AD BE EF"
        assert hx(responses[2]) == "7E 00"

    def test_fallthrough_policy_continues_down_the_ladder(self):
        p = probe_for(dict(CONFIG, uds={"on_handler_error": "fallthrough"}),
                      [self._exploding()])
        assert hx(p.send("22 F1 90")).startswith("62 F1 90 31 48")

    def test_silent_policy_sends_nothing(self):
        p = probe_for(dict(CONFIG, uds={"on_handler_error": "silent"}),
                      [self._exploding()])
        assert p.send("22 F1 90") is None

    def test_an_observer_that_raises_is_ignored_entirely(self):
        class BadWatcher(Plugin):
            name = "BadWatcher"

            @on_request()
            def watch(self, req, ctx):
                raise RuntimeError("observer blew up")

        assert hx(probe_for(CONFIG, [BadWatcher()]).send("3E 00")) == "7E 00"

    def test_a_handler_returning_the_wrong_type_is_skipped(self):
        class Confused(Plugin):
            name = "Confused"

            @read_did(0xF190)
            def vin(self, req, ctx):
                return "a string, not bytes"

        # falls through to the YAML table rather than sending garbage
        assert hx(probe_for(CONFIG, [Confused()]).send("22 F1 90")).startswith(
            "62 F1 90 31 48")


class TestResponsePending:
    def test_slow_handler_gets_an_automatic_0x78(self):
        class Slow(Plugin):
            name = "Slow"

            @on_service(0x22)
            async def read(self, req, ctx):
                await asyncio.sleep(0.12)          # p2_server_ms is 20 in BASE_CONFIG
                return req.positive(b"\x01")

        p = probe_for(CONFIG, [Slow()])
        assert hx(p.send("22 F1 90")) == "62 01"
        assert p.extra and all(hx(frame) == "7F 22 78" for frame in p.extra)

    def test_it_can_be_switched_off(self):
        class Slow(Plugin):
            name = "Slow"

            @on_service(0x22)
            async def read(self, req, ctx):
                await asyncio.sleep(0.08)
                return req.positive(b"\x01")

        p = probe_for(dict(CONFIG, uds={"auto_response_pending": False}), [Slow()])
        assert hx(p.send("22 F1 90")) == "62 01"
        assert p.extra == []

    def test_the_handler_is_never_cancelled_by_the_p2_timeout(self):
        finished = []

        class Slow(Plugin):
            name = "Slow"

            @on_service(0x22)
            async def read(self, req, ctx):
                await asyncio.sleep(0.1)
                finished.append(True)
                return req.positive(b"\x01")

        probe_for(CONFIG, [Slow()]).send("22 F1 90")
        assert finished == [True]


class TestDeterminism:
    def test_the_same_request_twice_gives_identical_bytes(self):
        for policy in ("nrc", "echo", "silent"):
            config = dict(CONFIG, uds={"unknown_service": policy,
                                       "unknown_did": policy})
            for request in ("22 F1 90", "22 99 99", "99 11 22", "27 01", "3E 00"):
                first = probe_for(config).send(request)
                second = probe_for(config).send(request)
                assert first == second, "%s is non-deterministic under %r" % (
                    request, policy)

    def test_no_module_uses_a_random_source(self):
        """A simulator you cannot assert against is not a simulator."""
        package = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "testecu")
        offenders = []
        for root, _dirs, files in os.walk(package):
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(root, name)
                with open(path) as handle:
                    body = handle.read()
                # Comments explaining why we do NOT use randomness are fine.
                code = "\n".join(line.split("#")[0] for line in body.splitlines())
                if re.search(r"\burandom\b|\brandom\.", code):
                    offenders.append(path)
        assert offenders == []


class TestIntrospection:
    def test_describe_lists_every_hook_in_dispatch_order(self):
        ecu = probe_for(CONFIG, [CatchAllPlugin(), ServicePlugin(), DidPlugin()]).ecu
        lines = ecu.dispatcher.describe()
        joined = "\n".join(lines)
        assert "service 0x22" in joined
        assert "service <any>" in joined
        assert "read_did 0xF190" in joined
        # specific service before the catch-all
        assert joined.index("service 0x22") < joined.index("service <any>")

    def test_duplicate_claims_are_warned_about(self, caplog):
        class Other(DidPlugin):
            name = "Other"

        probe_for(CONFIG, [DidPlugin(), Other()])
        assert any("claimed by 2 plugins" in record.message
                   for record in caplog.records)
