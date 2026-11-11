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
Failure paths of plugin ``setup()`` / ``teardown()`` as driven by ``EcuCore``.

The oracle is a call-order list written out literally in each test and filled
by recording plugins -- never anything computed from the production loop.
Whether plugins that already ran ``setup()`` are torn down when a strict
start-up aborts is an open design question, so no test here asserts anything
about teardown after a failed start-up (the recorded lists are filtered to the
calls the test is actually about).
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from conftest import make_ecu, run
from virtecu import Plugin

STRICT = {"plugins": {"strict": True}}


class Recording(Plugin):
    """Appends ``<name>.setup`` / ``<name>.teardown`` to a shared list, then may raise."""

    def __init__(self, calls, name, setup_raises=None, teardown_raises=None):
        super().__init__(name=name)
        self.calls = calls
        self.setup_raises = setup_raises
        self.teardown_raises = teardown_raises

    async def setup(self, ecu):
        self.calls.append("%s.setup" % self.name)
        if self.setup_raises is not None:
            raise self.setup_raises

    async def teardown(self, ecu):
        self.calls.append("%s.teardown" % self.name)
        if self.teardown_raises is not None:
            raise self.teardown_raises


def setups(calls):
    return [call for call in calls if call.endswith(".setup")]


def error_records(caplog):
    return [record for record in caplog.records if record.levelno >= logging.ERROR]


# ---------------------------------------------------------------------------
# setup() failures
# ---------------------------------------------------------------------------

class TestSetupFailure:
    def test_non_strict_logs_and_still_sets_up_the_next_plugin(self, caplog):
        calls = []
        plugins = [
            Recording(calls, "first"),
            Recording(calls, "broken", setup_raises=RuntimeError("boom in setup")),
            Recording(calls, "last"),
        ]
        ecu = make_ecu(plugins=plugins)

        with caplog.at_level(logging.ERROR):
            run(ecu.startup())                    # must complete, not raise

        assert calls == ["first.setup", "broken.setup", "last.setup"]
        records = error_records(caplog)
        assert len(records) == 1
        assert "broken" in records[0].getMessage()
        assert "setup" in records[0].getMessage()
        assert records[0].exc_info is not None
        assert isinstance(records[0].exc_info[1], RuntimeError)

    def test_non_strict_failure_of_the_first_plugin_does_not_stop_the_rest(self, caplog):
        calls = []
        plugins = [
            Recording(calls, "broken", setup_raises=ValueError("first fails")),
            Recording(calls, "second"),
            Recording(calls, "third"),
        ]
        ecu = make_ecu(plugins=plugins)

        with caplog.at_level(logging.ERROR):
            run(ecu.startup())

        assert calls == ["broken.setup", "second.setup", "third.setup"]
        assert len(error_records(caplog)) == 1

    def test_strict_reraises_the_original_exception_and_skips_later_plugins(self):
        calls = []
        original = RuntimeError("strict boom")
        plugins = [
            Recording(calls, "first"),
            Recording(calls, "broken", setup_raises=original),
            Recording(calls, "last"),
        ]
        ecu = make_ecu(STRICT, plugins=plugins)

        with pytest.raises(RuntimeError) as excinfo:
            run(ecu.startup())

        assert excinfo.value is original
        # Only the setup calls are judged: what a strict abort does about the
        # teardown of plugins that already started is deliberately unpinned.
        assert setups(calls) == ["first.setup", "broken.setup"]

    def test_strict_with_all_plugins_healthy_sets_up_every_plugin_in_order(self):
        calls = []
        ecu = make_ecu(STRICT, plugins=[Recording(calls, "a"), Recording(calls, "b"),
                                        Recording(calls, "c")])

        run(ecu.startup())

        assert calls == ["a.setup", "b.setup", "c.setup"]


# ---------------------------------------------------------------------------
# teardown() failures
# ---------------------------------------------------------------------------

class TestTeardownFailure:
    def test_failing_teardown_is_logged_and_the_remaining_teardowns_still_run(self, caplog):
        calls = []
        plugins = [
            Recording(calls, "a"),
            Recording(calls, "b", teardown_raises=RuntimeError("boom in teardown")),
            Recording(calls, "c"),
        ]
        ecu = make_ecu(plugins=plugins)

        with caplog.at_level(logging.ERROR):
            run(ecu.shutdown())                   # must not raise

        # Teardown follows the plugin list order (not reversed).
        assert calls == ["a.teardown", "b.teardown", "c.teardown"]
        records = error_records(caplog)
        assert len(records) == 1
        assert "plugin b:" in records[0].getMessage()
        assert "teardown" in records[0].getMessage()
        assert isinstance(records[0].exc_info[1], RuntimeError)

    def test_every_teardown_failing_is_logged_once_each_and_none_is_skipped(self, caplog):
        calls = []
        plugins = [
            Recording(calls, "a", teardown_raises=ValueError("a")),
            Recording(calls, "b", teardown_raises=KeyError("b")),
        ]
        ecu = make_ecu(plugins=plugins)

        with caplog.at_level(logging.ERROR):
            run(ecu.shutdown())

        assert calls == ["a.teardown", "b.teardown"]
        assert len(error_records(caplog)) == 2

    def test_strict_mode_does_not_make_a_teardown_failure_raise(self, caplog):
        calls = []
        plugins = [
            Recording(calls, "a", teardown_raises=RuntimeError("a")),
            Recording(calls, "b"),
        ]
        ecu = make_ecu(STRICT, plugins=plugins)

        with caplog.at_level(logging.ERROR):
            run(ecu.shutdown())

        assert calls == ["a.teardown", "b.teardown"]
        assert len(error_records(caplog)) == 1


# ---------------------------------------------------------------------------
# Cancellation is not a plugin failure
# ---------------------------------------------------------------------------

class TestCancellation:
    @pytest.mark.parametrize("strict", [False, True], ids=["non_strict", "strict"])
    def test_cancelled_error_in_setup_propagates_and_stops_start_up(self, strict, caplog):
        calls = []
        plugins = [
            Recording(calls, "first"),
            Recording(calls, "cancelled", setup_raises=asyncio.CancelledError()),
            Recording(calls, "last"),
        ]
        ecu = make_ecu(STRICT if strict else None, plugins=plugins)

        with caplog.at_level(logging.ERROR):
            with pytest.raises(asyncio.CancelledError):
                run(ecu.startup())

        assert setups(calls) == ["first.setup", "cancelled.setup"]
        assert error_records(caplog) == []        # not reported as a plugin fault

    def test_cancelled_error_in_teardown_propagates_and_is_not_logged_as_a_fault(self, caplog):
        calls = []
        plugins = [
            Recording(calls, "a"),
            Recording(calls, "cancelled", teardown_raises=asyncio.CancelledError()),
            Recording(calls, "c"),
        ]
        ecu = make_ecu(plugins=plugins)

        with caplog.at_level(logging.ERROR):
            with pytest.raises(asyncio.CancelledError):
                run(ecu.shutdown())

        # The plugin after the cancelled one is not reached.
        assert calls == ["a.teardown", "cancelled.teardown"]
        assert error_records(caplog) == []


# ---------------------------------------------------------------------------
# Repeated shutdown and restart
# ---------------------------------------------------------------------------

class TestShutdownRepeatAndRestart:
    def test_second_shutdown_runs_no_teardown_again(self):
        calls = []
        ecu = make_ecu(plugins=[Recording(calls, "a"), Recording(calls, "b")])

        async def scenario():
            await ecu.startup()
            await ecu.shutdown()
            await ecu.shutdown()

        run(scenario())

        assert calls == ["a.setup", "b.setup", "a.teardown", "b.teardown"]

    def test_startup_after_shutdown_sets_up_again_and_rearms_teardown(self):
        calls = []
        ecu = make_ecu(plugins=[Recording(calls, "a"), Recording(calls, "b")])

        async def scenario():
            await ecu.startup()
            await ecu.shutdown()
            await ecu.startup()
            await ecu.shutdown()
            await ecu.shutdown()

        run(scenario())

        assert calls == [
            "a.setup", "b.setup", "a.teardown", "b.teardown",
            "a.setup", "b.setup", "a.teardown", "b.teardown",
        ]
