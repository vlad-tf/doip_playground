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
Start-up, shutdown and ownership of long-lived resources.

The oracle throughout is what the event loop and the operating system can see
(``asyncio.all_tasks()``, a refused connect, a closed file descriptor, a
recording plugin's own call list) -- never the production shutdown path
judging itself.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

import virtecu.server as server_module
from conftest import make_ecu, merge, run
from virtecu import Plugin
from virtecu.server import VirtualEcuServer

LOOPBACK_V4 = {"listen": {"host": "127.0.0.1", "family": "ipv4", "port": 0},
               "udp": {"enabled": False}}


def pending_tasks():
    """Every unfinished task except the one running the calling test."""
    current = asyncio.current_task()
    return [task for task in asyncio.all_tasks() if task is not current and not task.done()]


def s3_tasks():
    return [task for task in pending_tasks() if task.get_coro().__name__ == "_s3_expiry"]


class Recorder(Plugin):
    """Records its own setup/teardown calls into a shared list."""

    def __init__(self, calls, name="rec", on_teardown=None):
        super().__init__(name=name)
        self.calls = calls
        self.on_teardown = on_teardown

    async def setup(self, ecu):
        self.calls.append("%s.setup" % self.name)

    async def teardown(self, ecu):
        self.calls.append("%s.teardown" % self.name)
        if self.on_teardown is not None:
            self.on_teardown()


def free_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


async def refused(port):
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
    except OSError:
        return True
    writer.close()
    return False


async def read_doip_frame(reader):
    header = await asyncio.wait_for(reader.readexactly(8), 2.0)
    body = await asyncio.wait_for(reader.readexactly(int.from_bytes(header[4:], "big")), 2.0)
    return int.from_bytes(header[2:4], "big"), body


# Hand-written frames: routing activation from 0x0E00, then DiagnosticSessionControl
# (extended) from 0x0E00 to the ECU at 0x0002.
ACTIVATE = bytes.fromhex("02FD0005" "00000007" "0E00" "00" "00000000")
EXTENDED_SESSION = bytes.fromhex("02FD8001" "00000006" "0E00" "0002" "1003")


async def activate(port):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(ACTIVATE)
    await writer.drain()
    ptype, body = await read_doip_frame(reader)
    assert ptype == 0x0006 and body[4] == 0x10
    return reader, writer


# ---------------------------------------------------------------------------
# EcuCore.shutdown() owns the retained per-tester state
# ---------------------------------------------------------------------------

class TestShutdownClosesRetainedState:
    def test_large_s3_timer_does_not_survive_shutdown(self):
        async def scenario():
            ecu = make_ecu({"uds": {"s3_server_ms": 600000}})
            state = ecu.session_for(0x0E00)
            state.enter_session(0x03)
            assert len(s3_tasks()) == 1          # the seam really armed a timer

            await ecu.shutdown()

            assert pending_tasks() == []
            assert ecu._session_states == {}

        run(scenario())

    def test_short_s3_does_not_fire_after_shutdown(self):
        async def scenario():
            ecu = make_ecu({"uds": {"s3_server_ms": 50}})
            state = ecu.session_for(0x0E00)
            state.enter_session(0x03)
            resets, drops = [], []
            real_reset = state.reset
            state.reset = lambda: (resets.append(1), real_reset())
            ecu.maybe_drop_session_state = lambda *a, **k: drops.append(a)

            await ecu.shutdown()
            await asyncio.sleep(0.2)             # well past the 50 ms S3

            assert resets == []
            assert drops == []
            assert state.session_type == 0x03    # not reverted to default
            assert ecu._session_states == {}

        run(scenario())

    def test_every_retained_state_is_closed(self):
        async def scenario():
            ecu = make_ecu({"uds": {"s3_server_ms": 600000}})
            for tester in (0x0E00, 0x0E01, 0x0E02):
                ecu.session_for(tester).enter_session(0x03)
            idle = ecu.session_for(0x0E03)       # retained but with no timer
            idle.security_level = 1
            assert len(s3_tasks()) == 3

            await ecu.shutdown()

            assert pending_tasks() == []
            assert ecu._session_states == {}

        run(scenario())

    def test_state_is_closed_before_any_plugin_teardown_runs(self):
        seen = []

        async def scenario():
            ecu = make_ecu({"uds": {"s3_server_ms": 600000}},
                           plugins=[Recorder([], on_teardown=lambda: seen.append(
                               (len(s3_tasks()), dict(ecu._session_states))))])
            ecu.session_for(0x0E00).enter_session(0x03)

            await ecu.shutdown()

        run(scenario())
        assert seen == [(0, {})]

    def test_failing_teardown_still_leaves_no_state_behind(self):
        class Bad(Plugin):
            async def teardown(self, ecu):
                raise RuntimeError("teardown boom")

        async def scenario():
            ecu = make_ecu({"uds": {"s3_server_ms": 600000}}, plugins=[Bad(name="bad")])
            ecu.session_for(0x0E00).enter_session(0x03)

            await ecu.shutdown()

            assert pending_tasks() == []
            assert ecu._session_states == {}

        run(scenario())

    def test_second_shutdown_is_a_no_op(self):
        calls = []

        async def scenario():
            ecu = make_ecu(plugins=[Recorder(calls)])
            ecu.session_for(0x0E00).enter_session(0x03)

            await ecu.shutdown()
            await ecu.shutdown()

            assert pending_tasks() == []

        run(scenario())
        assert calls == ["rec.teardown"]

    def test_core_can_be_started_and_shut_down_again(self):
        calls = []

        async def scenario():
            ecu = make_ecu(plugins=[Recorder(calls)])
            await ecu.startup()
            await ecu.shutdown()
            await ecu.startup()
            await ecu.shutdown()

        run(scenario())
        assert calls == ["rec.setup", "rec.teardown", "rec.setup", "rec.teardown"]

    def test_stopping_a_server_after_the_tester_left_leaves_no_s3_timer(self):
        async def scenario():
            ecu = make_ecu(merge(LOOPBACK_V4, {"uds": {"s3_server_ms": 600000}}))
            server = VirtualEcuServer(ecu)
            await server.start(serve_forever=False)
            reader, writer = await activate(server.port)
            writer.write(EXTENDED_SESSION)
            await writer.drain()
            frames = [await read_doip_frame(reader), await read_doip_frame(reader)]
            assert frames[1][1][4:6] == b"\x50\x03"
            writer.close()
            await asyncio.sleep(0.1)             # let the server notice the close
            assert len(s3_tasks()) == 1          # kept for a reconnect within S3

            await server.stop()

            assert pending_tasks() == []

        run(scenario())


# ---------------------------------------------------------------------------
# VirtualEcuServer.stop() owns the listener and the live sessions
# ---------------------------------------------------------------------------

class TestStopOwnsListenerAndSessions:
    def test_stop_closes_the_listener_and_ends_live_sessions(self):
        async def scenario():
            ecu = make_ecu(LOOPBACK_V4)
            server = VirtualEcuServer(ecu)
            await server.start(serve_forever=False)
            port = server.port
            active_reader, active_writer = await activate(port)
            idle_reader, idle_writer = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.sleep(0.05)
            assert len(pending_tasks()) >= 2     # the sessions really are running

            await asyncio.wait_for(server.stop(), 5.0)

            assert await refused(port)
            assert await asyncio.wait_for(active_reader.read(), 2.0) == b""
            assert await asyncio.wait_for(idle_reader.read(), 2.0) == b""
            assert pending_tasks() == []
            active_writer.close()
            idle_writer.close()

        run(scenario())

    def test_stop_without_sessions_and_stop_twice(self):
        async def scenario():
            server = VirtualEcuServer(make_ecu(LOOPBACK_V4))
            await server.start(serve_forever=False)
            port = server.port

            await asyncio.wait_for(server.stop(), 5.0)
            await asyncio.wait_for(server.stop(), 5.0)

            assert await refused(port)
            assert pending_tasks() == []

        run(scenario())

    def test_stop_on_a_server_that_never_started(self):
        async def scenario():
            await asyncio.wait_for(VirtualEcuServer(make_ecu(LOOPBACK_V4)).stop(), 5.0)

        run(scenario())

    def test_stop_after_the_caller_already_closed_the_listener(self):
        async def scenario():
            server = VirtualEcuServer(make_ecu(LOOPBACK_V4))
            listener = await server.start(serve_forever=False)
            listener.close()
            await listener.wait_closed()

            await asyncio.wait_for(server.stop(), 5.0)
            await asyncio.wait_for(server.stop(), 5.0)

        run(scenario())

    def test_ecu_shutdown_runs_after_listener_and_sessions_are_gone(self):
        observed = {}

        async def scenario():
            ecu = make_ecu(LOOPBACK_V4)
            server = VirtualEcuServer(ecu)
            await server.start(serve_forever=False)
            port = server.port
            _, writer = await activate(port)
            real_shutdown = ecu.shutdown

            async def spying_shutdown():
                observed["refused"] = await refused(port)
                observed["pending"] = pending_tasks()
                await real_shutdown()

            ecu.shutdown = spying_shutdown
            await server.stop()
            writer.close()

        run(scenario())
        assert observed == {"refused": True, "pending": []}

    def test_stop_stays_bounded_when_the_listener_never_finishes_closing(self, monkeypatch):
        monkeypatch.setattr(server_module, "_LISTENER_CLOSE_TIMEOUT", 0.05)

        class StuckListener:
            def close(self):
                pass

            async def wait_closed(self):
                await asyncio.Event().wait()

        async def scenario():
            server = VirtualEcuServer(make_ecu(LOOPBACK_V4))
            server._server = StuckListener()
            await asyncio.wait_for(server.stop(), 2.0)

        run(scenario())

    def test_stop_stays_bounded_when_a_session_refuses_to_unwind(self, monkeypatch):
        monkeypatch.setattr(server_module, "_SESSION_DRAIN_TIMEOUT", 0.05)
        release = []

        async def stubborn():
            while not release:
                try:
                    await asyncio.sleep(10)
                except asyncio.CancelledError:
                    pass

        async def scenario():
            server = VirtualEcuServer(make_ecu(LOOPBACK_V4))
            task = asyncio.ensure_future(stubborn())
            server._sessions.add(task)
            await asyncio.sleep(0)
            await asyncio.wait_for(server.stop(), 2.0)
            release.append(1)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        run(scenario())


# ---------------------------------------------------------------------------
# VirtualEcuServer.start() releases what it acquired when it fails
# ---------------------------------------------------------------------------

class SocketLedger:
    """Records every socket created while installed, to check none is left open."""

    def __init__(self, monkeypatch):
        self.created = []
        ledger = self

        class Recording(socket.socket):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                ledger.created.append(self)

        monkeypatch.setattr(socket, "socket", Recording)

    def open_sockets(self):
        # Only network sockets: the event loop's own wake-up pair is AF_UNIX.
        return [sock for sock in self.created
                if sock.fileno() != -1
                and sock.family in (socket.AF_INET, socket.AF_INET6)]


async def start_works_on(port, extra):
    """A later start on ``port`` succeeds, accepts a connection, and stops."""
    server = VirtualEcuServer(make_ecu(merge(extra, {"listen": {"port": port}})))
    await server.start(serve_forever=False)
    try:
        assert not await refused(port)
    finally:
        await server.stop()


class TestStartRollsBackOnFailure:
    def test_port_collision_leaves_nothing_open_and_plugins_torn_down(self, monkeypatch):
        calls = []
        ledger = SocketLedger(monkeypatch)

        async def scenario():
            occupant = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            occupant.bind(("127.0.0.1", 0))
            occupant.listen(1)
            port = occupant.getsockname()[1]
            extra = merge(LOOPBACK_V4, {"listen": {"port": port}})
            server = VirtualEcuServer(make_ecu(extra, plugins=[Recorder(calls)]))

            with pytest.raises(OSError):
                await server.start(serve_forever=False)

            assert pending_tasks() == []
            assert [s for s in ledger.open_sockets() if s is not occupant] == []
            occupant.close()
            await start_works_on(port, LOOPBACK_V4)

        run(scenario())
        assert calls == ["rec.setup", "rec.teardown"]

    def test_failure_while_starting_the_server(self, monkeypatch):
        calls = []
        ledger = SocketLedger(monkeypatch)
        boom = RuntimeError("start_server boom")

        async def failing_start_server(*args, **kwargs):
            raise boom

        monkeypatch.setattr(asyncio, "start_server", failing_start_server)

        async def scenario():
            port = free_port()
            extra = merge(LOOPBACK_V4, {"listen": {"port": port}})
            server = VirtualEcuServer(make_ecu(extra, plugins=[Recorder(calls)]))

            with pytest.raises(RuntimeError) as raised:
                await server.start(serve_forever=False)

            assert raised.value is boom
            assert ledger.open_sockets() == []
            assert pending_tasks() == []
            monkeypatch.undo()
            await start_works_on(port, LOOPBACK_V4)

        run(scenario())
        assert calls == ["rec.setup", "rec.teardown"]

    def test_failure_while_starting_udp(self, monkeypatch):
        calls = []
        ledger = SocketLedger(monkeypatch)
        boom = RuntimeError("announcer boom")

        def failing_announcer(*args, **kwargs):
            raise boom

        monkeypatch.setattr(server_module, "run_announcer", failing_announcer)

        async def scenario():
            port = free_port()
            extra = merge(LOOPBACK_V4, {"listen": {"port": port}, "udp": {"enabled": True}})
            server = VirtualEcuServer(make_ecu(extra, plugins=[Recorder(calls)]))

            with pytest.raises(RuntimeError) as raised:
                await server.start(serve_forever=False)

            assert raised.value is boom
            assert await refused(port)           # the listener was released
            assert ledger.open_sockets() == []
            assert pending_tasks() == []
            monkeypatch.undo()
            await start_works_on(port, LOOPBACK_V4)

        run(scenario())
        assert calls == ["rec.setup", "rec.teardown"]

    def test_cancellation_during_start(self, monkeypatch):
        calls = []
        ledger = SocketLedger(monkeypatch)
        entered = []

        async def hanging_start_server(*args, **kwargs):
            entered.append(1)
            await asyncio.Event().wait()

        monkeypatch.setattr(asyncio, "start_server", hanging_start_server)

        async def scenario():
            port = free_port()
            extra = merge(LOOPBACK_V4, {"listen": {"port": port}})
            server = VirtualEcuServer(make_ecu(extra, plugins=[Recorder(calls)]))
            starting = asyncio.ensure_future(server.start(serve_forever=False))
            while not entered:
                await asyncio.sleep(0.01)

            starting.cancel()
            with pytest.raises(asyncio.CancelledError):
                await starting

            assert ledger.open_sockets() == []
            assert pending_tasks() == []
            monkeypatch.undo()
            await start_works_on(port, LOOPBACK_V4)

        run(scenario())
        assert calls == ["rec.setup", "rec.teardown"]
