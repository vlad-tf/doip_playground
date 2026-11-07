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

"""F10: production connection dispatch must not share mutable fault state."""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, Mock, patch

import pytest
from scapy.contrib.automotive.doip import DoIP

from config import MiddlewareConfig
from server import DoIPServer
from session import DoIPSession
from tests.test_routing_activation import RecordingWriter
from tests.test_session import _make_app_config


def packet(source, data=b"\x22\xf1\x90"):
    payload = source.to_bytes(2, "big") + b"\x00\x03" + data
    return DoIP(b"\x02\xfd\x80\x01" + len(payload).to_bytes(4, "big") + payload)


@asynccontextmanager
async def connections(configs, use_tls):
    config = _make_app_config()
    config.middleware = configs
    server = DoIPServer(config)
    server._loop = asyncio.get_running_loop()
    ready = asyncio.Queue()
    releases = {}
    tasks = []

    async def run(session):
        release = asyncio.Event()
        releases[session] = release
        session.send_to_ecu = AsyncMock()
        await ready.put(session)
        try:
            await release.wait()
        finally:
            await session._cleanup()

    async def accept():
        task = asyncio.create_task(server._handle_connection(
            asyncio.StreamReader(), RecordingWriter(), use_tls
        ))
        tasks.append(task)
        return await asyncio.wait_for(ready.get(), 0.3)

    async def close(session):
        releases[session].set()
        await asyncio.sleep(0)

    try:
        with patch.object(DoIPSession, "run", run), patch.object(
            server, "_do_tls_handshake", AsyncMock(return_value=True)
        ):
            yield accept, close
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await server.stop()


@pytest.mark.parametrize("use_tls", [False, True])
def test_concurrent_replay_records_only_own_session(use_tls):
    async def scenario():
        async with connections([
            MiddlewareConfig("ReplayMiddleware", params={"record": True, "replay_count": 2})
        ], use_tls) as (accept, close):
            a, b = await asyncio.gather(accept(), accept())
            assert a.middleware_chain is not b.middleware_chain
            pa, pb = packet(0x0E00), packet(0x0E01)
            await asyncio.gather(
                a.middleware_chain.run(pa, "tester_to_ecu", a),
                b.middleware_chain.run(pb, "tester_to_ecu", b),
            )
            a.send_to_ecu.assert_not_awaited()
            b.send_to_ecu.assert_not_awaited()
            await a.middleware_chain.run(pa, "tester_to_ecu", a)
            assert [bytes(call.args[0]) for call in a.send_to_ecu.await_args_list] == [bytes(pa)] * 2
            b.send_to_ecu.assert_not_awaited()
            await b.middleware_chain.run(pb, "tester_to_ecu", b)
            assert [bytes(call.args[0]) for call in b.send_to_ecu.await_args_list] == [bytes(pb)] * 2
            await a.middleware_chain.run(pa, "tester_to_ecu", a)
            assert a.send_to_ecu.await_count == 2  # one shot remains connection-local

    asyncio.run(scenario())


@pytest.mark.parametrize("use_tls", [False, True])
def test_reconnect_starts_fresh_replay_state(use_tls):
    async def scenario():
        async with connections([
            MiddlewareConfig("ReplayMiddleware", params={"record": True, "replay_count": 2})
        ], use_tls) as (accept, close):
            old = await accept()
            stale = packet(0x0E00, b"\x10\x01")
            await old.middleware_chain.run(stale, "tester_to_ecu", old)
            await close(old)
            new = await accept()
            current = packet(0x0E00, b"\x22\xf1\x90")
            await new.middleware_chain.run(current, "tester_to_ecu", new)
            new.send_to_ecu.assert_not_awaited()
            await new.middleware_chain.run(current, "tester_to_ecu", new)
            assert [bytes(call.args[0]) for call in new.send_to_ecu.await_args_list] == [bytes(current)] * 2
            assert old.writer.closed
            old.send_to_ecu.assert_not_awaited()

    asyncio.run(scenario())


@pytest.mark.parametrize("use_tls", [False, True])
def test_header_fault_cadence_is_local_and_resets_on_reconnect(use_tls):
    async def scenario():
        async with connections([
            MiddlewareConfig("HeaderFaultMiddleware", params={
                "fault": "unknown_type", "inject_on_nth": 2, "direction": "both"
            })
        ], use_tls) as (accept, close):
            a, b = await asyncio.gather(accept(), accept())
            original = packet(0x0E00)
            for session in (a, b):
                first = await session.middleware_chain.run(original, "tester_to_ecu", session)
                assert bytes(first)[2:4] == b"\x80\x01"
            for session in (a, b):
                second = await session.middleware_chain.run(original, "ecu_to_tester", session)
                assert bytes(second)[2:4] == b"\xde\xad"
            await a.middleware_chain.run(original, "tester_to_ecu", a)
            await close(a)
            new = await accept()
            first = await new.middleware_chain.run(original, "tester_to_ecu", new)
            assert bytes(first)[2:4] == b"\x80\x01"
            assert bytes(original)[2:4] == b"\x80\x01"

    asyncio.run(scenario())


def test_enabled_order_and_shared_log_sink_are_preserved(tmp_path):
    async def scenario():
        async with connections([
            MiddlewareConfig("ReplayMiddleware", enabled=False, params={"record": True}),
            MiddlewareConfig("LoggerMiddleware", params={"log_path": str(tmp_path / "doip.log")}),
            MiddlewareConfig("HeaderFaultMiddleware", params={"inject_on_nth": 2}),
        ], False) as (accept, close):
            a, b = await asyncio.gather(accept(), accept())
            chain_a, chain_b = a.middleware_chain._chain, b.middleware_chain._chain
            assert [type(m).__name__ for m in chain_a] == ["LoggerMiddleware", "HeaderFaultMiddleware"]
            assert all(x is not y for x, y in zip(chain_a, chain_b))
            assert chain_a[0]._logger is chain_b[0]._logger
            assert len(chain_a[0]._logger.handlers) == 2
            await close(a)
            assert len(chain_b[0]._logger.handlers) == 2
            sink = chain_b[0]._logger
        assert sink.handlers == []  # Server shutdown owns handler release.

    asyncio.run(scenario())


def test_middleware_constructor_errors_still_fail_at_server_startup():
    config = _make_app_config()
    config.middleware = [MiddlewareConfig("HeaderFaultMiddleware", params={"fault": "invalid"})]
    with pytest.raises(ValueError, match="unknown fault mode"):
        DoIPServer(config)


@pytest.mark.parametrize("use_tls", [False, True])
def test_connection_middleware_failure_closes_writer_and_allows_next_session(use_tls):
    async def scenario():
        config = _make_app_config()
        config.middleware = []
        server = DoIPServer(config)
        writer = RecordingWriter()
        try:
            with patch("server._build_middleware", side_effect=[RuntimeError("setup failed"), []]), patch.object(
                server, "_do_tls_handshake", AsyncMock(return_value=True)
            ), patch.object(DoIPSession, "run", new_callable=AsyncMock) as run:
                await server._handle_connection(asyncio.StreamReader(), writer, use_tls)
                assert writer.closed
                run.assert_not_awaited()
                await server._handle_connection(asyncio.StreamReader(), RecordingWriter(), use_tls)
                run.assert_awaited_once()
        finally:
            await server.stop()

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["close", "wait_closed"])
def test_setup_failure_cleanup_errors_do_not_escape(failure, caplog):
    async def scenario():
        config = _make_app_config()
        config.middleware = []
        server = DoIPServer(config)
        writer = RecordingWriter()
        if failure == "close":
            writer.close = Mock(side_effect=OSError("close failed"))
        writer.wait_closed = AsyncMock(
            side_effect=OSError("wait failed") if failure == "wait_closed" else None
        )
        try:
            with patch("server._build_middleware", side_effect=RuntimeError("setup failed")), patch.object(
                DoIPSession, "run", new_callable=AsyncMock
            ) as run:
                await server._handle_connection(asyncio.StreamReader(), writer, False)
                run.assert_not_awaited()
                if failure == "close":
                    writer.close.assert_called_once()
                    writer.wait_closed.assert_not_awaited()
                else:
                    assert writer.closed
                    writer.wait_closed.assert_awaited_once()
        finally:
            await server.stop()

    with caplog.at_level("DEBUG", logger="server"):
        asyncio.run(scenario())
    assert "middleware setup failed" in caplog.text
    assert "writer cleanup failed" in caplog.text
