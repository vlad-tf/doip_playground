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

"""F16 capacity tests; async scenarios are deliberately driven by asyncio.run."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middleware import MiddlewareChain
from routing import RoutingTable
from session import DoIPProtocolError, DoIPSession
from session_registry import SessionRegistry
from tests.test_session import _make_app_config


class Writer:
    def __init__(self, name=0):
        self.name, self.frames, self.closed = name, [], False

    def get_extra_info(self, key):
        return ("127.0.0.1", 10000 + self.name)

    def write(self, data): self.frames.append(data)
    async def drain(self): pass
    def close(self): self.closed = True
    async def wait_closed(self): pass


def run(coro): return asyncio.run(coro)


def packet(sa):
    return SimpleNamespace(payload_type=0x0005, source_address=sa, activation_type=0)


def make(registry, name=0, config=None):
    config = config or _make_app_config()
    writer = Writer(name)
    session = DoIPSession(asyncio.StreamReader(), writer, config,
                           RoutingTable(config.routing_table),
                           MiddlewareChain([]), asyncio.get_running_loop(), None,
                           registry)
    return session, writer


async def activate(session, sa):
    await session._dispatch(packet(sa))


def response_code(writer): return writer.frames[-1][12]


def test_default_and_bounds_and_shared_status():
    assert SessionRegistry().max_connections == 8
    for value in (0, 255, True, 1.0):
        with pytest.raises(ValueError): SessionRegistry(value)
    async def scenario():
        r = SessionRegistry(2)
        writers = [Writer(i) for i in range(4)]
        assert [r.reserve(w) for w in writers] == [True, True, True, False]
        assert r.open_count() == 3
        cfg = _make_app_config(); assert r.status_payload(cfg) == bytes((1, 2, 3))
        r.release(writers[0]); r.release(writers[0]); assert r.open_count() == 2
    run(scenario())


def server_fixture(capacity):
    from server import DoIPServer
    from middleware.logger import LogSinkOwner
    obj = DoIPServer.__new__(DoIPServer)
    obj._log_sink_owner = LogSinkOwner()
    obj._registry = SessionRegistry(capacity)
    obj._closing = False
    obj._sessions = set()
    obj._connection_tasks = set()
    return obj


def test_server_reserves_n_plus_one_and_releases_all_exit_paths():
    from server import DoIPServer
    async def scenario():
        obj = server_fixture(1)
        obj._run_connection = AsyncMock(side_effect=RuntimeError("setup"))
        w = Writer()
        with pytest.raises(RuntimeError): await obj._handle_connection(None, w, False)
        assert obj._registry.open_count() == 0 and w.closed
        assert obj._registry.reserve(w)
        obj._run_connection = AsyncMock(side_effect=asyncio.CancelledError())
        with pytest.raises(asyncio.CancelledError): await obj._handle_connection(None, w, False)
        assert obj._registry.open_count() == 0
    run(scenario())


def test_constructor_cleanup_and_initial_timer_release_are_idempotent():
    async def scenario():
        r = SessionRegistry(1); s, w = make(r)
        assert r.open_count() == 1
        await s._cleanup(); await s._cleanup(); assert r.open_count() == 0
        cfg = _make_app_config(initial_s=0.01); s, w = make(r, config=cfg)
        s._start_initial_timer(); await asyncio.sleep(0.03)
        assert r.open_count() == 0 and w.closed and s._initial_timer_task.done()
    run(scenario())


def test_attach_enforces_the_reserved_socket_budget():
    async def scenario():
        r = SessionRegistry(1); first, _ = make(r); reserve = Writer(1)
        assert r.open_count() == 1 and r.reserve(reserve)
        with pytest.raises(RuntimeError): make(r, 2)
        assert r.open_count() == 2
        await first._cleanup(); r.release(reserve)
    run(scenario())


def test_full_capacity_all_alive_returns_01_without_eviction():
    async def scenario():
        r = SessionRegistry(2); owners = []
        for i, sa in enumerate((0x0E00, 0x0E01)):
            s, _ = make(r, i); await activate(s, sa); s.probe_alive = AsyncMock(return_value=True); owners.append(s)
        candidate, w = make(r, 9)
        with pytest.raises(DoIPProtocolError): await activate(candidate, 0x0E02)
        assert response_code(w) == 0x01 and r.count() == 2
        assert all(not s._closing for s in owners)
        await candidate._cleanup()
        for s in owners: await s._cleanup()
    run(scenario())


@pytest.mark.parametrize("dead", ["one", "all"])
def test_dead_current_owners_are_evicted_and_capacity_reclaimed(dead):
    async def scenario():
        r = SessionRegistry(2); owners = []
        for i, sa in enumerate((0x0E00, 0x0E01)):
            s, _ = make(r, i); await activate(s, sa)
            s.probe_alive = AsyncMock(return_value=(dead == "one" and i == 1)); owners.append(s)
        candidate, w = make(r, 9); await activate(candidate, 0x0E02)
        assert response_code(w) == 0x10
        assert r.count() == (2 if dead == "one" else 1)
        for s in owners + [candidate]: await s._cleanup()
    run(scenario())


def test_same_sa_conflict_precedes_capacity_and_reactivation_does_not_probe_all():
    async def scenario():
        r = SessionRegistry(2); old, old_writer = make(r); other, _ = make(r, 1)
        await activate(old, 0x0E00); await activate(other, 0x0E01)
        old.probe_alive = AsyncMock(return_value=True)
        contender, w = make(r, 2); contender._reclaim_capacity = AsyncMock()
        with pytest.raises(DoIPProtocolError): await activate(contender, 0x0E00)
        assert response_code(w) == 0x03; contender._reclaim_capacity.assert_not_awaited()
        old.probe_alive.reset_mock(); await activate(old, 0x0E00)
        old.probe_alive.assert_not_awaited(); assert response_code(old_writer) == 0x10
        for s in (old, other, contender): await s._cleanup()
    run(scenario())


def test_distinct_sa_concurrent_last_slot_never_exceeds_capacity():
    async def scenario():
        r = SessionRegistry(2); base, _ = make(r); await activate(base, 0x0E00)
        base.probe_alive = AsyncMock(return_value=True)
        contenders = [make(r, 10 + i) for i in range(2)]
        for s, _ in contenders: s.probe_alive = AsyncMock(return_value=True)
        results = await asyncio.gather(*(activate(s, 0x0E10 + i)
                                         for i, (s, _) in enumerate(contenders)),
                                       return_exceptions=True)
        assert sorted(response_code(w) for _, w in contenders) == [0x01, 0x10]
        assert sum(x is None for x in results) == 1 and r.count() == 2
        for s, _ in contenders + [(base, None)]: await s._cleanup()
    run(scenario())


def test_capacity_snapshot_does_not_evict_replaced_owner_or_cancelled_probe():
    async def scenario():
        r = SessionRegistry(1); owner, _ = make(r); await activate(owner, 0x0E00)
        entered = asyncio.Event(); release = asyncio.Event()
        async def probe(_): entered.set(); await release.wait(); return False
        owner.probe_alive = probe; candidate, _ = make(r, 2)
        task = asyncio.create_task(candidate._reclaim_capacity(0x0E01)); await entered.wait()
        replacement = SimpleNamespace(peer="replacement", probe_alive=AsyncMock(return_value=True),
                                      evict=Mock())
        r.register(0x0E00, replacement); release.set(); await task
        assert not owner._closing and r.lookup(0x0E00) is replacement
        await candidate._cleanup(); await owner._cleanup()
    run(scenario())


def test_cancelling_capacity_contender_drains_probes_without_eviction():
    async def scenario():
        r = SessionRegistry(1); owner, _ = make(r); await activate(owner, 0x0E00)
        blocked = asyncio.Event(); pending = asyncio.Event()
        async def probe(_): pending.set(); await blocked.wait()
        owner.probe_alive = AsyncMock(side_effect=probe)
        candidate, w = make(r, 1); task = asyncio.create_task(activate(candidate, 0x0E01))
        await pending.wait()
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        assert not owner._closing and not candidate._closing
        assert not any(t.get_coro().__qualname__.endswith("probe_alive")
                       for t in asyncio.all_tasks() if t is not asyncio.current_task())
        await candidate._cleanup(); await owner._cleanup()
    run(scenario())


def test_server_overflow_is_closed_before_handshake_on_both_listener_paths():
    from server import DoIPServer
    async def scenario():
        obj = server_fixture(1)
        entered = asyncio.Event(); release = asyncio.Event()
        async def hold(*args): entered.set(); await release.wait()
        obj._run_connection = hold
        writers = [Writer(i) for i in range(3)]
        tasks = [asyncio.create_task(obj._handle_connection(None, w, tls))
                 for w, tls in zip(writers, (False, True, False))]
        await entered.wait(); await asyncio.sleep(0)
        assert writers[2].closed and writers[2].frames == []
        release.set(); await asyncio.gather(*tasks)
        assert obj._registry.open_count() == 0
    run(scenario())


def test_handshake_middleware_and_constructor_failures_release_capacity():
    from server import DoIPServer
    async def scenario():
        obj = server_fixture(1)
        obj._config = _make_app_config(); obj._loop = asyncio.get_running_loop()
        obj._routing_table = RoutingTable(obj._config.routing_table)
        obj._executor = None
        obj._do_tls_handshake = AsyncMock(return_value=False)
        w = Writer()
        await obj._handle_connection(None, w, True)
        assert obj._registry.open_count() == 0 and w.closed
        with patch("server._build_middleware", side_effect=RuntimeError("mw")):
            await obj._handle_connection(None, Writer(1), False)
        assert obj._registry.open_count() == 0
        with patch("server.DoIPSession", side_effect=RuntimeError("ctor")):
            with pytest.raises(RuntimeError): await obj._handle_connection(None, Writer(2), False)
        assert obj._registry.open_count() == 0
    run(scenario())


def test_real_ephemeral_tcp_and_udp_status_share_registry_counts():
    from udp_announcer import _UDPProtocol, _build_frame, PT_ENTITY_STATUS_REQUEST
    async def scenario():
        from server import DoIPServer
        obj = server_fixture(2)
        entered, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def hold(*args): entered.set(); await release.wait()
        obj._run_connection = hold
        async def accept(reader, writer):
            try:
                await obj._handle_connection(reader, writer, False)
            finally:
                finished.set()
        tcp = await asyncio.start_server(accept, "127.0.0.1", 0)
        loop = asyncio.get_running_loop()
        cfg = _make_app_config(); cfg.doip.max_connections = 2
        udp, _ = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(cfg, obj._registry), local_addr=("127.0.0.1", 0))
        queue = asyncio.Queue()
        class Client(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr): queue.put_nowait(data)
        client, _ = await loop.create_datagram_endpoint(Client, local_addr=("127.0.0.1", 0))
        writer = None
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", tcp.sockets[0].getsockname()[1])
            await asyncio.wait_for(entered.wait(), 1)
            async def status(count):
                client.sendto(_build_frame(PT_ENTITY_STATUS_REQUEST, b""), udp.get_extra_info("sockname"))
                response = await asyncio.wait_for(queue.get(), 1)
                assert response == _build_frame(0x4002, bytes((1, 2, count)))
            await status(1)
            writer.close(); await writer.wait_closed(); release.set()
            await asyncio.wait_for(finished.wait(), 1)
            await status(0)
            assert obj._registry.open_count() == 0
        finally:
            release.set()
            if writer is not None: writer.close()
            client.close(); udp.close(); tcp.close(); await tcp.wait_closed()
    run(scenario())


def test_capacity_probe_timeout_is_bounded_and_unfinished_is_not_dead():
    async def scenario():
        r = SessionRegistry(1); owner, _ = make(r); await activate(owner, 0x0E00)
        async def probe(_): await asyncio.Future()
        owner.probe_alive = probe
        candidate, writer = make(r, 1)
        try:
            with patch("session.asyncio.wait", wraps=asyncio.wait) as wait:
                with pytest.raises(DoIPProtocolError):
                    await asyncio.wait_for(activate(candidate, 0x0E01), 3)
            assert wait.call_args.kwargs["timeout"] == 2.0
            assert response_code(writer) == 0x01 and not owner._closing
        finally:
            await candidate._cleanup(); await owner._cleanup()
    run(scenario())
