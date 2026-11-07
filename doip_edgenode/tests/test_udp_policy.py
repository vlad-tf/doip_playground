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

"""F14 UDP interface, filtering, scheduling, and lifecycle policy tests."""

from __future__ import annotations

import asyncio
import os
import socket
import sys
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import udp_announcer as udp  # noqa: E402
from tests.test_session import _make_app_config  # noqa: E402

ADDR = ("192.0.2.44", 49152)


def frame(payload_type: int, payload: bytes = b"") -> bytes:
    return (b"\x02\xfd" + payload_type.to_bytes(2, "big") +
            len(payload).to_bytes(4, "big") + payload)


def protocol():
    config = _make_app_config()
    transport = MagicMock()
    proto = udp._UDPProtocol(config)
    proto.connection_made(transport)
    return proto, transport


def discovery(proto, addr=ADDR):
    proto.datagram_received(frame(udp.PT_VEHICLE_ID_REQUEST), addr)


def test_source_filter_precedes_validation_and_is_silent(caplog):
    sources = ("not-an-ip", "0.0.0.0", "224.0.0.1", "255.255.255.255")
    for source in sources:
        proto, transport = protocol()
        with caplog.at_level("DEBUG", logger=udp.__name__):
            proto.datagram_received(b"malformed!", (source, 1))
        transport.sendto.assert_not_called()
        assert not caplog.records
        caplog.clear()


def test_valid_off_subnet_source_is_delayed_not_immediate():
    proto, transport = protocol()
    handle = MagicMock()
    with patch.object(asyncio, "get_running_loop") as get_loop:
        get_loop.return_value.call_later.return_value = handle
        discovery(proto, ("198.51.100.8", 1))
    transport.sendto.assert_not_called()
    get_loop.return_value.call_later.call_args.args[1]()
    transport.sendto.assert_called_once()


def test_source_filter_allows_unicast_without_network_mask():
    for source in ("192.0.2.255", "198.51.100.8"):
        proto, transport = protocol()
        handle = MagicMock()
        with patch.object(asyncio, "get_running_loop") as get_loop:
            get_loop.return_value.call_later.return_value = handle
            discovery(proto, (source, 1))
        transport.sendto.assert_not_called()
        assert len(proto._pending_responses) == 1


def test_discovery_scheduling_uses_running_loop_random_delay_and_no_drop_log(caplog):
    proto, transport = protocol()
    handle = MagicMock()
    with patch.object(udp.random, "uniform", return_value=.25) as uniform, \
         patch.object(asyncio, "get_running_loop") as get_loop:
        get_loop.return_value.call_later.return_value = handle
        with caplog.at_level("DEBUG", logger=udp.__name__):
            discovery(proto)
    uniform.assert_called_once_with(0.0, 0.5)
    assert get_loop.return_value.call_later.call_args.args[0] == .25
    assert get_loop.return_value.call_later.call_args.args[1] is not None
    transport.sendto.assert_not_called()
    assert not any("drop" in r.getMessage().lower() for r in caplog.records)


def test_discovery_requests_get_independent_random_delays():
    proto, _ = protocol()
    handles = [MagicMock(), MagicMock()]
    with patch.object(udp.random, "uniform", side_effect=(.1, .4)), \
         patch.object(asyncio, "get_running_loop") as get_loop:
        get_loop.return_value.call_later.side_effect = handles
        discovery(proto, ("192.0.2.1", 1))
        discovery(proto, ("192.0.2.2", 1))
    assert [c.args[0] for c in get_loop.return_value.call_later.call_args_list] == [.1, .4]
    assert len(proto._pending_responses) == 2


def test_pending_capacity_is_256_and_recovers_after_callback():
    proto, _ = protocol()
    handles = [MagicMock() for _ in range(257)]
    with patch.object(asyncio, "get_running_loop") as get_loop, \
         patch.object(udp.random, "uniform", return_value=0):
        get_loop.return_value.call_later.side_effect = handles
        for n in range(257):
            discovery(proto, ("192.0.2.%d" % (n % 250 + 1), n))
        assert get_loop.return_value.call_later.call_count == 256
        callback = get_loop.return_value.call_later.call_args_list[0].args[1]
        callback()
        assert len(proto._pending_responses) == 255
        discovery(proto, ("192.0.2.99", 9999))
        assert get_loop.return_value.call_later.call_count == 257


def test_connection_lost_cancels_pending_and_callbacks_cannot_send():
    proto, transport = protocol()
    handles = [MagicMock(), MagicMock()]
    with patch.object(asyncio, "get_running_loop") as get_loop:
        get_loop.return_value.call_later.side_effect = handles
        discovery(proto)
        discovery(proto, ("192.0.2.2", 1))
        callbacks = [c.args[1] for c in get_loop.return_value.call_later.call_args_list]
    proto.connection_lost(None)
    for handle in handles:
        handle.cancel.assert_called_once_with()
    for callback in callbacks:
        callback()
    assert not proto._pending_responses
    transport.sendto.assert_not_called()


def test_cancel_pending_is_idempotent_and_prevents_stale_send():
    proto, transport = protocol()
    handle = MagicMock()
    with patch.object(asyncio, "get_running_loop") as get_loop:
        get_loop.return_value.call_later.return_value = handle
        discovery(proto)
        callback = get_loop.return_value.call_later.call_args.args[1]
    proto.cancel_pending()
    proto.cancel_pending()
    handle.cancel.assert_called_once_with()
    callback()
    transport.sendto.assert_not_called()


def test_power_and_header_nack_paths_are_immediate():
    proto, transport = protocol()
    with patch.object(asyncio, "get_running_loop") as get_loop:
        proto.datagram_received(frame(udp.PT_POWER_MODE_REQUEST), ADDR)
        proto.datagram_received(frame(udp.PT_HEADER_NACK, b"\x01"), ADDR)
    assert transport.sendto.call_count == 1
    get_loop.return_value.call_later.assert_not_called()


def test_create_socket_sets_portable_options_and_bind():
    fake = MagicMock()
    with patch.object(udp.socket, "socket", return_value=fake) as make_socket:
        assert udp._create_udp_socket() is fake
    make_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
    fake.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    fake.setblocking.assert_called_once_with(False)
    fake.bind.assert_called_once_with(("0.0.0.0", udp.DOIP_UDP_PORT))


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_create_socket_is_platform_independent(platform):
    fake = MagicMock()
    with patch.object(sys, "platform", platform), patch.object(udp.socket, "socket", return_value=fake):
        assert udp._create_udp_socket() is fake


@pytest.mark.parametrize("failure", ["setsockopt", "setblocking", "bind"])
def test_create_socket_failures_close_socket(failure):
    fake = MagicMock()
    getattr(fake, failure).side_effect = OSError(failure)
    with patch.object(udp.socket, "socket", return_value=fake):
        with pytest.raises(OSError, match=failure):
            udp._create_udp_socket()
    fake.close.assert_called_once_with()


def test_announcements_sleep_initially_and_between_all_announcements():
    config = _make_app_config()
    config.udp.announce_count, config.udp.announce_interval_ms = 3, 200
    announcer = udp.UDPAnnouncer(config)
    announcer._transport = MagicMock()
    sleeps = []
    async def fake_sleep(value): sleeps.append(value)
    async def exercise():
        with patch.object(udp.random, "uniform", return_value=.37) as uniform, patch.object(udp.asyncio, "sleep", side_effect=fake_sleep):
            await announcer._send_announcements()
        uniform.assert_called_once_with(0.0, 0.5)
    asyncio.run(exercise())
    assert sleeps == [.37, .2, .2]
    assert announcer._transport.sendto.call_args_list == [
        call(frame(0x0004, udp._announcement_payload(config)), ("255.255.255.255", udp.DOIP_UDP_PORT))
    ] * 3


def test_stop_clears_references_after_cancel_and_close():
    announcer = udp.UDPAnnouncer(_make_app_config())
    transport, proto = MagicMock(), MagicMock()
    announcer._transport, announcer._protocol = transport, proto
    asyncio.run(announcer.stop())
    proto.cancel_pending.assert_called_once_with()
    transport.close.assert_called_once_with()
    assert announcer._transport is None and announcer._protocol is None


def test_real_loopback_socket_policy_delays_discovery_and_closes():
    async def exercise():
        config = _make_app_config()
        with patch.object(udp, "DOIP_UDP_PORT", 0), patch.object(udp.random, "uniform", return_value=.01):
            sock = udp._create_udp_socket()
            loop = asyncio.get_running_loop()
            queue = asyncio.Queue()
            class Client(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr): queue.put_nowait((data, addr))
            server, _ = await loop.create_datagram_endpoint(lambda: udp._UDPProtocol(config), sock=sock)
            client, _ = await loop.create_datagram_endpoint(Client, local_addr=("127.0.0.1", 0))
            try:
                client.sendto(frame(udp.PT_VEHICLE_ID_REQUEST), ("127.0.0.1", server.get_extra_info("sockname")[1]))
                data, source = await asyncio.wait_for(queue.get(), 1.0)
                assert int.from_bytes(data[2:4], "big") == udp.PT_VEHICLE_ID_RESPONSE
                assert source[0] == "127.0.0.1"
            finally:
                client.close(); server.close(); await asyncio.sleep(0)
    asyncio.run(exercise())


def test_cancellation_during_endpoint_creation_closes_raw_socket():
    async def exercise():
        raw = MagicMock()
        ready = asyncio.Event()
        loop = MagicMock()

        async def endpoint(*args, **kwargs):
            ready.set()
            await asyncio.Future()

        loop.create_datagram_endpoint = endpoint
        announcer = udp.UDPAnnouncer(_make_app_config())
        with patch.object(udp, "_create_udp_socket", return_value=raw), \
             patch.object(asyncio, "get_running_loop", return_value=loop):
            task = asyncio.create_task(announcer.start())
            await asyncio.wait_for(ready.wait(), 0.5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        raw.close.assert_called_once_with()
        assert announcer._transport is None and announcer._protocol is None

    asyncio.run(exercise())


def test_incoming_endpoint_matrix_does_not_schedule_responses_or_errors():
    proto, transport = protocol()
    ignored = ((0x0000, b"\x01"), (0x0004, b"A" * 32), (0x0004, b"A" * 33))
    unsupported = ((0x4001, b""), (0x4002, b"\x00\x01\x01"),
                   (0x4004, b"\x01"), (0x0005, b"\0" * 7),
                   (0x0006, b"\0" * 9), (0x0007, b""), (0x0008, b"\0" * 2),
                   (0x8001, b"\0" * 5), (0x8002, b"\0" * 5), (0x8003, b"\0" * 5))
    with patch.object(asyncio, "get_running_loop") as get_loop:
        for pt, body in ignored:
            proto.datagram_received(frame(pt, body), ADDR)
            transport.sendto.assert_not_called()
        for pt, body in unsupported:
            proto.datagram_received(frame(pt, body), ADDR)
            transport.sendto.assert_called_once_with(frame(0x0000, b"\x01"), ADDR)
            transport.reset_mock()
        proto.datagram_received(frame(0x4003), ADDR)
        transport.sendto.assert_called_once_with(frame(0x4004, b"\x01"), ADDR)
        get_loop.return_value.call_later.assert_not_called()


@pytest.mark.parametrize("delay", [0.0, 0.5])
def test_discovery_delay_endpoints_and_exact_callback_bytes(delay):
    proto, transport = protocol()
    with patch.object(asyncio, "get_running_loop") as get_loop, \
         patch.object(udp.random, "uniform", return_value=delay):
        discovery(proto)
        transport.sendto.assert_not_called()
        call_args = get_loop.return_value.call_later.call_args.args
        assert call_args[0] == delay
        call_args[1]()
    transport.sendto.assert_called_once_with(frame(0x0004, proto._payload), ADDR)
    assert not proto._pending_responses


def test_real_timer_orders_replies_and_power_does_not_wait():
    async def exercise():
        proto, transport = protocol()
        with patch.object(udp.random, "uniform", side_effect=(0.03, 0.0)):
            discovery(proto, ("192.0.2.1", 1))
            discovery(proto, ("192.0.2.2", 2))
        proto.datagram_received(frame(0x4003), ADDR)
        assert transport.sendto.call_args.args == (frame(0x4004, b"\x01"), ADDR)
        await asyncio.sleep(0.06)
        destinations = [c.args[1] for c in transport.sendto.call_args_list]
        assert destinations == [ADDR, ("192.0.2.2", 2), ("192.0.2.1", 1)]
        assert not proto._pending_responses

    asyncio.run(exercise())


@pytest.mark.parametrize("pt", [0x0001, 0x0002, 0x0003])
def test_matching_selectors_schedule_and_mismatches_create_no_timer(pt):
    proto, transport = protocol()
    body = {1: b"", 2: proto._payload[19:25], 3: proto._payload[:17]}[pt]
    with patch.object(asyncio, "get_running_loop") as get_loop, \
         patch.object(udp.random, "uniform", return_value=0.25):
        proto.datagram_received(frame(pt, body), ADDR)
        get_loop.return_value.call_later.assert_called_once()
        delay, callback = get_loop.return_value.call_later.call_args.args
        assert delay == 0.25
        callback()
        transport.sendto.assert_called_once_with(frame(0x0004, proto._payload), ADDR)
        get_loop.return_value.call_later.reset_mock()
        if pt != 1:
            proto.datagram_received(frame(pt, b"X" * len(body)), ADDR)
            get_loop.return_value.call_later.assert_not_called()


@pytest.mark.parametrize("pt,body", [(0x0000, b"\x01"), (0x0004, b"A" * 32), (0x0004, b"A" * 33)])
def test_incoming_responses_version_and_source_matrix(pt, body):
    proto, transport = protocol()
    for version, inverse, expected in ((2, 0xFD, None), (3, 0xFC, None),
                                      (2, 0, 0), (0xFF, 0, 0)):
        data = bytes((version, inverse)) + frame(pt, body)[2:]
        with patch.object(asyncio, "get_running_loop") as get_loop:
            proto.datagram_received(data, ("255.255.255.255", 1))
            transport.sendto.assert_not_called()
            proto.datagram_received(data, ADDR)
            if expected is None:
                transport.sendto.assert_not_called()
            else:
                transport.sendto.assert_called_once_with(frame(0, b"\0"), ADDR)
            get_loop.return_value.call_later.assert_not_called()
        transport.reset_mock()


def test_overload_has_no_random_draw_timer_log_or_send(caplog):
    proto, transport = protocol()
    with patch.object(asyncio, "get_running_loop") as get_loop, \
         patch.object(udp.random, "uniform") as uniform:
        get_loop.return_value.call_later.side_effect = [MagicMock() for _ in range(256)]
        for _ in range(256):
            discovery(proto)
        uniform.reset_mock()
        get_loop.return_value.call_later.reset_mock()
        with caplog.at_level("DEBUG", logger=udp.__name__):
            discovery(proto)
        uniform.assert_not_called()
        get_loop.return_value.call_later.assert_not_called()
        transport.sendto.assert_not_called()
        assert not caplog.records


def test_normal_start_initial_sleep_cancellation_and_repeated_stop():
    async def exercise():
        announcer = udp.UDPAnnouncer(_make_app_config())
        await announcer.stop()
        raw, transport = MagicMock(), MagicMock()
        proto = udp._UDPProtocol(announcer._config)
        proto.connection_made(transport)
        entered = asyncio.Event()

        async def initial_sleep(delay):
            entered.set()
            await asyncio.Future()

        async def endpoint(factory, **kwargs):
            assert kwargs == {"sock": raw}
            created = factory()
            return transport, proto

        loop = asyncio.get_running_loop()
        with patch.object(udp, "_create_udp_socket", return_value=raw), \
             patch.object(loop, "create_datagram_endpoint", side_effect=endpoint), \
             patch.object(udp.asyncio, "sleep", side_effect=initial_sleep):
            task = asyncio.create_task(announcer.start())
            await asyncio.wait_for(entered.wait(), .5)
            with pytest.raises(RuntimeError, match="already started"):
                await announcer.start()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        transport.sendto.assert_not_called()
        transport.close.assert_called_once()
        assert announcer._transport is None and announcer._protocol is None
        await announcer.stop()
        transport.close.assert_called_once()

    asyncio.run(exercise())


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_start_succeeds_without_configured_interface_or_primary_address(platform):
    async def exercise():
        config = _make_app_config()
        config.network.tester_interface = "not-a-local-interface"
        config.network.tester_ipv4 = "192.0.2.123"
        announcer = udp.UDPAnnouncer(config)
        raw, transport = MagicMock(), MagicMock()

        async def endpoint(factory, **kwargs):
            assert kwargs == {"sock": raw}
            proto = factory()
            assert isinstance(proto, udp._UDPProtocol)
            proto.connection_made(transport)
            return transport, proto

        async def announce():
            assert announcer._transport is transport

        loop = asyncio.get_running_loop()
        with patch.object(sys, "platform", platform), \
             patch.object(udp, "_create_udp_socket", return_value=raw) as create, \
             patch.object(loop, "create_datagram_endpoint", side_effect=endpoint), \
             patch.object(announcer, "_send_announcements", side_effect=announce):
            await announcer.start()
            create.assert_called_once_with()
        raw.close.assert_not_called()
        await announcer.stop()
        transport.close.assert_called_once_with()

    asyncio.run(exercise())


def test_endpoint_failure_closes_raw_socket():
    async def exercise():
        raw = MagicMock()
        announcer = udp.UDPAnnouncer(_make_app_config())
        loop = asyncio.get_running_loop()
        with patch.object(udp, "_create_udp_socket", return_value=raw), \
             patch.object(loop, "create_datagram_endpoint", side_effect=OSError("endpoint")):
            with pytest.raises(OSError, match="endpoint"):
                await announcer.start()
        raw.close.assert_called_once_with()
        assert announcer._transport is None and announcer._protocol is None

    asyncio.run(exercise())


def test_announcement_failure_closes_acquired_transport():
    async def exercise():
        raw, transport = MagicMock(), MagicMock()
        announcer = udp.UDPAnnouncer(_make_app_config())

        async def endpoint(factory, **kwargs):
            proto = factory()
            proto.connection_made(transport)
            return transport, proto

        loop = asyncio.get_running_loop()
        with patch.object(udp, "_create_udp_socket", return_value=raw), \
             patch.object(loop, "create_datagram_endpoint", side_effect=endpoint), \
             patch.object(announcer, "_send_announcements", side_effect=OSError("announce")):
            with pytest.raises(OSError, match="announce"):
                await announcer.start()
        transport.close.assert_called_once_with()
        raw.close.assert_not_called()
        assert announcer._transport is None and announcer._protocol is None

    asyncio.run(exercise())
