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

"""F08 ECU connection setup, framing, and routing-activation coverage."""

import asyncio
import struct
import sys
from unittest.mock import AsyncMock, patch

import pytest

from ecu_client import ECUConnection
from tests.test_routing_activation import RecordingWriter
from tests.test_session import _make_app_config


VER = 0x02
ENTRY_ECU = 0x0001
TESTER = 0x0E00
RA_REQUEST = 0x0005
RA_RESPONSE = 0x0006
ALIVE_REQUEST = 0x0007
ALIVE_RESPONSE = 0x0008
DIAGNOSTIC = 0x8001
POS_ACK = 0x8002
NEG_ACK = 0x8003
STATUS = 0x4002
POWER = 0x4004


def frame(ptype, payload=b"", version=VER, inverse=None):
    if inverse is None:
        inverse = 0xFF ^ version
    return struct.pack("!BBHI", version, inverse, ptype, len(payload)) + payload


def ra_payload(tester=TESTER, ecu=ENTRY_ECU, code=0x10, extra=b""):
    return struct.pack("!HHB", tester, ecu, code) + b"\0\0\0\0" + extra


def connection(max_payload=4096):
    cfg = _make_app_config()
    return ECUConnection(cfg.routing_table[0], cfg.tls, asyncio.get_running_loop(),
                         None, max_payload_bytes=max_payload)


class FakeSocket:
    def __init__(self):
        self.closed = False
        self.blocking = None

    def setblocking(self, value):
        self.blocking = value

    def close(self):
        self.closed = True


async def feed_reader(conn, data):
    conn._reader = asyncio.StreamReader()
    conn._reader.feed_data(data)
    conn._reader.feed_eof()


def test_read_frame_rejects_bad_header_before_body_read():
    async def scenario():
        for bad in (frame(POWER, b"", version=1),
                    frame(POWER, b"", inverse=0x00)):
            conn = connection()
            conn._reader = asyncio.StreamReader()
            conn._reader.feed_data(bad)
            with pytest.raises(RuntimeError):
                await conn._read_frame()

        conn = connection(max_payload=4)
        conn._reader = asyncio.StreamReader()
        conn._reader.feed_data(struct.pack("!BBHI", VER, 0xFD, POWER, 5))
        with pytest.raises(RuntimeError):
            await conn._read_frame()
        assert not conn._reader._buffer

    asyncio.run(scenario())


@pytest.mark.parametrize("ptype,payload", [
    (0x0000, b"x"), (RA_RESPONSE, b"x" * 9), (RA_RESPONSE, b"x" * 13),
    (ALIVE_REQUEST, b""), (ALIVE_RESPONSE, b"xx"),
    (DIAGNOSTIC, b"x" * 5), (POS_ACK, b"x" * 5),
    (NEG_ACK, b"x" * 5), (STATUS, b"x" * 3), (STATUS, b"x" * 7),
    (POWER, b"x"),
])
def test_read_frame_accepts_known_lengths(ptype, payload):
    async def scenario():
        conn = connection()
        await feed_reader(conn, frame(ptype, payload))
        assert await conn._read_frame() == frame(ptype, payload)

    asyncio.run(scenario())


@pytest.mark.parametrize("ptype,length", [
    (RA_RESPONSE, 8), (RA_RESPONSE, 10), (ALIVE_RESPONSE, 1),
    (DIAGNOSTIC, 4), (POS_ACK, 4), (NEG_ACK, 4),
    (STATUS, 2), (STATUS, 4), (STATUS, 6), (POWER, 0),
])
def test_read_frame_rejects_known_type_wrong_length(ptype, length):
    async def scenario():
        conn = connection()
        await feed_reader(conn, frame(ptype, b"x" * length))
        with pytest.raises(RuntimeError):
            await conn._read_frame()

    asyncio.run(scenario())


def test_read_frame_rejects_unknown_type_and_truncation():
    async def scenario():
        conn = connection()
        await feed_reader(conn, frame(0x1234, b"x"))
        with pytest.raises(RuntimeError):
            await conn._read_frame()
        conn = connection()
        conn._reader = asyncio.StreamReader()
        conn._reader.feed_data(frame(POWER, b"" )[:-1])
        conn._reader.feed_eof()
        with pytest.raises(asyncio.IncompleteReadError):
            await conn._read_frame()

    asyncio.run(scenario())


def test_ra_denied_malformed_and_wrong_identity_are_runtime_errors():
    async def scenario():
        for payload in (ra_payload(code=0x00), ra_payload(code=0x11),
                        ra_payload()[:8], ra_payload(tester=0x0E01),
                        ra_payload(ecu=0x0002)):
            conn = connection()
            conn._reader = asyncio.StreamReader()
            conn._writer = RecordingWriter()
            conn._connected = True
            conn._reader.feed_data(frame(RA_RESPONSE, payload))
            with pytest.raises(RuntimeError):
                await conn._do_routing_activation(TESTER)

    asyncio.run(scenario())


def test_ra_success_both_versions_starts_reader_and_lifecycle():
    async def scenario():
        for version, size in ((0x02, 9), (0x03, 13)):
            conn = connection()
            conn._reader = asyncio.StreamReader()
            conn._writer = RecordingWriter()
            conn._connected = True
            try:
                conn._reader.feed_data(frame(RA_RESPONSE, ra_payload() + b"x" * (size - 9), version))
                await conn._do_routing_activation(TESTER)
                assert conn._writer.frames[0] == frame(RA_REQUEST, struct.pack("!HB", TESTER, 0) + b"\0" * 4)
                conn._reader_task = asyncio.create_task(conn._background_reader())
                conn._reader.feed_data(frame(ALIVE_REQUEST, b"", version))
                conn._reader.feed_data(frame(DIAGNOSTIC, b"abcde", version))
                assert await asyncio.wait_for(conn.recv(), 0.3) == frame(DIAGNOSTIC, b"abcde", version)
            finally:
                await asyncio.wait_for(conn.close(), 0.3)
            assert conn._writer.closed

    asyncio.run(scenario())


def test_connect_refusal_closes_raw_socket_and_preserves_cause():
    async def scenario():
        conn = connection()
        raw = FakeSocket()
        failure = ConnectionRefusedError("refused")
        with patch("ecu_client.socket.socket", return_value=raw), \
             patch.object(conn._loop, "sock_connect", AsyncMock(side_effect=failure)), \
             patch("ecu_client.socket.if_nametoindex", return_value=1):
            with pytest.raises(ConnectionRefusedError) as caught:
                await conn.connect()
        assert caught.value is failure
        assert raw.closed
        assert not conn.connected
        assert conn._reader_task is None

    asyncio.run(scenario())


@pytest.mark.parametrize("cancel_after", ["sock", "stream"])
def test_connect_cancellation_closes_untransferred_resources(cancel_after):
    async def scenario():
        conn = connection()
        raw = FakeSocket()
        gate = asyncio.Event()
        async def block(*args):
            await gate.wait()
        async def open_stream(*args, **kwargs):
            await gate.wait()
        with patch("ecu_client.socket.socket", return_value=raw), \
             patch("ecu_client.socket.if_nametoindex", return_value=1), \
             patch.object(conn._loop, "sock_connect",
                          side_effect=block if cancel_after == "sock" else AsyncMock()), \
             patch("ecu_client.asyncio.open_connection", side_effect=open_stream):
            task = asyncio.create_task(conn.connect())
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert raw.closed
        assert not conn.connected
        assert conn._reader_task is None

    asyncio.run(scenario())


def test_open_connection_failure_closes_socket_and_is_terminal():
    async def scenario():
        conn = connection()
        raw = FakeSocket()
        failure = OSError("open failed")
        with patch("ecu_client.socket.socket", return_value=raw), \
             patch.object(conn._loop, "sock_connect", AsyncMock()), \
             patch("ecu_client.asyncio.open_connection", AsyncMock(side_effect=failure)), \
             patch("ecu_client.socket.if_nametoindex", return_value=1):
            with pytest.raises(OSError) as caught:
                await conn.connect()
        assert caught.value is failure
        assert raw.closed and not conn.connected
        with pytest.raises(ConnectionError):
            await conn.connect()

    asyncio.run(scenario())


def test_connect_guard_rejects_repeated_setup():
    async def scenario():
        conn = connection()
        conn._connected = True
        with pytest.raises(RuntimeError):
            await conn.connect()
        conn._connected = False
        conn._connecting = True
        with pytest.raises(RuntimeError):
            await conn.connect()

    asyncio.run(scenario())


def test_session_passes_configured_payload_limit():
    async def scenario():
        from middleware import MiddlewareChain
        from routing import RoutingTable
        from session import DoIPSession
        from unittest.mock import patch
        cfg = _make_app_config()
        cfg.doip.max_payload_bytes = 123
        session = DoIPSession(asyncio.StreamReader(), RecordingWriter(), cfg,
                              RoutingTable(cfg.routing_table), MiddlewareChain([]),
                              asyncio.get_running_loop(), None)
        with patch("ecu_client.ECUConnection") as cls:
            obj = cls.return_value
            obj.connect = AsyncMock()
            obj.close = AsyncMock()
            await session._connect_to_ecu(ENTRY_ECU, b"raw")
            assert cls.call_args.kwargs["max_payload_bytes"] == 123
        await session._cleanup()

    asyncio.run(scenario())


def test_background_reader_malformed_frame_is_terminal_without_client_nack():
    async def scenario():
        conn = connection()
        conn._reader = asyncio.StreamReader()
        conn._writer = RecordingWriter()
        conn._connected = True
        conn._reader.feed_data(frame(POWER, b""))
        conn._reader.feed_eof()
        task = asyncio.create_task(conn._background_reader())
        await asyncio.wait_for(task, 0.3)
        assert not conn.connected
        assert conn._writer.frames == []
        with pytest.raises(ConnectionError):
            await conn.recv()

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["denied", "shape", "tester", "entity", "eof", "timeout"])
def test_connect_ra_failure_closes_owned_writer(failure):
    async def scenario():
        conn, raw = connection(), FakeSocket()
        reader, writer = asyncio.StreamReader(), RecordingWriter()
        payloads = {"denied": ra_payload(code=3), "shape": ra_payload()[:5],
                    "tester": ra_payload(tester=0x0E55), "entity": ra_payload(ecu=2)}
        if failure in payloads:
            reader.feed_data(frame(RA_RESPONSE, payloads[failure]))
        reader.feed_eof()
        expected = {"eof": asyncio.IncompleteReadError, "timeout": asyncio.TimeoutError}.get(
            failure, RuntimeError)
        with patch("ecu_client.socket.socket", return_value=raw), \
             patch("ecu_client.socket.if_nametoindex", return_value=1), \
             patch.object(conn._loop, "sock_connect", AsyncMock()), \
             patch("ecu_client.asyncio.open_connection", AsyncMock(return_value=(reader, writer))):
            if failure == "timeout":
                conn._read_frame = AsyncMock(side_effect=asyncio.TimeoutError())
            with pytest.raises(expected) as caught:
                await asyncio.wait_for(conn.connect(), 0.5)
        assert writer.closed and not raw.closed  # stream transport owns raw
        assert not conn.connected and conn._reader_task is None
        assert conn._terminal_error is caught.value
        assert len(writer.frames) == 1  # RA only; no client Header NACK

    asyncio.run(scenario())


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("size", [9, 13])
def test_connect_success_transfers_ownership_and_starts_reader(version, size):
    async def scenario():
        conn, raw = connection(), FakeSocket()
        reader, writer = asyncio.StreamReader(), RecordingWriter()
        reader.feed_data(frame(RA_RESPONSE, ra_payload(extra=b"x" * (size - 9)), version))
        try:
            with patch("ecu_client.socket.socket", return_value=raw), \
                 patch("ecu_client.socket.if_nametoindex", return_value=1), \
                 patch.object(conn._loop, "sock_connect", AsyncMock()), \
                 patch("ecu_client.asyncio.open_connection", AsyncMock(return_value=(reader, writer))):
                await asyncio.wait_for(conn.connect(), 0.5)
            assert conn.connected and conn._reader_task is not None
            assert not raw.closed and not writer.closed
            reader.feed_data(frame(DIAGNOSTIC, b"abcde", version))
            assert await asyncio.wait_for(conn.recv(), 0.3) == frame(DIAGNOSTIC, b"abcde", version)
        finally:
            await asyncio.wait_for(conn.close(), 0.3)
        assert writer.closed and conn._reader_task.done()

    asyncio.run(scenario())


def test_repeated_cancellation_during_ra_finishes_writer_close():
    async def scenario():
        conn, raw = connection(), FakeSocket()
        reader, writer = asyncio.StreamReader(), RecordingWriter()
        entered, release = asyncio.Event(), asyncio.Event()
        async def wait_closed():
            entered.set()
            await release.wait()
        writer.wait_closed = wait_closed
        with patch("ecu_client.socket.socket", return_value=raw), \
             patch("ecu_client.socket.if_nametoindex", return_value=1), \
             patch.object(conn._loop, "sock_connect", AsyncMock()), \
             patch("ecu_client.asyncio.open_connection", AsyncMock(return_value=(reader, writer))):
            task = asyncio.create_task(conn.connect())
            try:
                async def sent():
                    while not writer.frames:
                        assert not task.done()
                        await asyncio.sleep(0)
                await asyncio.wait_for(sent(), 0.3)
                task.cancel()
                await asyncio.wait_for(entered.wait(), 0.3)
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done() and writer.closed
                release.set()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 0.3)
                assert not conn.connected and conn._reader_task is None
                assert not raw.closed
                assert isinstance(conn._terminal_error, asyncio.CancelledError)
            finally:
                release.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())


def test_setblocking_failure_closes_raw_socket():
    async def scenario():
        conn, raw = connection(), FakeSocket()
        raw.setblocking = lambda value: (_ for _ in ()).throw(OSError("setblocking failed"))
        with patch("ecu_client.socket.socket", return_value=raw), \
             patch("ecu_client.socket.if_nametoindex", return_value=1):
            with pytest.raises(OSError):
                await conn.connect()
        assert raw.closed and not conn.connected

    asyncio.run(scenario())


HEADER_NACK = 0x0000


@pytest.mark.parametrize("code", [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xFF])
def test_ra_ignores_each_valid_header_nack_code_before_valid_response(code):
    async def scenario():
        conn = connection()
        conn._reader = asyncio.StreamReader()
        conn._writer = RecordingWriter()
        conn._connected = True
        conn._reader.feed_data(frame(HEADER_NACK, bytes([code])))
        conn._reader.feed_data(frame(RA_RESPONSE, ra_payload()))

        await conn._do_routing_activation(TESTER)
        assert conn._writer.frames == [
            frame(RA_REQUEST, struct.pack("!HB", TESTER, 0) + b"\0" * 4)
        ]

    asyncio.run(scenario())


def test_background_valid_header_nack_is_ignored_and_diagnostic_is_only_received_frame():
    async def scenario():
        conn = connection()
        conn._reader = asyncio.StreamReader()
        conn._writer = RecordingWriter()
        conn._connected = True
        conn._tester_logical_addr = TESTER
        diagnostic = frame(DIAGNOSTIC, b"abcde")
        conn._reader.feed_data(frame(HEADER_NACK, b"\xFE"))
        conn._reader.feed_data(diagnostic)
        conn._reader_task = asyncio.create_task(conn._background_reader())
        try:
            assert await asyncio.wait_for(conn.recv(), 0.3) == diagnostic
            assert conn._writer.frames == []
        finally:
            await asyncio.wait_for(conn.close(), 0.3)

    asyncio.run(scenario())


@pytest.mark.parametrize("payload", [b"", b"\x00\x01"])
def test_background_malformed_header_nack_is_terminal_without_client_nack(payload):
    async def scenario():
        conn = connection()
        conn._reader = asyncio.StreamReader()
        conn._writer = RecordingWriter()
        conn._connected = True
        conn._reader.feed_data(frame(HEADER_NACK, payload))
        conn._reader_task = asyncio.create_task(conn._background_reader())
        await asyncio.wait_for(conn._reader_task, 0.3)

        assert not conn.connected
        assert conn._writer.frames == []
        with pytest.raises(ConnectionError):
            await conn.recv()

    asyncio.run(scenario())


def test_three_valid_header_nacks_during_ra_fail_with_bounded_setup_budget():
    async def scenario():
        conn = connection()
        conn._reader = asyncio.StreamReader()
        conn._writer = RecordingWriter()
        conn._connected = True
        for code in (0x00, 0x01, 0xFF):
            conn._reader.feed_data(frame(HEADER_NACK, bytes([code])))

        with pytest.raises(RuntimeError, match="no Routing Activation Response"):
            await asyncio.wait_for(conn._do_routing_activation(TESTER), 0.3)
        assert conn._writer.frames == [
            frame(RA_REQUEST, struct.pack("!HB", TESTER, 0) + b"\0" * 4)
        ]

    asyncio.run(scenario())
