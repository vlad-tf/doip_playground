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

"""TCP stream framing validation (F15)."""

import asyncio
import struct
from unittest.mock import AsyncMock, Mock, patch

import pytest

import session as session_module
from session import DoIPProtocolError, DoIPSession
from middleware import MiddlewareChain
from routing import RoutingTable
from tests.test_routing_activation import RecordingWriter, make_session
from tests.test_ecu_setup import frame
from tests.test_session import _make_app_config


SUPPORTED = (0x0000, 0x0005, 0x0007, 0x0008, 0x4001, 0x4003, 0x8001)
SHAPES = {
    0x0000: (1,), 0x0005: (7, 11), 0x0007: (0,), 0x0008: (2,),
    0x4001: (0,), 0x4003: (0,), 0x8001: "diag",
}


def _session(max_payload=64):
    cfg = _make_app_config()
    cfg.doip.max_payload_bytes = max_payload
    return DoIPSession(asyncio.StreamReader(), RecordingWriter(), cfg,
                       RoutingTable(cfg.routing_table), MiddlewareChain([]),
                       asyncio.get_running_loop(), None)


def _header(ptype, length, version=2, inverse=None):
    if inverse is None:
        inverse = 0xFF ^ version
    return struct.pack("!BBHI", version, inverse, ptype, length)


def _valid_payloads():
    for ptype, shape in SHAPES.items():
        lengths = (5,) if shape == "diag" else shape
        for length in lengths:
            yield ptype, (b"\0\1\0\2x" if shape == "diag" else b"x" * length)


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("ptype,payload", list(_valid_payloads()))
def test_supported_shapes_are_validated_before_or_after_activation(activated, ptype, payload):
    async def scenario():
        sess = _session()
        sess.activated = activated
        sess.reader.feed_data(frame(ptype, payload))
        assert await sess._read_frame() == frame(ptype, payload)
        await sess._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("ptype,bad_length", [
    (0x0000, 0), (0x0005, 6), (0x0005, 8), (0x0005, 9), (0x0005, 10), (0x0005, 12),
    (0x0007, 1), (0x0008, 1), (0x0008, 3),
    (0x4001, 1), (0x4003, 1), (0x8001, 4),
])
def test_wrong_supported_shape_closes_before_reading_body(activated, ptype, bad_length):
    async def scenario():
        sess = _session()
        sess.activated = activated
        sess.reader.feed_data(_header(ptype, bad_length))
        with pytest.raises(DoIPProtocolError):
            await sess._read_frame()
        assert sess.writer.frames[-1] == frame(0, b"\x04")
        await sess._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("ptype", [0x0006, 0x0009, 0x4002, 0x4004, 0x8002, 0x8003,
                                    0x0001, 0x0002, 0x0003, 0x0004, 0x4005])
def test_unsupported_response_and_udp_types_return_code_one_before_cap_or_shape(ptype):
    async def scenario():
        sess = _session(1)
        # Two body bytes exceed the cap, while a one-byte body would not.
        sess.reader.feed_data(_header(ptype, 2) + b"xx")
        assert await sess._read_frame() is None
        assert sess.writer.frames[-1] == frame(0, b"\x01")
        await sess._cleanup()
    asyncio.run(scenario())


def test_invalid_pattern_is_protocol_error_and_does_not_consume_body():
    async def scenario():
        sess = _session()
        sess.reader.feed_data(_header(0x4003, 0, version=0x01))
        with pytest.raises(DoIPProtocolError):
            await sess._read_frame()
        assert sess.writer.frames[-1] == frame(0, b"\0")
        await sess._cleanup()
    asyncio.run(scenario())


@pytest.mark.parametrize("declared", [0, 65])
def test_supported_cap_boundary_and_oversize_discard(declared):
    async def scenario():
        sess = _session(64)
        body = b"a" * declared
        sess.reader.feed_data(_header(0x4003, declared) + body + frame(0x4003))
        if declared == 0:
            assert await sess._read_frame() == frame(0x4003)
        else:
            assert await sess._read_frame() is None
            assert await sess._read_frame() == frame(0x4003)
        await sess._cleanup()
    asyncio.run(scenario())


class ChunkReader:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.calls = []

    async def readexactly(self, size):
        self.calls.append(size)
        if not self.chunks:
            raise asyncio.IncompleteReadError(b"", size)
        data = self.chunks.pop(0)
        if len(data) != size:
            raise AssertionError((size, len(data)))
        await asyncio.sleep(0)
        return data


@pytest.mark.parametrize("cancel", [False, True])
def test_discard_uses_bounded_chunks_yields_and_cancellation_is_safe(cancel):
    async def scenario():
        declared = 9000
        sess = _session(10)
        body = [b"a" * 4096, b"b" * 4096, b"c" * 808]
        reader = ChunkReader([_header(0x4003, declared), *body])
        sess.reader = reader
        with patch.object(session_module, "_TCP_DISCARD_TIMEOUT_S", .01):
            task = asyncio.create_task(sess._read_frame())
            await asyncio.sleep(0)
            if cancel:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                assert await task is None
                assert reader.calls == [8, 4096, 4096, 808]
        await sess._cleanup()
    asyncio.run(scenario())


def test_discard_timeout_closes_without_dispatching_following_frame():
    async def scenario():
        sess = _session(1)
        sess.reader = BlockingReader(_header(0x4003, 4096))
        sess._dispatch = AsyncMock()
        with patch.object(session_module, "_TCP_DISCARD_TIMEOUT_S", .01), \
             pytest.raises(DoIPProtocolError):
            await sess._session_loop()
        sess._dispatch.assert_not_awaited()
        await sess._cleanup()
    asyncio.run(scenario())


def test_actual_run_malformed_frame_never_reaches_scapy_or_dispatch():
    async def scenario():
        sess = _session()
        sess.reader.feed_data(_header(0x0008, 1) + b"x")
        sess.reader.feed_eof()
        sess._dissect = Mock(side_effect=AssertionError("Scapy reached"))
        sess._dispatch = AsyncMock()
        await asyncio.wait_for(sess.run(), .5)
        sess._dissect.assert_not_called()
        sess._dispatch.assert_not_awaited()
        assert sess.writer.closed
    asyncio.run(scenario())


def test_received_nack_is_ignored_then_valid_power_is_handled():
    async def scenario():
        sess = _session()
        writer = sess.writer
        sess._dissect = lambda raw: type("Packet", (), {"payload_type": int.from_bytes(raw[2:4], "big")})()
        async def power():
            await sess._send_raw(frame(0x4004, b"\0"))
        sess._handle_power_mode = AsyncMock(side_effect=power)
        sess.reader.feed_data(frame(0, b"\x01") + frame(0x4003))
        sess.reader.feed_eof()
        await asyncio.wait_for(sess.run(), .5)
        sess._handle_power_mode.assert_awaited_once()
        assert writer.frames == [frame(0x4004, b"\0")]
    asyncio.run(scenario())


def test_invalid_ra_does_not_cancel_initial_timer():
    async def scenario():
        sess, _, _ = make_session(False)
        sess._start_initial_timer()
        timer = sess._initial_timer_task
        sess.reader.feed_data(_header(0x0005, 6) + b"x" * 6)
        with pytest.raises(DoIPProtocolError):
            await sess._session_loop()
        assert sess._initial_timer_task is timer
        assert not timer.done()
        await sess._cleanup()
    asyncio.run(scenario())


class BlockingReader:
    def __init__(self, header):
        self.header = header
        self.calls = []

    async def readexactly(self, size):
        self.calls.append(size)
        if size == 8:
            return self.header
        await asyncio.sleep(10)
        return b"x" * size


def test_fragmented_stream_header_and_body_is_reassembled():
    async def scenario():
        sess = _session()
        raw = frame(0x8001, b"\0\1\0\2x")
        task = asyncio.create_task(sess._read_frame())
        for byte in raw:
            sess.reader.feed_data(bytes([byte]))
            await asyncio.sleep(0)
        assert await task == raw
        await sess._cleanup()
    asyncio.run(scenario())


def test_coalesced_rejected_body_is_consumed_before_following_valid_frame():
    async def scenario():
        sess = _session(1)
        rejected = frame(0x4003, b"xx")
        healthy = frame(0x4003)
        sess.reader.feed_data(rejected + healthy)
        assert await sess._read_frame() is None
        assert await sess._read_frame() == healthy
        await sess._cleanup()
    asyncio.run(scenario())


def test_huge_declared_length_is_bounded_and_allocates_no_body():
    async def scenario():
        sess = _session(1)
        sess.reader = BlockingReader(_header(0x4003, 0xFFFFFFFF))
        with patch.object(session_module, "_TCP_DISCARD_TIMEOUT_S", .01), \
             pytest.raises(DoIPProtocolError):
            await sess._read_frame()
        assert sess.reader.calls == [8, 4096]
        await sess._cleanup()
    asyncio.run(scenario())


def test_eof_during_rejected_body_propagates_and_cleanup_closes():
    async def scenario():
        sess = _session(1)
        sess.reader.feed_data(_header(0x4003, 2) + b"x")
        sess.reader.feed_eof()
        with pytest.raises(asyncio.IncompleteReadError):
            await sess._read_frame()
        await sess._cleanup()
        assert sess.writer.closed
    asyncio.run(scenario())


@pytest.mark.parametrize("version,inverse", [(1, 0xFE), (2, 0x00)])
def test_full_run_pattern_error_sends_zero_and_closes(version, inverse):
    async def scenario():
        sess = _session()
        sess.reader.feed_data(_header(0x4003, 0, version, inverse))
        sess.reader.feed_eof()
        await asyncio.wait_for(sess.run(), .5)
        assert sess.writer.frames == [frame(0, b"\0")]
        assert sess.writer.closed
    asyncio.run(scenario())


@pytest.mark.parametrize("ptype,length", [(0x4003, 1), (0x0008, 3), (0x0005, 8)])
def test_full_run_shape_error_sends_four_and_closes(ptype, length):
    async def scenario():
        sess = _session()
        sess.reader.feed_data(_header(ptype, length) + b"x" * length)
        sess.reader.feed_eof()
        await asyncio.wait_for(sess.run(), .5)
        assert sess.writer.frames == [frame(0, b"\x04")]
        assert sess.writer.closed
    asyncio.run(scenario())


@pytest.mark.parametrize("ptype", [0x0006, 0x4002, 0x0001])
def test_full_run_unsupported_discards_and_dispatches_following_healthy_frame(ptype):
    async def scenario():
        sess = _session(1)
        packet = Mock(payload_type=0x4003)
        sess._dissect = Mock(return_value=packet)
        async def power():
            await sess._send_raw(frame(0x4004, b"\0"))
        sess._handle_power_mode = AsyncMock(side_effect=power)
        sess.reader.feed_data(_header(ptype, 2) + b"xx" + frame(0x4003))
        sess.reader.feed_eof()
        await asyncio.wait_for(sess.run(), .5)
        assert sess.writer.frames == [frame(0, b"\x01"), frame(0x4004, b"\0")]
        sess._dissect.assert_called_once_with(frame(0x4003))
        sess._handle_power_mode.assert_awaited_once()
    asyncio.run(scenario())


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("code", [0, 1, 2, 3, 4, 0xFF])
def test_wire_nack_never_reaches_dissection_or_dispatch(activated, code):
    async def scenario():
        sess = _session()
        sess.activated = activated
        sess._dissect = Mock(side_effect=AssertionError("NACK reached Scapy"))
        sess._dispatch = AsyncMock()
        sess.reader.feed_data(frame(0, bytes([code])))
        sess.reader.feed_eof()
        await asyncio.wait_for(sess.run(), .5)
        sess._dissect.assert_not_called()
        sess._dispatch.assert_not_awaited()
        assert sess.writer.frames == []
        assert sess.writer.closed
    asyncio.run(scenario())


@pytest.mark.parametrize("ptype,code", [(0x0006, 1), (0x8001, 2)])
def test_fragmented_rejected_body_with_embedded_header_then_healthy_dispatch(ptype, code):
    async def scenario():
        sess = _session(1)
        healthy = frame(0x4003)
        # A valid-looking header inside the rejected body is data, not a message.
        body = healthy + b"discard me"
        sess._dissect = Mock(return_value=Mock(payload_type=0x4003))
        async def power():
            await sess._send_raw(frame(0x4004, b"\0"))
        sess._handle_power_mode = AsyncMock(side_effect=power)
        task = asyncio.create_task(sess.run())
        sess.reader.feed_data(_header(ptype, len(body)))
        for byte in body:
            sess.reader.feed_data(bytes([byte]))
            await asyncio.sleep(0)
            sess._dissect.assert_not_called()
        sess.reader.feed_data(healthy)
        sess.reader.feed_eof()
        await asyncio.wait_for(task, .5)
        sess._dissect.assert_called_once_with(healthy)
        assert sess.writer.frames == [frame(0, bytes([code])), frame(0x4004, b"\0")]
        assert sess.writer.closed
    asyncio.run(scenario())


@pytest.mark.parametrize("length", [5, 64])
def test_diagnostic_minimum_and_exact_cap_are_accepted(length):
    async def scenario():
        sess = _session(64)
        raw = frame(0x8001, b"x" * length)
        sess.reader.feed_data(raw)
        assert await asyncio.wait_for(sess._read_frame(), .5) == raw
        assert sess.writer.frames == []
        await sess._cleanup()
    asyncio.run(scenario())


def test_two_byte_header_nack_is_invalid_before_body_read():
    async def scenario():
        sess = _session()
        sess.reader.feed_data(_header(0, 2))
        with pytest.raises(DoIPProtocolError):
            await asyncio.wait_for(sess._read_frame(), .5)
        assert sess.writer.frames == [frame(0, b"\x04")]
        await sess._cleanup()
    asyncio.run(scenario())
