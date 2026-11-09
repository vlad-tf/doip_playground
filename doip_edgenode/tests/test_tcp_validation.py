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


# ---------------------------------------------------------------------------
# Header NACK action matrix on the tester-facing stream.
#
# Every vector below is spelled out as hex text so the expected bytes do not
# depend on the production frame builder or validator.  Behaviour under test:
#   bad version/inverse -> NACK 00, then the connection is closed
#   unsupported type    -> NACK 01, declared body discarded, connection stays
#   over the cap        -> NACK 02, declared body discarded, connection stays
#   wrong shape         -> NACK 04, then closed, body never read
# ---------------------------------------------------------------------------

NACK_00 = bytes.fromhex("02fd 0000 00000001 00")
NACK_01 = bytes.fromhex("02fd 0000 00000001 01")
NACK_02 = bytes.fromhex("02fd 0000 00000001 02")
NACK_04 = bytes.fromhex("02fd 0000 00000001 04")
POWER_REQUEST = bytes.fromhex("02fd 4003 00000000")
POWER_RESPONSE = bytes.fromhex("02fd 4004 00000001 01")


def _wire(ptype_hex, length, version_hex="02fd"):
    """Header text -> bytes, with the 4-byte length written as hex digits."""
    return bytes.fromhex(f"{version_hex}{ptype_hex}{length:08x}")


class RecordingReader:
    """StreamReader stand-in that records every requested read size."""

    def __init__(self):
        self._inner = asyncio.StreamReader()
        self.sizes = []

    def feed_data(self, data):
        self._inner.feed_data(data)

    def feed_eof(self):
        self._inner.feed_eof()

    async def readexactly(self, size):
        self.sizes.append(size)
        return await self._inner.readexactly(size)


def _spied_session(max_payload=64, activated=False):
    """Session whose Scapy and dispatch seams fail the test if reached."""
    sess = _session(max_payload)
    sess.activated = activated
    sess.reader = RecordingReader()
    sess._dissect = Mock(side_effect=AssertionError("rejected input reached Scapy"))
    sess._dispatch = AsyncMock()
    return sess


async def _run_until_session_closes(sess, data):
    """Feed bytes without EOF; run() must end on its own, i.e. the session closed."""
    sess.reader.feed_data(data)
    await asyncio.wait_for(sess.run(), .5)
    assert sess.writer.closed


async def _run_while_open(sess, data, expected_frames):
    """Feed bytes without EOF; the socket must still be open once replies are out."""
    task = asyncio.create_task(sess.run())
    sess.reader.feed_data(data)
    for _ in range(100):
        if len(sess.writer.frames) >= expected_frames or task.done():
            break
        await asyncio.sleep(.005)
    assert not task.done()
    assert not sess.writer.closed
    sess.reader.feed_eof()
    await asyncio.wait_for(task, .5)


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("version_hex", [
    "01fe",  # version below the accepted set, consistent inverse
    "04fb",  # version above the accepted set, consistent inverse
    "00ff",
    "ff00",  # discovery-only default pattern is not valid on the stream
    "0200",  # inverse byte missing
    "0202",  # inverse not complemented
    "02fe",
    "03fd",  # accepted version with the wrong inverse
    "03ff",
])
def test_matrix_tcp_bad_pattern_sends_00_then_closes_without_reading_body(activated, version_hex):
    async def scenario():
        sess = _spied_session(activated=activated)
        # The follow-up frame is valid but must be neither read nor answered.
        await _run_until_session_closes(
            sess, _wire("4003", 0, version_hex) + POWER_REQUEST)
        assert sess.writer.frames == [NACK_00]
        assert sess.reader.sizes == [8]
        sess._dissect.assert_not_called()
        sess._dispatch.assert_not_awaited()
    asyncio.run(scenario())


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("ptype_hex,body_len", [
    ("0006", 13), ("0006", 0), ("0001", 0), ("0002", 6), ("0003", 17),
    ("0004", 33), ("4002", 3), ("4004", 1), ("8002", 5), ("8003", 5),
    ("1234", 1), ("ffff", 30),
    ("0006", 300),  # also above the cap: the type check comes first
])
def test_matrix_tcp_unsupported_type_sends_01_discards_body_and_stays_open(
        activated, ptype_hex, body_len):
    async def scenario():
        sess = _spied_session(max_payload=64, activated=activated)
        del sess._dissect  # let the real dissector handle the healthy follow-up
        del sess._dispatch
        body = b"\xa5" * body_len
        data = _wire(ptype_hex, body_len) + body + POWER_REQUEST + POWER_REQUEST
        await _run_while_open(sess, data, expected_frames=3)
        # A rejected body that looks like a frame is data; both follow-ups answered.
        assert sess.writer.frames == [NACK_01, POWER_RESPONSE, POWER_RESPONSE]
        assert sess.reader.sizes[:2] == ([8, body_len] if body_len else [8, 8])
    asyncio.run(scenario())


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("ptype_hex,declared", [
    ("4003", 65),  # also the wrong shape; the cap is evaluated first
    ("8001", 65),
    ("0005", 100),
    ("0007", 200),
    ("0008", 65),
    ("4001", 4096),
    ("0000", 65),
])
def test_matrix_tcp_over_cap_sends_02_discards_body_and_stays_open(
        activated, ptype_hex, declared):
    async def scenario():
        sess = _spied_session(max_payload=64, activated=activated)
        del sess._dissect
        del sess._dispatch
        # Embedded bytes that spell a valid request must not be answered.
        body = (POWER_REQUEST + b"\x00" * declared)[:declared]
        data = _wire(ptype_hex, declared) + body + POWER_REQUEST
        await _run_while_open(sess, data, expected_frames=2)
        assert sess.writer.frames == [NACK_02, POWER_RESPONSE]
        assert sess.reader.sizes[:2] == [8, declared]
    asyncio.run(scenario())


def test_matrix_tcp_over_cap_discard_reads_in_bounded_chunks_then_recovers():
    async def scenario():
        sess = _spied_session(max_payload=64)
        del sess._dissect
        del sess._dispatch
        declared = 9000
        data = _wire("8001", declared) + b"\x00" * declared + POWER_REQUEST
        await _run_while_open(sess, data, expected_frames=2)
        assert sess.writer.frames == [NACK_02, POWER_RESPONSE]
        assert sess.reader.sizes[:4] == [8, 4096, 4096, 808]
        assert max(sess.reader.sizes) <= 4096
    asyncio.run(scenario())


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("ptype_hex,length", [
    ("0000", 0), ("0000", 2),
    ("0005", 0), ("0005", 6), ("0005", 8), ("0005", 12),
    ("0007", 1), ("0008", 0), ("0008", 1), ("0008", 3),
    ("4001", 1), ("4003", 1), ("4003", 64),  # last one is exactly the cap
    ("8001", 0), ("8001", 4),
])
def test_matrix_tcp_wrong_shape_sends_04_then_closes_without_body_or_dispatch(
        activated, ptype_hex, length):
    async def scenario():
        sess = _spied_session(max_payload=64, activated=activated)
        data = _wire(ptype_hex, length) + b"x" * length + POWER_REQUEST
        await _run_until_session_closes(sess, data)
        assert sess.writer.frames == [NACK_04]
        assert sess.reader.sizes == [8]
        sess._dissect.assert_not_called()
        sess._dispatch.assert_not_awaited()
    asyncio.run(scenario())


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("ptype_hex,declared,supplied,nack", [
    ("0006", 10, 3, NACK_01),   # unsupported type, body cut short
    ("0006", 10, 0, NACK_01),   # unsupported type, no body at all
    ("4003", 100, 10, NACK_02),  # over the cap, body cut short
    ("8001", 100, 0, NACK_02),
])
def test_matrix_tcp_eof_while_discarding_closes_without_dispatch(
        activated, ptype_hex, declared, supplied, nack):
    async def scenario():
        sess = _spied_session(max_payload=64, activated=activated)
        sess.reader.feed_data(_wire(ptype_hex, declared) + b"x" * supplied)
        sess.reader.feed_eof()
        await asyncio.wait_for(sess.run(), .5)
        assert sess.writer.frames == [nack]
        assert sess.writer.closed
        sess._dissect.assert_not_called()
        sess._dispatch.assert_not_awaited()
    asyncio.run(scenario())


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("ptype_hex,declared,nack", [
    ("0006", 4096, NACK_01),
    ("4003", 4096, NACK_02),
    ("0006", 0xFFFFFFFF, NACK_01),
    ("8001", 0xFFFFFFFF, NACK_02),
])
def test_matrix_tcp_discard_deadline_closes_without_dispatch(
        activated, ptype_hex, declared, nack):
    async def scenario():
        sess = _spied_session(max_payload=64, activated=activated)
        sess.reader = BlockingReader(_wire(ptype_hex, declared))
        with patch.object(session_module, "_TCP_DISCARD_TIMEOUT_S", .01):
            await asyncio.wait_for(sess.run(), .5)
        assert sess.writer.frames == [nack]
        assert sess.writer.closed
        assert sess.reader.calls == [8, 4096]
        sess._dissect.assert_not_called()
        sess._dispatch.assert_not_awaited()
    asyncio.run(scenario())


@pytest.mark.parametrize("activated", [False, True])
def test_matrix_tcp_version_three_header_with_valid_frame_is_accepted(activated):
    async def scenario():
        sess = _session()
        sess.activated = activated
        sess.reader = RecordingReader()
        await _run_while_open(
            sess, bytes.fromhex("03fc 4003 00000000"), expected_frames=1)
        assert len(sess.writer.frames) == 1
        reply = sess.writer.frames[0]
        # Only the type and body are pinned here; the reply's edition byte is
        # a separate policy that this matrix deliberately does not fix.
        assert reply[1] == reply[0] ^ 0xFF
        assert reply[2:] == POWER_RESPONSE[2:]
    asyncio.run(scenario())


# Real loopback sockets: the NACK reaches the peer as exactly nine bytes and the
# peer then observes either an open, healthy stream or an orderly close.

def _loopback_exchange(script, max_payload=64):
    async def scenario():
        loop = asyncio.get_running_loop()
        cfg = _make_app_config()
        cfg.doip.max_payload_bytes = max_payload
        handlers = []

        async def handler(reader, writer):
            handlers.append(asyncio.current_task())
            sess = DoIPSession(reader, writer, cfg, RoutingTable(cfg.routing_table),
                               MiddlewareChain([]), loop, None)
            await sess.run()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await asyncio.wait_for(script(reader, writer), 3)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            if handlers:
                await asyncio.wait_for(asyncio.gather(*handlers), 3)
            server.close()
            await asyncio.wait_for(server.wait_closed(), 3)
    asyncio.run(scenario())


async def _read_exact(reader, size):
    return await asyncio.wait_for(reader.readexactly(size), 1.0)


@pytest.mark.parametrize("ptype_hex,body_len,nack", [
    ("0006", 20, NACK_01),   # unsupported type
    ("8001", 65, NACK_02),   # supported type above the cap of 64
])
def test_loopback_discard_rejections_keep_socket_open_for_healthy_request(
        ptype_hex, body_len, nack):
    async def script(reader, writer):
        writer.write(_wire(ptype_hex, body_len) + b"\x5a" * body_len)
        await writer.drain()
        assert await _read_exact(reader, 9) == nack
        for _ in range(2):
            writer.write(POWER_REQUEST)
            await writer.drain()
            assert await _read_exact(reader, 9) == POWER_RESPONSE
    _loopback_exchange(script)


@pytest.mark.parametrize("header,nack", [
    (bytes.fromhex("02fe 4003 00000000"), NACK_00),  # wrong inverse
    (bytes.fromhex("01fe 4003 00000000"), NACK_00),  # unsupported version
    (bytes.fromhex("02fd 4003 00000001"), NACK_04),  # request must be empty
    (bytes.fromhex("02fd 0008 00000003"), NACK_04),  # alive reply must be 2 bytes
])
def test_loopback_close_rejections_send_nack_then_end_of_stream(header, nack):
    async def script(reader, writer):
        writer.write(header)
        await writer.drain()
        assert await _read_exact(reader, 9) == nack
        assert await asyncio.wait_for(reader.read(), 1.0) == b""
    _loopback_exchange(script)
